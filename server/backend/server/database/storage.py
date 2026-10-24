import uuid
# server/database/storage.py — SQLite storage layer (WAL mode, thread-local)
"""
Thread-local persistent connections, write lock with retry on contention,
paginated export, alert dedup, and single-query system+alert counts.

Write contention handling:
  SQLite WAL mode allows concurrent readers but serialises writers.
  Under 10+ agents sending events simultaneously, the Python-level
  _write_lock prevents most contention, but the DB itself can still
  return OperationalError("database is locked") if a write takes >5s.
  _write() wraps every write with up to WRITE_RETRIES retries and
  exponential back-off so events are never silently dropped.
"""
import sqlite3, os, time, json, threading
from typing import List, Optional
from server.config import DB_PATH, ALERT_DEDUP_SECS

_write_lock   = threading.Lock()
_local        = threading.local()
WRITE_RETRIES = 5          # max attempts on OperationalError
WRITE_BACKOFF = 0.05       # initial back-off seconds (doubles each retry)

# ── Connection pooling for high concurrency (50 agents) ──────────────────────
_connection_pool = []
_pool_lock = threading.Lock()
MAX_POOL_SIZE = 20         # Maximum number of pooled connections
CONN_MAX_AGE = 3600        # Connection lifetime in seconds (1 hour)


def _get_pooled_conn():
    """
    Get a connection from the pool or create a new one.
    Closes stale connections (age > CONN_MAX_AGE) to prevent handle leaks.
    """
    now = time.time()
    
    with _pool_lock:
        # Try to reuse an existing connection
        while _connection_pool:
            conn, created_at = _connection_pool.pop(0)
            # Check if connection is still valid and not too old
            if now - created_at < CONN_MAX_AGE:
                try:
                    # Test connection with a simple query
                    conn.execute("SELECT 1")
                    return conn
                except Exception:
                    # Connection is broken, close and continue
                    try:
                        conn.close()
                    except Exception:
                        pass
            else:
                # Connection too old, close it
                try:
                    conn.close()
                except Exception:
                    pass
    
    # No valid connection in pool, create new one
    return _create_connection()


def _return_to_pool(conn):
    """Return a connection to the pool if pool is not full."""
    with _pool_lock:
        if len(_connection_pool) < MAX_POOL_SIZE:
            _connection_pool.append((conn, time.time()))
            return
    
    # Pool is full, close the connection
    try:
        conn.close()
    except Exception:
        pass


def _create_connection():
    """Create a new optimized SQLite connection for high concurrency."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    c = sqlite3.connect(DB_PATH, check_same_thread=False,
                        timeout=20,          # Increased from 10s for better concurrency
                        isolation_level=None)  # Autocommit mode for WAL performance
    c.row_factory = sqlite3.Row
    
    # Optimized settings for 50-agent concurrent writes
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA synchronous=FULL")         # Commit acknowledgements survive a completed disk flush
    c.execute("PRAGMA cache_size=-16000")        # 16MB cache (increased from 8MB)
    c.execute("PRAGMA temp_store=MEMORY")
    c.execute("PRAGMA busy_timeout=20000")       # 20s busy handler (increased)
    c.execute("PRAGMA wal_autocheckpoint=1000")  # Checkpoint every 1000 pages
    c.execute("PRAGMA mmap_size=268435456")      # 256MB mmap for performance
    
    return c


def _conn():
    """Return a persistent per-thread SQLite connection with pooling."""
    if not getattr(_local, "conn", None):
        _local.conn = _get_pooled_conn()
    return _local.conn


def close_thread_connection():
    """
    Close the current thread's connection and return it to the pool.
    Call this from long-running threads when they exit to prevent leaks.
    """
    conn = getattr(_local, "conn", None)
    if conn:
        _return_to_pool(conn)
        _local.conn = None


def _execute_write(fn):
    """
    Execute a write function inside _write_lock with retry on DB lock contention.
    fn receives a connection object and must call conn.commit() before returning.
    Retries up to WRITE_RETRIES times with exponential back-off.
    Raises RuntimeError if all retries are exhausted.
    """
    delay = WRITE_BACKOFF
    last_err = None
    for attempt in range(1, WRITE_RETRIES + 1):
        try:
            with _write_lock:
                fn(_conn())
            return
        except sqlite3.OperationalError as e:
            last_err = e
            if "locked" in str(e).lower() and attempt < WRITE_RETRIES:
                time.sleep(delay)
                delay *= 2   # exponential back-off: 50ms, 100ms, 200ms, 400ms
                # Force a fresh connection — the old one may be in a bad state
                _local.conn = None
            else:
                raise
    raise RuntimeError(
        f"DB write failed after {WRITE_RETRIES} retries: {last_err}"
    )


def init_db():
    c = _conn()
    c.executescript("""
        CREATE TABLE IF NOT EXISTS events(
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            system_id TEXT    NOT NULL,
            parent    TEXT    NOT NULL,
            child     TEXT    NOT NULL,
            pid       INTEGER NOT NULL,
            cmdline   TEXT    DEFAULT '',
            sha256    TEXT    DEFAULT '',
            timestamp INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS alerts(
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            system_id  TEXT    NOT NULL,
            process    TEXT    NOT NULL,
            risk_level TEXT    NOT NULL,
            risk_score INTEGER NOT NULL,
            reason     TEXT    NOT NULL,
            technique  TEXT    DEFAULT '',
            confidence TEXT    DEFAULT 'MEDIUM',
            ioc_hit    TEXT    DEFAULT '',
            timestamp  INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS commands(
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            system_id   TEXT    NOT NULL,
            action      TEXT    NOT NULL,
            params      TEXT    NOT NULL DEFAULT '{}',
            status      TEXT    NOT NULL DEFAULT 'pending',
            result      TEXT,
            created_at  INTEGER NOT NULL,
            executed_at INTEGER
        );
        CREATE TABLE IF NOT EXISTS systems(
            system_id   TEXT PRIMARY KEY,
            hostname    TEXT,
            platform    TEXT,
            ip_address  TEXT,
            agent_ver   TEXT    DEFAULT '3.0',
            first_seen  INTEGER NOT NULL,
            last_seen   INTEGER NOT NULL,
            status      TEXT    DEFAULT 'online'
        );
        CREATE TABLE IF NOT EXISTS audit_log(
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            username  TEXT    NOT NULL,
            action    TEXT    NOT NULL,
            detail    TEXT    DEFAULT '',
            ip        TEXT    DEFAULT '',
            timestamp INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS suppressions(
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            system_id     TEXT    NOT NULL,
            child         TEXT    NOT NULL,
            reason_prefix TEXT    NOT NULL,
            added_by      TEXT    DEFAULT 'system',
            created_at    INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS incidents(
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            system_id   TEXT    NOT NULL,
            title       TEXT    NOT NULL,
            severity    TEXT    NOT NULL DEFAULT 'MEDIUM',
            status      TEXT    NOT NULL DEFAULT 'open',
            alert_ids   TEXT    NOT NULL DEFAULT '[]',
            first_seen  INTEGER NOT NULL,
            last_seen   INTEGER NOT NULL,
            summary     TEXT    DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS alert_feedback(
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id  INTEGER NOT NULL,
            verdict   TEXT    NOT NULL,
            username  TEXT    NOT NULL,
            reason    TEXT    DEFAULT '',
            timestamp INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS ie_sid  ON events(system_id);
        CREATE INDEX IF NOT EXISTS ie_ts   ON events(timestamp DESC);
        CREATE INDEX IF NOT EXISTS ie_hash ON events(sha256) WHERE sha256 != '';
        CREATE INDEX IF NOT EXISTS ia_sid  ON alerts(system_id);
        CREATE INDEX IF NOT EXISTS ia_ts   ON alerts(timestamp DESC);
        CREATE INDEX IF NOT EXISTS ic_sid  ON commands(system_id, status);
        CREATE INDEX IF NOT EXISTS iaudit  ON audit_log(timestamp DESC);
        CREATE INDEX IF NOT EXISTS ifb_aid ON alert_feedback(alert_id);
    """)
    for table, columns in {
        'events': {'event_id': "TEXT", 'ppid': 'INTEGER DEFAULT 0', 'create_time': 'REAL DEFAULT 0', 'parent_create_time': 'REAL DEFAULT 0', 'exe_path': "TEXT DEFAULT ''", 'user': "TEXT DEFAULT ''"},
        'alerts': {'event_id': "TEXT DEFAULT ''", 'pid': 'INTEGER DEFAULT 0', 'create_time': 'REAL DEFAULT 0', 'sha256': "TEXT DEFAULT ''", 'exe_path': "TEXT DEFAULT ''"},
        'commands': {'command_uuid': 'TEXT', 'expires_at': 'INTEGER DEFAULT 0', 'lease_until': 'INTEGER DEFAULT 0'},
    }.items():
        existing = {row['name'] for row in c.execute(f'PRAGMA table_info({table})')}
        for column, definition in columns.items():
            if column not in existing:
                c.execute(f'ALTER TABLE {table} ADD COLUMN {column} {definition}')
    # Legacy leased commands may already have executed under integer identities.
    # Cancel them rather than reissuing them under new identities.
    c.execute("UPDATE commands SET status='cancelled' WHERE command_uuid IS NULL AND status IN ('pending','leased')")
    for row in c.execute('SELECT id FROM commands WHERE command_uuid IS NULL').fetchall():
        c.execute('UPDATE commands SET command_uuid=? WHERE id=?', (uuid.uuid4().hex, row['id']))
    c.execute('CREATE UNIQUE INDEX IF NOT EXISTS command_identity ON commands(command_uuid)')
    c.execute('CREATE UNIQUE INDEX IF NOT EXISTS event_identity ON events(system_id,event_id)')
    c.commit()
    print(f"[DB] Ready: {DB_PATH}")


# ── Events ────────────────────────────────────────────────────────────────────

def save_event(e):
    with _write_lock:
        cur = _conn().execute(
            "INSERT OR IGNORE INTO events(system_id,parent,child,pid,cmdline,sha256,timestamp,event_id,ppid,create_time,parent_create_time,exe_path,user) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (e['system_id'], e['parent'], e['child'], e['pid'], e.get('cmdline',''), e.get('sha256',''), e['time'], e['event_id'], e.get('ppid',0), e.get('create_time',0), e.get('parent_create_time',0), e.get('exe_path',''), e.get('user','')))
        return cur.rowcount == 1


def get_events(limit=100, system_id=None):
    if system_id:
        rows = _conn().execute(
            "SELECT * FROM events WHERE system_id=? ORDER BY timestamp DESC LIMIT ?",
            (system_id, limit)).fetchall()
    else:
        rows = _conn().execute(
            "SELECT * FROM events ORDER BY timestamp DESC LIMIT ?", (limit,)).fetchall()
    return [dict(r) for r in rows]


def get_all_events_for_graph():
    rows = _conn().execute(
        "SELECT * FROM (SELECT * FROM events ORDER BY id DESC LIMIT 10000) ORDER BY id ASC"
    ).fetchall()
    return [dict(r) for r in rows]


def get_event_count(system_id=None):
    if system_id:
        r = _conn().execute(
            "SELECT COUNT(*) as n FROM events WHERE system_id=?", (system_id,)).fetchone()
    else:
        r = _conn().execute("SELECT COUNT(*) as n FROM events").fetchone()
    return r["n"]


def get_timeline(system_id, limit=200):
    rows = _conn().execute(
        "SELECT * FROM events WHERE system_id=? ORDER BY timestamp ASC LIMIT ?",
        (system_id, limit)).fetchall()
    return [dict(r) for r in rows]


# ── Alerts ────────────────────────────────────────────────────────────────────

def save_alert(a):
    """Atomic dedup-check + insert. Returns False if duplicate suppressed."""
    cutoff = int(time.time()) - ALERT_DEDUP_SECS
    result = [False]   # use list so inner function can set it

    def _write(c):
        dup = c.execute(
            "SELECT COUNT(*) as n FROM alerts"
            " WHERE system_id=? AND process=? AND reason=? AND "
            "((event_id<>'' AND event_id=?) OR (event_id='' AND ?='' AND pid=? AND create_time>0 AND create_time=? AND timestamp>?))",
            (a["system_id"], a["process"], a["reason"], a.get("event_id", ""), a.get("event_id", ""), a.get("pid", 0), a.get("create_time", 0), cutoff)).fetchone()["n"]
        if dup:
            return   # result stays False
        cur = c.execute(
            "INSERT INTO alerts(system_id,process,risk_level,risk_score,reason,"
            "technique,confidence,ioc_hit,timestamp,event_id,pid,create_time,sha256,exe_path) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (a["system_id"], a["process"], a["risk_level"],
             a.get("risk_score", 0), a.get("reason", ""),
             a.get("technique", ""), a.get("confidence", "MEDIUM"),
             a.get("ioc_hit", ""),
             a.get("timestamp", int(time.time())), a.get("event_id", ""), a.get("pid", 0), a.get("create_time", 0), a.get("sha256", ""), a.get("exe_path", "")))
        c.commit()
        result[0] = cur.lastrowid

    _execute_write(_write)
    return result[0]


def get_alerts(limit=100, system_id=None):
    if system_id:
        rows = _conn().execute(
            "SELECT * FROM alerts WHERE system_id=? ORDER BY timestamp DESC LIMIT ?",
            (system_id, limit)).fetchall()
    else:
        rows = _conn().execute(
            "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,)).fetchall()
    return [dict(r) for r in rows]


def alert_count(system_id=None):
    if system_id:
        r = _conn().execute(
            "SELECT COUNT(*) as n FROM alerts WHERE system_id=?", (system_id,)).fetchone()
    else:
        r = _conn().execute("SELECT COUNT(*) as n FROM alerts").fetchone()
    return r["n"]


def get_alert_stats():
    rows = _conn().execute(
        "SELECT risk_level, COUNT(*) as n FROM alerts GROUP BY risk_level").fetchall()
    tp = _conn().execute(
        "SELECT process, COUNT(*) as n FROM alerts"
        " GROUP BY process ORDER BY n DESC LIMIT 1").fetchone()
    s = {r["risk_level"]: r["n"] for r in rows}
    s["top_process"] = tp["process"] if tp else "-"
    return s


# ── Systems ───────────────────────────────────────────────────────────────────

def upsert_system(info):
    now = int(time.time())
    def _write(c):
        c.execute(
            "INSERT INTO systems(system_id,hostname,platform,ip_address,agent_ver,"
            "first_seen,last_seen,status) VALUES(?,?,?,?,?,?,?,'online')"
            " ON CONFLICT(system_id) DO UPDATE SET"
            " last_seen=excluded.last_seen, status='online',"
            " ip_address=excluded.ip_address,"
            " hostname=COALESCE(excluded.hostname, hostname),"
            " platform=COALESCE(excluded.platform, platform),"
            " agent_ver=COALESCE(excluded.agent_ver, agent_ver)",
            (info.get("system_id", "?"), info.get("hostname"),
             info.get("platform"), info.get("ip_address", ""),
             info.get("agent_ver"), now, now))
        c.commit()
    _execute_write(_write)


def mark_stale(timeout):
    cutoff = int(time.time()) - timeout
    def _write(c):
        c.execute(
            "UPDATE systems SET status='offline' WHERE last_seen<?", (cutoff,))
        c.commit()
    _execute_write(_write)


def get_systems():
    rows = _conn().execute(
        "SELECT * FROM systems ORDER BY last_seen DESC").fetchall()
    return [dict(r) for r in rows]


def get_systems_with_alert_counts():
    """Single JOIN query — no N+1."""
    rows = _conn().execute("""
        SELECT s.*,
               COALESCE(a.total,    0) AS alert_count,
               COALESCE(a.critical, 0) AS critical_count,
               COALESCE(a.high,     0) AS high_count,
               COALESCE(a.med,      0) AS medium_count
        FROM systems s
        LEFT JOIN (
            SELECT system_id,
                   COUNT(*) AS total,
                   SUM(CASE WHEN risk_level='CRITICAL' THEN 1 ELSE 0 END) AS critical,
                   SUM(CASE WHEN risk_level='HIGH'     THEN 1 ELSE 0 END) AS high,
                   SUM(CASE WHEN risk_level='MEDIUM'   THEN 1 ELSE 0 END) AS med
            FROM alerts
            GROUP BY system_id
        ) a ON s.system_id = a.system_id
        ORDER BY s.last_seen DESC
    """).fetchall()
    return [dict(r) for r in rows]


# ── Commands ──────────────────────────────────────────────────────────────────

def queue_cmd(system_id, action, params=None):
    from server.commands import validate_command
    validate_command(action, params or {})
    now = int(time.time())
    with _write_lock:
        cid = uuid.uuid4().hex
        _conn().execute("INSERT INTO commands(system_id,action,params,status,created_at,expires_at,command_uuid) VALUES(?,?,?,'pending',?,?,?)",
                        (system_id, action, json.dumps(params or {}), now, now + 300, cid))
        return cid


def get_pending_cmds(system_id):
    now = int(time.time())
    with _write_lock:
        c = _conn()
        c.execute("UPDATE commands SET status='expired' WHERE status IN ('pending','leased') AND expires_at<=?", (now,))
        rows = c.execute("SELECT * FROM commands WHERE system_id=? AND expires_at>? AND (status='pending' OR (status='leased' AND lease_until<?)) ORDER BY id LIMIT 20", (system_id, now, now)).fetchall()
        for row in rows:
            c.execute("UPDATE commands SET status='leased',lease_until=? WHERE id=?", (now+60, row['id']))
    return [{**dict(row), 'id': row['command_uuid'], 'params': json.loads(row['params'])} for row in rows]


def mark_cmd_done(cid, result, system_id):
    with _write_lock:
        cur = _conn().execute("UPDATE commands SET status='executed',result=?,executed_at=? WHERE command_uuid=? AND system_id=? AND status IN ('leased','executed','expired')",
                              (result, int(time.time()), cid, system_id))
        return cur.rowcount == 1


def get_cmds(system_id=None, limit=50):
    if system_id:
        rows = _conn().execute(
            "SELECT * FROM commands WHERE system_id=? ORDER BY id DESC LIMIT ?",
            (system_id, limit)).fetchall()
    else:
        rows = _conn().execute(
            "SELECT * FROM commands ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    result = []
    for r in rows:
        d = dict(r)
        if 'command_uuid' in d:
            d['id'] = d['command_uuid']
        d["params"] = json.loads(d["params"])
        result.append(d)
    return result


# ── Export / Clear ────────────────────────────────────────────────────────────

def export_all():
    """Paginated export — not one giant memory load."""
    events, alerts = [], []
    page, offset = 500, 0
    while True:
        rows = _conn().execute(
            "SELECT * FROM events ORDER BY id ASC LIMIT ? OFFSET ?",
            (page, offset)).fetchall()
        if not rows:
            break
        events.extend([dict(r) for r in rows])
        offset += page
    offset = 0
    while True:
        rows = _conn().execute(
            "SELECT * FROM alerts ORDER BY id ASC LIMIT ? OFFSET ?",
            (page, offset)).fetchall()
        if not rows:
            break
        alerts.extend([dict(r) for r in rows])
        offset += page
    return {"events": events, "alerts": alerts}


def clear_all():
    def _write(c):
        for t in ("events", "alerts", "commands", "systems"):
            c.execute("DELETE FROM " + t)
        c.commit()
    _execute_write(_write)


# ── Audit log ─────────────────────────────────────────────────────────────────

def write_audit(username: str, action: str, detail: str = "", ip: str = ""):
    def _write(c):
        c.execute(
            "INSERT INTO audit_log(username,action,detail,ip,timestamp)"
            " VALUES(?,?,?,?,?)",
            (username, action, detail, ip, int(time.time())))
        c.commit()
    _execute_write(_write)


def get_audit(limit: int = 200) -> list:
    rows = _conn().execute(
        "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ?", (limit,)).fetchall()
    return [dict(r) for r in rows]


# ── Alert suppression (false positive list) ───────────────────────────────────

def add_suppression(system_id: str, child: str, reason_prefix: str,
                    added_by: str = "system") -> bool:
    """
    Suppress future alerts for a specific (system_id, child, reason_prefix).
    reason_prefix is matched as a LIKE prefix so 'HEURISTIC: Web request' suppresses
    any alert starting with that string on that system for that process.
    """
    result = [False]
    def _write(c):
        dup = c.execute(
            "SELECT COUNT(*) as n FROM suppressions"
            " WHERE system_id=? AND child=? AND reason_prefix=?",
            (system_id, child.lower(), reason_prefix)).fetchone()["n"]
        if dup:
            return
        c.execute(
            "INSERT INTO suppressions(system_id,child,reason_prefix,added_by,created_at)"
            " VALUES(?,?,?,?,?)",
            (system_id, child.lower(), reason_prefix, added_by, int(time.time())))
        c.commit()
        result[0] = True
    _execute_write(_write)
    return result[0]


def remove_suppression(suppression_id: int) -> bool:
    def _write(c):
        c.execute("DELETE FROM suppressions WHERE id=?", (suppression_id,))
        c.commit()
    _execute_write(_write)
    return True


def get_suppressions(system_id: str = None) -> list:
    if system_id:
        rows = _conn().execute(
            "SELECT * FROM suppressions WHERE system_id=? ORDER BY created_at DESC",
            (system_id,)).fetchall()
    else:
        rows = _conn().execute(
            "SELECT * FROM suppressions ORDER BY created_at DESC").fetchall()
    return [dict(r) for r in rows]


def is_suppressed(system_id: str, child: str, reason: str) -> bool:
    """Return True if this alert should be suppressed."""
    child_lc = child.lower()
    rows = _conn().execute(
        "SELECT reason_prefix FROM suppressions WHERE system_id=? AND child=?",
        (system_id, child_lc)).fetchall()
    for row in rows:
        if reason.startswith(row["reason_prefix"]):
            return True
    return False


# ── Alert feedback (Active Learning) ──────────────────────────────────────────

def save_alert_feedback(alert_id: int, verdict: str, username: str, reason: str = "") -> bool:
    """Save analyst feedback for an alert (active learning)."""
    result = [False]
    def _write(c):
        c.execute(
            "INSERT INTO alert_feedback(alert_id,verdict,username,reason,timestamp)"
            " VALUES(?,?,?,?,?)",
            (alert_id, verdict, username, reason, int(time.time())))
        c.commit()
        result[0] = True
    try:
        _execute_write(_write)
    except Exception as e:
        print(f"[DB] Save feedback error: {e}")
    return result[0]


def load_all_feedback() -> List[dict]:
    """Load all alert feedback for active learning initialization."""
    rows = _conn().execute(
        "SELECT * FROM alert_feedback ORDER BY timestamp ASC").fetchall()
    return [dict(r) for r in rows]


def get_alert_by_id(alert_id: int) -> Optional[dict]:
    """Get alert by ID."""
    row = _conn().execute(
        "SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
    return dict(row) if row else None


def get_events_for_alerts(alert_ids: List[int]) -> List[dict]:
    """Get events that correspond to alerts (for active learning)."""
    if not alert_ids:
        return []
    
    # Get alerts first
    placeholders = ",".join("?" * len(alert_ids))
    alert_rows = _conn().execute(
        f"SELECT * FROM alerts WHERE id IN ({placeholders})", tuple(alert_ids)
    ).fetchall()
    
    # Get corresponding events by matching system_id, process, and approximate timestamp
    events = []
    for alert in alert_rows:
        alert_dict = dict(alert)
        system_id = alert_dict.get("system_id")
        process = alert_dict.get("process")
        timestamp = alert_dict.get("timestamp", 0)
        
        # Get events within ±5 seconds of alert
        event_rows = _conn().execute(
            "SELECT * FROM events WHERE system_id=? AND child=? "
            "AND timestamp BETWEEN ? AND ? LIMIT 10",
            (system_id, process, timestamp - 5, timestamp + 5)
        ).fetchall()
        
        events.extend([dict(r) for r in event_rows])
    
    return events
