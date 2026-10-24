"""SQLite outbox. Acknowledgement, not transmission, removes a record."""
import json
import sqlite3
import threading
import time
import uuid
from pathlib import Path


class Spool:
    def __init__(self, path, max_records=100000):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS outbox(id INTEGER PRIMARY KEY, path TEXT, event_id TEXT UNIQUE, payload TEXT, error TEXT DEFAULT '');
            CREATE TABLE IF NOT EXISTS command_results_v2(id TEXT PRIMARY KEY, result TEXT NOT NULL, acknowledged INTEGER DEFAULT 0);
            CREATE TABLE IF NOT EXISTS source_state(name TEXT PRIMARY KEY, state TEXT NOT NULL);
        """)
        self.conn.commit()
        self.lock = threading.Lock()
        self.max_records = max_records

    def source_state(self, name):
        with self.lock:
            row = self.conn.execute('SELECT state FROM source_state WHERE name=?', (name,)).fetchone()
        return json.loads(row[0]) if row else {}

    def commit_source(self, name, state, routed_events=()):
        """Commit observations and their bookmark together, or neither."""
        with self.lock, self.conn:
            unique = {event['event_id']: (path, event) for path, event in routed_events}
            new = [(path, event) for identity, (path, event) in unique.items()
                   if not self.conn.execute('SELECT 1 FROM outbox WHERE event_id=?', (identity,)).fetchone()]
            if self.conn.execute('SELECT COUNT(*) FROM outbox').fetchone()[0] + len(new) > self.max_records:
                raise OverflowError('Endpoint spool full; source bookmark retained')
            for path, event in new:
                self.conn.execute('INSERT OR IGNORE INTO outbox(path,event_id,payload) VALUES(?,?,?)',
                                  (path, event['event_id'], json.dumps(event, allow_nan=False)))
            self.conn.execute('INSERT INTO source_state VALUES(?,?) ON CONFLICT(name) DO UPDATE SET state=excluded.state',
                              (name, json.dumps(state, allow_nan=False)))

    def put(self, path, event):
        item = dict(event)
        item.setdefault("event_id", uuid.uuid4().hex)
        with self.lock:
            if self.conn.execute('SELECT 1 FROM outbox WHERE event_id=?', (item['event_id'],)).fetchone():
                return item['event_id']
            if self.conn.execute("SELECT COUNT(*) FROM outbox").fetchone()[0] >= self.max_records:
                raise OverflowError("Endpoint spool is full; telemetry collection cannot keep up")
            self.conn.execute("INSERT OR IGNORE INTO outbox(path,event_id,payload) VALUES(?,?,?)", (path, item["event_id"], json.dumps(item, allow_nan=False)))
            self.conn.commit()
        return item["event_id"]

    def peek(self, limit=100):
        with self.lock:
            first = self.conn.execute("SELECT path FROM outbox WHERE error='' ORDER BY id LIMIT 1").fetchone()
            if not first:
                return None, []
            rows = self.conn.execute("SELECT payload FROM outbox WHERE path=? AND error='' ORDER BY id LIMIT ?", (first[0], limit)).fetchall()
        return first[0], [json.loads(row[0]) for row in rows]

    def acknowledge(self, ids):
        with self.lock:
            self.conn.executemany("DELETE FROM outbox WHERE event_id=?", [(identity,) for identity in ids])
            self.conn.commit()

    def reject(self, ids, reason):
        with self.lock:
            self.conn.executemany("UPDATE outbox SET error=? WHERE event_id=?", [(reason[:1000], identity) for identity in ids])
            self.conn.commit()

    def stats(self):
        with self.lock:
            return {"queued": self.conn.execute("SELECT COUNT(*) FROM outbox WHERE error=''").fetchone()[0],
                    "rejected": self.conn.execute("SELECT COUNT(*) FROM outbox WHERE error!=''").fetchone()[0]}

    def execute_once(self, cmd, executor):
        """Reserve before execution. A crash leaves an uncertain result, never a repeated kill."""
        cid = cmd["id"]
        if not isinstance(cid, str) or len(cid) != 32 or any(c not in "0123456789abcdef" for c in cid):
            raise ValueError("Unsupported legacy command identity; upgrade server and agent together")
        with self.lock:
            row = self.conn.execute("SELECT result FROM command_results_v2 WHERE id=?", (cid,)).fetchone()
            if row:
                return json.loads(row[0])
            self.conn.execute("INSERT INTO command_results_v2(id,result) VALUES(?,?)", (cid, json.dumps({"error": "Execution interrupted; outcome unknown. Inspect before issuing a new command."})))
            self.conn.commit()
        try:
            result = executor(cmd) if cmd.get("expires_at", 0) > time.time() else {"error": "Command expired"}
        except Exception as exc:
            result = {"error": str(exc)}
        with self.lock:
            self.conn.execute("UPDATE command_results_v2 SET result=? WHERE id=?", (json.dumps(result), cid))
            self.conn.commit()
        return result

    def pending_results(self):
        with self.lock:
            return [(row[0], json.loads(row[1])) for row in self.conn.execute("SELECT id,result FROM command_results_v2 WHERE acknowledged=0 LIMIT 20")]

    def acknowledge_result(self, cid):
        with self.lock:
            self.conn.execute("UPDATE command_results_v2 SET acknowledged=1 WHERE id=?", (cid,))
            self.conn.commit()
