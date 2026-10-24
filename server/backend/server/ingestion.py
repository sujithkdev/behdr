"""Durable, bounded telemetry inbox with retry visibility and one ordered worker."""
import hashlib
import json
import logging
import math
import re
import threading
import time

from server.database.storage import _conn, _write_lock, save_event
from server.core.processor import normalize

log = logging.getLogger(__name__)
KINDS = {
    "/events": {"process_spawn"},
    "/dll_events": {"dll_load"},
    "/net_events": {"network_connect"},
    "/file_events": {"file_event"},
    "/etw_events": {"etw_process_create", "etw_thread_inject", "etw_image_load", "etw_network_connect", "etw_registry_write", "etw_dns_query", "etw_scriptblock", "etw_task_create", "etw_service_install", "etw_account_change"},
    "/yara_hits": {"yara_hit"},
}
_worker_lock = threading.Lock()
_started = False
_thread = None
_stop = threading.Event()
_worker_state = {'heartbeat': None, 'in_flight_since': None, 'last_success': None, 'last_error': None}
from server.config import MAX_PENDING_EVENTS
MAX_PENDING = MAX_PENDING_EVENTS


def init_inbox():
    from server.core.recovery import init_journal
    init_journal()
    _conn().executescript("""
        CREATE TABLE IF NOT EXISTS collector_health (
            system_id TEXT PRIMARY KEY, payload TEXT NOT NULL, received REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS telemetry (
            id INTEGER PRIMARY KEY, system_id TEXT NOT NULL, event_id TEXT NOT NULL,
            payload TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
            attempts INTEGER NOT NULL DEFAULT 0, next_attempt REAL NOT NULL DEFAULT 0,
            error TEXT NOT NULL DEFAULT '', received REAL NOT NULL,
            UNIQUE(system_id,event_id)
        );
        CREATE INDEX IF NOT EXISTS telemetry_pending ON telemetry(status,next_attempt,id);
    """)
    columns = {row["name"] for row in _conn().execute("PRAGMA table_info(telemetry)")}
    if "assessment" not in columns:
        _conn().execute("ALTER TABLE telemetry ADD COLUMN assessment TEXT NOT NULL DEFAULT '{}'")


def validate_event(item, path):
    if not isinstance(item.get("event"), str) or item.get("event") not in KINDS[path]:
        raise ValueError("Unexpected telemetry type")
    if item["event"] == "process_spawn":
        return normalize(item)
    event = dict(item)
    for key in ('time', 'create_time'):
        if key in event and (type(event[key]) not in (int, float) or not math.isfinite(event[key]) or event[key] < 0):
            raise ValueError(f'Invalid {key}')
    for key in ('process_guid', 'parent_process_guid'):
        if key in event and (not isinstance(event[key], str) or len(event[key]) > 64):
            raise ValueError(f'Invalid {key}')
    if 'is_internal' in event and type(event['is_internal']) is not bool:
        raise ValueError('Invalid is_internal')
    encoded = json.dumps(event, sort_keys=True, allow_nan=False)
    if len(encoded) > 65536:
        raise ValueError("Event exceeds 64 KiB")
    for key in ("pid", "ppid", "source_pid", "target_pid", "remote_port"):
        value = event.get(key, 0)
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 2**32:
            raise ValueError(f"Invalid {key}")
    for key in ("process", "parent_proc", "source_proc", "target_proc", "file_path", "dll_path", "image_path", "remote_ip", "cmdline", "domain", "scriptblock"):
        if key in event and not isinstance(event[key], str):
            raise ValueError(f"Invalid {key}")
    event["event_id"] = event.get("event_id") or hashlib.sha256(encoded.encode()).hexdigest()
    if not isinstance(event["event_id"], str) or not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", event["event_id"]):
        raise ValueError("Invalid event_id")
    return event


def accept(events):
    """Commit the whole batch or none; retries use a stable host/event identity."""
    with _write_lock:
        c = _conn()
        c.execute("BEGIN IMMEDIATE")
        try:
            pending = c.execute("SELECT COUNT(*) FROM telemetry WHERE status='pending'").fetchone()[0]
            new = {}
            for event in events:
                key = (event['system_id'], event['event_id'])
                if key not in new and not c.execute('SELECT 1 FROM telemetry WHERE system_id=? AND event_id=?', key).fetchone() and not c.execute('SELECT 1 FROM telemetry_tombstones WHERE system_id=? AND event_id=?', key).fetchone():
                    new[key] = event
            if pending + len(new) > MAX_PENDING:
                raise OverflowError("Analysis backlog is full; retry later")
            if new:
                from server.operations import storage_status
                size = sum(len(json.dumps(event, allow_nan=False).encode()) for event in new.values())
                if not storage_status(size)['available']:
                    raise OverflowError('Storage budget unavailable; retain telemetry and retry later')
            for event in new.values():
                c.execute("INSERT OR IGNORE INTO telemetry(system_id,event_id,payload,received) VALUES(?,?,?,?)",
                          (event["system_id"], event["event_id"], json.dumps(event, allow_nan=False), time.time()))
            c.commit()
        except Exception:
            c.rollback()
            raise
    return [event["event_id"] for event in events]


def analyze_telemetry(event):
    from server.core import detector as d
    from server.core.graph import add_event
    kind = event["event"]
    token = d._current_event.set(event)
    try:
        if kind == "etw_process_create":
            event = normalize({**event, "event": "process_spawn", "parent": event.get("parent_proc", "unknown"),
                               "child": event.get("process", "unknown"), "exe_path": event.get("image_path", "")})
            kind = "process_spawn"
        if kind == "process_spawn":
            save_event(event)
            add_event(event)
            from server.core.development_guard import evaluate
            assessment = evaluate(event)
            from server.core.sigma_subset import evaluate as evaluate_sigma
            assessment['sigma'] = evaluate_sigma(event)
            with _write_lock:
                _conn().execute("UPDATE telemetry SET assessment=? WHERE system_id=? AND event_id=?",
                                (json.dumps(assessment), event["system_id"], event["event_id"]))
            for finding in assessment["findings"]:
                alert = d._make_alert(event["system_id"], event["child"], finding["score"], "MEDIUM",
                                      finding["rule_id"] + ": " + finding["reason"])
                alert["never_suppress"] = True
                d._emit(alert)
            for finding in assessment['sigma']['matches']:
                score = {'medium': 50, 'high': 70, 'critical': 90}[finding['level']]
                reason = ('SIGMA ' + finding['id'] + ': ' + finding['title']
                          + ' | Author: ' + finding['author'] + ' | License: ' + finding['license']
                          + ' | SHA256: ' + finding['sha256'])
                d._emit(d._make_alert(event['system_id'], event['child'], score,
                                     finding['level'].upper(), reason))
            d.analyze(event)
        elif kind in {"network_connect", "etw_network_connect", "file_event"}:
            from server.core.temporal import assess
            score, reasons, assessment = assess(event, d._file_rules, event.get('_received_at', time.time()))
            assessment['processed_at'] = time.time()
            with _write_lock:
                _conn().execute("UPDATE telemetry SET assessment=? WHERE system_id=? AND event_id=?",
                                (json.dumps(assessment, allow_nan=False), event['system_id'], event['event_id']))
            if score >= d.RISK_MEDIUM:
                label = 'FILE' if kind == 'file_event' else 'NETWORK'
                d._emit(d._make_alert(event['system_id'], event.get('process', 'unknown'), score, 'MEDIUM',
                                     label + ': ' + ' | '.join(reasons), 'T1486' if label == 'FILE' else 'T1071'))
        elif kind == "dll_load":
            process = event.get("process", "unknown")
            d.add_dll_event(event["system_id"], process, event.get("dll_name", ""), event.get("dll_path", ""), event.get("signed"))
            score, reasons = d.check_dll_hijacking(event["system_id"], process, event.get("exe_path", ""))
            if score >= d.RISK_MEDIUM:
                d._emit(d._make_alert(event["system_id"], process, score, "MEDIUM", "DLL: " + " | ".join(reasons), "T1574"))
        elif kind == "yara_hit":
            d.handle_yara_hit(event)
        else:
            d.handle_etw_event(event)
    finally:
        d._current_event.reset(token)


def process_one():
    row = _conn().execute("SELECT * FROM telemetry WHERE status='pending' AND next_attempt<=? ORDER BY id LIMIT 1", (time.time(),)).fetchone()
    if not row:
        return False
    try:
        analyze_telemetry({**json.loads(row["payload"]), "_received_at": row["received"]})
        with _write_lock:
            from server.core.recovery import STATE, fingerprint
            c = _conn()
            c.execute('BEGIN IMMEDIATE')
            try:
                c.execute('INSERT OR IGNORE INTO recovery_journal(system_id,event_id,payload,received,rules_hash) VALUES(?,?,?,?,?)',
                          (row['system_id'], row['event_id'], row['payload'], row['received'], STATE.get('rules_hash') or fingerprint()))
                c.execute("UPDATE telemetry SET status='done',error='' WHERE id=?", (row["id"],))
                c.commit()
            except Exception:
                c.rollback()
                raise
    except Exception as exc:
        log.exception("Telemetry analysis failed: %s", row["id"])
        attempts = row["attempts"] + 1
        with _write_lock:
            _conn().execute("UPDATE telemetry SET status=?,attempts=?,next_attempt=?,error=? WHERE id=?",
                            ("failed" if attempts >= 5 else "pending", attempts, time.time() + min(60, 2**attempts), str(exc)[:1000], row["id"]))
    return True


def start_worker():
    global _started, _thread
    with _worker_lock:
        if _started:
            return
        _started = True
        _stop.clear()
        _worker_state.update(heartbeat=time.time(), in_flight_since=None, last_error=None)
    def run():
        while not _stop.is_set():
            try:
                _worker_state.update(heartbeat=time.time(), in_flight_since=time.time())
                worked = process_one()
                _worker_state.update(heartbeat=time.time(), in_flight_since=None, last_success=time.time(), last_error=None)
                if not worked:
                    _stop.wait(1)
            except Exception:
                _worker_state.update(heartbeat=time.time(), in_flight_since=None, last_error=time.time())
                log.exception("Inbox worker failure")
                _stop.wait(5)
    _thread = threading.Thread(target=run, name="telemetry-analysis", daemon=True)
    _thread.start()


def stop_worker(timeout=10):
    """Stop taking new work and allow an in-flight analysis to finish."""
    global _started
    _stop.set()
    if _thread is not None:
        _thread.join(timeout)
        if _thread.is_alive():
            log.warning("Analysis did not stop before deadline; pending work remains durable")
            return False
    with _worker_lock:
        _started = False
    return True


def backlog():
    return {r["status"]: r["n"] for r in _conn().execute("SELECT status,COUNT(*) AS n FROM telemetry GROUP BY status")}


def worker_health(now=None):
    from server.config import BACKGROUND_ENABLED
    now = time.time() if now is None else now
    state = dict(_worker_state)
    alive = _thread is not None and _thread.is_alive()
    age = max(0, now - state['heartbeat']) if state['heartbeat'] is not None else None
    healthy = not BACKGROUND_ENABLED or (alive and age is not None and age <= 120 and state['last_error'] is None)
    return {**state, 'enabled': BACKGROUND_ENABLED, 'alive': alive, 'heartbeat_age_seconds': age,
            'healthy': healthy, 'stall_threshold_seconds': 120}
