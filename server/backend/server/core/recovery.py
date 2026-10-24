"""Replay committed analysis inputs into graph/windows without detector side effects."""
import hashlib
import json
from pathlib import Path
import time

from server.config import RULES_DIR
from server.database.storage import _conn

STATE = {'state': 'not_started', 'replayed': 0}


def fingerprint():
    digest = hashlib.sha256(b'behedr-recovery-v1')
    paths = sorted(p for p in Path(RULES_DIR).rglob('*') if p.is_file())
    paths += [Path(__file__).with_name(name) for name in ('temporal.py', 'graph.py', 'file_behavior.py')]
    for path in paths:
        digest.update(path.name.encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()


def init_journal():
    _conn().executescript('''
        CREATE TABLE IF NOT EXISTS recovery_checkpoint(
            id INTEGER PRIMARY KEY CHECK(id=1), sequence INTEGER NOT NULL,
            rules_hash TEXT NOT NULL, payload TEXT NOT NULL, checksum TEXT NOT NULL, created REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS telemetry_tombstones(
            system_id TEXT NOT NULL, event_id TEXT NOT NULL, retired REAL NOT NULL,
            PRIMARY KEY(system_id,event_id));
    ''')
    _conn().execute('''CREATE TABLE IF NOT EXISTS recovery_journal(
        sequence INTEGER PRIMARY KEY AUTOINCREMENT, system_id TEXT NOT NULL,
        event_id TEXT NOT NULL, payload TEXT NOT NULL, received REAL NOT NULL,
        rules_hash TEXT NOT NULL, origin TEXT NOT NULL DEFAULT 'committed', UNIQUE(system_id,event_id))''')


def restore(rules):
    from server.core import graph, temporal
    from server.core.processor import normalize
    STATE.update(state='restoring', replayed=0, started_at=time.time(), error=None)
    version = fingerprint()
    try:
        checkpoint = _conn().execute('SELECT * FROM recovery_checkpoint WHERE id=1').fetchone()
        if checkpoint and checkpoint['rules_hash'] != version:
            raise RuntimeError('Recovery checkpoint rules/code mismatch')
        # Fail before changing memory if replay semantics differ from the journal.
        mismatch = _conn().execute('SELECT 1 FROM recovery_journal WHERE rules_hash<>? LIMIT 1', (version,)).fetchone()
        if mismatch:
            raise RuntimeError('Recovery rules/code mismatch; retain backup and perform a reviewed replay migration')
        # Pre-journal releases did not retain completion order or rule versions.
        # Preserve that uncertainty explicitly; do not claim exact reconstruction.
        c = _conn()
        c.execute('BEGIN IMMEDIATE')
        try:
            if not checkpoint:
                c.execute("""INSERT OR IGNORE INTO recovery_journal(system_id,event_id,payload,received,rules_hash,origin)
                SELECT system_id,event_id,payload,received,?,'legacy_inferred'
                FROM telemetry WHERE status='done' ORDER BY id""", (version,))
            c.commit()
        except Exception:
            c.rollback()
            raise
        with graph._lock:
            graph._graphs.clear()
        with temporal._lock:
            temporal._windows.clear()
        if checkpoint:
            from server.core.checkpoint import restore as restore_checkpoint
            restore_checkpoint(checkpoint['payload'], checkpoint['checksum'])
        after = checkpoint['sequence'] if checkpoint else 0
        for row in _conn().execute('SELECT payload,received FROM recovery_journal WHERE sequence>? ORDER BY sequence', (after,)):
            event = json.loads(row['payload'])
            event['_received_at'] = row['received']
            kind = event['event']
            if kind == 'etw_process_create':
                event = normalize({**event, 'event': 'process_spawn', 'parent': event.get('parent_proc', 'unknown'),
                                   'child': event.get('process', 'unknown'), 'exe_path': event.get('image_path', '')})
                kind = 'process_spawn'
            if kind == 'process_spawn':
                graph.add_event(event)
            elif kind in {'network_connect', 'etw_network_connect', 'file_event'}:
                temporal.assess(event, rules, row['received'])
            STATE['replayed'] += 1
        legacy = _conn().execute("SELECT COUNT(*) FROM recovery_journal WHERE origin='legacy_inferred'").fetchone()[0]
        STATE.update(state='ready', rules_hash=version, legacy_inferred=legacy, checkpoint_sequence=after, finished_at=time.time())
    except Exception as exc:
        STATE.update(state='failed', error=str(exc))
        raise
