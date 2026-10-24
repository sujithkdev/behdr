"""Offline bounded retention, mandatory backup and atomic checkpoint publication."""
import json
from pathlib import Path
import sqlite3
import shutil
import time

from server.config import DATA_DIR, DB_PATH
from server.database.storage import _conn, _write_lock
from server.runtime_lock import exclusive_instance


def maintain(days, batch_size, backup, compact=False):
    if type(days) is not int or not 1 <= days <= 3650 or type(batch_size) is not int or not 1 <= batch_size <= 10000:
        raise ValueError('Days must be 1–3650 and batch size 1–10000')
    from server.ingestion import _thread
    if _thread is not None and _thread.is_alive():
        raise RuntimeError('Stop the analysis worker before retention')
    with exclusive_instance(Path(DATA_DIR) / 'server.lock'):
        backup = Path(backup)
        # Exclusive file creation prevents accidentally overwriting any backup or database.
        with backup.open('xb'):
            pass
        c = _conn()
        with sqlite3.connect(backup) as target:
            c.backup(target)
            if target.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
                raise RuntimeError('Backup verification failed; retention aborted')
        from server.core import detector, recovery, checkpoint
        recovery.restore(detector._file_rules)
        payload, checksum = checkpoint.capture()
        state = json.loads(payload)
        protected = {(key[0], identity) for key, window in state['windows'] for identity in window['events']}
        cutoff = time.time() - days * 86400
        with _write_lock:
            c.execute('BEGIN IMMEDIATE')
            try:
                c.execute('CREATE TEMP TABLE IF NOT EXISTS retention_protected(system_id TEXT,event_id TEXT,PRIMARY KEY(system_id,event_id))')
                c.execute('DELETE FROM retention_protected')
                c.executemany('INSERT INTO retention_protected VALUES(?,?)', protected)
                # Conservative evidence hold: preserve all rows for hosts with any alert.
                rows = c.execute("""SELECT system_id,event_id FROM telemetry t
                    WHERE status='done' AND received<? AND NOT EXISTS(
                        SELECT 1 FROM alerts a WHERE a.system_id=t.system_id)
                    AND NOT EXISTS(SELECT 1 FROM retention_protected p
                        WHERE p.system_id=t.system_id AND p.event_id=t.event_id)
                    ORDER BY id LIMIT ?""", (cutoff, batch_size)).fetchall()
                previous = c.execute('SELECT sequence FROM recovery_checkpoint WHERE id=1').fetchone()
                last = c.execute('SELECT COALESCE(MAX(sequence),0) FROM recovery_journal').fetchone()[0]
                highwater = max(last, previous[0] if previous else 0)
                c.execute('INSERT OR REPLACE INTO recovery_checkpoint VALUES(1,?,?,?,?,?)',
                          (highwater, recovery.fingerprint(), payload, checksum, time.time()))
                for row in rows:
                    key = (row['system_id'], row['event_id'])
                    if key in protected:
                        continue
                    c.execute('INSERT OR IGNORE INTO telemetry_tombstones VALUES(?,?,?)', (*key, time.time()))
                    c.execute('DELETE FROM events WHERE system_id=? AND event_id=?', key)
                    c.execute('DELETE FROM recovery_journal WHERE system_id=? AND event_id=? AND sequence<=?', (*key, highwater))
                    c.execute('DELETE FROM telemetry WHERE system_id=? AND event_id=?', key)
                deleted = sum((row['system_id'], row['event_id']) not in protected for row in rows)
                result = {'deleted_completed_rows': deleted, 'checkpoint_sequence': highwater,
                          'checkpoint_sha256': checksum, 'backup': str(backup.resolve()),
                          'evidence_hold': 'all hosts with alerts and active temporal evidence', 'tombstones_expire': False}
                c.execute('INSERT INTO audit_log(username,action,detail,ip,timestamp) VALUES(?,?,?,?,?)',
                          ('local-admin', 'retention', json.dumps(result), 'local', int(time.time())))
                c.commit()
            except Exception:
                c.rollback()
                raise
        # Optional compaction runs offline, after the recovery-safe transaction.
        result['compaction'] = 'not_requested'
        if compact:
            from server.config import MIN_FREE_BYTES
            if shutil.disk_usage(DATA_DIR).free < Path(DB_PATH).stat().st_size + MIN_FREE_BYTES:
                result['compaction'] = 'skipped_insufficient_temporary_space'
            else:
                try:
                    c.execute('PRAGMA wal_checkpoint(TRUNCATE)')
                    c.execute('VACUUM')
                    result['compaction'] = 'completed'
                except sqlite3.Error as exc:
                    result['compaction'] = 'failed_after_retention_commit'
                    result['compaction_error'] = str(exc)
        return result
