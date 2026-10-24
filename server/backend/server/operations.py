"""Storage admission and operational inventory."""
from pathlib import Path
import shutil
import time

from server.config import DATA_DIR, DB_PATH, MIN_FREE_BYTES, MAX_DATABASE_BYTES
from server.database.storage import _conn


def storage_status(incoming_bytes=0):
    try:
        used = sum(Path(str(DB_PATH) + suffix).stat().st_size
                   for suffix in ('', '-wal', '-shm') if Path(str(DB_PATH) + suffix).exists())
        free = shutil.disk_usage(DATA_DIR).free
        # Conservative admission headroom, not a hard quota on later analysis writes.
        reserve = incoming_bytes * 4
        reasons = []
        if free - reserve < MIN_FREE_BYTES:
            reasons.append('disk_free_below_reserve')
        if used + reserve >= MAX_DATABASE_BYTES:
            reasons.append('database_budget_reached')
        return {'available': not reasons, 'reasons': reasons, 'database_bytes': used,
                'disk_free_bytes': free, 'minimum_free_bytes': MIN_FREE_BYTES,
                'database_budget_bytes': MAX_DATABASE_BYTES}
    except OSError:
        return {'available': False, 'reasons': ['storage_probe_failed']}


def report(retention_days=30):
    from server.ingestion import worker_health
    if type(retention_days) is not int or not 1 <= retention_days <= 3650:
        raise ValueError('Retention days must be between 1 and 3650')
    now = time.time()
    c = _conn()
    oldest = c.execute("SELECT MIN(received) FROM telemetry WHERE status='pending'").fetchone()[0]
    counts = {r['status']: r['n'] for r in c.execute('SELECT status,COUNT(*) n FROM telemetry GROUP BY status')}
    old = c.execute("SELECT COUNT(*) FROM telemetry WHERE status='done' AND received<?",
                    (now - retention_days * 86400,)).fetchone()[0]
    held = c.execute("""SELECT COUNT(*) FROM telemetry t WHERE status='done' AND received<?
        AND EXISTS(SELECT 1 FROM alerts a WHERE a.system_id=t.system_id)""", (now-retention_days*86400,)).fetchone()[0]
    return {'storage': storage_status(), 'backlog': counts, 'worker': worker_health(),
            'degraded': bool(counts.get('failed', 0)) or not worker_health()['healthy'],
            'oldest_pending_age_seconds': max(0, now - oldest) if oldest is not None else None,
            'retention': {'days': retention_days, 'old_completed_rows': old,
                          'journal_rows': c.execute('SELECT COUNT(*) FROM recovery_journal').fetchone()[0],
                          'automatic_deletion': False, 'offline_cleanup_supported': True,
                          'evidence_held_rows': held, 'eligible_rows': old-held,
                          'tombstones': c.execute('SELECT COUNT(*) FROM telemetry_tombstones').fetchone()[0],
                          'policy': 'Offline checkpoint and verified backup required; hosts with alerts are held; tombstones do not expire.'}}
