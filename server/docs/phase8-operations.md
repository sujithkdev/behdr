# Phase 8 — Queue, retention and operational validation

Implementation date: 2026-10-23. Phase numbering follows Phase 0 issue I12. Phase 6 live calibration and Phase 7 research experiments remain separate and pending.

## Implemented

- Server inbox and endpoint spool count distinct new IDs. Durable retries are acknowledged at capacity; overflowing mixed batches roll back.
- New telemetry admission checks disk reserve and database/WAL/SHM size. Storage pressure returns HTTP 503 with Retry-After; endpoints retain unacknowledged data.
- Admin-only `/api/operations` exposes storage, backlog, oldest pending age, failed records, worker heartbeat and retention inventory. Readiness rejects an absent or stalled enabled worker. The stall threshold is 120 seconds, not a measured latency SLA.
- Offline retention makes an integrity-checked backup, rebuilds committed state, and publishes a versioned JSON checkpoint atomically with deletions, permanent event-ID tombstones and an audit entry.
- Checksum or rule-version mismatches fail recovery closed. No executable serialization is used. Retired retries are acknowledged without reanalysis; authenticated evidence lookup returns HTTP 410.
- Optional offline compaction reclaims pages when sufficient temporary disk space exists.

## Budgets

| Variable | Default | Meaning |
|---|---:|---|
| EDR_MAX_PENDING_EVENTS | 100000 | Pending-event limit, range 1–1000000 |
| EDR_MIN_FREE_BYTES | 268435456 | Free-space reserve, 256 MiB |
| EDR_MAX_DATABASE_BYTES | 10737418240 | Database/WAL/SHM admission budget, 10 GiB |

Defaults are policy values, not measured capacity. Admission estimates four times serialized input size as headroom. This is not a filesystem quota: analysis, indexes, journal growth and other writers can exceed it. Pending work continues draining. Administrative/authentication writes are outside this ingestion guard.

## Retention runbook

Inspect first:

```powershell
.\.venv\Scripts\python.exe manage.py retention-report --days 30
```

Stop the server cleanly. Use a new backup filename in an existing directory with enough space:

```powershell
.\.venv\Scripts\python.exe manage.py retention-apply --days 30 --batch-size 1000 --backup C:\BehEDRBackups\before-retention-unique.db --compact
```

The command acquires the server's OS lock and refuses an active local analysis worker. It never overwrites a backup. Checkpoint publication, selected deletions, tombstones and the audit entry are one SQLite transaction. Restart afterward and inspect `/ready` and `/api/operations`. Validate backup recovery in a separate data directory; never overwrite an active database. Repeated batches require distinct backup filenames.

Without `--compact`, SQLite can reuse freed pages but the file may not shrink. Compaction runs after the retention transaction and reports success, insufficient space or failure separately. Compaction failure does not undo committed retention. It can need approximately another database-sized free allocation.

## Evidence preservation and privacy limits

Only completed telemetry older than the receipt-time cutoff is eligible. Pending and failed records remain. Hosts with any alert are held, as are events referenced by active temporal windows. For selected rows, matching process-event and journal rows are deleted with telemetry. The report's age/host eligibility count is an upper bound: maintenance additionally applies the active-window hold.

The checkpoint preserves bounded graph and temporal state under Phase 5 semantics. It does not snapshot every legacy heuristic counter or promise bit-identical whole-detector behavior across restart. Only journal entries after the checkpoint are replayed. State is reconstructed from committed inputs before checkpoint capture, excluding partial failed analysis attempts.

Tombstones never expire because a maximum endpoint retry age has not been established. They grow with retired event count but omit raw command lines. Alerts, incidents, feedback, commands, audit/authentication data, backups and checkpoint-held evidence are not erased by telemetry retention. This is conservative operational cleanup, not whole-system privacy erasure. Backup lifecycle and release of incident evidence need administrator policy. No automatic destructive cleanup job is enabled.

## Validation artifacts

Artifacts are under `var/phase8/`:

- Synthetic load probes: 300/1000/2000 events, 1/4/8 simulated hosts, batches of 25/50/100. Measures admission/drain time, processing latency, CPU seconds, sampled RSS, SQLite sizes and replay time; verifies retry deduplication and database integrity.
- Real ENOSPC probe: disposable 16 MiB Docker tmpfs, no host mounts or networking, read-only container root. Rejected input has no partial persistence; processing succeeds after releasing space.
- Regression faults: real SQLite SQLITE_FULL under a page limit, and abrupt process exit inside retention followed by integrity and application recovery checks. These do not simulate physical power loss or faulty disks.
- Docker: rebuilt pinned-base image, non-root/read-only execution, HTTPS CA/hostname checks, authentication/CSRF, worker health, isolated retention/checkpoint/retry, volume persistence, application backup restore, invalid-secret rejection, dependency consistency and graceful shutdown.

## Interpretation

Short runs measure this machine and synthetic workload only. Admission is in-process followed by sequential drain, not sustained simultaneous HTTPS traffic. Serialized input bytes are not network traffic. Sampled RSS can miss peaks. Do not infer maximum fleet size, HA or malware accuracy. Single-process SQLite remains the supported architecture.

The Phase 8 implementation and bounded validation do not replace a representative sustained deployment pilot. Soak tests, physical power-loss qualification and fleet capacity remain deployment-specific work. Research/publication readiness still depends on live Phase 6/7 evidence.
