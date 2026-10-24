# Operating the release candidate

## Deployment boundary

Run **one server process** against each data directory. `manage.py serve` enforces an OS lock, uses Waitress with 16 threads, and processes the durable inbox in order. In-memory detection windows do not support multiple workers or high availability. Do not use multiple Gunicorn workers or scale Compose replicas. SQLite is intended here for a measured small pilot; no endpoint-count or throughput guarantee has been established.

Use a dedicated service account, restrict the data directory and `.env` to that account, and keep port 5000 private. Expose HTTPS through the provided Caddy configuration or an existing managed proxy. The Compose proxy needs working DNS and certificate issuance access. The Python and Caddy images are pinned by digest; review and refresh them deliberately. See `phase2-deployment.md` for the separate localhost-only verification lab.

Login rate limiting uses the socket peer address. Behind the supplied proxy it is shared across users, intentionally conservative. Forwarded headers are not trusted automatically. Configure trusted proxy handling explicitly before introducing per-client policies.

## Identities and response

Create users with `manage.py create-user NAME --role viewer|analyst|admin`. Administrators can manage users and enroll/revoke agents through the API. Passwords use scrypt. Sessions last one hour by default; logout revokes every existing session for that user, and deletion revokes access immediately. Cookie writes require the returned CSRF token. API automation may use a valid Bearer token; login deliberately does not expose a browser token to local storage.

Each agent credential is hashed in storage and bound to one `system_id`. Rotation invalidates the old token immediately. A compromised endpoint can still falsify its own telemetry; this is not hardware-backed attestation. There is no SSO, MFA, tamper protection or signed installer yet.

Supported commands are `collect_info`, `get_processes`, `get_network`, and administrator-only `kill_process`. A kill request requires `params` containing an exact `pid`, `create_time` and lowercase `sha256`. There is no process-name kill, arbitrary shell action or automatic kill. The endpoint checks the live process identity and protects critical processes. Termination remains a disruptive action and requires operator investigation.

Commands expire after five minutes and are leased for 60 seconds. Endpoint results are durable and resent until acknowledged. If the endpoint crashes after reserving an action, it reports an uncertain outcome and does not repeat that action automatically. Reassess before issuing a new command. Spool records are tied to one server and identity: do not reuse an outbox when moving an endpoint to a different server or resetting server command IDs.

## Windows service

Opt-in Sysmon collection and its current supported-event matrix are documented in [Phase 3 Sysmon](phase3-sysmon.md). Set `EDR_SYSMON=true` and optionally `EDR_PROCESS_SOURCE=sysmon` in the endpoint service environment after validating the source in a lab. These settings do not install Sysmon or change audit policy automatically.

Install requirements using a machine-accessible Python 3.12 installation. Supply configuration as machine/service-account environment variables, not only in the interactive PowerShell window. Review directory ACLs. From an elevated terminal:

```powershell
python endpoint/agent_service.py install
python endpoint/agent_service.py start
```

Stop and remove with the corresponding `stop` and `remove` arguments. Test the service account, startup environment, reboot behavior, stop timing and recovery settings in a Windows VM before rollout. This session did not install or run the service. The old EXE and installer are archived and unsupported.

Process polling can miss short-lived processes. Event Log collection depends on configured Windows process-creation auditing and PowerShell logging. The fallback now reads XML and advances by record ID during a run; restart bookmarks and log-clear recovery are still outstanding. SilkETW is optional third-party software and is not bundled, downloaded or verified by this project. Optional YARA memory collection requires separate validation and installation of `yara-python`.

## Durability, health and capacity

The API acknowledges a telemetry batch only after committing it to SQLite. Stable event IDs deduplicate retries per endpoint. An ordered worker retries errors with backoff up to five attempts, then preserves them as failed jobs. Administrators inspect `/api/analysis/failures` and retry a repaired job with `POST /api/analysis/ID/retry` and `{}`.

`/health` is liveness; `/ready` checks database access and backlog capacity. The authenticated console shows pending and failed counts. `/ready` is not proof that all endpoint collectors or every detection layer is healthy. Monitor growing backlog, failed jobs, server logs, disk capacity and stale endpoint heartbeats separately.

The endpoint outbox retains unacknowledged telemetry across restarts. Invalid records remain in the outbox with an error, rather than blocking healthy records. Its 100,000-record cap logs collection gaps when exhausted; this is not unlimited offline retention. TLS and authorization failures retain events and retry. Optional collectors and filesystem buffering still need stress and crash testing.

No automatic retention or deletion policy is enabled. Plan storage capacity and establish a reviewed retention policy before long-running deployment. Server telemetry and process tables both consume disk; alerts may contain sensitive usernames, paths and command lines.

## Backup and restore

Use `python manage.py backup C:\Backups\behedr-YYYYMMDD.db`. It uses SQLite's online backup API and checks integrity. Store backups outside the server disk, restrict access, and include `.env` and deployment configuration in a separately protected backup. A database backup contains password and token hashes and operational telemetry.

Restore only while the server is stopped. First preserve the current database and its WAL/SHM files as a rollback set. Restore the checked backup into a fresh data directory, set `EDR_DATA_DIR` to that directory, and start one server process. Never overwrite an open SQLite database or attach old WAL files to a restored database. Verify users, agents, event counts and detection before reconnecting clients. Restoring an older database can revive older credentials and command states; rotate credentials and reconcile endpoint outboxes as part of disaster recovery.

## Release gates still required

Run a Windows VM test matrix covering reboot, service recovery, PID reuse, Event Log permissions, offline delivery, certificate rotation, disk exhaustion and process termination against a disposable test process. Measure CPU, memory, disk use and end-to-end latency under a stated load. Evaluate the detector on labeled benign and malicious telemetry; count missed detections and false positives. Complete an independent security review, dependency/image audit, signed packaging, upgrade/rollback drill and restored-backup drill. These are prerequisites for a defensible production rating.
