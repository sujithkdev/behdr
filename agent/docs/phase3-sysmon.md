# Phase 3: Sysmon telemetry implementation

Date: 22 October 2026. Status: initial adapter and regression implementation; live Windows acceptance incomplete.

## Implemented

- `endpoint/sysmon_collector.py` reads the Microsoft-Windows-Sysmon/Operational channel using bounded wevtutil queries without shell interpolation. This polls persisted Windows events, rather than sampling the live process list, so short-lived process records can be recovered when Sysmon actually captured and retained them.
- Maps event 1 process creation, 3 network connection (including IPv6), 11 file creation/overwrite and 22 DNS. Other event IDs are counted as unsupported and advance the bookmark; they are not represented as supported detection coverage.
- Preserves source record/event identifiers, UTC time, process GUID, parent GUID on process creation, and the parsed source record. Process normalization preserves this metadata in the durable inbox. The parsed source object is not byte-for-byte original XML.
- Commits a batch's outbox events and bookmark in the same SQLite transaction. If capacity is exceeded or mapping fails, the bookmark does not advance. Event IDs derive from source record fingerprints, supporting replay deduplication across endpoint restarts.
- Checks the prior anchor record and oldest retained record. Missing or changed anchors report a gap/reset and restart from retained history. This cannot recover records already lost to retention or prove every log clear was detected.
- Reports last successful poll, observed/supported event types, unsupported count, gap history and errors through authenticated heartbeat/status. Health is an agent assertion, not attestation. `received` time must be consulted to recognize stale reports.
- Adds explicit Sysmon-primary process selection with stale/error fallback. Polling and legacy event-log process-create emissions are suppressed while the configured primary is recently readable and has observed process-create evidence. Other collector families remain independent.
- Existing event-log XML parsing now preserves provider/computer metadata. Persistent bookmarks apply to the new Sysmon source only; older Security/PowerShell collection bookmarks are not migrated by this change.

## Enable in an isolated Windows VM

Use the official [Sysmon distribution and documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon). Sysmon is an external Microsoft component, not bundled source. Review the downloaded executable's signature and record its version. Review and accept its license yourself; this change does not silently install a driver or accept an EULA.

`deploy/sysmon-lab.xml` is a proposed lab-only configuration: process creation, network connections, DNS, and file creation under `C:\BehEDRLab\`, SHA-256 hashing. Validate its schema with the installed Sysmon version before applying it. It is not yet validated against the user's VM and is not a production-wide collection policy. Network/DNS event volume and privacy need measurement.

After Sysmon installation/configuration and a verified agent enrollment, set these in the agent's actual execution/service environment:

```powershell
$env:EDR_SYSMON = 'true'
$env:EDR_PROCESS_SOURCE = 'sysmon'
```

Restart the agent. With EDR_SYSMON unset/false the collector is disabled, preserving existing deployments. With EDR_SYSMON=true but EDR_PROCESS_SOURCE unset, observation runs alongside existing process polling; expect overlapping evidence. Primary mode is explicit because channel readability does not prove that collection filters capture every process.

The first run reads retained history in bounded batches, not only new activity. This can generate historical alerts: source-time scoring is Phase 4 work. Use a fresh lab channel/configuration and inspect the backlog before drawing conclusions. Network and file observations can overlap existing collectors; cross-source reconciliation is not complete. FileCreate is not comprehensive write/rename/read coverage and its `create` action is not falsely labelled as encryption.

## Failure behavior

Missing channel, denied access, timeout, malformed data or full outbox produces error health. No blanket fallback turns an error into a clean verdict. A malformed supported record currently blocks its batch for review; a bounded quarantine/reprocessing workflow remains future work. Successful polling removes the current error text but retains historical last-error/gap metadata.

GUIDs are preserved but current detector windows still group some evidence by process name and processing time. Phase 4 must use the new identifiers/timestamps consistently before claiming corrected attribution or delay robustness. The process graph's current identity scheme is not replaced here.

## Validation matrix

Final local verification: **98 tests passed in 50.14 seconds**; Ruff checks passed for backend, endpoint, launcher and tests. These tests ran in isolated temporary databases with synthetic records. The Docker image has not been rebuilt for Phase 3, and the guest collector has not been exercised live.

| Requirement | Current evidence |
|---|---|
| Process metadata survives server normalization | Synthetic regression |
| Network IPv6/file/DNS routing | Synthetic regression |
| Bookmark survives spool reopen | SQLite regression |
| Full outbox retains bookmark and commits no partial batch | SQLite regression |
| Reused record ID after reset does not hide changed record | Synthetic replay regression |
| Unsupported types counted | Regression |
| Health is host-bound and visible to authenticated users | API regression |
| Primary source freshness/error fallback | Regression |
| Short-lived process capture and actual event schema | Requires Windows VM |
| Real log clear/rollover, audit policy and permissions | Requires Windows VM |
| Actual collector overhead and duplicate rates | Requires Windows VM |

No live agent or Sysmon collector was run on the development host. The Windows 10 VMware VM has a Phase 2 snapshot but VMware Tools still reported not running during this phase. Guest login, Sysmon setup and trusted guest-to-server HTTPS connectivity remain prerequisites. Do not describe Phase 3 as fully accepted until that matrix is executed.
