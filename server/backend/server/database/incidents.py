# server/database/incidents.py — Incident correlation storage
"""
Groups related alerts into incidents based on:
  - Same system_id
  - Time window (alerts within INCIDENT_WINDOW seconds of each other)
  - Same or related process chain

An incident has:
  - title: auto-generated from the highest-severity alert
  - severity: highest severity across all member alerts
  - status: open | investigating | resolved | false_positive
  - alert_ids: JSON list of alert IDs in this incident
  - first_seen / last_seen timestamps
  - summary: concatenated reasons
"""
import json, time, threading
from server.database.storage import _conn, _write_lock

# Alerts within this many seconds of each other get grouped
INCIDENT_WINDOW = 300   # 5 minutes


def _severity_rank(s: str) -> int:
    return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(s, 0)


def correlate_alert(alert_id: int, alert: dict) -> int:
    """
    Find an open incident for this system within the time window,
    or create a new one. Returns the incident id.
    """
    sid       = alert["system_id"]
    now       = int(alert.get("timestamp", time.time()))
    cutoff    = now - INCIDENT_WINDOW
    severity  = alert.get("risk_level", "MEDIUM")
    reason    = alert.get("reason", "")
    technique = alert.get("technique", "")

    with _write_lock:
        c = _conn()

        # Find an open incident for this system within time window
        row = c.execute(
            "SELECT id, alert_ids, severity, summary, title"
            " FROM incidents"
            " WHERE system_id=? AND status='open' AND last_seen>=?"
            " ORDER BY last_seen DESC LIMIT 1",
            (sid, cutoff)).fetchone()

        if row:
            # Add alert to existing incident
            inc_id    = row["id"]
            ids       = json.loads(row["alert_ids"])
            ids.append(alert_id)
            # Escalate severity if this alert is higher
            cur_rank  = _severity_rank(row["severity"])
            new_rank  = _severity_rank(severity)
            new_sev   = severity if new_rank > cur_rank else row["severity"]
            # Append reason to summary (deduplicated, max 500 chars)
            summary   = row["summary"]
            short     = reason[:80]
            if short not in summary:
                summary = (summary + " | " + short)[:500]

            c.execute(
                "UPDATE incidents SET alert_ids=?, severity=?, last_seen=?, summary=?"
                " WHERE id=?",
                (json.dumps(ids), new_sev, now, summary, inc_id))
            c.commit()
            return inc_id

        else:
            # Create new incident
            title = _make_title(alert)
            c.execute(
                "INSERT INTO incidents(system_id,title,severity,status,"
                "alert_ids,first_seen,last_seen,summary)"
                " VALUES(?,?,?,?,?,?,?,?)",
                (sid, title, severity, "open",
                 json.dumps([alert_id]), now, now, reason[:500]))
            inc_id = c.execute("SELECT last_insert_rowid()").fetchone()[0]
            c.commit()
            return inc_id


def _make_title(alert: dict) -> str:
    """Generate a human-readable incident title from the first alert."""
    proc = alert.get("process", "unknown")
    sid  = alert.get("system_id", "?")
    tech = alert.get("technique", "")
    lvl  = alert.get("risk_level", "")
    if tech:
        return f"[{lvl}] {tech} on {sid}"
    reason = alert.get("reason", "")[:60]
    return f"[{lvl}] {proc} — {reason}"


def get_incidents(status: str = None, system_id: str = None,
                  limit: int = 100) -> list:
    """Return incidents with their alert count."""
    where, params = [], []
    if status:
        where.append("status=?"); params.append(status)
    if system_id:
        where.append("system_id=?"); params.append(system_id)
    clause = ("WHERE " + " AND ".join(where)) if where else ""
    params.append(limit)

    rows = _conn().execute(
        f"SELECT *, json_array_length(alert_ids) as alert_count"
        f" FROM incidents {clause}"
        f" ORDER BY last_seen DESC LIMIT ?",
        params).fetchall()
    return [dict(r) for r in rows]


def get_incident(incident_id: int) -> dict | None:
    row = _conn().execute(
        "SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
    if not row:
        return None
    d = dict(row)
    d["alert_ids"] = json.loads(d["alert_ids"])
    return d


def update_incident_status(incident_id: int, status: str,
                            updated_by: str = "system") -> bool:
    valid = {"open", "investigating", "resolved", "false_positive"}
    if status not in valid:
        return False
    with _write_lock:
        cursor = _conn().execute(
            "UPDATE incidents SET status=? WHERE id=?",
            (status, incident_id))
        _conn().commit()
    return cursor.rowcount == 1


def get_incident_alerts(incident_id: int) -> list:
    """Return full alert rows for an incident."""
    row = _conn().execute(
        "SELECT alert_ids FROM incidents WHERE id=?",
        (incident_id,)).fetchone()
    if not row:
        return []
    ids = json.loads(row["alert_ids"])
    if not ids:
        return []
    placeholders = ",".join("?" * len(ids))
    rows = _conn().execute(
        f"SELECT * FROM alerts WHERE id IN ({placeholders})"
        " ORDER BY timestamp ASC", ids).fetchall()
    return [dict(r) for r in rows]


def incident_stats() -> dict:
    """Quick summary counts for the dashboard."""
    rows = _conn().execute(
        "SELECT status, COUNT(*) as n FROM incidents GROUP BY status"
    ).fetchall()
    s = {r["status"]: r["n"] for r in rows}
    s["total"] = sum(s.values())
    return s
