# server/notifier.py — Alert notification dispatcher
"""
Sends alerts to configured channels when they cross the severity threshold.

Supported channels
──────────────────
  slack      — Slack incoming webhook (one message per alert)
  teams      — Microsoft Teams incoming webhook (Adaptive Card)
  email      — SMTP (TLS/STARTTLS, supports Gmail, Outlook, custom)
  pagerduty  — PagerDuty Events API v2 (trigger / resolve)

Configuration — environment variables
──────────────────────────────────────
  Slack:
    EDR_NOTIFY_SLACK_URL          Incoming webhook URL
    EDR_NOTIFY_SLACK_MIN_LEVEL    Minimum severity to notify (default: CRITICAL)

  Teams:
    EDR_NOTIFY_TEAMS_URL          Incoming webhook URL
    EDR_NOTIFY_TEAMS_MIN_LEVEL    Minimum severity (default: CRITICAL)

  Email:
    EDR_NOTIFY_EMAIL_HOST         SMTP host (e.g. smtp.gmail.com)
    EDR_NOTIFY_EMAIL_PORT         SMTP port (default: 587)
    EDR_NOTIFY_EMAIL_USER         SMTP username
    EDR_NOTIFY_EMAIL_PASS         SMTP password / app password
    EDR_NOTIFY_EMAIL_FROM         From address
    EDR_NOTIFY_EMAIL_TO           Comma-separated recipient list
    EDR_NOTIFY_EMAIL_MIN_LEVEL    Minimum severity (default: CRITICAL)

  PagerDuty:
    EDR_NOTIFY_PD_KEY             Integration key (Events API v2)
    EDR_NOTIFY_PD_MIN_LEVEL       Minimum severity (default: CRITICAL)

  Global:
    EDR_NOTIFY_ENABLED            Set to 'false' to disable all notifications
                                  (default: true)

Routing logic
─────────────
  CRITICAL → all configured channels
  HIGH     → channels whose MIN_LEVEL is HIGH or lower
  MEDIUM   → channels whose MIN_LEVEL is MEDIUM or lower
  LOW      → only channels explicitly set to LOW

  Default is CRITICAL only — avoids paging on every anomaly.

Architecture
────────────
  notify_alert(alert)  — public entry point, called from detector._emit()
  Each channel runs in a background thread so it never blocks detection.
  Failures are logged but never raised — notification is best-effort.
"""

import os
import json
import time
import logging
import smtplib
import threading
import urllib.request
import urllib.error
from datetime import datetime, timezone
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional

log = logging.getLogger("notifier")

# ── Global enable switch ──────────────────────────────────────────────────────
_ENABLED = os.environ.get("EDR_NOTIFY_ENABLED", "true").lower() != "false"

# ── Severity rank — higher number = more severe ───────────────────────────────
_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def _rank(level: str) -> int:
    return _RANK.get(level.upper(), 0)


# ── Dedup — avoid sending the same alert twice within 5 minutes ───────────────
_sent: dict = {}
_sent_lock = threading.Lock()
_DEDUP_SECS = 300


def _is_duplicate(alert: dict) -> bool:
    key = (alert.get("system_id", ""),
           alert.get("process", ""),
           alert.get("risk_level", ""),
           alert.get("reason", "")[:80])
    now = time.time()
    with _sent_lock:
        last = _sent.get(key, 0)
        if now - last < _DEDUP_SECS:
            return True
        _sent[key] = now
        # Evict old entries
        if len(_sent) > 2000:
            cutoff = now - _DEDUP_SECS
            for k in [k for k, v in list(_sent.items()) if v < cutoff]:
                del _sent[k]
    return False


# ── Formatting helpers ────────────────────────────────────────────────────────

def _ts_human(ts: int) -> str:
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return str(ts)


def _level_emoji(level: str) -> str:
    return {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(
        level.upper(), "⚪")


def _short_reason(reason: str, max_len: int = 200) -> str:
    return reason[:max_len] + ("…" if len(reason) > max_len else "")


# ═════════════════════════════════════════════════════════════════════════════
# SLACK
# ═════════════════════════════════════════════════════════════════════════════

def _send_slack(alert: dict):
    url = os.environ.get("EDR_NOTIFY_SLACK_URL", "").strip()
    if not url:
        return

    min_level = os.environ.get("EDR_NOTIFY_SLACK_MIN_LEVEL", "CRITICAL").upper()
    if _rank(alert.get("risk_level", "LOW")) < _rank(min_level):
        return

    emoji  = _level_emoji(alert["risk_level"])
    color  = {"CRITICAL": "#FF0000", "HIGH": "#FF6600",
               "MEDIUM": "#FFCC00", "LOW": "#36A64F"}.get(
                   alert["risk_level"], "#888888")

    payload = {
        "attachments": [{
            "color":    color,
            "fallback": f"{emoji} [{alert['risk_level']}] {alert.get('process','?')} on {alert.get('system_id','?')}",
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": f"{emoji} BehEDR {alert['risk_level']} Alert",
                    }
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*System*\n{alert.get('system_id','?')}"},
                        {"type": "mrkdwn", "text": f"*Process*\n{alert.get('process','?')}"},
                        {"type": "mrkdwn", "text": f"*Score*\n{alert.get('risk_score', 0)}"},
                        {"type": "mrkdwn", "text": f"*Time*\n{_ts_human(alert.get('timestamp', 0))}"},
                    ]
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Reason*\n{_short_reason(alert.get('reason',''))}",
                    }
                },
            ],
        }]
    }

    if alert.get("technique"):
        payload["attachments"][0]["blocks"].append({
            "type": "context",
            "elements": [{"type": "mrkdwn",
                          "text": f"MITRE: {alert['technique']}  |  Confidence: {alert.get('confidence','?')}"}]
        })

    _http_post_json(url, payload, "Slack")


# ═════════════════════════════════════════════════════════════════════════════
# MICROSOFT TEAMS
# ═════════════════════════════════════════════════════════════════════════════

def _send_teams(alert: dict):
    url = os.environ.get("EDR_NOTIFY_TEAMS_URL", "").strip()
    if not url:
        return

    min_level = os.environ.get("EDR_NOTIFY_TEAMS_MIN_LEVEL", "CRITICAL").upper()
    if _rank(alert.get("risk_level", "LOW")) < _rank(min_level):
        return

    emoji  = _level_emoji(alert["risk_level"])
    color  = {"CRITICAL": "FF0000", "HIGH": "FF6600",
               "MEDIUM": "FFCC00", "LOW": "36A64F"}.get(alert["risk_level"], "888888")

    # Teams Adaptive Card payload
    payload = {
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type": "AdaptiveCard",
                "version": "1.4",
                "body": [
                    {
                        "type": "TextBlock",
                        "text": f"{emoji} BehEDR {alert['risk_level']} Alert",
                        "weight": "Bolder",
                        "size": "Large",
                        "color": "Attention" if alert["risk_level"] in ("CRITICAL", "HIGH") else "Warning",
                    },
                    {
                        "type": "FactSet",
                        "facts": [
                            {"title": "System",     "value": alert.get("system_id", "?")},
                            {"title": "Process",    "value": alert.get("process", "?")},
                            {"title": "Score",      "value": str(alert.get("risk_score", 0))},
                            {"title": "Confidence", "value": alert.get("confidence", "?")},
                            {"title": "Technique",  "value": alert.get("technique", "—")},
                            {"title": "Time",       "value": _ts_human(alert.get("timestamp", 0))},
                        ]
                    },
                    {
                        "type": "TextBlock",
                        "text": _short_reason(alert.get("reason", "")),
                        "wrap": True,
                    }
                ]
            }
        }]
    }

    _http_post_json(url, payload, "Teams")


# ═════════════════════════════════════════════════════════════════════════════
# EMAIL (SMTP)
# ═════════════════════════════════════════════════════════════════════════════

def _send_email(alert: dict):
    host     = os.environ.get("EDR_NOTIFY_EMAIL_HOST", "").strip()
    user     = os.environ.get("EDR_NOTIFY_EMAIL_USER", "").strip()
    password = os.environ.get("EDR_NOTIFY_EMAIL_PASS", "").strip()
    from_    = os.environ.get("EDR_NOTIFY_EMAIL_FROM", user).strip()
    to_raw   = os.environ.get("EDR_NOTIFY_EMAIL_TO",   "").strip()
    port     = int(os.environ.get("EDR_NOTIFY_EMAIL_PORT", "587"))

    if not host or not user or not password or not to_raw:
        return

    min_level = os.environ.get("EDR_NOTIFY_EMAIL_MIN_LEVEL", "CRITICAL").upper()
    if _rank(alert.get("risk_level", "LOW")) < _rank(min_level):
        return

    to_list = [t.strip() for t in to_raw.split(",") if t.strip()]
    emoji   = _level_emoji(alert["risk_level"])
    subject = (f"{emoji} BehEDR [{alert['risk_level']}] "
               f"{alert.get('process','?')} on {alert.get('system_id','?')}")

    # HTML body
    html = f"""
<html><body style="font-family:sans-serif;max-width:600px">
<h2 style="color:{'#cc0000' if alert['risk_level']=='CRITICAL' else '#ff6600'}">
  {emoji} BehEDR {alert['risk_level']} Alert
</h2>
<table cellpadding="6" cellspacing="0" border="1" style="border-collapse:collapse;width:100%">
  <tr><td><b>System</b></td>    <td>{alert.get('system_id','?')}</td></tr>
  <tr><td><b>Process</b></td>   <td>{alert.get('process','?')}</td></tr>
  <tr><td><b>Score</b></td>     <td>{alert.get('risk_score',0)}</td></tr>
  <tr><td><b>Confidence</b></td><td>{alert.get('confidence','?')}</td></tr>
  <tr><td><b>Technique</b></td> <td>{alert.get('technique','—')}</td></tr>
  <tr><td><b>Time</b></td>      <td>{_ts_human(alert.get('timestamp',0))}</td></tr>
  <tr><td><b>Reason</b></td>    <td>{alert.get('reason','')}</td></tr>
</table>
<p style="color:#888;font-size:12px">BehEDR Behavioral EDR</p>
</body></html>"""

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = from_
    msg["To"]      = ", ".join(to_list)
    msg.attach(MIMEText(html, "html"))

    try:
        with smtplib.SMTP(host, port, timeout=10) as smtp:
            smtp.ehlo()
            smtp.starttls()
            smtp.login(user, password)
            smtp.sendmail(from_, to_list, msg.as_string())
        log.info("[Notify] Email sent to %s", to_list)
    except Exception as e:
        log.error("[Notify] Email failed: %s", e)


# ═════════════════════════════════════════════════════════════════════════════
# PAGERDUTY (Events API v2)
# ═════════════════════════════════════════════════════════════════════════════

_PD_URL = "https://events.pagerduty.com/v2/enqueue"
# Track open PagerDuty incidents by dedup_key so we can resolve them later
_pd_open: dict = {}   # dedup_key → True
_pd_lock = threading.Lock()


def _send_pagerduty(alert: dict):
    key = os.environ.get("EDR_NOTIFY_PD_KEY", "").strip()
    if not key:
        return

    min_level = os.environ.get("EDR_NOTIFY_PD_MIN_LEVEL", "CRITICAL").upper()
    if _rank(alert.get("risk_level", "LOW")) < _rank(min_level):
        return

    # Severity mapping: PD uses critical/error/warning/info
    pd_severity = {
        "CRITICAL": "critical",
        "HIGH":     "error",
        "MEDIUM":   "warning",
        "LOW":      "info",
    }.get(alert.get("risk_level", "LOW"), "error")

    dedup_key = (f"behedr-{alert.get('system_id','?')}-"
                 f"{alert.get('process','?')}-"
                 f"{alert.get('risk_level','?')}")

    payload = {
        "routing_key":  key,
        "event_action": "trigger",
        "dedup_key":    dedup_key,
        "payload": {
            "summary":   (f"[{alert['risk_level']}] {alert.get('process','?')} "
                          f"on {alert.get('system_id','?')}"),
            "source":    alert.get("system_id", "unknown"),
            "severity":  pd_severity,
            "timestamp": _ts_human(alert.get("timestamp", 0)),
            "custom_details": {
                "process":    alert.get("process", "?"),
                "risk_score": alert.get("risk_score", 0),
                "confidence": alert.get("confidence", "?"),
                "technique":  alert.get("technique", "—"),
                "reason":     _short_reason(alert.get("reason", ""), 500),
            }
        }
    }

    result = _http_post_json(_PD_URL, payload, "PagerDuty")
    if result:
        with _pd_lock:
            _pd_open[dedup_key] = True
        log.info("[Notify] PagerDuty incident triggered: %s", dedup_key)


def resolve_pagerduty(system_id: str, process: str, risk_level: str):
    """
    Resolve a PagerDuty incident when an alert is manually closed.
    Call from the dashboard /api/alerts/<id>/resolve endpoint.
    """
    key = os.environ.get("EDR_NOTIFY_PD_KEY", "").strip()
    if not key:
        return

    dedup_key = f"behedr-{system_id}-{process}-{risk_level}"
    with _pd_lock:
        if dedup_key not in _pd_open:
            return

    payload = {
        "routing_key":  key,
        "event_action": "resolve",
        "dedup_key":    dedup_key,
    }
    _http_post_json(_PD_URL, payload, "PagerDuty-resolve")
    with _pd_lock:
        _pd_open.pop(dedup_key, None)


# ═════════════════════════════════════════════════════════════════════════════
# HTTP helper
# ═════════════════════════════════════════════════════════════════════════════

def _http_post_json(url: str, payload: dict, label: str) -> bool:
    """
    POST JSON to a URL using stdlib urllib (no extra dependencies).
    Returns True on success (2xx), False on any error.
    """
    try:
        data = json.dumps(payload).encode("utf-8")
        req  = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json",
                     "User-Agent": "BehEDR/4.0"},
            method="POST")
        with urllib.request.urlopen(req, timeout=10) as resp:
            status = resp.getcode()
            if 200 <= status < 300:
                log.info("[Notify] %s: sent OK (HTTP %d)", label, status)
                return True
            else:
                log.warning("[Notify] %s: HTTP %d", label, status)
                return False
    except urllib.error.URLError as e:
        log.error("[Notify] %s: network error — %s", label, e)
        return False
    except Exception as e:
        log.error("[Notify] %s: unexpected error — %s", label, e)
        return False


# ═════════════════════════════════════════════════════════════════════════════
# PUBLIC API
# ═════════════════════════════════════════════════════════════════════════════

def notify_alert(alert: dict):
    """
    Dispatch an alert to all configured notification channels.
    Called from detector._emit() after every new alert is saved.

    Runs each channel in a background daemon thread so it never
    blocks the detection pipeline.  All failures are logged silently.
    """
    if not _ENABLED:
        return

    if _is_duplicate(alert):
        return

    level = alert.get("risk_level", "LOW")

    # Only notify for MEDIUM and above by default.
    # LOW alerts are informational only — too noisy for paging.
    if _rank(level) < _rank("MEDIUM"):
        return

    channels = [_send_slack, _send_teams, _send_email, _send_pagerduty]

    for fn in channels:
        threading.Thread(
            target=_safe_call,
            args=(fn, alert),
            daemon=True).start()


def _safe_call(fn, alert: dict):
    """Call a notification function, catching all exceptions."""
    try:
        fn(alert)
    except Exception as e:
        log.error("[Notify] Channel %s crashed: %s", fn.__name__, e)


def is_configured() -> dict:
    """
    Return a dict showing which channels are configured.
    Useful for the /health endpoint and startup banner.
    """
    return {
        "slack":     bool(os.environ.get("EDR_NOTIFY_SLACK_URL")),
        "teams":     bool(os.environ.get("EDR_NOTIFY_TEAMS_URL")),
        "email":     bool(os.environ.get("EDR_NOTIFY_EMAIL_HOST") and
                          os.environ.get("EDR_NOTIFY_EMAIL_TO")),
        "pagerduty": bool(os.environ.get("EDR_NOTIFY_PD_KEY")),
        "enabled":   _ENABLED,
    }


def send_notification(title: str, message: str, severity: str = "info"):
    """
    Send a generic notification (non-alert) to configured channels.
    Used by backup system, health monitor, etc.
    
    Args:
        title: Notification title
        message: Notification message body
        severity: info, warning, critical (maps to risk_level for routing)
    """
    if not _ENABLED:
        return
    
    # Map severity to risk_level for consistent routing
    level_map = {
        "info": "MEDIUM",
        "warning": "HIGH", 
        "critical": "CRITICAL"
    }
    risk_level = level_map.get(severity.lower(), "MEDIUM")
    
    # Create a pseudo-alert dict for compatibility with existing channels
    pseudo_alert = {
        "system_id": "EDR-Server",
        "process": "System",
        "risk_level": risk_level,
        "risk_score": 0,
        "reason": title,
        "technique": message,
        "timestamp": int(time.time()),
    }
    
    # Send through standard channels
    notify_alert(pseudo_alert)
