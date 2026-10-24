# server/playbooks.py — Automated response playbook engine
"""
Executes structured action sequences in response to alerts.

Each playbook defines:
  - A trigger condition  (risk_level + optional technique/process filters)
  - A list of actions    (queued as agent commands via queue_cmd)
  - A cooldown           (minimum seconds between executions for the same system)

Built-in playbooks
──────────────────

  ransomware_response
    Trigger: CRITICAL, techniques T1490 / T1486 / L7 file events
    Actions: isolate_network → collect_forensics → kill_process (if named)
    Cooldown: 300s per system

  credential_dump_response
    Trigger: CRITICAL, techniques T1003.*
    Actions: collect_forensics → kill_process
    Cooldown: 120s per system

  c2_beaconing_response
    Trigger: HIGH+, technique T1071 / C2 beaconing
    Actions: collect_forensics → isolate_network
    Cooldown: 300s per system

  process_injection_response
    Trigger: CRITICAL, technique T1055
    Actions: collect_forensics → kill_process
    Cooldown: 120s per system

  defender_disable_response
    Trigger: CRITICAL, technique T1562.001
    Actions: collect_forensics
    Cooldown: 60s per system

Custom playbooks
────────────────
  Drop a YAML file at data/playbooks.yaml to override or extend the
  built-in set.  The YAML schema matches the _BUILTIN dict below.
  Custom playbooks are merged with built-ins (custom wins on name collision).

  Example data/playbooks.yaml:
    playbooks:
      - name: my_custom_playbook
        enabled: true
        trigger:
          risk_level: [CRITICAL, HIGH]
          technique_contains: ["T1059"]
        cooldown: 180
        actions:
          - action: collect_forensics
            params: {}
          - action: kill_process
            params: {target: "{process}"}

  {process}, {system_id} are substituted from the alert at execution time.

Architecture
────────────
  run_playbooks(alert)   — called from detector._emit() after every new alert
  _execute_playbook()    — validates cooldown, queues all actions
  _matches()             — checks whether an alert triggers a playbook
"""

import os
import re
import time
import json
import logging
import threading
import yaml
from typing import Optional

log = logging.getLogger("playbooks")

# ── Playbook cooldown tracker ─────────────────────────────────────────────────
# {(playbook_name, system_id): last_triggered_ts}
_cooldowns: dict = {}
_cd_lock = threading.Lock()


def _on_cooldown(name: str, system_id: str, cooldown: int) -> bool:
    key = (name, system_id)
    now = time.time()
    with _cd_lock:
        last = _cooldowns.get(key, 0)
        if now - last < cooldown:
            return True
        _cooldowns[key] = now
        # Evict stale entries
        if len(_cooldowns) > 500:
            cutoff = now - 3600
            for k in [k for k, v in list(_cooldowns.items()) if v < cutoff]:
                del _cooldowns[k]
    return False


# ── Built-in playbooks ────────────────────────────────────────────────────────

_BUILTIN = [
    {
        "name":    "ransomware_response",
        "enabled": True,
        "description": "Ransomware detected — isolate host, collect forensics",
        "trigger": {
            "risk_level":         ["CRITICAL"],
            "technique_contains": ["T1490", "T1486", "T1485"],
            "reason_contains":    ["shadow copy", "ransomware", "mass file", "ransom note",
                                   ".encrypted", ".locked"],
            "match_any": True,   # technique OR reason match is enough
        },
        "cooldown": 300,
        "actions": [
            {"action": "collect_forensics", "params": {}},
            {"action": "isolate_network",   "params": {}},
            # kill_process only when a specific process name is in the alert
            {"action": "kill_process",      "params": {"target": "{process}"},
             "condition": "process_not_protected"},
        ],
    },
    {
        "name":    "credential_dump_response",
        "enabled": True,
        "description": "Credential dumping detected — collect forensics, kill tool",
        "trigger": {
            "risk_level":         ["CRITICAL"],
            "technique_contains": ["T1003"],
            "match_any": False,
        },
        "cooldown": 120,
        "actions": [
            {"action": "collect_forensics", "params": {}},
            {"action": "kill_process",      "params": {"target": "{process}"},
             "condition": "process_not_protected"},
        ],
    },
    {
        "name":    "c2_beaconing_response",
        "enabled": True,
        "description": "C2 beaconing detected — collect forensics, isolate if CRITICAL",
        "trigger": {
            "risk_level":         ["CRITICAL", "HIGH"],
            "technique_contains": ["T1071", "T1095", "T1008"],
            "reason_contains":    ["C2 beaconing", "beaconing pattern"],
            "match_any": True,
        },
        "cooldown": 300,
        "actions": [
            {"action": "collect_forensics", "params": {}},
            # Isolate only on CRITICAL — HIGH gets forensics only
            {"action": "isolate_network",   "params": {},
             "condition": "level_is_critical"},
        ],
    },
    {
        "name":    "process_injection_response",
        "enabled": True,
        "description": "Process injection detected — collect forensics, kill injector",
        "trigger": {
            "risk_level":         ["CRITICAL"],
            "technique_contains": ["T1055"],
            "match_any": False,
        },
        "cooldown": 120,
        "actions": [
            {"action": "collect_forensics", "params": {}},
            {"action": "kill_process",      "params": {"target": "{process}"},
             "condition": "process_not_protected"},
        ],
    },
    {
        "name":    "defender_disable_response",
        "enabled": True,
        "description": "Defender disabled — collect forensics immediately",
        "trigger": {
            "risk_level":         ["CRITICAL"],
            "technique_contains": ["T1562"],
            "match_any": False,
        },
        "cooldown": 60,
        "actions": [
            {"action": "collect_forensics", "params": {}},
        ],
    },
    {
        "name":    "lateral_movement_response",
        "enabled": True,
        "description": "Lateral movement detected — collect forensics",
        "trigger": {
            "risk_level":         ["CRITICAL", "HIGH"],
            "technique_contains": ["T1021", "T1047", "T1569"],
            "reason_contains":    ["lateral movement", "psexec", "remote"],
            "match_any": True,
        },
        "cooldown": 180,
        "actions": [
            {"action": "collect_forensics", "params": {}},
        ],
    },
]

# Processes that must never be killed by a playbook (subset of NEVER_KILL)
_PROTECTED_PROCS = {
    "lsass.exe", "csrss.exe", "smss.exe", "wininit.exe",
    "services.exe", "svchost.exe", "winlogon.exe", "explorer.exe",
    "dwm.exe", "system", "registry",
}


# ── YAML loader ───────────────────────────────────────────────────────────────

def _load_custom_playbooks() -> list:
    """Load custom playbooks from data/playbooks.yaml if it exists."""
    try:
        from server.config import DATA_DIR
        path = os.path.join(DATA_DIR, "playbooks.yaml")
        if not os.path.exists(path):
            return []
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        custom = data.get("playbooks", [])
        log.info("[Playbooks] Loaded %d custom playbook(s) from %s",
                 len(custom), path)
        return custom
    except Exception as e:
        log.error("[Playbooks] Error loading custom playbooks: %s", e)
        return []


def _get_playbooks() -> list:
    """Return merged list: built-ins + custom (custom wins on name collision)."""
    custom = _load_custom_playbooks()
    custom_names = {p["name"] for p in custom}
    merged = [p for p in _BUILTIN if p["name"] not in custom_names]
    merged.extend(custom)
    return merged


# ── Trigger matching ──────────────────────────────────────────────────────────

def _matches(playbook: dict, alert: dict) -> bool:
    """
    Return True if the alert satisfies the playbook's trigger conditions.

    Logic:
      - risk_level must match (always AND)
      - if match_any=True:  technique_contains OR reason_contains
      - if match_any=False: technique_contains AND reason_contains
                            (empty list = always matches for that field)
    """
    trigger = playbook.get("trigger", {})

    # ── Risk level check ──────────────────────────────────────────────────
    allowed_levels = [l.upper() for l in trigger.get("risk_level", [])]
    if allowed_levels and alert.get("risk_level", "").upper() not in allowed_levels:
        return False

    technique  = alert.get("technique", "")
    reason     = alert.get("reason",    "").lower()
    match_any  = trigger.get("match_any", False)

    tech_patterns  = trigger.get("technique_contains", [])
    reason_patterns = trigger.get("reason_contains",   [])

    # Technique match: any of the patterns is a prefix/substring of the technique
    tech_hit = (
        not tech_patterns or
        any(technique.startswith(p) or p in technique
            for p in tech_patterns)
    )

    # Reason match: any keyword appears in the reason string
    reason_hit = (
        not reason_patterns or
        any(kw.lower() in reason for kw in reason_patterns)
    )

    if match_any:
        return tech_hit or reason_hit
    else:
        return tech_hit and reason_hit


# ── Action execution ──────────────────────────────────────────────────────────

def _resolve_params(params: dict, alert: dict) -> dict:
    """
    Substitute {process} and {system_id} placeholders in action params.
    """
    resolved = {}
    for k, v in params.items():
        if isinstance(v, str):
            v = v.replace("{process}",   alert.get("process",   ""))
            v = v.replace("{system_id}", alert.get("system_id", ""))
        resolved[k] = v
    return resolved


def _check_condition(condition: Optional[str], alert: dict) -> bool:
    """
    Evaluate an optional per-action condition.
    Returns True (action should run) if condition is met or absent.
    """
    if not condition:
        return True

    if condition == "process_not_protected":
        proc = alert.get("process", "").lower()
        # Strip arrows for injection alerts like "notepad.exe → svchost.exe"
        proc = proc.split("→")[-1].strip() if "→" in proc else proc
        proc = proc.split("->")[-1].strip() if "->" in proc else proc
        return proc not in _PROTECTED_PROCS

    if condition == "level_is_critical":
        return alert.get("risk_level", "").upper() == "CRITICAL"

    return True   # unknown condition — allow by default


def _execute_playbook(playbook: dict, alert: dict):
    """
    Queue all actions for a matching playbook.
    Respects cooldown, condition checks, and protected process list.
    """
    from server.database.storage import queue_cmd

    name      = playbook["name"]
    system_id = alert.get("system_id", "")
    cooldown  = int(playbook.get("cooldown", 300))

    if _on_cooldown(name, system_id, cooldown):
        log.debug("[Playbooks] '%s' on cooldown for system %s", name, system_id)
        return

    log.info("[Playbooks] Triggering '%s' for system %s (alert: %s %s)",
             name, system_id,
             alert.get("risk_level", "?"), alert.get("technique", ""))

    queued = []
    for step in playbook.get("actions", []):
        action    = step.get("action", "")
        params    = _resolve_params(step.get("params", {}), alert)
        condition = step.get("condition")

        if not _check_condition(condition, alert):
            log.debug("[Playbooks]   Skipping '%s' (condition '%s' not met)",
                      action, condition)
            continue

        try:
            cmd_id = queue_cmd(system_id, action, params)
            queued.append(f"{action}(id={cmd_id})")
            log.info("[Playbooks]   Queued: %s %s → cmd_id=%s",
                     action, params, cmd_id)
        except Exception as e:
            log.error("[Playbooks]   Failed to queue '%s': %s", action, e)

    if queued:
        # Write a playbook execution record to the audit log
        try:
            from server.database.storage import write_audit
            write_audit(
                username="playbook_engine",
                action=f"playbook:{name}",
                detail=f"system={system_id} actions=[{', '.join(queued)}] "
                       f"alert_level={alert.get('risk_level')} "
                       f"technique={alert.get('technique','')}",
                ip="127.0.0.1",
            )
        except Exception:
            pass


# ── Public API ────────────────────────────────────────────────────────────────

def run_playbooks(alert: dict):
    """
    Check all enabled playbooks against an alert and execute any that match.
    Called from detector._emit() after every new alert is saved.
    Runs in a background thread so it never blocks the detection pipeline.
    """
    threading.Thread(
        target=_run_playbooks_bg,
        args=(alert,),
        daemon=True).start()


def _run_playbooks_bg(alert: dict):
    try:
        for pb in _get_playbooks():
            if not pb.get("enabled", True):
                continue
            if _matches(pb, alert):
                _execute_playbook(pb, alert)
    except Exception as e:
        log.error("[Playbooks] Unexpected error: %s", e)


def get_playbook_status() -> list:
    """
    Return a summary of all playbooks and their last-triggered times.
    Used by the /api/playbooks endpoint.
    """
    now = time.time()
    result = []
    for pb in _get_playbooks():
        name = pb["name"]
        # Find latest cooldown entry for any system
        with _cd_lock:
            last_triggered = max(
                (v for k, v in _cooldowns.items() if k[0] == name),
                default=0)
        result.append({
            "name":           name,
            "enabled":        pb.get("enabled", True),
            "description":    pb.get("description", ""),
            "cooldown":       pb.get("cooldown", 300),
            "last_triggered": int(last_triggered),
            "actions":        [s.get("action") for s in pb.get("actions", [])],
            "trigger":        pb.get("trigger", {}),
        })
    return result
