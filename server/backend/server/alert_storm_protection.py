# server/alert_storm_protection.py — Alert Storm Protection
"""
Protects analysts from being overwhelmed during alert storms (e.g., compromised
host generating 1000s of alerts, mass malware outbreak, config error).

Features:
  • Per-system alert rate limiting (max alerts/minute)
  • Global alert rate limiting (max total alerts/minute)
  • Automatic alert aggregation when storm detected
  • Storm status API for dashboard visibility
  • Auto-recovery when storm subsides

Integration:
  Call check_alert_storm() before save_alert() in detector.py.
  Returns (allow: bool, reason: str).
"""

import time
import threading
from collections import defaultdict, deque

# ── Configuration ─────────────────────────────────────────────────────────────
PER_SYSTEM_MAX_PER_MIN = 30      # Max alerts per system per minute
GLOBAL_MAX_PER_MIN = 200         # Max total alerts per minute across all systems
STORM_THRESHOLD = 50             # Alerts/min to trigger "storm" status
STORM_COOLDOWN = 300             # Seconds to remain in storm mode after subsiding
TRACKING_WINDOW = 60             # Seconds to track alert rates

# ── State tracking ────────────────────────────────────────────────────────────
_per_system_alerts = defaultdict(lambda: deque(maxlen=100))  # system_id → [timestamps]
_global_alerts = deque(maxlen=500)                           # All alert timestamps
_storm_status = {}               # system_id → {"in_storm": bool, "entered_at": ts, "suppressed_count": int}
_lock = threading.Lock()


def check_alert_storm(system_id: str, alert: dict) -> tuple:
    """
    Check if this alert should be allowed or suppressed due to storm protection.
    
    Returns:
        (allow: bool, reason: str)
        - (True, "") if alert is allowed
        - (False, "reason") if alert is suppressed
    """
    now = time.time()
    
    with _lock:
        # Record this alert attempt
        _per_system_alerts[system_id].append(now)
        _global_alerts.append(now)
        
        # Clean old entries
        _clean_old_entries(now)
        
        # Check per-system rate
        system_rate = _get_rate(_per_system_alerts[system_id], now)
        if system_rate > PER_SYSTEM_MAX_PER_MIN:
            _enter_storm(system_id, now)
            return (False, f"Per-system storm: {system_rate} alerts/min (max {PER_SYSTEM_MAX_PER_MIN})")
        
        # Check global rate
        global_rate = _get_rate(_global_alerts, now)
        if global_rate > GLOBAL_MAX_PER_MIN:
            return (False, f"Global storm: {global_rate} alerts/min (max {GLOBAL_MAX_PER_MIN})")
        
        # Check if system was in storm but has recovered
        if system_id in _storm_status:
            if system_rate < STORM_THRESHOLD:
                elapsed = now - _storm_status[system_id].get("entered_at", now)
                if elapsed > STORM_COOLDOWN:
                    _exit_storm(system_id)
                else:
                    # Still in cooldown period
                    return (False, f"Storm cooldown: {int(STORM_COOLDOWN - elapsed)}s remaining")
        
        return (True, "")


def _clean_old_entries(now: float):
    """Remove entries older than TRACKING_WINDOW."""
    cutoff = now - TRACKING_WINDOW
    
    # Clean per-system tracking
    for sid in list(_per_system_alerts.keys()):
        alerts = _per_system_alerts[sid]
        # Remove old timestamps
        while alerts and alerts[0] < cutoff:
            alerts.popleft()
        # Remove empty systems
        if not alerts:
            del _per_system_alerts[sid]
    
    # Clean global tracking
    while _global_alerts and _global_alerts[0] < cutoff:
        _global_alerts.popleft()


def _get_rate(alert_queue, now: float) -> float:
    """Observed count in a full rolling minute, including the initial minute."""
    return sum(now - TRACKING_WINDOW <= ts <= now for ts in alert_queue) * 60 / TRACKING_WINDOW


def _enter_storm(system_id: str, now: float):
    """Mark a system as being in alert storm."""
    if system_id not in _storm_status:
        _storm_status[system_id] = {
            "in_storm": True,
            "entered_at": now,
            "suppressed_count": 0
        }
        print(f"[STORM] ⚠️  Alert storm detected on {system_id}")
    
    _storm_status[system_id]["suppressed_count"] += 1


def _exit_storm(system_id: str):
    """Mark a system as having recovered from alert storm."""
    if system_id in _storm_status:
        count = _storm_status[system_id]["suppressed_count"]
        print(f"[STORM] ✅ Alert storm ended on {system_id} "
              f"(suppressed {count} alerts during storm)")
        del _storm_status[system_id]


def get_storm_status() -> dict:
    """
    Get current storm status for all systems.
    
    Returns:
        {
            "global_rate": float,  # Alerts per minute (all systems)
            "systems": {
                "SYSTEM-1": {
                    "rate": float,
                    "in_storm": bool,
                    "suppressed_count": int,
                    "storm_duration": int  # seconds
                },
                ...
            }
        }
    """
    now = time.time()
    
    with _lock:
        _clean_old_entries(now)
        
        global_rate = _get_rate(_global_alerts, now)
        
        systems = {}
        for sid, alerts in _per_system_alerts.items():
            rate = _get_rate(alerts, now)
            storm_info = _storm_status.get(sid, {})
            
            systems[sid] = {
                "rate": round(rate, 1),
                "in_storm": storm_info.get("in_storm", False),
                "suppressed_count": storm_info.get("suppressed_count", 0),
                "storm_duration": int(now - storm_info["entered_at"]) if storm_info else 0
            }
        
        # Add systems in storm but with no recent attempts
        for sid, storm_info in _storm_status.items():
            if sid not in systems:
                systems[sid] = {
                    "rate": 0,
                    "in_storm": True,
                    "suppressed_count": storm_info["suppressed_count"],
                    "storm_duration": int(now - storm_info["entered_at"])
                }
        
        return {
            "global_rate": round(global_rate, 1),
            "per_system_limit": PER_SYSTEM_MAX_PER_MIN,
            "global_limit": GLOBAL_MAX_PER_MIN,
            "systems": systems
        }


def reset_storm(system_id: str = None):
    """
    Manually reset storm protection for a system or all systems.
    Used by analysts to clear false-positive storm detection.
    """
    with _lock:
        if system_id:
            if system_id in _storm_status:
                del _storm_status[system_id]
            if system_id in _per_system_alerts:
                _per_system_alerts[system_id].clear()
            print(f"[STORM] Storm protection reset for {system_id}")
        else:
            _storm_status.clear()
            _per_system_alerts.clear()
            _global_alerts.clear()
            print("[STORM] Storm protection reset for all systems")
