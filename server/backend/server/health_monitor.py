# server/health_monitor.py — Health Monitoring System
"""
Monitors agent and server health with alerting.

Features:
  • Agent health tracking (last heartbeat, missed checks)
  • Server resource monitoring (CPU, memory, disk)
  • Automatic alert on agent offline
  • Health status API for dashboard
  • Configurable thresholds

Integration:
  Called automatically by heartbeat endpoint in api.py
"""

import time
import psutil
import threading
from collections import defaultdict

# ── Configuration ─────────────────────────────────────────────────────────────
AGENT_OFFLINE_THRESHOLD = 300      # 5 minutes no heartbeat = offline
AGENT_WARNING_THRESHOLD = 120      # 2 minutes = warning
HEALTH_CHECK_INTERVAL = 60         # Check every minute
MEMORY_WARNING_PERCENT = 80        # Warn at 80% memory
DISK_WARNING_PERCENT = 85          # Warn at 85% disk
CPU_WARNING_PERCENT = 90           # Warn at 90% CPU (sustained)

# ── State ─────────────────────────────────────────────────────────────────────
_agent_heartbeats = {}             # system_id → last_heartbeat_timestamp
_agent_status = {}                 # system_id → {"status": "online|warning|offline", "last_seen": ts}
_server_health = {
    "status": "healthy",
    "cpu_percent": 0,
    "memory_percent": 0,
    "disk_percent": 0,
    "last_check": 0
}
_health_lock = threading.Lock()
_health_thread = None
_stop_event = threading.Event()


def record_agent_heartbeat(system_id: str):
    """Record agent heartbeat (called from /heartbeat endpoint)."""
    now = time.time()
    
    with _health_lock:
        old_status = _agent_status.get(system_id, {}).get("status")
        _agent_heartbeats[system_id] = now
        _agent_status[system_id] = {
            "status": "online",
            "last_seen": now,
            "last_heartbeat": now
        }
        
        # If agent was offline and came back online, log recovery
        if old_status == "offline":
            print(f"[HEALTH] ✅ Agent {system_id} came back online")
            _notify_agent_recovery(system_id)


def _check_agent_health():
    """Check all agents for missed heartbeats."""
    now = time.time()
    offline_agents = []
    warning_agents = []
    
    with _health_lock:
        for system_id, last_heartbeat in list(_agent_heartbeats.items()):
            time_since_heartbeat = now - last_heartbeat
            
            if time_since_heartbeat > AGENT_OFFLINE_THRESHOLD:
                # Agent is offline
                old_status = _agent_status.get(system_id, {}).get("status")
                _agent_status[system_id] = {
                    "status": "offline",
                    "last_seen": last_heartbeat,
                    "last_heartbeat": last_heartbeat,
                    "offline_duration": int(time_since_heartbeat)
                }
                
                # Only alert on status change (not every check)
                if old_status != "offline":
                    offline_agents.append(system_id)
                    
            elif time_since_heartbeat > AGENT_WARNING_THRESHOLD:
                # Agent is late but not offline yet
                _agent_status[system_id] = {
                    "status": "warning",
                    "last_seen": last_heartbeat,
                    "last_heartbeat": last_heartbeat,
                    "seconds_since_heartbeat": int(time_since_heartbeat)
                }
                
                # Only alert once when entering warning state
                old_status = _agent_status.get(system_id, {}).get("status")
                if old_status == "online":
                    warning_agents.append(system_id)
    
    # Send notifications for status changes
    for system_id in offline_agents:
        print(f"[HEALTH] ⚠️  Agent {system_id} is OFFLINE (no heartbeat for {AGENT_OFFLINE_THRESHOLD}s)")
        _notify_agent_offline(system_id)
    
    for system_id in warning_agents:
        print(f"[HEALTH] ⚠️  Agent {system_id} is LATE (no heartbeat for {AGENT_WARNING_THRESHOLD}s)")


def _check_server_health():
    """Check server resource usage."""
    global _server_health
    
    try:
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        status = "healthy"
        warnings = []
        
        if cpu_percent > CPU_WARNING_PERCENT:
            status = "warning"
            warnings.append(f"High CPU: {cpu_percent:.1f}%")
        
        if memory.percent > MEMORY_WARNING_PERCENT:
            status = "warning"
            warnings.append(f"High memory: {memory.percent:.1f}%")
        
        if disk.percent > DISK_WARNING_PERCENT:
            status = "warning"
            warnings.append(f"High disk: {disk.percent:.1f}%")
        
        with _health_lock:
            _server_health = {
                "status": status,
                "cpu_percent": round(cpu_percent, 1),
                "memory_percent": round(memory.percent, 1),
                "memory_used_gb": round(memory.used / (1024**3), 2),
                "memory_total_gb": round(memory.total / (1024**3), 2),
                "disk_percent": round(disk.percent, 1),
                "disk_used_gb": round(disk.used / (1024**3), 2),
                "disk_total_gb": round(disk.total / (1024**3), 2),
                "warnings": warnings,
                "last_check": int(time.time())
            }
        
        if warnings:
            for warning in warnings:
                print(f"[HEALTH] ⚠️  Server: {warning}")
            
    except Exception as e:
        print(f"[HEALTH] Server health check error: {e}")


def _health_check_loop():
    """Background thread for health monitoring."""
    print(f"[HEALTH] Monitor started (check interval: {HEALTH_CHECK_INTERVAL}s)")
    
    while not _stop_event.wait(timeout=HEALTH_CHECK_INTERVAL):
        _check_agent_health()
        _check_server_health()
    
    print("[HEALTH] Monitor stopped")


def start_health_monitor():
    """Start the health monitoring background thread."""
    global _health_thread
    
    if _health_thread and _health_thread.is_alive():
        print("[HEALTH] Monitor already running")
        return
    
    _stop_event.clear()
    _health_thread = threading.Thread(target=_health_check_loop, daemon=True, name="HealthMonitor")
    _health_thread.start()


def stop_health_monitor():
    """Stop the health monitoring background thread."""
    global _health_thread
    
    if _health_thread and _health_thread.is_alive():
        print("[HEALTH] Stopping monitor...")
        _stop_event.set()
        _health_thread.join(timeout=5)
        _health_thread = None


def get_health_status() -> dict:
    """Get current health status of all agents and server."""
    now = time.time()
    
    with _health_lock:
        # Get agent summary
        online_count = sum(1 for s in _agent_status.values() if s.get("status") == "online")
        warning_count = sum(1 for s in _agent_status.values() if s.get("status") == "warning")
        offline_count = sum(1 for s in _agent_status.values() if s.get("status") == "offline")
        
        agents = []
        for system_id, status in _agent_status.items():
            agents.append({
                "system_id": system_id,
                "status": status.get("status", "unknown"),
                "last_seen": status.get("last_seen", 0),
                "seconds_since_heartbeat": int(now - status.get("last_heartbeat", 0)),
                "offline_duration": status.get("offline_duration", 0)
            })
        
        # Sort: offline first, then warning, then online
        status_priority = {"offline": 0, "warning": 1, "online": 2, "unknown": 3}
        agents.sort(key=lambda x: (status_priority.get(x["status"], 3), x["system_id"]))
        
        return {
            "server": _server_health.copy(),
            "agents": {
                "total": len(_agent_status),
                "online": online_count,
                "warning": warning_count,
                "offline": offline_count,
                "details": agents
            },
            "thresholds": {
                "agent_offline_seconds": AGENT_OFFLINE_THRESHOLD,
                "agent_warning_seconds": AGENT_WARNING_THRESHOLD,
                "server_memory_percent": MEMORY_WARNING_PERCENT,
                "server_disk_percent": DISK_WARNING_PERCENT,
                "server_cpu_percent": CPU_WARNING_PERCENT
            }
        }


def _notify_agent_offline(system_id: str):
    """Send notification when agent goes offline."""
    try:
        from server.notifier import send_notification
        
        message = f"⚠️ EDR Agent Offline\n"
        message += f"System: {system_id}\n"
        message += f"Last seen: {int(time.time() - _agent_heartbeats.get(system_id, 0))}s ago\n"
        message += f"Action: Check agent status, review logs"
        
        send_notification("Agent Offline", message, "warning")
    except Exception as e:
        print(f"[HEALTH] Notification failed: {e}")


def _notify_agent_recovery(system_id: str):
    """Send notification when offline agent comes back online."""
    try:
        from server.notifier import send_notification
        
        message = f"✅ EDR Agent Recovered\n"
        message += f"System: {system_id}\n"
        message += f"Status: Online"
        
        send_notification("Agent Recovered", message, "info")
    except Exception as e:
        print(f"[HEALTH] Notification failed: {e}")


def get_agent_health(system_id: str) -> dict:
    """Get health status for a specific agent."""
    now = time.time()
    
    with _health_lock:
        if system_id not in _agent_status:
            return {"status": "unknown", "message": "Agent never connected"}
        
        status = _agent_status[system_id].copy()
        status["seconds_since_heartbeat"] = int(now - status.get("last_heartbeat", 0))
        
        return status
