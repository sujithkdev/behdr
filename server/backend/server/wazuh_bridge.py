# server/wazuh_bridge.py — Wazuh → EDR detection engine bridge
"""
Receives normalized events from Wazuh Manager and feeds them into
the 7-layer detection engine — giving the engine full Sysmon/EventLog
context instead of just psutil process names.

Two integration modes:

MODE 1 — Wazuh HTTP integration (recommended)
  Configure Wazuh Manager to POST alerts to this endpoint:
  In /var/ossec/etc/ossec.conf add:
    <integration>
      <name>custom-edr</name>
      <hook_url>http://YOUR_EDR_SERVER:5000/wazuh/events</hook_url>
      <api_key>YOUR_EDR_API_KEY</api_key>
      <alert_format>json</alert_format>
    </integration>

MODE 2 — Syslog receiver (UDP 514)
  Wazuh sends CEF/JSON syslog to this server.
  Enable with: python -m server.wazuh_bridge --syslog
  Or set WAZUH_SYSLOG_ENABLED=true in environment.

Event normalization:
  Wazuh events contain different fields depending on source
  (Sysmon, Windows Event Log, auditd).
  This bridge normalizes them all into your standard event format:
  {system_id, event, parent, child, pid, cmdline, sha256, exe_path, time}
"""

import json, socket, threading, time, logging, os
from flask import Blueprint, request, jsonify
from server.config import API_KEY
from server.core.processor import process
from server.core.detector import analyze
from server.core.graph import add_event
from server.database.storage import save_event, upsert_system

log = logging.getLogger("wazuh_bridge")

wazuh_bp = Blueprint("wazuh", __name__)

# ── Wazuh event ID mappings ───────────────────────────────────────────────────
# Sysmon Event IDs
SYSMON_PROCESS_CREATE  = "1"    # process creation — maps to process_spawn
SYSMON_NETWORK_CONNECT = "3"    # network connection — feeds L6
SYSMON_FILE_CREATE     = "11"   # file created — feeds L7
SYSMON_REG_SET         = "13"   # registry set — feeds L7

# Windows Security Event IDs
WIN_PROCESS_CREATE  = "4688"   # process creation with cmdline
WIN_SCHED_TASK      = "4698"   # scheduled task created
WIN_SERVICE_INSTALL = "7045"   # new service installed
WIN_LOGON_SUCCESS   = "4624"
WIN_LOGON_FAIL      = "4625"
WIN_REG_MODIFIED    = "4657"
WIN_FILE_ACCESS     = "4663"
WIN_LOG_CLEARED     = "1102"   # audit log cleared


# ── Normalization ─────────────────────────────────────────────────────────────

def _normalize_sysmon(wazuh_event: dict) -> dict | None:
    """
    Convert a Wazuh/Sysmon event into your standard event format.
    Returns None if the event is not actionable for the detection engine.
    """
    data    = wazuh_event.get("data", {})
    agent   = wazuh_event.get("agent", {})
    rule    = wazuh_event.get("rule", {})
    ev_id   = str(data.get("win", {}).get("eventdata", {}).get("eventId", "")
                  or rule.get("id", ""))

    system_id = agent.get("name", agent.get("id", "unknown"))
    now       = int(time.time())

    # ── Sysmon Event 1 — Process Create ──────────────────────────────────
    if ev_id == SYSMON_PROCESS_CREATE or "ProcessCreate" in str(data):
        ed = data.get("win", {}).get("eventdata", {})
        return {
            "system_id": system_id,
            "event":     "process_spawn",
            "parent":    _basename(ed.get("parentImage", "unknown")),
            "child":     _basename(ed.get("image", "unknown")),
            "pid":       int(ed.get("processId", 0) or 0),
            "cmdline":   ed.get("commandLine", "")[:512],
            "sha256":    ed.get("hashes", "").split("SHA256=")[-1].split(",")[0].lower(),
            "exe_path":  ed.get("image", ""),
            "user":      ed.get("user", ""),
            "time":      now,
            "source":    "sysmon",
        }

    # ── Windows Event 4688 — Process Create ──────────────────────────────
    if ev_id == WIN_PROCESS_CREATE:
        ed = data.get("win", {}).get("eventdata", {})
        return {
            "system_id": system_id,
            "event":     "process_spawn",
            "parent":    _basename(ed.get("parentProcessName", "unknown")),
            "child":     _basename(ed.get("newProcessName", "unknown")),
            "pid":       int(ed.get("newProcessId", "0").replace("0x", ""), 16)
                         if "0x" in str(ed.get("newProcessId", "")) else
                         int(ed.get("newProcessId", 0) or 0),
            "cmdline":   ed.get("commandLine", ed.get("processCommandLine", ""))[:512],
            "sha256":    "",
            "exe_path":  ed.get("newProcessName", ""),
            "user":      ed.get("subjectUserName", ""),
            "time":      now,
            "source":    "winevent",
        }

    # ── Sysmon Event 3 — Network Connect — feeds L6 ──────────────────────
    if ev_id == SYSMON_NETWORK_CONNECT or "NetworkConnect" in str(data):
        ed = data.get("win", {}).get("eventdata", {})
        proc     = _basename(ed.get("image", "unknown"))
        dest_ip  = ed.get("destinationIp", "")
        dest_port = int(ed.get("destinationPort", 0) or 0)
        if dest_ip and dest_port:
            from server.core.detector import add_network_event
            add_network_event(system_id, proc, dest_ip, dest_port)
        return None   # network events don't create process alerts directly

    # ── Sysmon Event 11 / Windows 4663 — File Create/Access — feeds L7 ──
    if ev_id in (SYSMON_FILE_CREATE, WIN_FILE_ACCESS) or "FileCreate" in str(data):
        ed   = data.get("win", {}).get("eventdata", {})
        proc = _basename(ed.get("image", ed.get("processName", "unknown")))
        path = ed.get("targetFilename", ed.get("objectName", ""))
        if path:
            from server.core.detector import add_file_event
            add_file_event(system_id, proc, path, "write")
        return None

    # ── Sysmon Event 13 / Windows 4657 — Registry — feeds L7 ────────────
    if ev_id in (SYSMON_REG_SET, WIN_REG_MODIFIED) or "RegistryEvent" in str(data):
        ed   = data.get("win", {}).get("eventdata", {})
        proc = _basename(ed.get("image", ed.get("processName", "unknown")))
        key  = ed.get("targetObject", ed.get("objectName", ""))
        if key:
            from server.core.detector import add_file_event
            add_file_event(system_id, proc, key, "registry_write")
        # If Run key modified → synthesize a process event for detection
        if "CurrentVersion\\Run" in key or "CurrentVersion\\RunOnce" in key:
            return {
                "system_id": system_id,
                "event":     "process_spawn",
                "parent":    proc,
                "child":     proc,
                "pid":       0,
                "cmdline":   f"reg add {key}",
                "sha256":    "",
                "exe_path":  "",
                "user":      "",
                "time":      now,
                "source":    "registry",
            }
        return None

    # ── Scheduled task created — synthesize event for L1 rule ────────────
    if ev_id == WIN_SCHED_TASK:
        ed = data.get("win", {}).get("eventdata", {})
        return {
            "system_id": system_id,
            "event":     "process_spawn",
            "parent":    "taskschd.exe",
            "child":     "schtasks.exe",
            "pid":       0,
            "cmdline":   f"/create /tn {ed.get('taskName', '')}",
            "sha256":    "",
            "exe_path":  "",
            "user":      ed.get("subjectUserName", ""),
            "time":      now,
            "source":    "winevent",
        }

    # ── Service installed — synthesize event for L1 rule ────────────────
    if ev_id == WIN_SERVICE_INSTALL:
        ed = data.get("win", {}).get("eventdata", {})
        return {
            "system_id": system_id,
            "event":     "process_spawn",
            "parent":    "services.exe",
            "child":     "sc.exe",
            "pid":       0,
            "cmdline":   f"create {ed.get('serviceName', '')} binpath= {ed.get('imagePath', '')}",
            "sha256":    "",
            "exe_path":  "",
            "user":      ed.get("subjectUserName", "SYSTEM"),
            "time":      now,
            "source":    "winevent",
        }

    # ── Event log cleared — synthesize event for L1 rule ────────────────
    if ev_id == WIN_LOG_CLEARED:
        return {
            "system_id": system_id,
            "event":     "process_spawn",
            "parent":    "eventlog_service",
            "child":     "wevtutil.exe",
            "pid":       0,
            "cmdline":   "cl Security",
            "sha256":    "",
            "exe_path":  "",
            "user":      "",
            "time":      now,
            "source":    "winevent",
        }

    return None   # unhandled event type


def _basename(path: str) -> str:
    """Extract filename from a full Windows path."""
    return os.path.basename(path.replace("\\", "/")).lower() if path else "unknown"


def _pipeline(raw_event: dict):
    """Normalize → validate → detect → store."""
    event = process(raw_event)
    if not event:
        return None
    save_event(event)
    add_event(event)
    alerts = analyze(event)
    return alerts


# ── Flask endpoint: Wazuh HTTP integration ────────────────────────────────────

@wazuh_bp.route("/wazuh/events", methods=["POST"])
def wazuh_events():
    """
    Wazuh Manager POSTs JSON alerts here via its integration module.
    One event per POST (Wazuh's default), or a list for batch mode.
    """
    if request.headers.get("API-Key", "") != API_KEY:
        return jsonify({"error": "Unauthorized"}), 401

    raw = request.get_json(silent=True)
    if not raw:
        return jsonify({"error": "Invalid JSON"}), 400

    items = raw if isinstance(raw, list) else [raw]
    processed = 0
    alerts_fired = 0

    for item in items:
        # Register the agent as a system if not already known
        agent = item.get("agent", {})
        if agent.get("name"):
            upsert_system({
                "system_id":  agent["name"],
                "hostname":   agent.get("name"),
                "ip_address": agent.get("ip", ""),
                "agent_ver":  f"wazuh-{item.get('manager', {}).get('name', '')}",
                "platform":   "windows",
            })

        normalized = _normalize_sysmon(item)
        if normalized:
            result = _pipeline(normalized)
            processed += 1
            if result:
                alerts_fired += len(result)

    return jsonify({
        "status":       "ok",
        "processed":    processed,
        "alerts_fired": alerts_fired,
    }), 200


@wazuh_bp.route("/wazuh/health", methods=["GET"])
def wazuh_health():
    return jsonify({"status": "ok", "bridge": "wazuh-edr-v1"}), 200


# ── Syslog UDP receiver (Mode 2) ──────────────────────────────────────────────

class SyslogReceiver:
    """
    UDP syslog listener. Wazuh can forward events as JSON over syslog.
    Run in background thread.
    """
    def __init__(self, host="0.0.0.0", port=5514):
        self.host = host
        self.port = port
        self._stop = threading.Event()

    def start(self):
        t = threading.Thread(target=self._run, name="SyslogReceiver", daemon=True)
        t.start()
        log.info("[WAZUH BRIDGE] Syslog receiver started on UDP %s:%d", self.host, self.port)

    def _run(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind((self.host, self.port))
            sock.settimeout(1.0)
        except OSError as e:
            log.warning("[WAZUH BRIDGE] Could not bind syslog port %d: %s", self.port, e)
            return

        while not self._stop.is_set():
            try:
                data, addr = sock.recvfrom(65535)
                msg = data.decode("utf-8", errors="replace").strip()
                # Wazuh JSON syslog: strip syslog header if present
                json_start = msg.find("{")
                if json_start >= 0:
                    try:
                        event = json.loads(msg[json_start:])
                        normalized = _normalize_sysmon(event)
                        if normalized:
                            _pipeline(normalized)
                    except json.JSONDecodeError:
                        pass
            except socket.timeout:
                continue
            except Exception as e:
                log.debug("[WAZUH BRIDGE] Syslog recv error: %s", e)

        sock.close()


# Start syslog receiver if enabled
_syslog_receiver = None
if os.environ.get("WAZUH_SYSLOG_ENABLED", "").lower() in ("1", "true", "yes"):
    _syslog_port = int(os.environ.get("WAZUH_SYSLOG_PORT", 5514))
    _syslog_receiver = SyslogReceiver(port=_syslog_port)
    _syslog_receiver.start()
