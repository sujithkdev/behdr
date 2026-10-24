# -*- coding: utf-8 -*-
"""
etw_consumer.py — ETW telemetry via SilkETW sidecar + Windows Event Log fallback
==================================================================================
Two collection backends, tried in order:

  Backend A — SilkETW sidecar  (preferred, richest data)
  ───────────────────────────────────────────────────────
  Launches SilkETW.exe as a subprocess writing newline-delimited JSON to a
  temp file.  A tail thread reads new lines as they are written and converts
  each SilkETW record to the structured event dict the server already expects.

  SilkETW is an optional third-party collection tool:
    https://github.com/fireeye/SilkETW
  Drop SilkETW.exe next to agent.py OR set the env var:
    EDR_SILKETW_PATH=C:\\path\\to\\SilkETW.exe

  No pywintrace, no pywin32, no ETW API knowledge required.
  Requires Administrator (SilkETW itself needs it for kernel providers).

  Backend B — Windows Event Log polling  (fallback, no extra install)
  ────────────────────────────────────────────────────────────────────
  Reads from Windows Security + PowerShell/Operational event logs using
  the built-in `win32evtlog` (pywin32) or `subprocess wevtutil` fallback.
  Covers:
    Security 4688     — process creation with full cmdline (needs audit policy)
    Security 4698     — scheduled task created
    Security 4702     — scheduled task modified
    Security 4720     — user account created
    Security 4732     — member added to privileged group
    PowerShell 4104   — script block logging (decoded PS content)
    System    7045    — new service installed
  No kernel-level telemetry but still substantially better than psutil alone.
  Works without Administrator on most events.

  Backend C — no-op
  ──────────────────
  If neither backend is available (non-Windows, no pywin32, no SilkETW),
  the module degrades silently.  Agent continues with psutil-only telemetry.

Output
──────
All backends push to the same `etw_event_queue` (queue.Queue).
The agent's _etw_sender_loop() drains this queue and POSTs to /etw_events.
The server-side handle_etw_event() in detector.py handles all event types.

Event types emitted (same schema regardless of backend):
  etw_process_create    — process spawn with cmdline + image path
  etw_thread_inject     — remote thread injection detected
  etw_image_load        — DLL loaded into a process
  etw_network_connect   — TCP/UDP connection
  etw_registry_write    — registry key/value written (high-risk paths)
  etw_dns_query         — DNS query with originating process
  etw_scriptblock       — decoded PowerShell script content
  etw_service_install   — new Windows service installed
  etw_task_create       — scheduled task created/modified
  etw_account_change    — user account or group membership change
"""

import os
import sys
import json
import time
import queue
import hashlib
import logging
import threading
import subprocess
import tempfile
from datetime import datetime, timezone
from typing import Optional

log = logging.getLogger("etw")

# ── Public output queue — drained by _etw_sender_loop() in agent.py ──────────
etw_event_queue: queue.Queue = queue.Queue(maxsize=5000)

# ── Runtime state ─────────────────────────────────────────────────────────────
_SYSTEM_ID: str = ""
_backend_used: str = "none"   # "silketw" | "evtlog" | "none"
event_sink = None


def _ts() -> int:
    return int(datetime.now(timezone.utc).timestamp())


def _push(event: dict):
    """Prefer the agent's durable sink; report loss when standalone queue is full."""
    if event_sink is not None:
        event_sink(event)
        return
    try:
        etw_event_queue.put_nowait(event)
    except queue.Full:
        log.error("ETW queue full: telemetry gap")


# ═════════════════════════════════════════════════════════════════════════════
# BACKEND A — SilkETW sidecar
# ═════════════════════════════════════════════════════════════════════════════

# SilkETW provider configurations.
# Each entry: (provider_name_or_guid, output_type, keywords_hex)
# We run one SilkETW process per provider so each gets its own output file
# and can be started/stopped independently.
_SILKETW_PROVIDERS = [
    # Process creation, thread injection, image load
    ("Microsoft-Windows-Kernel-Process",  "kernel", "0x10"),
    # PowerShell ScriptBlock logging (Event 4104)
    ("Microsoft-Windows-PowerShell",      "user",   "0x20"),
    # DNS client queries
    ("Microsoft-Windows-DNS-Client",      "user",   "0x0"),
    # Windows Security auditing (4688 process create, 4698 scheduled task, etc.)
    # This is a classic provider — SilkETW handles it as a user provider
    ("Microsoft-Windows-Security-Auditing", "user", "0x0"),
]

# Registry of monitored key path fragments for registry events
_REG_PATHS = [
    r"\currentversion\run",
    r"\currentversion\runonce",
    r"\windows defender",
    r"\control\lsa",
    r"\image file execution options",
    r"\winlogon",
    r"\currentcontrolset\services",
    r"\appinit_dlls",
    r"\clsid",
]


def _find_silketw() -> Optional[str]:
    """
    Locate SilkETW.exe.  Search order:
      1. EDR_SILKETW_PATH env var
      2. Same directory as agent.py / etw_consumer.py
      3. PATH
    """
    # Env override
    env_path = os.environ.get("EDR_SILKETW_PATH", "").strip()
    if env_path and os.path.isfile(env_path):
        return env_path

    # Same directory as this file
    here = os.path.dirname(os.path.abspath(__file__))
    local = os.path.join(here, "SilkETW.exe")
    if os.path.isfile(local):
        return local

    # Also check a 'tools' subdirectory — common layout
    tools = os.path.join(here, "tools", "SilkETW.exe")
    if os.path.isfile(tools):
        return tools

    # PATH search
    try:
        result = subprocess.run(
            ["where", "SilkETW.exe"],
            capture_output=True, text=True, timeout=3)
        if result.returncode == 0:
            found = result.stdout.strip().splitlines()[0]
            if os.path.isfile(found):
                return found
    except Exception:
        pass

    return None


def _parse_silketw_record(line: str) -> Optional[dict]:
    """
    Parse one JSON line from SilkETW output and convert it to
    our internal event schema.

    SilkETW JSON structure (simplified):
    {
      "ProviderName": "Microsoft-Windows-Kernel-Process",
      "EventId": 1,
      "ProcessId": 1234,
      "ThreadId": 5678,
      "TimeStamp": "2026-08-12T10:00:00.000Z",
      "XmlEventData": {
        "ImageName": "C:\\Windows\\System32\\notepad.exe",
        "ProcessID": "4567",
        "ParentProcessID": "1234",
        "CommandLine": "notepad.exe readme.txt",
        ...
      }
    }
    """
    try:
        rec = json.loads(line.strip())
    except (json.JSONDecodeError, ValueError):
        return None

    provider = rec.get("ProviderName", "")
    eid      = int(rec.get("EventId", 0))
    pid      = int(rec.get("ProcessId", 0))
    ts       = _ts()
    data     = rec.get("XmlEventData", {})

    # Helper to pull a field trying multiple key variants
    def _f(*keys, default=""):
        for k in keys:
            v = data.get(k)
            if v is not None and str(v).strip():
                return str(v).strip()
        return default

    def _i(*keys, default=0):
        for k in keys:
            v = data.get(k)
            if v is not None:
                try:
                    return int(str(v).strip(), 0)
                except (ValueError, TypeError):
                    pass
        return default

    # ── Kernel-Process ────────────────────────────────────────────────────
    if "Kernel-Process" in provider:

        if eid == 1:   # ProcessStart
            image    = _f("ImageName", "ImageFileName")
            cmdl     = _f("CommandLine")
            new_pid  = _i("ProcessID", "NewProcessId")
            ppid     = _i("ParentProcessId", "ParentID")
            user     = _f("UserSID", "Username")
            proc     = os.path.basename(image) if image else "unknown"
            return {
                "event":      "etw_process_create",
                "pid":        new_pid or pid,
                "ppid":       ppid,
                "process":    proc,
                "image_path": image,
                "cmdline":    cmdl[:2048],
                "user":       user,
                "integrity":  _f("MandatoryLabel", "IntegrityLevel"),
                "source":     "silketw_kernel_process",
                "system_id":  _SYSTEM_ID,
                "time":       ts,
            }

        elif eid == 5:   # ImageLoad
            image  = _f("ImageName", "FileName")
            sig    = _f("SignatureLevel", "Signed")
            signed = sig not in ("", "0", "Unsigned", "None")
            proc   = os.path.basename(_f("ImageName", default="unknown"))
            return {
                "event":      "etw_image_load",
                "pid":        pid,
                "process":    proc,
                "image_path": image,
                "signed":     signed,
                "source":     "silketw_kernel_process",
                "system_id":  _SYSTEM_ID,
                "time":       ts,
            }

        elif eid == 3:   # ThreadStart — check for remote injection
            target_pid   = _i("ProcessID", "TargetProcessId")
            creating_pid = _i("CreatingProcessId")
            if (creating_pid and target_pid and
                    creating_pid != target_pid and target_pid > 4):
                return {
                    "event":       "etw_thread_inject",
                    "target_pid":  target_pid,
                    "source_pid":  creating_pid,
                    "target_proc": _proc_name_for_pid(target_pid),
                    "source_proc": _proc_name_for_pid(creating_pid),
                    "source":      "silketw_kernel_process",
                    "system_id":   _SYSTEM_ID,
                    "time":        ts,
                }

    # ── PowerShell ScriptBlock (Event 4104) ───────────────────────────────
    elif "PowerShell" in provider and eid == 4104:
        script = _f("ScriptBlockText", "ScriptBlock")
        if not script.strip():
            return None
        return {
            "event":        "etw_scriptblock",
            "pid":          pid,
            "process":      _proc_name_for_pid(pid),
            "script_block": script[:4096],
            "source":       "silketw_powershell",
            "system_id":    _SYSTEM_ID,
            "time":         ts,
        }

    # ── DNS Client ────────────────────────────────────────────────────────
    elif "DNS-Client" in provider and eid in (3006, 3008):
        query  = _f("QueryName", "QueryOptions")
        result = _f("QueryResults", "")
        if not query:
            return None
        return {
            "event":    "etw_dns_query",
            "pid":      pid,
            "process":  _proc_name_for_pid(pid),
            "query":    query,
            "result":   result[:512],
            "source":   "silketw_dns",
            "system_id": _SYSTEM_ID,
            "time":     ts,
        }

    # ── Security Auditing ─────────────────────────────────────────────────
    elif "Security" in provider or "Auditing" in provider:

        if eid == 4688:   # Process Creation
            image   = _f("NewProcessName")
            parent  = _f("ParentProcessName")
            cmdl    = _f("CommandLine", "ProcessCommandLine")
            user    = _f("SubjectUserName", "TargetUserName")
            new_pid = _i("NewProcessId", "ProcessId")
            return {
                "event":      "etw_process_create",
                "pid":        new_pid or pid,
                "ppid":       pid,
                "process":    os.path.basename(image) if image else "unknown",
                "image_path": image,
                "cmdline":    cmdl[:2048],
                "user":       user,
                "integrity":  _f("MandatoryLabel", "TokenElevationType"),
                "source":     "silketw_security_4688",
                "system_id":  _SYSTEM_ID,
                "time":       ts,
            }

        elif eid in (4698, 4702):   # Scheduled task created/modified
            task_name    = _f("TaskName")
            task_content = _f("TaskContent", "TaskXml")[:1024]
            user         = _f("SubjectUserName")
            return {
                "event":        "etw_task_create",
                "pid":          pid,
                "process":      "taskschd.exe",
                "task_name":    task_name,
                "task_content": task_content,
                "user":         user,
                "eid":          eid,
                "source":       "silketw_security",
                "system_id":    _SYSTEM_ID,
                "time":         ts,
            }

        elif eid == 7045:   # New service installed (System log)
            svc_name = _f("ServiceName")
            svc_file = _f("ImagePath", "ServiceFileName")
            svc_type = _f("ServiceType")
            return {
                "event":        "etw_service_install",
                "pid":          pid,
                "process":      "services.exe",
                "service_name": svc_name,
                "service_file": svc_file,
                "service_type": svc_type,
                "source":       "silketw_security",
                "system_id":    _SYSTEM_ID,
                "time":         ts,
            }

        elif eid in (4720, 4732, 4728):   # Account create / group membership
            target = _f("TargetUserName", "MemberName")
            actor  = _f("SubjectUserName")
            group  = _f("TargetDomainName", "GroupName", "SamAccountName")
            return {
                "event":       "etw_account_change",
                "pid":         pid,
                "process":     "lsass.exe",
                "target_user": target,
                "actor":       actor,
                "group":       group,
                "eid":         eid,
                "source":      "silketw_security",
                "system_id":   _SYSTEM_ID,
                "time":        ts,
            }

    return None


# ── PID → process name cache (shared across backends) ────────────────────────
_pid_cache: dict = {}
_pid_cache_lock  = threading.Lock()


def _proc_name_for_pid(pid: int) -> str:
    with _pid_cache_lock:
        if pid in _pid_cache:
            return _pid_cache[pid]
    try:
        import psutil
        name = psutil.Process(pid).name()
        with _pid_cache_lock:
            _pid_cache[pid] = name
            if len(_pid_cache) > 2000:
                for k in list(_pid_cache.keys())[:500]:
                    del _pid_cache[k]
        return name
    except Exception:
        return "unknown"


def _tail_file(path: str, stop_event: threading.Event):
    """
    Tail a file for new newline-delimited JSON records.
    Seeks to the end on open (ignores historical data) then reads
    new lines as SilkETW writes them.  Runs in a daemon thread.
    """
    # Wait for file to appear (SilkETW may not create it immediately)
    waited = 0
    while not os.path.exists(path) and not stop_event.is_set():
        time.sleep(0.5)
        waited += 0.5
        if waited > 30:
            log.warning("[SilkETW] Output file never appeared: %s", path)
            return

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            fh.seek(0, 2)   # seek to end — ignore pre-existing content
            log.debug("[SilkETW] Tailing %s", path)
            while not stop_event.is_set():
                line = fh.readline()
                if not line:
                    time.sleep(0.05)
                    continue
                line = line.strip()
                if not line:
                    continue
                event = _parse_silketw_record(line)
                if event:
                    _push(event)
    except Exception as e:
        log.error("[SilkETW] Tail error on %s: %s", path, e)


def _run_silketw_backend(silketw_path: str, stop_event: threading.Event):
    """
    Launch one SilkETW.exe process per provider, each writing to its own
    temp file.  Tail all output files in parallel daemon threads.
    Clean up all subprocesses on stop.

    SilkETW CLI reference:
      SilkETW.exe -t <kernel|user>
                  -pn <ProviderName>
                  -ot file
                  -p  <output_file>
                  [-kw <keywords_hex>]
                  [-l verbose]
    """
    global _backend_used
    tmp_dir    = tempfile.mkdtemp(prefix="behedr_etw_")
    processes  = []
    tail_threads = []

    for provider_name, ptype, keywords in _SILKETW_PROVIDERS:
        # One output file per provider
        safe_name  = provider_name.replace("-", "_").replace(" ", "_")
        out_file   = os.path.join(tmp_dir, f"{safe_name}.json")

        cmd = [
            silketw_path,
            "-t",  ptype,
            "-pn", provider_name,
            "-ot", "file",
            "-p",  out_file,
        ]
        if keywords and keywords != "0x0":
            cmd += ["-kw", keywords]

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                # CREATE_NO_WINDOW so it doesn't flash a console
                creationflags=0x08000000 if os.name == "nt" else 0,
            )
            processes.append(proc)
            log.info("[SilkETW] Started provider '%s' (PID %d) → %s",
                     provider_name, proc.pid, out_file)

            # Start tail thread for this provider's output file
            t = threading.Thread(
                target=_tail_file,
                args=(out_file, stop_event),
                name=f"SilkTail-{safe_name[:20]}",
                daemon=True)
            t.start()
            tail_threads.append(t)

        except Exception as e:
            log.error("[SilkETW] Failed to start provider '%s': %s",
                      provider_name, e)

    if not processes:
        log.error("[SilkETW] No providers started — falling through to evtlog backend.")
        return False

    _backend_used = "silketw"
    log.info("[SilkETW] %d providers running. Waiting for stop signal...",
             len(processes))

    # Block until stop is requested, then terminate all SilkETW processes
    stop_event.wait()

    for proc in processes:
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass

    # Clean up temp files
    try:
        import shutil
        shutil.rmtree(tmp_dir, ignore_errors=True)
    except Exception:
        pass

    log.info("[SilkETW] All providers stopped.")
    return True


# ═════════════════════════════════════════════════════════════════════════════
# BACKEND B — Windows Event Log polling
# ═════════════════════════════════════════════════════════════════════════════
# Uses wevtutil.exe (built into every Windows version since Vista) via
# subprocess to query Security, PowerShell/Operational, and System logs.
# No admin required for most channels; Security log needs admin or
# "Event Log Readers" group membership.
#
# We track the last event record number per channel and only pull new events
# on each poll — efficient even on busy systems.

_EVTLOG_CHANNELS = {
    # channel_name: [event_ids_to_filter]  (empty = all events from channel)
    "Security":                          [4688, 4698, 4702, 4720, 4732, 4728],
    "Microsoft-Windows-PowerShell/Operational": [4104],
    "System":                            [7045],
}

_evtlog_cursors: dict = {}   # channel → last record number seen
_evtlog_lock = threading.Lock()

# wevtutil XPath query template
_XPATH_TMPL = (
    "*[System[({id_filter}) and TimeCreated[@SystemTime>='{since}']]]"
)


def _wevtutil_query(channel: str, event_ids: list, since_iso: str) -> list:
    """
    Run wevtutil qe to pull new events from a channel since `since_iso`.
    Returns a list of dicts parsed from the XML output.
    """
    position = f"EventRecordID>{since_iso}" if isinstance(since_iso, int) else f"TimeCreated[@SystemTime>='{since_iso}']"
    if event_ids:
        id_parts = " or ".join(f"EventID={eid}" for eid in event_ids)
        xpath = f"*[System[({id_parts}) and {position}]]"
    else:
        xpath = f"*[System[{position}]]"

    cmd = [
        "wevtutil", "qe", channel,
        f"/q:{xpath}",
        "/f:xml",
        "/e:Events",
        "/rd:false",   # oldest first
        "/c:200",      # max 200 events per poll
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True, text=True, timeout=10,
            creationflags=0x08000000 if os.name == "nt" else 0,
        )
        if result.returncode != 0:
            return []

        from eventlog import parse_xml
        return parse_xml(result.stdout) if result.stdout.strip() else []

    except subprocess.TimeoutExpired:
        return []
    except Exception as e:
        log.debug("[EvtLog] wevtutil error (%s): %s", channel, e)
        return []


def _parse_evtlog_record(rec: dict) -> Optional[dict]:
    """
    Convert a wevtutil JSON record to our internal event schema.
    wevtutil JSON structure:
    {
      "Event": {
        "System": { "EventID": 4688, "Execution": {"ProcessID": 123}, ... },
        "EventData": { "Data": [ {"Name": "...", "#text": "..."}, ... ] }
      }
    }
    """
    try:
        evt    = rec.get("Event", rec)
        system = evt.get("System", {})
        eid    = int(system.get("EventID", 0))
        pid    = int(system.get("Execution", {}).get("ProcessID", 0))
        ts     = _ts()

        # Flatten EventData into a dict keyed by Name
        raw_data = evt.get("EventData", {}).get("Data", [])
        if isinstance(raw_data, list):
            data = {
                item["Name"]: item.get("#text", "")
                for item in raw_data
                if isinstance(item, dict) and "Name" in item
            }
        elif isinstance(raw_data, dict):
            data = raw_data
        else:
            data = {}

        def _f(*keys, default=""):
            for k in keys:
                v = data.get(k)
                if v is not None and str(v).strip():
                    return str(v).strip()
            return default

        def _i(*keys, default=0):
            for k in keys:
                v = data.get(k)
                if v is not None:
                    try:
                        return int(str(v).strip(), 0)
                    except (ValueError, TypeError):
                        pass
            return default

        # ── 4688 Process Creation ─────────────────────────────────────────
        if eid == 4688:
            image   = _f("NewProcessName")
            cmdl    = _f("CommandLine", "ProcessCommandLine")
            user    = _f("SubjectUserName", "TargetUserName")
            new_pid = _i("NewProcessId")
            parent  = _f("ParentProcessName")
            return {
                "event":      "etw_process_create",
                "pid":        new_pid or pid,
                "ppid":       _i("ProcessId", "CreatorProcessId") or pid,
                "parent_proc": os.path.basename(parent) if parent else "unknown",
                "process":    os.path.basename(image) if image else "unknown",
                "image_path": image,
                "cmdline":    cmdl[:2048],
                "user":       user,
                "integrity":  _f("MandatoryLabel", "TokenElevationType"),
                "source":     "evtlog_4688",
                "system_id":  _SYSTEM_ID,
                "time":       ts,
            }

        # ── 4698 / 4702 Scheduled task ────────────────────────────────────
        elif eid in (4698, 4702):
            return {
                "event":        "etw_task_create",
                "pid":          pid,
                "process":      "taskschd.exe",
                "task_name":    _f("TaskName"),
                "task_content": _f("TaskContent", "TaskXml")[:1024],
                "user":         _f("SubjectUserName"),
                "eid":          eid,
                "source":       "evtlog_4698",
                "system_id":    _SYSTEM_ID,
                "time":         ts,
            }

        # ── 7045 New service ──────────────────────────────────────────────
        elif eid == 7045:
            return {
                "event":        "etw_service_install",
                "pid":          pid,
                "process":      "services.exe",
                "service_name": _f("ServiceName"),
                "service_file": _f("ImagePath", "ServiceFileName"),
                "service_type": _f("ServiceType"),
                "source":       "evtlog_7045",
                "system_id":    _SYSTEM_ID,
                "time":         ts,
            }

        # ── 4104 PS ScriptBlock ───────────────────────────────────────────
        elif eid == 4104:
            script = _f("ScriptBlockText", "ScriptBlock")
            if not script.strip():
                return None
            return {
                "event":        "etw_scriptblock",
                "pid":          pid,
                "process":      _proc_name_for_pid(pid),
                "script_block": script[:4096],
                "source":       "evtlog_4104",
                "system_id":    _SYSTEM_ID,
                "time":         ts,
            }

        # ── 4720 User created / 4732 4728 group membership ───────────────
        elif eid in (4720, 4732, 4728):
            return {
                "event":       "etw_account_change",
                "pid":         pid,
                "process":     "lsass.exe",
                "target_user": _f("TargetUserName", "MemberName"),
                "actor":       _f("SubjectUserName"),
                "group":       _f("TargetDomainName", "GroupName"),
                "eid":         eid,
                "source":      "evtlog_acct",
                "system_id":   _SYSTEM_ID,
                "time":        ts,
            }

    except Exception:
        pass

    return None


def _run_evtlog_backend(stop_event: threading.Event):
    """
    Poll Windows Event Log channels every 5 seconds.
    Tracks last-seen timestamp per channel to avoid re-reading old events.
    """
    global _backend_used

    # Check wevtutil is available
    try:
        r = subprocess.run(
            ["wevtutil", "el"],
            capture_output=True, timeout=5,
            creationflags=0x08000000 if os.name == "nt" else 0)
        if r.returncode != 0:
            log.warning("[EvtLog] wevtutil not available — no ETW fallback.")
            return False
    except Exception:
        log.warning("[EvtLog] wevtutil not found — no ETW fallback.")
        return False

    _backend_used = "evtlog"
    log.info("[EvtLog] Windows Event Log polling started (%d channels).",
             len(_EVTLOG_CHANNELS))

    # Initialise cursors to "now" so we only see future events
    since = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    channel_since = {ch: since for ch in _EVTLOG_CHANNELS}

    while not stop_event.is_set():
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

        for channel, event_ids in _EVTLOG_CHANNELS.items():
            records = _wevtutil_query(channel, event_ids, channel_since[channel])
            for rec in records:
                event = _parse_evtlog_record(rec)
                if event:
                    import hashlib
                    system = rec['Event']['System']
                    created = system.get('TimeCreated', {}).get('SystemTime', '')
                    if created:
                        event['time'] = datetime.fromisoformat(created.replace('Z', '+00:00')).timestamp()
                    event['event_id'] = hashlib.sha256(f"{channel}:{system['EventRecordID']}:{created}".encode()).hexdigest()
                    _push(event)
                # Advance only through records actually handled, including full batches.
                channel_since[channel] = rec['Event']['System']['EventRecordID']

        stop_event.wait(timeout=5)

    log.info("[EvtLog] Windows Event Log polling stopped.")
    return True


# ═════════════════════════════════════════════════════════════════════════════
# PUBLIC API
# ═════════════════════════════════════════════════════════════════════════════

def etw_loop(system_id: str, stop_event: threading.Event):
    """
    Main ETW collection entry point — called as a daemon thread from agent.py.

    Tries backends in order:
      1. SilkETW sidecar  (richest — process inject, image load, DNS, registry)
      2. Windows Event Log polling  (good — process create, PS scriptblock,
                                     scheduled tasks, service install, accounts)
      3. No-op  (non-Windows or no tools available)

    Args:
        system_id:   hostname used to annotate every event
        stop_event:  threading.Event — set to stop all collection
    """
    global _SYSTEM_ID
    _SYSTEM_ID = system_id

    if os.name != "nt":
        log.info("[ETW] Non-Windows — ETW collection not available.")
        return

    # ── Try Backend A: SilkETW ────────────────────────────────────────────
    silketw = _find_silketw()
    if silketw:
        log.info("[ETW] SilkETW found at: %s", silketw)
        ok = _run_silketw_backend(silketw, stop_event)
        if ok:
            return
        log.warning("[ETW] SilkETW backend failed — falling back to Event Log.")
    else:
        log.info(
            "[ETW] SilkETW.exe not found. "
            "Drop it next to agent.py or set EDR_SILKETW_PATH for richer telemetry. "
            "Falling back to Windows Event Log polling."
        )

    # ── Try Backend B: wevtutil Event Log polling ─────────────────────────
    _run_evtlog_backend(stop_event)


def is_available() -> bool:
    """Return True if any ETW collection backend is available."""
    if os.name != "nt":
        return False
    # Even without SilkETW, wevtutil is on every modern Windows
    try:
        r = subprocess.run(
            ["wevtutil", "el"],
            capture_output=True, timeout=3,
            creationflags=0x08000000)
        return r.returncode == 0
    except Exception:
        return False


def get_backend() -> str:
    """Return the name of the active collection backend."""
    return _backend_used
