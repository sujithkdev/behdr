"""Windows endpoint collectors. Deploy the complete endpoint directory.

Configuration and service setup are documented in docs/operations.md.
Telemetry uses a disk-backed outbox and individually enrolled credentials.
"""

import os, sys, time, socket, platform, threading, logging, json, queue, hashlib
import requests, psutil
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler

# ── Configuration ─────────────────────────────────────────────────────────────
from urllib.parse import urlparse
from spool import Spool
from response import execute

_BASE = os.environ.get("EDR_SERVER_URL", "https://localhost").rstrip("/")
_TLS_CA_CERT = os.environ.get("EDR_TLS_CA_CERT", "")
_TLS_ENABLED = urlparse(_BASE).scheme == "https"
_TLS_VERIFY = _TLS_CA_CERT or True
API_KEY = os.environ.get("EDR_API_KEY", "")
SYSTEM_ID = os.environ.get("EDR_SYSTEM_ID", socket.gethostname())
_AGENT_DATA = os.path.abspath(os.environ.get("EDR_AGENT_DATA", os.path.join(os.environ.get("PROGRAMDATA", os.path.dirname(__file__)), "BehEDR")))
os.makedirs(_AGENT_DATA, exist_ok=True)
_spool = Spool(os.path.join(_AGENT_DATA, "outbox.db"))
EVENTS_URL = _BASE + "/events"
CMDS_URL = _BASE + "/commands/" + SYSTEM_ID
RESULT_URL = _BASE + "/commands/result"
HB_URL = _BASE + "/heartbeat"
REG_URL = _BASE + "/register"
DLL_URL = _BASE + "/dll_events"
NET_URL = _BASE + "/net_events"
FILE_URL = _BASE + "/file_events"
ETW_URL = _BASE + "/etw_events"
YARA_URL = _BASE + "/yara_hits"
HEADERS = {"API-Key": API_KEY, "Content-Type": "application/json"}
_TELEMETRY_URLS = {EVENTS_URL, DLL_URL, NET_URL, FILE_URL, ETW_URL, YARA_URL}

POLL_SECS  = 2      # process scan interval
CMD_SECS   = 5      # command poll interval
HB_SECS    = 15     # heartbeat interval
NET_SECS   = 10     # network scan interval
FILE_SECS  = 5      # file system event flush interval
TIMEOUT    = 5      # HTTP timeout
MAX_RETRY  = 3      # retries per request
PID_TTL    = 300    # seconds before a PID entry expires

# ── Shared state ──────────────────────────────────────────────────────────────
_event_queue: queue.Queue = queue.Queue(maxsize=10_000)
_stop    = threading.Event()
_pid_seen: dict = {}    # {pid: first_seen_timestamp}
_pid_lock = threading.Lock()

# ── Logging ───────────────────────────────────────────────────────────────────
_LOG_FILE = os.path.join(_AGENT_DATA, "agent.log")
logging.basicConfig(
    handlers=[
        RotatingFileHandler(_LOG_FILE, maxBytes=5*1024*1024, backupCount=3, encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ],
    format="%(asctime)s | %(levelname)-8s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    level=logging.INFO,
)
log = logging.getLogger("agent")

def _pid_is_new(pid):
    try:
        created = psutil.Process(pid).create_time()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return False
    with _pid_lock:
        if _pid_seen.get(pid) == created:
            return False
        _pid_seen[pid] = created
        return True


def _seed_baseline():
    with _pid_lock:
        for process in psutil.process_iter(['pid', 'create_time']):
            _pid_seen[process.pid] = process.info['create_time']


def _post(url, data, label="POST"):
    if url in _TELEMETRY_URLS:
        for event in data.get("events", [data]):
            _spool.put(url[len(_BASE):], event)
        return {"status": "spooled"}
    for attempt in range(1, MAX_RETRY + 1):
        try:
            r = requests.post(
                url, json=data, headers=HEADERS,
                timeout=TIMEOUT, verify=_TLS_VERIFY)
            if r.status_code == 200:
                return r.json()
            elif r.status_code == 401:
                log.error("Auth failed — check API_KEY matches server config.")
                return None
            else:
                log.warning("%s HTTP %d (attempt %d/%d)", label, r.status_code, attempt, MAX_RETRY)
        except requests.exceptions.SSLError as e:
            log.error(
                "%s: TLS/SSL error — verify EDR_TLS_CA_CERT points to the correct CA bundle. "
                "Details: %s", label, e)
            break   # SSL errors won't resolve with retries
        except requests.exceptions.ConnectionError:
            log.warning("%s: server unreachable (attempt %d/%d)", label, attempt, MAX_RETRY)
        except requests.exceptions.Timeout:
            log.warning("%s: timeout (attempt %d/%d)", label, attempt, MAX_RETRY)
        except Exception as e:
            log.error("%s error: %s", label, e)
            break
        if attempt < MAX_RETRY:
            time.sleep(2)
    return None


def _get(url, label="GET"):
    try:
        r = requests.get(url, headers=HEADERS, timeout=TIMEOUT, verify=_TLS_VERIFY)
        if r.status_code == 200:
            return r.json()
        elif r.status_code == 401:
            log.error("Auth failed on GET %s", url)
    except requests.exceptions.SSLError as e:
        log.error(
            "%s: TLS/SSL error — verify EDR_TLS_CA_CERT points to the correct CA bundle. "
            "Details: %s", label, e)
    except requests.exceptions.ConnectionError:
        log.debug("%s: server unreachable", label)
    except Exception as e:
        log.error("%s error: %s", label, e)
    return None


# ── Process monitoring ─────────────────────────────────────────────────────────

def _parent_name(ppid):
    try:
        return psutil.Process(ppid).name()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return "unknown"


def _parent_created(ppid):
    try:
        return psutil.Process(ppid).create_time()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return 0


def _cmdline(proc):
    try:
        parts = proc.cmdline()
        return " ".join(parts)[:2048] if parts else ""
    except Exception:
        return ""


def _sha256_of(proc) -> str:
    """Return SHA-256 of the process executable, or empty string on failure."""
    try:
        path = proc.exe()
        if not path or not os.path.isfile(path):
            return ""
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
        return ""


def _exe_path(proc) -> str:
    """Return the full path of the process executable."""
    try:
        return proc.exe() or ""
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return ""


def _build_event(proc):
    try:
        with proc.oneshot():
            ppid = proc.ppid()
            from process_context import capture
            context = capture(proc)
            if context["ancestors"] and context["ancestors"][0]["pid"] != ppid:
                context["ancestors"] = []
                context["ancestry_status"] = "incomplete"
            parent_created = context["ancestors"][0]["create_time"] if context["ancestors"] else _parent_created(ppid)
            return {
                **context,
                "system_id": SYSTEM_ID,
                "event":     "process_spawn",
                "parent":    _parent_name(ppid),
                "child":     proc.name(),
                "pid":       proc.pid,
                "ppid": ppid,
                "parent_create_time": parent_created,
                "create_time": proc.create_time(),
                "user": proc.username(),
                "cmdline":   _cmdline(proc),
                "sha256":    _sha256_of(proc),
                "exe_path":  _exe_path(proc),
                "time":      int(datetime.now(timezone.utc).timestamp()),
            }
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None


# ── DLL monitoring ────────────────────────────────────────────────────────────

_known_dll_loads: dict = {}   # pid → set of dll paths already reported
_dll_lock2 = threading.Lock()

# Cache signing results per DLL path — avoid re-checking the same DLL repeatedly.
# Most processes load the same system DLLs (kernel32, ntdll, etc.) and we only
# need to check each unique path once per agent session.
_dll_sign_cache: dict = {}   # dll_path_lower → bool (signed)
_dll_sign_lock = threading.Lock()


def _is_dll_signed(dll_path: str) -> bool:
    """
    Check if a DLL is authenticode-signed (Windows only, best-effort).
    Results are cached per unique DLL path — each path is only checked once.
    Falls back to True (assume signed) on non-Windows or on error, which is
    the safe direction for this check (path-based checks in dll_monitor.py
    catch hijacks regardless of signing status).
    """
    if os.name != "nt":
        return True

    dll_path_lc = dll_path.lower()

    # Return cached result if available — avoids spawning PowerShell again
    with _dll_sign_lock:
        if dll_path_lc in _dll_sign_cache:
            return _dll_sign_cache[dll_path_lc]

    try:
        import subprocess
        # Single-line PowerShell with -NonInteractive to avoid profile loading
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             "(Get-AuthenticodeSignature -LiteralPath $env:BEHEDR_SIGNATURE_PATH).Status"],
            capture_output=True, text=True, timeout=4, env={**os.environ, "BEHEDR_SIGNATURE_PATH": dll_path}, creationflags=0x08000000)
        result = r.returncode == 0 and r.stdout.strip() == "Valid"
    except Exception:
        result = None   # unknown; do not claim a verified signature

    with _dll_sign_lock:
        _dll_sign_cache[dll_path_lc] = result
        # Keep cache bounded — evict oldest half when it exceeds 2000 entries
        if len(_dll_sign_cache) > 2000:
            keys = list(_dll_sign_cache.keys())
            for k in keys[:1000]:
                del _dll_sign_cache[k]

    return result


def _scan_process_dlls(proc) -> list:
    """
    Return list of DLL load events for new DLLs loaded by this process.
    Only reports each DLL once per PID.
    Signing check is performed via PowerShell Get-AuthenticodeSignature —
    results are cached per path so the check only runs once per unique DLL path.
    """
    events = []
    try:
        pid = proc.pid
        with _dll_lock2:
            seen = _known_dll_loads.setdefault(pid, set())

        maps = proc.memory_maps(grouped=True)
        for m in maps:
            path = m.path.lower() if hasattr(m, 'path') else ""
            if not path.endswith(".dll"):
                continue
            if path in seen:
                continue
            with _dll_lock2:
                seen.add(path)

            dll_name = os.path.basename(path)
            # Call the signing check — result cached inside _is_dll_signed
            signed = _is_dll_signed(path)
            events.append({
                "system_id": SYSTEM_ID,
                "event":     "dll_load",
                "process":   proc.name(),
                "pid":       pid,
                "dll_name":  dll_name,
                "dll_path":  path,
                "signed":    signed,
                "time":      int(datetime.now(timezone.utc).timestamp()),
            })
    except (psutil.NoSuchProcess, psutil.AccessDenied, Exception):
        pass
    return events


# ── AMSI note ─────────────────────────────────────────────────────────────────
# AMSI scanning has been intentionally removed from this agent.
# Reason: AMSI fires at script-engine load time (before execution). Scanning
# a cmdline AFTER the process is already running provides no prevention value —
# the payload has already started executing. Windows Defender and any installed
# AV product register as AMSI providers automatically; there is no benefit to
# duplicating that scan in a user-space agent.
# Detection of malicious script behaviour is handled server-side by the
# 10-layer detection engine (L1 chain rules, L2 heuristics, L4 MITRE intent,
# L10 sequence ML) which all operate on the cmdline reported in the event.
# ─────────────────────────────────────────────────────────────────────────────


# ── Network connection monitoring ─────────────────────────────────────────────

_known_connections: set = set()   # (pid, laddr, raddr) already reported
_net_lock2 = threading.Lock()


def _scan_network_connections() -> list:
    """
    Scan all active network connections and return new ones.
    Feeds L6 (network beaconing + lateral movement detection) on the server.

    Filtering policy:
      - Loopback (127.x.x.x) and link-local (169.254.x.x) are always skipped —
        these are purely local and never relevant for threat detection.
      - Private RFC1918 IPs (10.x, 172.16-31.x, 192.168.x) ARE reported when
        they involve lateral movement ports (445 SMB, 3389 RDP, 135 DCOM,
        139 NetBIOS, 5985/5986 WinRM).  Lateral movement is 100% internal
        by definition — filtering private IPs made it completely invisible.
      - All external (public) IPs are always reported — feeds C2 beaconing
        detection on the server side.
    """
    LATERAL_PORTS = {445, 3389, 135, 139, 5985, 5986}

    events = []
    try:
        conns = psutil.net_connections(kind="inet")
        now   = int(datetime.now(timezone.utc).timestamp())

        for c in conns:
            if not c.raddr or not c.pid:
                continue
            rip, rport = c.raddr.ip, c.raddr.port

            # Always skip loopback and link-local — never actionable
            if _is_loopback_or_linklocal(rip):
                continue

            # For private IPs, only report lateral movement ports.
            # Reporting every internal connection (browser → intranet, etc.)
            # would generate enormous noise with no detection value.
            if _is_private_ip(rip) and rport not in LATERAL_PORTS:
                continue

            key = (c.pid, str(c.laddr), str(c.raddr))
            with _net_lock2:
                if key in _known_connections:
                    continue
                _known_connections.add(key)
                if len(_known_connections) > 5000:
                    _known_connections.clear()

            try:
                observed_process = psutil.Process(c.pid)
                proc_name = observed_process.name()
                process_created = observed_process.create_time()
                if process_created > now:
                    process_created = 0  # Socket snapshot may refer to an older PID instance.
            except Exception:
                proc_name = "unknown"
                process_created = 0

            events.append({
                "system_id":   SYSTEM_ID,
                "event":       "network_connect",
                "process":     proc_name,
                "pid":         c.pid,
                "create_time": process_created,
                "source":      "psutil_network_snapshot",
                "local_addr":  f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
                "remote_ip":   rip,
                "remote_port": rport,
                "status":      c.status,
                # Tag whether this is an internal lateral movement connection
                # so the server can route it to the right L6 detection branch.
                "is_internal": _is_private_ip(rip),
                "time":        now,
            })
    except Exception as e:
        log.debug("Network scan error: %s", e)

    return events


def _is_loopback_or_linklocal(ip: str) -> bool:
    """Return True for 127.x.x.x and 169.254.x.x — always skip these."""
    try:
        parts = list(map(int, ip.split(".")))
        if parts[0] == 127: return True
        if parts[0] == 169 and parts[1] == 254: return True
        return False
    except Exception:
        return True   # unparseable — skip


def _is_private_ip(ip: str) -> bool:
    """Return True if IP is RFC1918 private (but NOT loopback/link-local)."""
    try:
        parts = list(map(int, ip.split(".")))
        if parts[0] == 10: return True
        if parts[0] == 172 and 16 <= parts[1] <= 31: return True
        if parts[0] == 192 and parts[1] == 168: return True
        return False
    except Exception:
        return False   # unparseable external — report it


def _network_loop():
    """Scan network connections every NET_SECS and send to server."""
    log.info("Network monitor started. Scanning every %ds.", NET_SECS)
    while not _stop.is_set():
        events = _scan_network_connections()
        if events:
            _post(NET_URL, {"events": events}, "NET_EVENTS")
        _stop.wait(timeout=NET_SECS)
    log.info("Network monitor stopped.")


# ── File system monitoring ────────────────────────────────────────────────────
# Watches directories that are common staging/execution locations for malware:
#   - User temp dirs       (AppData\Local\Temp, Temp)
#   - Public dirs          (C:\Users\Public, C:\Windows\Temp)
#   - Desktop & Downloads  (common drop locations)
#
# Uses ReadDirectoryChangesW on Windows (built into the winapi via ctypes).
# Falls back to a polling stat-based approach on non-Windows or on error.
# Feeds L7 (ransomware: mass file modification, ransom notes, encrypted extensions).

_file_event_queue: list = []
_file_eq_lock = threading.Lock()

# Directories to watch — only writable user/temp paths that attackers favour
_WATCH_DIRS = [
    os.path.expandvars(r"%TEMP%"),
    os.path.expandvars(r"%LOCALAPPDATA%\Temp"),
    r"C:\Windows\Temp",
    r"C:\Users\Public",
    os.path.expandvars(r"%USERPROFILE%\Desktop"),
    os.path.expandvars(r"%USERPROFILE%\Downloads"),
]

# Only report these extensions — avoids flooding on log/cache churn.
# Includes common document types (ransomware targets) + suspicious extensions.
_WATCH_EXTENSIONS = {
    ".exe", ".dll", ".bat", ".ps1", ".vbs", ".js", ".hta", ".cmd",
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf",
    ".zip", ".rar", ".7z",
    ".encrypted", ".locked", ".crypto", ".crypt", ".enc",
    ".txt", ".html", ".hta",   # ransom note formats
}


def _rdcw_watch(watch_dir: str):
    """
    Watch a single directory with ReadDirectoryChangesW (Windows only).
    Pushes (action_str, full_path) tuples into _file_event_queue.
    Runs in its own daemon thread — one thread per watched directory.
    """
    if os.name != "nt":
        return

    import ctypes
    from ctypes import wintypes

    FILE_LIST_DIRECTORY    = 0x0001
    FILE_SHARE_READ        = 0x00000001
    FILE_SHARE_WRITE       = 0x00000002
    FILE_SHARE_DELETE      = 0x00000004
    OPEN_EXISTING          = 3
    FILE_FLAG_BACKUP_SEMANTICS = 0x02000000

    FILE_NOTIFY_CHANGE_FILE_NAME  = 0x00000001
    FILE_NOTIFY_CHANGE_SIZE       = 0x00000008
    FILE_NOTIFY_CHANGE_LAST_WRITE = 0x00000010

    _ACTION_MAP = {1: "create", 2: "delete", 3: "modify", 4: "rename", 5: "rename"}

    kernel32 = ctypes.windll.kernel32

    try:
        hDir = kernel32.CreateFileW(
            watch_dir,
            FILE_LIST_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS, None)
        if hDir == ctypes.wintypes.HANDLE(-1).value:
            log.debug("RDCW: cannot open %s (may not exist)", watch_dir)
            return

        buf  = ctypes.create_string_buffer(65536)
        ret  = ctypes.wintypes.DWORD(0)
        flags = (FILE_NOTIFY_CHANGE_FILE_NAME |
                 FILE_NOTIFY_CHANGE_SIZE |
                 FILE_NOTIFY_CHANGE_LAST_WRITE)

        log.info("File monitor watching: %s", watch_dir)
        while not _stop.is_set():
            ok = kernel32.ReadDirectoryChangesW(
                hDir, buf, ctypes.sizeof(buf), True,
                flags, ctypes.byref(ret), None, None)
            if not ok:
                break

            offset = 0
            while True:
                # Parse FILE_NOTIFY_INFORMATION struct
                next_entry = ctypes.wintypes.DWORD.from_buffer_copy(buf, offset).value
                action     = ctypes.wintypes.DWORD.from_buffer_copy(buf, offset + 4).value
                name_len   = ctypes.wintypes.DWORD.from_buffer_copy(buf, offset + 8).value
                name_raw   = buf.raw[offset + 12: offset + 12 + name_len]
                filename   = name_raw.decode("utf-16-le", errors="replace")
                full_path  = os.path.join(watch_dir, filename)
                ext        = os.path.splitext(filename)[1].lower()

                if ext in _WATCH_EXTENSIONS:
                    action_str = _ACTION_MAP.get(action, "modify")
                    with _file_eq_lock:
                        _file_event_queue.append((action_str, full_path))
                        # Cap queue to avoid unbounded growth during storms
                        if len(_file_event_queue) > 2000:
                            _file_event_queue.clear()

                if next_entry == 0:
                    break
                offset += next_entry

        kernel32.CloseHandle(hDir)
    except Exception as e:
        log.debug("RDCW watcher error (%s): %s", watch_dir, e)


def _start_file_watchers():
    """Start one RDCW watcher thread per watch directory (Windows only)."""
    if os.name != "nt":
        log.info("File monitor: RDCW not available on non-Windows — L7 disabled.")
        return
    for d in _WATCH_DIRS:
        if os.path.isdir(d):
            threading.Thread(
                target=_rdcw_watch, args=(d,),
                name=f"FileWatcher-{os.path.basename(d)}",
                daemon=True).start()
        else:
            log.debug("File monitor: skipping non-existent dir %s", d)


def _file_loop():
    """
    Flush the file event queue every FILE_SECS and send to server.
    Batches events and attributes them to the process most recently
    seen running from the same directory (best-effort; ransomware
    typically runs from Temp/Public so this is usually accurate).
    """
    _start_file_watchers()
    log.info("File event sender started. Flush every %ds.", FILE_SECS)
    now_ts = lambda: int(datetime.now(timezone.utc).timestamp())

    while not _stop.is_set():
        _stop.wait(timeout=FILE_SECS)

        with _file_eq_lock:
            if not _file_event_queue:
                continue
            batch, _file_event_queue[:] = _file_event_queue[:200], _file_event_queue[200:]

        events = []
        ts = now_ts()
        for action, path in batch:
            proc_name = "unknown"  # Directory changes do not identify the writer.
            events.append({
                "system_id": SYSTEM_ID,
                "event":     "file_event",
                "process":   proc_name,
                "file_path": path,
                "action":    action,
                "time":      ts,
            })

        if events:
            _post(FILE_URL, {"events": events}, "FILE_EVENTS")
            log.debug("Sent %d file event(s).", len(events))

    log.info("File event sender stopped.")


# ── ETW telemetry ─────────────────────────────────────────────────────────────

def _etw_sender_loop():
    """
    Drain the ETW event queue produced by etw_consumer.etw_loop()
    and send batches to the server via /etw_events.

    Runs as its own thread so it never blocks the psutil monitor loop.
    The ETW consumer thread (started separately) fills etw_consumer.etw_event_queue;
    this thread drains it.
    """
    try:
        from etw_consumer import etw_event_queue, is_available
    except ImportError:
        log.warning("[ETW] etw_consumer.py not found — ETW sender disabled.")
        return

    if not is_available():
        log.info("[ETW] ETW not available — sender thread exiting.")
        return

    log.info("[ETW] ETW event sender started.")
    while not _stop.is_set():
        batch = []
        try:
            batch.append(etw_event_queue.get(timeout=2))
            while len(batch) < 100:
                try:
                    batch.append(etw_event_queue.get_nowait())
                except queue.Empty:
                    break
        except queue.Empty:
            continue

        if batch:
            _post(ETW_URL, {"events": batch}, "ETW_EVENTS")
            log.debug("[ETW] Sent %d ETW event(s).", len(batch))

    log.info("[ETW] ETW event sender stopped.")


def _etw_collection_loop():
    """
    Wrapper that starts the ETW consumer session.
    Runs as its own daemon thread — blocks on ETW ProcessTrace() internally.
    """
    try:
        import etw_consumer
        def sink(event):
            if event.get('event') == 'etw_process_create' and _sysmon_primary_ready():
                return
            _spool.put('/etw_events', event)
        etw_consumer.event_sink = sink
        from etw_consumer import etw_loop
    except ImportError:
        log.warning("[ETW] etw_consumer.py not found — ETW collection disabled.")
        return

    log.info("[ETW] Starting ETW collection session...")
    etw_loop(SYSTEM_ID, _stop)


# ── YARA memory scanning ───────────────────────────────────────────────────────

def _yara_scan_loop():
    """
    Wrapper that starts the YARA in-memory scanner.
    Degrades gracefully if yara-python is not installed.
    """
    try:
        import yara_scanner
        yara_scanner.event_sink = lambda event: _spool.put("/yara_hits", event)
        from yara_scanner import yara_scan_loop, is_available
    except ImportError:
        log.warning("[YARA] yara_scanner.py not found — memory scanning disabled.")
        return

    if not is_available():
        log.info("[YARA] yara-python not installed — memory scanning disabled.")
        return

    # Resolve rules dir relative to agent.py location
    here      = os.path.dirname(os.path.abspath(__file__))
    rules_dir = os.environ.get("EDR_YARA_RULES", os.path.join(os.path.dirname(here), "rules", "yara"))

    log.info("[YARA] Starting memory scanner...")
    yara_scan_loop(SYSTEM_ID, _stop, rules_dir=rules_dir)


def _yara_sender_loop():
    """
    Drain YARA hits from yara_scanner.yara_hit_queue and POST to /yara_hits.
    Marks the originating PID as priority for follow-up scanning.
    """
    try:
        from yara_scanner import yara_hit_queue, add_priority_pid, is_available
    except ImportError:
        log.warning("[YARA] yara_scanner.py not found — YARA sender disabled.")
        return

    if not is_available():
        return

    log.info("[YARA] YARA hit sender started.")
    while not _stop.is_set():
        batch = []
        try:
            batch.append(yara_hit_queue.get(timeout=2))
            while len(batch) < 50:
                try:
                    batch.append(yara_hit_queue.get_nowait())
                except queue.Empty:
                    break
        except queue.Empty:
            continue

        if batch:
            _post(YARA_URL, {"events": batch}, "YARA_HITS")
            log.warning("[YARA] Sent %d YARA hit(s) to server.", len(batch))

    log.info("[YARA] YARA hit sender stopped.")

def _sysmon_primary_ready():
    if os.environ.get('EDR_SYSMON', 'false').lower() != 'true' or os.environ.get('EDR_PROCESS_SOURCE') != 'sysmon':
        return False
    from sysmon_collector import process_source_ready
    return process_source_ready(_spool.source_state('sysmon'))


def _monitor_loop():
    """Scan for new processes + DLL loads every POLL_SECS; enqueue events."""
    _seed_baseline()
    log.info("Monitor started. Scanning every %ds.", POLL_SECS)
    while not _stop.is_set():
        try:
            for proc in psutil.process_iter(["pid", "name"]):
                pid = proc.pid

                # ── New process detection ──────────────────────────────
                if not _sysmon_primary_ready() and _pid_is_new(pid):
                    ev = _build_event(proc)
                    if ev:
                        log.debug("NEW: %s -> %s (PID %d)",
                                  ev["parent"], ev["child"], ev["pid"])
                        try:
                            _spool.put("/events", ev)
                        except OverflowError:
                            with _pid_lock:
                                _pid_seen.pop(pid, None)
                            log.error("Spool full: process telemetry gap; will retry if still running")

                # ── DLL load scanning (every process, not just new) ────
                # Only scan processes that are script engines or LOLBins
                # to keep CPU low — full DLL scanning is expensive
                try:
                    proc_name = proc.name().lower()
                    if proc_name in (
                            "powershell.exe", "pwsh.exe", "rundll32.exe",
                            "regsvr32.exe", "mshta.exe", "wscript.exe",
                            "cscript.exe", "installutil.exe", "msbuild.exe"):
                        dll_evs = _scan_process_dlls(proc)
                        for dev in dll_evs:
                            try:
                                _spool.put("/dll_events", dev)
                            except OverflowError:
                                log.error("Spool full: DLL telemetry gap")
                                break
                except Exception:
                    pass

            live = set(psutil.pids())
            with _pid_lock:
                for old_pid in list(_pid_seen):
                    if old_pid not in live:
                        _pid_seen.pop(old_pid, None)
            with _dll_lock2:
                for old_pid in list(_known_dll_loads):
                    if old_pid not in live:
                        _known_dll_loads.pop(old_pid, None)
        except Exception as e:
            log.error("Scan error: %s", e)
        _stop.wait(timeout=POLL_SECS)
    log.info("Monitor stopped.")


# ── Async sender ──────────────────────────────────────────────────────────────

def _sender_loop():
    while not _stop.is_set():
        path, batch = _spool.peek()
        if not batch:
            _stop.wait(1)
            continue
        try:
            response = requests.post(_BASE + path, json={"events": batch}, headers=HEADERS, timeout=TIMEOUT, verify=_TLS_VERIFY)
            if response.status_code == 200:
                accepted = set(response.json().get("accepted", []))
                _spool.acknowledge([e["event_id"] for e in batch if e["event_id"] in accepted])
                if not accepted:
                    _stop.wait(5)
            elif response.status_code in (400, 413, 422):
                if len(batch) > 1:
                    # Isolate a bad record rather than rejecting its healthy neighbours.
                    for event in batch:
                        single = requests.post(_BASE + path, json={"events": [event]}, headers=HEADERS, timeout=TIMEOUT, verify=_TLS_VERIFY)
                        if single.status_code == 200 and event["event_id"] in single.json().get("accepted", []):
                            _spool.acknowledge([event["event_id"]])
                        elif single.status_code in (400, 413, 422):
                            _spool.reject([event["event_id"]], single.text)
                else:
                    _spool.reject([batch[0]["event_id"]], response.text)
                log.error("Telemetry rejected; inspect spool error records")
            else:
                log.warning("Telemetry delivery deferred: HTTP %s", response.status_code)
                _stop.wait(5)
        except (requests.RequestException, ValueError):
            log.warning("Telemetry delivery failed; retained on disk", exc_info=True)
            _stop.wait(5)


def _heartbeat_loop():
    log.info("Heartbeat started. Interval: %ds.", HB_SECS)
    while not _stop.is_set():
        _post(HB_URL, {"system_id": SYSTEM_ID, "collector_health": {
            "sysmon": _spool.source_state('sysmon') or {"state": "disabled"},
            "outbox": _spool.stats()}}, "HEARTBEAT")
        _stop.wait(timeout=HB_SECS)
    log.info("Heartbeat stopped.")


# ── C2 command handler ────────────────────────────────────────────────────────

def _exec_command(cmd):
    _spool.execute_once(cmd, execute)


def _cmd_loop():
    log.info("Command handler started. Polling every %ds.", CMD_SECS)
    while not _stop.is_set():
        data = _get(CMDS_URL, "COMMANDS")
        if data:
            for cmd in data.get("commands", []):
                try:
                    _exec_command(cmd)
                except Exception as e:
                    log.error("Command error: %s", e)
        for cid, result in _spool.pending_results():
            if _post(RESULT_URL, {"id": cid, "system_id": SYSTEM_ID, "result": result}, "CMD_RESULT"):
                _spool.acknowledge_result(cid)
        _stop.wait(timeout=CMD_SECS)
    log.info("Command handler stopped.")


# ── Registration ──────────────────────────────────────────────────────────────

def _register():
    data = {
        "system_id":  SYSTEM_ID,
        "hostname":   socket.gethostname(),
        "platform":   platform.platform(),
        "ip_address": "",
        "agent_ver":  "4.1.0-rc1",
    }
    result = _post(REG_URL, data, "REGISTER")
    if result:
        log.info("Registered with server: %s", result)
    else:
        log.warning("Registration failed — server may not be ready yet.")


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    if not API_KEY or len(API_KEY) < 32:
        raise RuntimeError("Enroll this endpoint and set EDR_API_KEY")
    parsed = urlparse(_BASE)
    if not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path:
        raise RuntimeError("EDR_SERVER_URL must be an origin URL")
    if not _TLS_ENABLED and not (os.environ.get("EDR_ENV") == "development" and parsed.hostname in {"127.0.0.1", "localhost"} and parsed.scheme == "http"):
        raise RuntimeError("HTTPS is required; HTTP is permitted only on development loopback")
    print("=" * 54)
    print("  BehEDR Agent 4.1.0-rc1")
    print(f"  System  : {SYSTEM_ID}")
    print(f"  Server  : {_BASE}")
    print(f"  Log     : {_LOG_FILE}")
    print("=" * 54)

    log.info("Agent starting. System: %s  Server: %s", SYSTEM_ID, _BASE)
    _register()

    threads = [
        threading.Thread(target=_monitor_loop,   name="Monitor",    daemon=True),
        threading.Thread(target=_sender_loop,     name="Sender",     daemon=True),
        threading.Thread(target=_heartbeat_loop,  name="Heartbeat",  daemon=True),
        threading.Thread(target=_cmd_loop,        name="CmdHandler", daemon=True),
        threading.Thread(target=_network_loop,    name="NetMonitor",  daemon=True),
        threading.Thread(target=_file_loop,       name="FileMonitor", daemon=True),
        threading.Thread(target=_etw_collection_loop, name="ETWSession", daemon=True),
        threading.Thread(target=_etw_sender_loop,     name="ETWSender",  daemon=True),
        threading.Thread(target=_yara_scan_loop,      name="YARAScan",   daemon=True),
        threading.Thread(target=_yara_sender_loop,    name="YARASender", daemon=True),
    ]
    if os.environ.get('EDR_SYSMON', 'false').lower() == 'true':
        from sysmon_collector import run as run_sysmon
        threads.append(threading.Thread(target=run_sysmon, args=(_spool, SYSTEM_ID, _stop),
                                        name='Sysmon', daemon=True))
    else:
        _spool.commit_source('sysmon', {"state": "disabled"})
    for t in threads:
        t.start()
        log.info("Thread started: %s", t.name)

    try:
        while not _stop.wait(1):
            if any(not t.is_alive() for t in threads[:6]):
                raise RuntimeError("An essential agent worker stopped")
    except KeyboardInterrupt:
        pass
    finally:
        log.info("Stopping agent…")
        _stop.set()
        for t in threads:
            t.join(timeout=5)
        log.info("Agent stopped.")
        print("\n[*] Agent stopped.")


if __name__ == "__main__":
    main()
