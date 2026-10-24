# -*- coding: utf-8 -*-
"""
yara_scanner.py — In-memory YARA scanning for fileless malware detection
=========================================================================
Scans the virtual memory of running processes for shellcode, injected
payloads, and known malware signatures using YARA rules.

This catches what psutil + ETW cannot see:
  - Cobalt Strike beacons injected into svchost.exe / explorer.exe
  - Meterpreter living in a legitimate process
  - Reflectively loaded PEs with no file on disk
  - Shellcode stubs in RWX memory regions

Architecture
────────────
  yara_scan_loop()    — entry point, called as a daemon thread from agent.py
  _scan_process()     — scans one process: enumerate RWX regions → YARA match
  _get_rwx_regions()  — returns suspicious memory regions via VirtualQueryEx
  _read_region()      — reads memory via ReadProcessMemory
  _build_ruleset()    — compiles built-in rules + any .yar files in rules/yara/

Scanning strategy (keeps CPU under ~2%)
────────────────────────────────────────
  Priority 1 — processes already flagged HIGH/CRITICAL by the detection engine
               (flag shared via _priority_pids set, set by server callback)
  Priority 2 — processes with MEM_PRIVATE + PAGE_EXECUTE_READWRITE regions
               (RWX private memory is almost never legitimate)
  Priority 3 — 5% random sample of remaining processes (catch novel techniques)

  Scan interval: 60 seconds for priority-2/3, 10 seconds for priority-1

Requirements
────────────
  pip install yara-python

  Degrades gracefully if yara-python is not installed or OS is not Windows.
  All functions become no-ops; agent continues with other telemetry.

Output
──────
  Hits are placed on yara_hit_queue (queue.Queue).
  The agent's _yara_sender_loop() drains this and POSTs to /yara_hits.
  The server-side handle_yara_hit() in detector.py emits the alert.
"""

import os
import sys
import time
import queue
import random
import hashlib
import logging
import threading
import ctypes
from ctypes import wintypes
from datetime import datetime, timezone
from typing import List, Optional, Tuple

log = logging.getLogger("yara")

# ── Public output queue ───────────────────────────────────────────────────────
yara_hit_queue: queue.Queue = queue.Queue(maxsize=1000)

# ── Priority PID set — populated by server response callbacks ────────────────
# When the server returns a CRITICAL/HIGH alert, agent.py adds the PID to this
# set so it gets scanned on the next fast cycle (10s) rather than slow (60s).
priority_pids: set = set()
_priority_lock = threading.Lock()

# ── Runtime state ─────────────────────────────────────────────────────────────
_SYSTEM_ID: str = ""
_yara_available = False
_ruleset         = None   # compiled yara.Rules object
_rules_lock      = threading.Lock()

# ── Recent hit dedup — avoid re-alerting on the same match every 60s ─────────
_recent_hits: dict = {}    # (pid, rule_name) → last_alert_ts
_hits_lock = threading.Lock()
HIT_DEDUP_SECS = 300       # suppress re-alert for 5 minutes


# ── YARA availability check ───────────────────────────────────────────────────
if os.name == "nt":
    try:
        import yara    # type: ignore
        _yara_available = True
        log.info("[YARA] yara-python available — memory scanning enabled.")
    except ImportError:
        log.warning(
            "[YARA] yara-python not installed — memory scanning disabled. "
            "Run: pip install yara-python"
        )
else:
    log.info("[YARA] Non-Windows — memory scanning not available.")


# ═════════════════════════════════════════════════════════════════════════════
# BUILT-IN YARA RULES
# ═════════════════════════════════════════════════════════════════════════════
# Curated from public sources: Elastic, Mandiant, CAPE sandbox, community.
# These catch the most common post-exploitation frameworks and shellcode stubs.
# Add your own .yar files to rules/yara/ — they are auto-loaded at startup.

BUILTIN_RULES = r"""

// ── Cobalt Strike Beacon ──────────────────────────────────────────────────
rule CobaltStrike_Beacon_Strings {
    meta:
        description = "Cobalt Strike beacon — internal format strings"
        mitre       = "T1055, T1071"
        severity    = "CRITICAL"
        confidence  = "HIGH"
    strings:
        $cs1 = "%s as %s\\%s: %d"           ascii wide
        $cs2 = "ReflectiveLoader"            ascii wide
        $cs3 = "beacon.dll"                  ascii wide nocase
        $cs4 = "%d is an x64 process"        ascii wide
        $cs5 = "SMB Beacon"                  ascii wide
        $cs6 = "could not connect to pipe"   ascii wide
        $cs7 = { 4D 5A 41 52 55 48 89 E5 }  // CS reflective PE header stub
    condition:
        2 of them
}

rule CobaltStrike_Config_Marker {
    meta:
        description = "Cobalt Strike default config block marker"
        mitre       = "T1055"
        severity    = "CRITICAL"
        confidence  = "HIGH"
    strings:
        // Default CS config header bytes (seen in every default-profile beacon)
        $cfg = { 00 01 00 01 00 02 ?? ?? 00 02 00 04 }
    condition:
        $cfg and filesize < 5MB
}

// ── Metasploit / Meterpreter ──────────────────────────────────────────────
rule Meterpreter_Strings {
    meta:
        description = "Metasploit Meterpreter in-memory strings"
        mitre       = "T1055, T1059"
        severity    = "CRITICAL"
        confidence  = "HIGH"
    strings:
        $m1 = "metsrv.dll"           ascii wide nocase
        $m2 = "meterpreter"          ascii wide nocase
        $m3 = "ReflectiveDllInject"  ascii wide
        $m4 = "GetProcAddress"       ascii wide
        $m5 = "WinHttpOpen"          ascii wide
        $m6 = { FC E8 8? 00 00 00 }  // classic Metasploit shellcode stub
        $m7 = "metsrv"               ascii wide nocase
    condition:
        3 of them
}

// ── Common shellcode stubs ────────────────────────────────────────────────
rule Shellcode_XOR_Decoder_Stub {
    meta:
        description = "XOR decoder loop — common shellcode obfuscation stub"
        mitre       = "T1027"
        severity    = "HIGH"
        confidence  = "MEDIUM"
    strings:
        // short XOR decode loop: xor [edi+ecx], al; inc ecx; loop
        $xor1 = { 30 04 0F 40 3B C8 75 }
        // common x64 XOR stub
        $xor2 = { 48 31 C9 48 81 E9 ?? ?? ?? ?? 48 8D 05 }
        // jmp/call decoder pattern
        $jmp1 = { EB ?? 5E 31 C0 88 46 }
    condition:
        any of them
}

rule Shellcode_EggHunter {
    meta:
        description = "Egghunter shellcode — used in staged exploits"
        mitre       = "T1203"
        severity    = "HIGH"
        confidence  = "MEDIUM"
    strings:
        $egg1 = { 66 81 CA FF 0F 42 52 6A 43 58 CD 2E 3C 05 5A }
        $egg2 = { 90 50 66 81 CA FF 0F 42 52 6A 02 58 CD 2E }
    condition:
        any of them
}

// ── Process injection markers ────────────────────────────────────────────
rule Reflective_DLL_Inject {
    meta:
        description = "Reflective DLL injection loader"
        mitre       = "T1055.001"
        severity    = "CRITICAL"
        confidence  = "HIGH"
    strings:
        $r1 = "ReflectiveLoader"            ascii wide
        $r2 = { 4D 5A }                     // MZ header in unexpected region
        $r3 = "This program cannot be run"  ascii
        $r4 = "VirtualAlloc"                ascii wide
        $r5 = "LoadLibraryA"                ascii wide
    condition:
        $r1 or ($r2 and $r3 and ($r4 or $r5))
}

// ── Credential dumping in memory ─────────────────────────────────────────
rule Mimikatz_Memory_Strings {
    meta:
        description = "Mimikatz strings detected in process memory"
        mitre       = "T1003.001"
        severity    = "CRITICAL"
        confidence  = "HIGH"
    strings:
        $mz1 = "sekurlsa::logonpasswords"  ascii wide nocase
        $mz2 = "sekurlsa::wdigest"         ascii wide nocase
        $mz3 = "lsadump::dcsync"           ascii wide nocase
        $mz4 = "lsadump::sam"              ascii wide nocase
        $mz5 = "SekurLSA"                  ascii wide
        $mz6 = "gentilkiwi"                ascii wide nocase
        $mz7 = "benjamin@gentilkiwi"       ascii wide nocase
        $mz8 = "mimikatz"                  ascii wide nocase
    condition:
        2 of them
}

// ── PowerShell AMSI bypass in memory ────────────────────────────────────
rule AMSI_Bypass_InMemory {
    meta:
        description = "AMSI bypass code detected in process memory"
        mitre       = "T1562.001"
        severity    = "HIGH"
        confidence  = "HIGH"
    strings:
        $a1 = "AmsiScanBuffer"    ascii wide nocase
        $a2 = "amsiInitFailed"    ascii wide nocase
        $a3 = "AmsiUtils"         ascii wide nocase
        $a4 = { B8 57 00 07 80 C3 }   // common AmsiScanBuffer patch bytes
        $a5 = { 31 C0 C3 }            // xor eax,eax; ret — patch stub
    condition:
        ($a1 or $a2 or $a3) and ($a4 or $a5)
}

// ── Sliver C2 framework ──────────────────────────────────────────────────
rule Sliver_C2_Strings {
    meta:
        description = "Sliver C2 framework in-memory indicators"
        mitre       = "T1071, T1055"
        severity    = "CRITICAL"
        confidence  = "MEDIUM"
    strings:
        $s1 = "sliver"              ascii wide nocase
        $s2 = "SliverMetaData"      ascii wide
        $s3 = "implant/sliver"      ascii wide
        $s4 = "github.com/bishopfox/sliver" ascii
    condition:
        2 of them
}

// ── Brute Ratel C4 ───────────────────────────────────────────────────────
rule BruteRatel_C4 {
    meta:
        description = "Brute Ratel C4 badger in-memory indicators"
        mitre       = "T1055, T1071"
        severity    = "CRITICAL"
        confidence  = "MEDIUM"
    strings:
        $b1 = "BruteRatel"          ascii wide nocase
        $b2 = "brute_ratel"         ascii wide nocase
        $b3 = { 48 8B 05 ?? ?? ?? ?? FF D0 48 85 C0 74 }  // BRC4 reflective stub
    condition:
        2 of ($b1, $b2, $b3)
}

// ── Generic PE in RWX region (high suspicion) ────────────────────────────
rule PE_In_RWX_Region {
    meta:
        description = "PE file loaded into RWX private memory — likely injected"
        mitre       = "T1055"
        severity    = "HIGH"
        confidence  = "MEDIUM"
    strings:
        $mz  = { 4D 5A }
        $pe  = { 50 45 00 00 }
        $dos = "This program cannot be run in DOS mode"
    condition:
        $mz at 0 and $pe and $dos
}

"""


# ═════════════════════════════════════════════════════════════════════════════
# WINDOWS MEMORY API (ctypes)
# ═════════════════════════════════════════════════════════════════════════════

# Memory protection constants
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_EXECUTE_READ      = 0x20
PAGE_EXECUTE           = 0x10
MEM_COMMIT             = 0x1000
MEM_PRIVATE            = 0x20000

# Process access rights
PROCESS_VM_READ            = 0x0010
PROCESS_QUERY_INFORMATION  = 0x0400
PROCESS_QUERY_LIMITED_INFO = 0x1000


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress",       ctypes.c_void_p),
        ("AllocationBase",    ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize",        ctypes.c_size_t),
        ("State",             wintypes.DWORD),
        ("Protect",           wintypes.DWORD),
        ("Type",              wintypes.DWORD),
    ]


def _open_process(pid: int):
    """Open a process handle for reading memory. Returns handle or None."""
    if os.name != "nt":
        return None
    try:
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.OpenProcess(
            PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
            False, pid)
        if handle == 0:
            # Try limited info rights (works on some protected processes)
            handle = kernel32.OpenProcess(
                PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFO,
                False, pid)
        return handle if handle else None
    except Exception:
        return None


def _close_handle(handle):
    try:
        ctypes.windll.kernel32.CloseHandle(handle)
    except Exception:
        pass


def _get_suspicious_regions(handle) -> List[Tuple[int, int]]:
    """
    Walk the process virtual address space and return (address, size) tuples
    for memory regions that are:
      - Committed (MEM_COMMIT)
      - Private (MEM_PRIVATE) — not backed by a file on disk
      - Executable (any PAGE_EXECUTE_* protection)

    This combination is the primary indicator of injected shellcode or
    reflectively loaded PE files.  Legitimate DLLs are file-backed (MEM_IMAGE),
    not MEM_PRIVATE.  Heap/stack are private but not executable.

    Max region size capped at 32 MB to avoid scanning enormous heaps.
    """
    regions = []
    if os.name != "nt" or not handle:
        return regions

    kernel32  = ctypes.windll.kernel32
    addr      = 0
    mbi       = MEMORY_BASIC_INFORMATION()
    mbi_size  = ctypes.sizeof(mbi)
    MAX_REGION = 32 * 1024 * 1024  # 32 MB cap

    EXEC_PROTECTIONS = {
        PAGE_EXECUTE_READWRITE,
        PAGE_EXECUTE_WRITECOPY,
        PAGE_EXECUTE_READ,
        PAGE_EXECUTE,
    }

    while True:
        ret = kernel32.VirtualQueryEx(
            handle,
            ctypes.c_void_p(addr),
            ctypes.byref(mbi),
            mbi_size)
        if ret == 0:
            break

        size = mbi.RegionSize
        if size == 0:
            break

        if (mbi.State    == MEM_COMMIT and
                mbi.Type == MEM_PRIVATE and
                mbi.Protect in EXEC_PROTECTIONS and
                0 < size <= MAX_REGION):
            regions.append((mbi.BaseAddress, size))

        # Advance to next region
        try:
            addr = mbi.BaseAddress + size
            if addr >= 0x7FFFFFFFFFFF:   # past user-space limit
                break
        except (TypeError, OverflowError):
            break

    return regions


def _read_region(handle, address: int, size: int) -> Optional[bytes]:
    """Read `size` bytes from `address` in the target process."""
    if os.name != "nt" or not handle:
        return None
    try:
        kernel32 = ctypes.windll.kernel32
        buf      = ctypes.create_string_buffer(size)
        bytes_read = ctypes.c_size_t(0)
        ok = kernel32.ReadProcessMemory(
            handle,
            ctypes.c_void_p(address),
            buf,
            size,
            ctypes.byref(bytes_read))
        if ok and bytes_read.value > 0:
            return buf.raw[:bytes_read.value]
    except Exception:
        pass
    return None


# ═════════════════════════════════════════════════════════════════════════════
# RULE LOADING
# ═════════════════════════════════════════════════════════════════════════════

def _build_ruleset(rules_dir: Optional[str] = None):
    """
    Compile YARA rules.  Combines:
      1. Built-in rules (always loaded)
      2. Any .yar / .yara files found in rules/yara/ directory

    Returns compiled yara.Rules or None on failure.
    """
    if not _yara_available:
        return None

    import yara  # type: ignore

    sources = {"builtin": BUILTIN_RULES}

    # Load external rule files from rules/yara/
    if rules_dir and os.path.isdir(rules_dir):
        for fname in os.listdir(rules_dir):
            if fname.endswith((".yar", ".yara")):
                fpath = os.path.join(rules_dir, fname)
                try:
                    with open(fpath, encoding="utf-8", errors="replace") as f:
                        sources[fname] = f.read()
                    log.info("[YARA] Loaded external rules: %s", fname)
                except Exception as e:
                    log.warning("[YARA] Could not load %s: %s", fname, e)

    try:
        rules = yara.compile(sources=sources)
        rule_count = sum(1 for _ in rules)
        log.info("[YARA] Compiled %d rules from %d source(s).",
                 rule_count, len(sources))
        return rules
    except yara.SyntaxError as e:
        log.error("[YARA] Rule syntax error: %s", e)
        return None
    except Exception as e:
        log.error("[YARA] Rule compile error: %s", e)
        return None


# ═════════════════════════════════════════════════════════════════════════════
# PROCESS SCANNER
# ═════════════════════════════════════════════════════════════════════════════

def _scan_process(pid: int, proc_name: str, rules) -> List[dict]:
    """
    Scan one process for YARA matches in its private executable memory regions.

    Returns a list of hit dicts (may be empty).
    Each hit:  {rule, severity, mitre, description, pid, process,
                address_hex, region_size, matched_strings}
    """
    hits = []
    handle = _open_process(pid)
    if not handle:
        return hits

    try:
        regions = _get_suspicious_regions(handle)
        if not regions:
            return hits

        for addr, size in regions:
            data = _read_region(handle, addr, size)
            if not data or len(data) < 16:
                continue

            try:
                matches = rules.match(data=data, timeout=5)
            except Exception:
                continue

            for match in matches:
                rule_name = match.rule
                dedup_key = (pid, rule_name)

                with _hits_lock:
                    last = _recent_hits.get(dedup_key, 0)
                    if time.time() - last < HIT_DEDUP_SECS:
                        continue
                    _recent_hits[dedup_key] = time.time()
                    # Evict old entries
                    if len(_recent_hits) > 2000:
                        oldest = sorted(_recent_hits, key=_recent_hits.get)[:500]
                        for k in oldest:
                            del _recent_hits[k]

                meta       = match.meta
                severity   = meta.get("severity",    "HIGH")
                mitre      = meta.get("mitre",       "T1055")
                desc       = meta.get("description", rule_name)

                # Collect matched string snippets for the alert reason
                matched_strs = []
                for s in match.strings[:5]:
                    # yara-python 4.x: s is a StringMatch object
                    try:
                        identifier = s.identifier
                        instances  = s.instances
                        snippet    = instances[0].matched_data[:64] if instances else b""
                        matched_strs.append(
                            f"{identifier}={snippet.hex() if isinstance(snippet, bytes) else snippet}"
                        )
                    except AttributeError:
                        # yara-python 3.x: s is (offset, identifier, data)
                        try:
                            matched_strs.append(
                                f"{s[1]}={s[2][:32].hex()}"
                            )
                        except Exception:
                            pass

                hits.append({
                    "rule":            rule_name,
                    "severity":        severity,
                    "mitre":           mitre,
                    "description":     desc,
                    "pid":             pid,
                    "process":         proc_name,
                    "address_hex":     hex(addr),
                    "region_size":     size,
                    "matched_strings": matched_strs[:5],
                })

                log.warning("[YARA] HIT: rule=%s pid=%d process=%s addr=%s",
                            rule_name, pid, proc_name, hex(addr))

    finally:
        _close_handle(handle)

    return hits


event_sink = None


def _push_hit(hit: dict):
    hit["system_id"] = _SYSTEM_ID
    hit["event"]     = "yara_hit"
    hit["time"]      = int(datetime.now(timezone.utc).timestamp())
    if event_sink is not None:
        event_sink(hit)
        return
    try:
        yara_hit_queue.put_nowait(hit)
    except queue.Full:
        log.error("YARA queue full: telemetry gap")


# ═════════════════════════════════════════════════════════════════════════════
# SCAN LOOP
# ═════════════════════════════════════════════════════════════════════════════

def yara_scan_loop(system_id: str, stop_event: threading.Event,
                   rules_dir: Optional[str] = None):
    """
    Main YARA scan loop — call as a daemon thread from agent.py.

    Scanning strategy:
      Every 10s: scan priority_pids (processes flagged HIGH/CRITICAL by server)
      Every 60s: scan all processes with RWX private memory +
                 a 5% random sample of remaining processes

    Args:
        system_id:   hostname for event annotation
        stop_event:  threading.Event to stop the loop
        rules_dir:   path to directory containing extra .yar files
                     (defaults to rules/yara/ relative to this file)
    """
    global _SYSTEM_ID, _ruleset
    _SYSTEM_ID = system_id

    if not _yara_available:
        log.info("[YARA] Not available — scan loop exiting.")
        return

    # Resolve rules directory
    if rules_dir is None:
        here      = os.path.dirname(os.path.abspath(__file__))
        rules_dir = os.path.join(here, "edr_clean", "rules", "yara")
        if not os.path.isdir(rules_dir):
            rules_dir = os.path.join(here, "rules", "yara")

    # Compile rules
    with _rules_lock:
        _ruleset = _build_ruleset(rules_dir)

    if _ruleset is None:
        log.error("[YARA] Rule compilation failed — scan loop exiting.")
        return

    import psutil

    log.info("[YARA] Scan loop started. Priority scan: 10s, full scan: 60s.")

    last_full_scan = 0.0

    while not stop_event.is_set():
        now = time.time()

        # ── Priority scan (10s cadence) ───────────────────────────────────
        with _priority_lock:
            pids_to_scan = set(priority_pids)

        if pids_to_scan:
            log.debug("[YARA] Priority scanning %d PID(s).", len(pids_to_scan))
            for pid in pids_to_scan:
                if stop_event.is_set():
                    break
                try:
                    proc_name = psutil.Process(pid).name()
                except Exception:
                    with _priority_lock:
                        priority_pids.discard(pid)
                    continue
                with _rules_lock:
                    rules = _ruleset
                for hit in _scan_process(pid, proc_name, rules):
                    _push_hit(hit)

        # ── Full scan (60s cadence) ────────────────────────────────────────
        if now - last_full_scan >= 60:
            last_full_scan = now
            try:
                all_procs = list(psutil.process_iter(["pid", "name"]))
            except Exception:
                all_procs = []

            # Always skip PIDs 0 and 4 (Idle, System) and known safe procs
            SKIP_PROCS = {
                "idle", "system", "registry", "smss.exe", "csrss.exe",
                "wininit.exe", "winlogon.exe", "lsass.exe",
                "services.exe", "svchost.exe", "dwm.exe",
                "fontdrvhost.exe", "memory compression",
            }

            # Build two scan lists: RWX candidates + random sample
            rwx_pids   = []
            other_pids = []

            for p in all_procs:
                pid  = p.pid
                name = (p.info.get("name") or "").lower()
                if name in SKIP_PROCS or pid <= 4:
                    continue
                # Quick check: does this process have any RWX private regions?
                handle = _open_process(pid)
                if handle:
                    regions = _get_suspicious_regions(handle)
                    _close_handle(handle)
                    if regions:
                        rwx_pids.append((pid, p.info.get("name", "unknown")))
                    else:
                        other_pids.append((pid, p.info.get("name", "unknown")))

            # Random 5% sample of processes without RWX (coverage scan)
            sample_size = max(1, len(other_pids) // 20)
            sample = random.sample(other_pids, min(sample_size, len(other_pids)))

            scan_list = rwx_pids + sample
            if scan_list:
                log.debug("[YARA] Full scan: %d RWX + %d sampled processes.",
                          len(rwx_pids), len(sample))

            with _rules_lock:
                rules = _ruleset

            for pid, proc_name in scan_list:
                if stop_event.is_set():
                    break
                for hit in _scan_process(pid, proc_name, rules):
                    _push_hit(hit)

        stop_event.wait(timeout=10)

    log.info("[YARA] Scan loop stopped.")


def add_priority_pid(pid: int):
    """
    Mark a PID for priority scanning on the next 10s cycle.
    Called from agent.py when the server returns a HIGH/CRITICAL alert
    for a specific process — we want to immediately scan it for injected code.
    """
    with _priority_lock:
        priority_pids.add(pid)
        # Keep bounded
        if len(priority_pids) > 200:
            priority_pids.clear()


def is_available() -> bool:
    """Return True if YARA scanning is available on this system."""
    return _yara_available
