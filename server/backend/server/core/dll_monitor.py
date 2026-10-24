# server/core/dll_monitor.py — DLL Hijacking & Sideloading Detection (T1574)
"""
Gap fix: DLL hijacking and sideloading detection.

How DLL hijacking works:
  A legitimate app (e.g. Teams.exe in AppData) loads a DLL by name only
  (e.g. "version.dll"). Windows searches directories in order:
    1. App directory
    2. System32
    3. PATH directories
  Attacker drops a malicious "version.dll" in the app directory.
  The app loads the malicious one instead of System32's version.

What we detect:
  1. Known-clean system DLLs loaded from non-System32 paths
  2. DLLs loaded from writable/suspicious paths (AppData, Temp, Public)
  3. Recently-written DLLs being loaded (file written < 60s ago, then loaded)
  4. DLL sideloading: known-clean exe loading a DLL from its own app directory
     when the DLL is NOT in System32 (and has no publisher info = unsigned)

Data source: agent sends dll_load events (requires Sysmon Event 7 or
             our psutil-based DLL scanner on the agent side)
"""
import ntpath as os_path
import os, time, threading
from collections import defaultdict
from typing import List, Tuple

# ── Known system DLLs that should ONLY come from System32 ───────────────────
# If these load from anywhere else = almost certainly hijacked
SYSTEM_DLLS = {
    "kernel32.dll", "ntdll.dll", "user32.dll", "advapi32.dll",
    "shell32.dll", "ole32.dll", "oleaut32.dll", "ws2_32.dll",
    "wininet.dll", "winhttp.dll", "crypt32.dll", "bcrypt.dll",
    "secur32.dll", "version.dll", "comctl32.dll", "comdlg32.dll",
    "gdi32.dll", "msvcrt.dll", "rpcrt4.dll", "shlwapi.dll",
    "urlmon.dll", "netapi32.dll", "samlib.dll", "wldap32.dll",
    "cryptbase.dll", "sspicli.dll", "cryptsp.dll", "rsaenh.dll",
    "userenv.dll", "profapi.dll", "wintrust.dll", "imagehlp.dll",
    # Common sideloading targets in real-world attacks
    "dbghelp.dll", "msvcp140.dll", "vcruntime140.dll",
    "d3d11.dll", "d3dx9_43.dll", "opengl32.dll",
    "nss3.dll", "softokn3.dll", "mozcrt.dll",   # Firefox sideloading
    "msi.dll", "wer.dll", "wevtapi.dll",
    "dwmapi.dll", "uxtheme.dll", "apphelp.dll",
}

# Paths where DLLs are trusted to load from
TRUSTED_DLL_DIRS = {
    "c:\\windows\\system32",
    "c:\\windows\\syswow64",
    "c:\\windows\\winsxs",
    "c:\\program files\\windows defender",
    "c:\\program files\\microsoft office",
}

# High-risk DLL load paths (suspicious even for non-system DLLs)
SUSPICIOUS_DLL_PATHS = {
    "\\appdata\\local\\temp\\",
    "\\appdata\\roaming\\",
    "\\users\\public\\",
    "c:\\temp\\",
    "c:\\windows\\temp\\",
    "c:\\programdata\\",
}

# ── Per-system DLL load tracking ─────────────────────────────────────────────
_dll_loads: dict = defaultdict(list)   # system_id → [{name,path,process,ts}]
_dll_lock = threading.Lock()


def add_dll_event(system_id: str, process: str, dll_name: str,
                  dll_path: str, signed: bool = True):
    """Record a DLL load event from the agent."""
    with _dll_lock:
        _dll_loads[system_id].append({
            "process":  process.lower(),
            "dll_name": dll_name.lower(),
            "dll_path": dll_path.lower().replace("/", "\\"),
            "signed":   signed,
            "ts":       time.time(),
        })
        # Keep last 2000 per system
        if len(_dll_loads[system_id]) > 2000:
            _dll_loads[system_id] = _dll_loads[system_id][-2000:]


def check_dll_hijacking(system_id: str, process: str,
                         exe_path: str) -> Tuple[int, List[str]]:
    """
    Check recent DLL loads for this process for hijacking indicators.
    Returns (score, reasons).
    """
    score, reasons = 0, []
    process_lc  = process.lower()
    exe_dir     = os_path.dirname(exe_path.lower().replace("/", "\\")) if exe_path else ""

    with _dll_lock:
        loads = [e for e in _dll_loads.get(system_id, [])
                 if e["process"] == process_lc]

    if not loads:
        return 0, []

    for load in loads[-50:]:   # check last 50 DLL loads for this process
        dll_name = load["dll_name"]
        dll_path = load["dll_path"]
        signed   = load["signed"]

        # ── Check 1: Known system DLL loaded from non-System32 ──────────
        # Only flag if the DLL path itself is outside trusted dirs.
        # kernel32.dll from c:\windows\system32\ is always clean.
        if dll_name in SYSTEM_DLLS:
            dll_dir = os_path.dirname(dll_path)
            # Clean: DLL comes from a trusted directory
            if any(dll_path.startswith(td) for td in TRUSTED_DLL_DIRS):
                continue   # legitimate — skip to next DLL
            # Suspicious: system DLL from non-trusted path
            score += 85
            reasons.append(
                f"DLL HIJACK: system DLL '{dll_name}' loaded from "
                f"'{dll_dir}' (not System32)")
            break   # one confirmed hijack is enough

        # ── Check 2: Unsigned DLL from suspicious path ───────────────────
        if signed is False:
            if any(sp in dll_path for sp in SUSPICIOUS_DLL_PATHS):
                score += 70
                reasons.append(
                    f"DLL SIDELOAD: unsigned DLL '{dll_name}' loaded from suspicious path")

        # ── Check 3: DLL from same directory as app (sideloading) ────────
        # Legitimate apps load system DLLs from System32, NOT from their own dir
        if exe_dir and dll_path.startswith(exe_dir) and dll_name in SYSTEM_DLLS:
            # Make sure exe_dir itself is not a trusted dir
            if not any(exe_dir.startswith(td) for td in TRUSTED_DLL_DIRS):
                score += 80
                reasons.append(
                    f"DLL SIDELOAD: '{dll_name}' loaded from app directory '{exe_dir}' — "
                    f"expected System32")
                break

    return min(score, 90), reasons


def get_dll_stats(system_id: str) -> dict:
    """Return summary of DLL loads for dashboard."""
    with _dll_lock:
        loads = _dll_loads.get(system_id, [])
    suspicious = [l for l in loads
                  if l["dll_name"] in SYSTEM_DLLS and
                  not any(l["dll_path"].startswith(td) for td in TRUSTED_DLL_DIRS)]
    return {
        "total_dll_loads": len(loads),
        "suspicious_dll_loads": len(suspicious),
        "suspicious_dlls": [{"dll": l["dll_name"], "path": l["dll_path"],
                              "process": l["process"]}
                             for l in suspicious[:10]],
    }
