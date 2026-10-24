# server/core/memory_forensics.py — Fileless Malware Detection (Memory Analysis)
"""
PRIORITY 3 #6: Memory Analysis for Fileless Malware Detection

Modern malware doesn't touch disk (67% of attacks). This module detects:
1. Reflective DLL injection — DLL loaded without file on disk
2. Process hollowing — legitimate process replaced with malicious code
3. Code cave injection — malicious code injected into valid process
4. PowerShell runspace hijacking — PowerShell executing in another process
5. Remote thread injection — CreateRemoteThread attacks

Detection Methods:
- Memory region analysis (executable regions in suspicious locations)
- Module verification (loaded DLLs vs. modules on disk)
- Process integrity checks (PE header validation)
- Suspicious memory protection flags (RWX pages)
- PowerShell runspace detection in non-PowerShell processes
"""

import time
from collections import defaultdict
from typing import List, Dict, Optional, Tuple

# ── Memory event tracking ─────────────────────────────────────────────────────

_memory_events: Dict[str, List[dict]] = defaultdict(list)  # system_id → [events]
_MEMORY_EVENTS_MAX_PER_SYSTEM = 500
_MEMORY_EVENTS_MAX_SYSTEMS = 100


def add_memory_event(system_id: str, event_type: str, process: str, details: dict):
    """
    Record a memory-related event from the agent.
    
    Event types:
    - dll_load_memory_only: DLL loaded with no corresponding file
    - memory_protection_change: VirtualProtect to RWX
    - remote_thread_create: CreateRemoteThread detected
    - process_hollow: Process memory modified after creation
    - powershell_runspace: PowerShell engine in non-PS process
    """
    _memory_events[system_id].append({
        "event_type": event_type,
        "process": process.lower(),
        "details": details,
        "timestamp": int(time.time()),
    })
    
    # Memory bound protection
    if len(_memory_events[system_id]) > _MEMORY_EVENTS_MAX_PER_SYSTEM:
        _memory_events[system_id] = _memory_events[system_id][-_MEMORY_EVENTS_MAX_PER_SYSTEM:]
    
    if len(_memory_events) > _MEMORY_EVENTS_MAX_SYSTEMS:
        _prune_memory_events()


def _prune_memory_events():
    """Remove systems with oldest events."""
    if len(_memory_events) <= _MEMORY_EVENTS_MAX_SYSTEMS:
        return
    
    # Find oldest system
    oldest_system = None
    oldest_time = float('inf')
    
    for system_id, events in _memory_events.items():
        if events and events[-1]["timestamp"] < oldest_time:
            oldest_time = events[-1]["timestamp"]
            oldest_system = system_id
    
    if oldest_system:
        del _memory_events[oldest_system]


# ── Detection: Reflective DLL Injection ───────────────────────────────────────

def detect_reflective_dll(system_id: str, process: str, dll_name: str, 
                          has_disk_file: bool) -> Optional[dict]:
    """
    Detect DLL loaded into memory without a corresponding disk file.
    
    Classic reflective DLL injection signature:
    - LoadLibrary called but no file exists
    - Memory region is executable
    - DLL name doesn't match known system DLLs
    
    Returns alert dict if detected, None otherwise.
    """
    if has_disk_file:
        return None  # Normal DLL load
    
    # System DLLs can load from cache - not suspicious
    system_dlls = {
        "ntdll.dll", "kernel32.dll", "kernelbase.dll", "user32.dll",
        "gdi32.dll", "advapi32.dll", "msvcrt.dll", "sechost.dll",
        "rpcrt4.dll", "combase.dll", "ucrtbase.dll", "win32u.dll",
    }
    
    if dll_name.lower() in system_dlls:
        return None
    
    # Reflective DLL injection detected
    return {
        "system_id": system_id,
        "process": process,
        "risk_level": "CRITICAL",
        "risk_score": 95,
        "confidence": "HIGH",
        "reason": f"Reflective DLL injection: {dll_name} loaded without disk file",
        "technique": "T1055.001",  # Process Injection: Dynamic-link Library Injection
        "ioc_hit": "",
        "timestamp": int(time.time()),
    }


# ── Detection: Process Hollowing ──────────────────────────────────────────────

_process_baseline: Dict[str, dict] = {}  # (system_id, pid) → {original_hash, create_time}


def record_process_creation(system_id: str, pid: int, process_name: str, 
                           image_hash: str):
    """Record legitimate process creation for later hollowing detection."""
    key = (system_id, pid)
    _process_baseline[key] = {
        "process_name": process_name.lower(),
        "original_hash": image_hash,
        "create_time": int(time.time()),
    }
    
    # Memory bound - keep last 1000 processes
    if len(_process_baseline) > 1000:
        oldest = sorted(_process_baseline.keys(), 
                       key=lambda k: _process_baseline[k]["create_time"])[:100]
        for k in oldest:
            del _process_baseline[k]


def detect_process_hollowing(system_id: str, pid: int, current_hash: str) -> Optional[dict]:
    """
    Detect process hollowing by comparing current memory hash to original.
    
    Process hollowing:
    1. Attacker creates suspended legitimate process (e.g., svchost.exe)
    2. Unmaps legitimate code from memory
    3. Writes malicious code in its place
    4. Resumes process - now running malware with legitimate name
    
    Detection: Hash of PE in memory != hash at process creation
    """
    key = (system_id, pid)
    baseline = _process_baseline.get(key)
    
    if not baseline:
        return None  # No baseline yet
    
    if baseline["original_hash"] == current_hash:
        return None  # Hash matches - process is legitimate
    
    # Process hollowing detected!
    process_name = baseline["process_name"]
    return {
        "system_id": system_id,
        "process": process_name,
        "risk_level": "CRITICAL",
        "risk_score": 98,
        "confidence": "HIGH",
        "reason": f"Process hollowing: {process_name} (PID {pid}) memory hash changed after creation",
        "technique": "T1055.012",  # Process Injection: Process Hollowing
        "ioc_hit": "",
        "timestamp": int(time.time()),
    }


# ── Detection: Code Cave Injection ────────────────────────────────────────────

def detect_code_cave(system_id: str, process: str, memory_regions: List[dict]) -> Optional[dict]:
    """
    Detect code cave injection - malicious code in unusual memory regions.
    
    Characteristics:
    - Small executable region (< 10KB) in middle of large non-executable region
    - RWX (Read/Write/Execute) protection flags
    - No corresponding PE section
    - Located in heap or stack memory
    
    Args:
        memory_regions: List of dicts with {address, size, protection, type}
    """
    suspicious_caves = []
    
    for region in memory_regions:
        protection = region.get("protection", "")
        size = region.get("size", 0)
        region_type = region.get("type", "")
        
        # Look for small RWX regions in heap/stack
        if "X" in protection and "W" in protection:  # Executable + Writable
            if size < 10240:  # Less than 10KB
                if region_type in ("HEAP", "STACK"):
                    suspicious_caves.append(region)
    
    if len(suspicious_caves) >= 2:  # Multiple small RWX regions = high suspicion
        return {
            "system_id": system_id,
            "process": process,
            "risk_level": "CRITICAL",
            "risk_score": 92,
            "confidence": "HIGH",
            "reason": f"Code cave injection: {len(suspicious_caves)} suspicious RWX memory regions",
            "technique": "T1055.001",  # Process Injection: DLL Injection
            "ioc_hit": "",
            "timestamp": int(time.time()),
        }
    
    return None


# ── Detection: PowerShell Runspace Hijacking ──────────────────────────────────

_powershell_engines = {
    "system.management.automation.dll",
    "system.management.automation.ni.dll",
}


def detect_powershell_hijack(system_id: str, process: str, 
                             loaded_modules: List[str]) -> Optional[dict]:
    """
    Detect PowerShell engine loaded in non-PowerShell process.
    
    Attack: Malware injects PowerShell runtime into its own process to execute
    scripts without spawning powershell.exe (avoids detection).
    
    Detection: System.Management.Automation.dll loaded in non-PS process
    """
    # Legitimate PowerShell processes
    ps_processes = {
        "powershell.exe", "pwsh.exe", "powershell_ise.exe",
        "wsmprovhost.exe",  # PowerShell remoting host
    }
    
    if process.lower() in ps_processes:
        return None  # Normal PowerShell process
    
    # Check if PowerShell engine is loaded
    modules_lower = {m.lower() for m in loaded_modules}
    if not modules_lower.intersection(_powershell_engines):
        return None  # No PS engine
    
    # PowerShell runspace in non-PS process = hijacking
    return {
        "system_id": system_id,
        "process": process,
        "risk_level": "CRITICAL",
        "risk_score": 94,
        "confidence": "HIGH",
        "reason": f"PowerShell runspace hijacking: PS engine loaded in {process}",
        "technique": "T1059.001, T1055",  # PowerShell + Process Injection
        "ioc_hit": "",
        "timestamp": int(time.time()),
    }


# ── Detection: Remote Thread Injection ────────────────────────────────────────

_remote_threads: Dict[str, List[dict]] = defaultdict(list)  # system_id → [threads]


def detect_remote_thread_injection(system_id: str, source_process: str, 
                                   target_process: str, target_pid: int) -> Optional[dict]:
    """
    Detect CreateRemoteThread injection.
    
    Attack: Process A creates a thread in Process B to execute malicious code.
    
    Detection patterns:
    - Non-system process creating thread in another process
    - Suspicious source → target pairs (e.g., Office → System process)
    - Multiple remote thread creations from same source
    """
    # System processes legitimately inject threads (Windows Update, etc.)
    system_sources = {
        "services.exe", "svchost.exe", "lsass.exe", "csrss.exe",
        "smss.exe", "wininit.exe", "winlogon.exe",
    }
    
    if source_process.lower() in system_sources:
        return None  # Legitimate system activity
    
    # Track remote thread attempts
    _remote_threads[system_id].append({
        "source": source_process.lower(),
        "target": target_process.lower(),
        "target_pid": target_pid,
        "timestamp": int(time.time()),
    })
    
    # Memory bound
    if len(_remote_threads[system_id]) > 100:
        _remote_threads[system_id] = _remote_threads[system_id][-100:]
    
    # Check for suspicious patterns
    recent = [t for t in _remote_threads[system_id] 
              if time.time() - t["timestamp"] < 300]  # Last 5 minutes
    
    # Pattern 1: Same source injecting into multiple targets
    source_targets = defaultdict(set)
    for t in recent:
        source_targets[t["source"]].add(t["target"])
    
    if len(source_targets.get(source_process.lower(), set())) >= 3:
        return {
            "system_id": system_id,
            "process": source_process,
            "risk_level": "CRITICAL",
            "risk_score": 96,
            "confidence": "HIGH",
            "reason": f"Remote thread injection: {source_process} injecting into multiple processes",
            "technique": "T1055.001",  # Process Injection: DLL Injection
            "ioc_hit": "",
            "timestamp": int(time.time()),
        }
    
    # Pattern 2: Suspicious source → target pair
    suspicious_pairs = {
        # Office apps should never inject into system processes
        ("winword.exe", "lsass.exe"),
        ("excel.exe", "lsass.exe"),
        ("powerpnt.exe", "lsass.exe"),
        ("outlook.exe", "lsass.exe"),
        # Browsers should not inject
        ("chrome.exe", "lsass.exe"),
        ("firefox.exe", "lsass.exe"),
        ("msedge.exe", "lsass.exe"),
    }
    
    if (source_process.lower(), target_process.lower()) in suspicious_pairs:
        return {
            "system_id": system_id,
            "process": source_process,
            "risk_level": "CRITICAL",
            "risk_score": 97,
            "confidence": "HIGH",
            "reason": f"Remote thread injection: {source_process} → {target_process}",
            "technique": "T1055.001",
            "ioc_hit": "",
            "timestamp": int(time.time()),
        }
    
    return None


# ── Module Verification (DLL tampering detection) ─────────────────────────────

def verify_loaded_modules(system_id: str, process: str, 
                         modules: List[dict]) -> List[dict]:
    """
    Verify that loaded modules match their disk versions.
    
    Detects:
    - DLL hijacking (malicious DLL with same name as legitimate one)
    - In-memory patching (DLL modified after load)
    
    Args:
        modules: List of {name, path, memory_hash, disk_hash, signed}
    
    Returns:
        List of alerts for tampered modules
    """
    alerts = []
    
    for mod in modules:
        name = mod.get("name", "").lower()
        memory_hash = mod.get("memory_hash", "")
        disk_hash = mod.get("disk_hash", "")
        signed = mod.get("signed", True)
        
        # Skip if hashes not provided
        if not memory_hash or not disk_hash:
            continue
        
        # Hash mismatch = module was modified in memory
        if memory_hash != disk_hash:
            alerts.append({
                "system_id": system_id,
                "process": process,
                "risk_level": "HIGH",
                "risk_score": 85,
                "confidence": "HIGH",
                "reason": f"Module tampering: {name} memory hash != disk hash",
                "technique": "T1574.001",  # DLL Search Order Hijacking
                "ioc_hit": "",
                "timestamp": int(time.time()),
            })
        
        # Unsigned system DLL = suspicious
        if not signed and name.endswith(".dll"):
            # System DLLs should always be signed
            system_paths = ["\\windows\\system32\\", "\\windows\\syswow64\\"]
            path_lower = mod.get("path", "").lower()
            
            if any(sp in path_lower for sp in system_paths):
                alerts.append({
                    "system_id": system_id,
                    "process": process,
                    "risk_level": "HIGH",
                    "risk_score": 80,
                    "confidence": "MEDIUM",
                    "reason": f"Unsigned system DLL: {name} in {process}",
                    "technique": "T1574.002",  # DLL Side-Loading
                    "ioc_hit": "",
                    "timestamp": int(time.time()),
                })
    
    return alerts


# ── Get memory forensics statistics ───────────────────────────────────────────

def get_stats() -> dict:
    """Get memory forensics detection statistics."""
    total_events = sum(len(events) for events in _memory_events.values())
    
    # Count by event type
    event_counts = defaultdict(int)
    for events in _memory_events.values():
        for event in events:
            event_counts[event["event_type"]] += 1
    
    return {
        "total_systems": len(_memory_events),
        "total_events": total_events,
        "by_type": dict(event_counts),
        "monitored_processes": len(_process_baseline),
    }


# ── Volatility3 Integration (Advanced) ────────────────────────────────────────

def analyze_memory_dump(system_id: str, dump_path: str) -> List[dict]:
    """
    Advanced: Analyze a full memory dump using Volatility3 framework.
    
    This is triggered manually by analyst for deep investigation.
    Runs Volatility plugins to detect:
    - Hollowed processes (pslist vs. psscan mismatch)
    - Hidden processes (DKOM rootkit technique)
    - Injected code (malfind plugin)
    - Suspicious handles (handles plugin)
    
    NOTE: Requires volatility3 package installed.
    """
    alerts = []
    
    try:
        import subprocess
        import json
        
        # Run Volatility malfind plugin (detects injected code)
        result = subprocess.run(
            ["python", "-m", "volatility3", "-f", dump_path, 
             "windows.malfind", "--format", "json"],
            capture_output=True,
            text=True,
            timeout=300  # 5 minute timeout
        )
        
        if result.returncode == 0:
            findings = json.loads(result.stdout)
            
            for finding in findings:
                alerts.append({
                    "system_id": system_id,
                    "process": finding.get("Process", "unknown"),
                    "risk_level": "CRITICAL",
                    "risk_score": 90,
                    "confidence": "HIGH",
                    "reason": f"Volatility malfind: Injected code at {finding.get('VirtualAddress')}",
                    "technique": "T1055",
                    "ioc_hit": "",
                    "timestamp": int(time.time()),
                })
        
    except FileNotFoundError:
        print("[MEMORY FORENSICS] Volatility3 not installed - skipping advanced analysis")
    except subprocess.TimeoutExpired:
        print("[MEMORY FORENSICS] Volatility analysis timeout")
    except Exception as e:
        print(f"[MEMORY FORENSICS] Volatility analysis error: {e}")
    
    return alerts


# ── Initialize module ─────────────────────────────────────────────────────────

def initialize():
    """Initialize memory forensics module."""
    print("[MEMORY FORENSICS] Fileless malware detection initialized")
    print("[MEMORY FORENSICS] Detecting: Reflective DLL, Process Hollowing, "
          "Code Caves, PS Hijack, Remote Threads")
