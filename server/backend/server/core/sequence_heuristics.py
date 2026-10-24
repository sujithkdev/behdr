"""Process frequency and sequence heuristics; no trained malware classifier."""
import time, threading, math
from collections import defaultdict, deque
from typing import Tuple

# ── Per-system event sequence tracking ───────────────────────────────────────
# Sliding window of last 200 process-spawn events per system.
# 50 was too small: a real attack chain spread over 30 minutes can have
# hundreds of normal events between stages, evicting relevant context
# before the timestamp-based detection checks even run.
_sequences: dict = defaultdict(lambda: deque(maxlen=200))
_seq_lock = threading.Lock()

# ── Per-system (parent→child) frequency counters ─────────────────────────────
# {system_id: {(parent, child): count}}
_pair_counts: dict = defaultdict(lambda: defaultdict(int))
_pair_totals: dict = defaultdict(int)   # total events per system
_freq_lock = threading.Lock()

# ── Global bigram frequency (across all systems, used as prior) ──────────────
_global_pairs: dict = defaultdict(int)
_global_total: int  = 0
_global_lock = threading.Lock()

# Minimum observations before frequency scoring is meaningful
MIN_OBSERVATIONS = 200


def record_event(system_id: str, parent: str, child: str, cmdline: str = ""):
    """
    Record a process spawn event for sequence and frequency tracking.
    Call this for every event BEFORE running detection.
    """
    global _global_total
    p, c = parent.lower(), child.lower()
    pair = (p, c)

    with _freq_lock:
        _pair_counts[system_id][pair] += 1
        _pair_totals[system_id] += 1

    with _global_lock:
        _global_pairs[pair] += 1
        _global_total += 1

    with _seq_lock:
        _sequences[system_id].append({
            "parent": p, "child": c,
            "cmdline": cmdline[:128],
            "ts": time.time(),
        })


def score_frequency(system_id: str, parent: str, child: str) -> Tuple[int, str]:
    """
    Score based on how rare this (parent→child) pair is for this system.

    Logic: if the system has seen 200+ events and this pair has NEVER
    appeared before, it's unusual. Score by rarity.

    Returns (score 0-40, reason_str)
    """
    p, c = parent.lower(), child.lower()
    pair = (p, c)

    with _freq_lock:
        total  = _pair_totals.get(system_id, 0)
        count  = _pair_counts.get(system_id, {}).get(pair, 0)

    if total < MIN_OBSERVATIONS:
        return 0, ""   # not enough data to be meaningful

    # Probability of this pair on this system
    p_local = count / total if total > 0 else 0

    with _global_lock:
        g_count = _global_pairs.get(pair, 0)
        g_total = _global_total

    # Probability globally (across all systems we've seen)
    p_global = g_count / g_total if g_total > 0 else 0

    # If seen locally > 1% of the time: definitely normal, skip
    if p_local > 0.01:
        return 0, ""

    # Never seen locally but common globally → medium suspicion
    # Never seen anywhere → highest suspicion
    if count == 0 and p_global < 0.001:
        # Completely novel pair
        score = 35
        reason = (f"RARE PAIR: '{p}' → '{c}' never seen on this system "
                  f"or globally ({total} events baseline)")
        return score, reason

    if count == 0 and p_global < 0.01:
        score = 25
        reason = (f"UNUSUAL PAIR: '{p}' → '{c}' never seen on this system "
                  f"(rare globally: {g_count}/{g_total})")
        return score, reason

    if count <= 2 and total > 500:
        # Seen only once or twice on a system with lots of data
        score = 18
        reason = (f"INFREQUENT PAIR: '{p}' → '{c}' seen only {count}x "
                  f"in {total} events on this system")
        return score, reason

    return 0, ""


def score_sequence(system_id: str, parent: str, child: str) -> Tuple[int, str]:
    """
    Score based on what has happened recently in the sequence.

    Specific patterns we detect:
    - Recon burst: >3 recon tools (whoami, systeminfo, ipconfig, net) in last 60s
    - Persistence after execution: reg.exe or schtasks.exe shortly after a shell
    - Download then execute: certutil/bitsadmin then a new executable within 30s
    - Rapid process spawning: >10 new child processes in 5 seconds (process storm)
    """
    c = child.lower()
    p = parent.lower()

    with _seq_lock:
        recent = list(_sequences.get(system_id, []))

    # ── Pattern 2: Download-then-execute ─────────────────────────────────
    DOWNLOADER_TOOLS = {"certutil.exe", "bitsadmin.exe", "curl.exe",
                        "wget.exe", "msiexec.exe", "desktopimgdownldr.exe",
                        "certreq.exe"}
    EXECUTOR_TOOLS   = {"powershell.exe", "pwsh.exe", "cmd.exe",
                        "wscript.exe", "cscript.exe", "rundll32.exe",
                        "mshta.exe", "regsvr32.exe"}
    # Pattern 2 only needs 1+ prior event — download, then execute
    # Check even if recent has only 1 entry
    if c in EXECUTOR_TOOLS:
        has_download = any(e["child"] in DOWNLOADER_TOOLS for e in recent)
        if has_download:
            return 50, ("DOWNLOAD-EXECUTE SEQUENCE: download tool seen in "
                        "recent history before this script engine execution")

    # Patterns 1 + 3-5 need at least 2 prior events to be meaningful
    if len(recent) < 2:
        return 0, ""

    now = time.time()

    # ── Pattern 1: Recon burst ───────────────────────────────────────────
    RECON_TOOLS = {"whoami.exe", "systeminfo.exe", "ipconfig.exe", "net.exe",
                   "net1.exe", "arp.exe", "nltest.exe", "nslookup.exe",
                   "hostname.exe", "qwinsta.exe", "query.exe"}
    recon_recent = [e for e in recent if e["child"] in RECON_TOOLS
                    and now - e["ts"] < 120]
    if len(recon_recent) >= 4:
        return 55, (f"RECON BURST: {len(recon_recent)} recon tools executed "
                    f"in last 2 minutes — host fingerprinting pattern")

    # ── Pattern 3: Persistence after shell ───────────────────────────────
    PERSISTENCE_TOOLS = {"reg.exe", "schtasks.exe", "sc.exe", "at.exe"}
    SHELL_TOOLS = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe"}
    has_shell = any(e["child"] in SHELL_TOOLS for e in recent)
    if has_shell and c in PERSISTENCE_TOOLS:
        return 45, (f"PERSISTENCE AFTER SHELL: '{c}' used after shell "
                    f"execution — possible persistence installation")

    # ── Pattern 4: Rapid child spawn (process storm / injection mimic) ───
    very_recent = [e for e in recent if now - e["ts"] < 5]
    if len(very_recent) >= 8 and p in SHELL_TOOLS:
        return 60, (f"PROCESS STORM: {len(very_recent)} processes spawned "
                    f"in 5 seconds from '{p}' — possible injection or dropper")

    # ── Pattern 5: Credential access sequence ────────────────────────────
    CRED_TOOLS = {"mimikatz.exe", "procdump.exe", "wce.exe", "ntdsutil.exe",
                  "vssadmin.exe", "esentutl.exe"}
    cred_recent = [e for e in recent if e["child"] in CRED_TOOLS
                   and now - e["ts"] < 300]
    if len(cred_recent) >= 2:
        return 70, (f"CREDENTIAL ACCESS CHAIN: {len(cred_recent)} credential "
                    f"tools used in last 5 minutes on this system")

    return 0, ""


def get_stats(system_id: str) -> dict:
    """Return sequence/frequency stats for dashboard."""
    with _freq_lock:
        total = _pair_totals.get(system_id, 0)
        pairs = dict(_pair_counts.get(system_id, {}))
    top_pairs = sorted(pairs.items(), key=lambda x: x[1], reverse=True)[:10]
    return {
        "total_events_tracked": total,
        "unique_pairs": len(pairs),
        "top_pairs": [{"parent": k[0], "child": k[1], "count": v}
                      for k, v in top_pairs],
    }

