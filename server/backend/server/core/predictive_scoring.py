# server/core/predictive_scoring.py — Predictive Threat Scoring Engine
"""
Tracks attack TTPs (Tactics, Techniques, Procedures) in progress and predicts
what the attacker will do next. Enables proactive response BEFORE damage is done.

Kill Chain Tracking:
  Recon → Weaponization → Delivery → Exploitation → Installation → C2 → Actions

Each stage detected raises alert level and predicts next likely action.

Priority 2 Enhancement #5 (from roadmap)
"""

import time, threading
from collections import defaultdict, deque
from typing import List, Tuple, Dict, Optional

# ── Configuration ─────────────────────────────────────────────────────────────
CHAIN_WINDOW = 3600         # Track chains within 1 hour window
MAX_CHAINS_PER_SYSTEM = 100 # Memory limit per endpoint
PREDICTION_CONFIDENCE_THRESHOLD = 0.7

# ── State ─────────────────────────────────────────────────────────────────────
_attack_chains: Dict[str, deque] = defaultdict(lambda: deque(maxlen=MAX_CHAINS_PER_SYSTEM))
_predictions: Dict[str, dict] = {}  # system_id → {predicted_stage, confidence, timestamp}
_lock = threading.Lock()


# ═════════════════════════════════════════════════════════════════════════════
# KILL CHAIN DEFINITIONS
# ═════════════════════════════════════════════════════════════════════════════

# MITRE ATT&CK Kill Chain stages and associated techniques
KILL_CHAIN_STAGES = {
    "reconnaissance": {
        "techniques": ["T1082", "T1083", "T1087", "T1069", "T1016", "T1033"],
        "keywords": ["whoami", "net user", "ipconfig", "systeminfo", "hostname", "net group", "query"],
        "processes": ["net.exe", "whoami.exe", "ipconfig.exe", "systeminfo.exe", "hostname.exe"],
        "next_likely": ["credential_access", "privilege_escalation"],
        "threat_level": "LOW",
    },
    "credential_access": {
        "techniques": ["T1003", "T1555", "T1552", "T1558"],
        "keywords": ["mimikatz", "sekurlsa", "lsadump", "sam", "ntds.dit", "logonpasswords"],
        "processes": ["procdump.exe", "reg.exe", "vssadmin.exe"],
        "next_likely": ["lateral_movement", "privilege_escalation"],
        "threat_level": "HIGH",
    },
    "privilege_escalation": {
        "techniques": ["T1055", "T1134", "T1068", "T1548"],
        "keywords": ["runas", "psexec", "bypass", "elevate"],
        "processes": ["psexec.exe", "runas.exe"],
        "next_likely": ["persistence", "lateral_movement"],
        "threat_level": "HIGH",
    },
    "persistence": {
        "techniques": ["T1053", "T1543", "T1547", "T1546"],
        "keywords": ["schtasks", "sc create", "reg add", "startup", "runonce"],
        "processes": ["schtasks.exe", "sc.exe", "reg.exe"],
        "next_likely": ["defense_evasion", "command_and_control"],
        "threat_level": "HIGH",
    },
    "defense_evasion": {
        "techniques": ["T1562", "T1070", "T1027", "T1140"],
        "keywords": ["disablerealtimemonitoring", "wevtutil", "clear", "del /f", "cipher"],
        "processes": ["wevtutil.exe", "cipher.exe"],
        "next_likely": ["command_and_control", "lateral_movement"],
        "threat_level": "CRITICAL",
    },
    "lateral_movement": {
        "techniques": ["T1021", "T1570", "T1563"],
        "keywords": ["psexec", "wmic", "rdp", "smb", "winrm"],
        "processes": ["psexec.exe", "wmic.exe", "mstsc.exe"],
        "next_likely": ["collection", "exfiltration"],
        "threat_level": "CRITICAL",
    },
    "command_and_control": {
        "techniques": ["T1071", "T1090", "T1095", "T1219"],
        "keywords": ["downloadstring", "webclient", "http", "https", "invoke-webrequest"],
        "processes": ["powershell.exe", "cmd.exe"],
        "next_likely": ["exfiltration", "impact"],
        "threat_level": "CRITICAL",
    },
    "collection": {
        "techniques": ["T1560", "T1039", "T1005"],
        "keywords": ["7z", "rar", "zip", "compress-archive", "copy"],
        "processes": ["7z.exe", "rar.exe", "xcopy.exe"],
        "next_likely": ["exfiltration"],
        "threat_level": "HIGH",
    },
    "exfiltration": {
        "techniques": ["T1048", "T1041", "T1567"],
        "keywords": ["ftp", "scp", "curl", "wget", "upload"],
        "processes": ["ftp.exe", "curl.exe", "pscp.exe"],
        "next_likely": ["impact"],
        "threat_level": "CRITICAL",
    },
    "impact": {
        "techniques": ["T1486", "T1490", "T1489", "T1491"],
        "keywords": ["vssadmin delete", "bcdedit", "cipher", "encrypt", "ransom"],
        "processes": ["vssadmin.exe", "bcdedit.exe", "cipher.exe"],
        "next_likely": [],  # End of chain
        "threat_level": "CRITICAL",
    },
}


# ═════════════════════════════════════════════════════════════════════════════
# STAGE CLASSIFICATION
# ═════════════════════════════════════════════════════════════════════════════

def classify_stage(event: dict, alert: dict) -> Optional[str]:
    """
    Classify which kill chain stage this event/alert belongs to.
    
    Uses:
      - MITRE technique ID from alert
      - Process name
      - Cmdline keywords
    
    Returns: stage name or None
    """
    # Check technique ID first (most reliable)
    technique = alert.get("technique", "")
    for stage, data in KILL_CHAIN_STAGES.items():
        if any(t in technique for t in data["techniques"]):
            return stage
    
    # Check process name
    process = event.get("child", "").lower()
    for stage, data in KILL_CHAIN_STAGES.items():
        if process in data["processes"]:
            return stage
    
    # Check cmdline keywords
    cmdline = event.get("cmdline", "").lower()
    for stage, data in KILL_CHAIN_STAGES.items():
        if any(kw in cmdline for kw in data["keywords"]):
            return stage
    
    return None


# ═════════════════════════════════════════════════════════════════════════════
# CHAIN TRACKING
# ═════════════════════════════════════════════════════════════════════════════

def record_stage(system_id: str, stage: str, event: dict, alert: dict):
    """
    Record that a kill chain stage was detected on this system.
    Updates attack chain and generates predictions.
    """
    if not stage:
        return
    
    now = time.time()
    
    with _lock:
        # Add to chain
        _attack_chains[system_id].append({
            "stage": stage,
            "timestamp": now,
            "process": event.get("child", ""),
            "technique": alert.get("technique", ""),
            "score": alert.get("risk_score", 0),
        })
        
        # Analyze chain and predict next stage
        chain = list(_attack_chains[system_id])
        prediction = _predict_next_stage(chain)
        
        if prediction:
            _predictions[system_id] = {
                "current_stage": stage,
                "predicted_stage": prediction["next_stage"],
                "confidence": prediction["confidence"],
                "threat_level": prediction["threat_level"],
                "timestamp": now,
                "chain_length": len(chain),
            }


def _predict_next_stage(chain: List[dict]) -> Optional[dict]:
    """
    Analyze attack chain and predict next likely stage.
    
    Returns:
      - next_stage: Predicted stage name
      - confidence: 0.0-1.0
      - threat_level: CRITICAL, HIGH, MEDIUM, LOW
    """
    if not chain:
        return None
    
    # Get recent stages (last hour)
    now = time.time()
    recent = [entry for entry in chain if now - entry["timestamp"] < CHAIN_WINDOW]
    
    if not recent:
        return None
    
    # Get unique stages seen
    stages_seen = {entry["stage"] for entry in recent}
    
    # Find the most recent stage
    latest = recent[-1]
    current_stage = latest["stage"]
    
    # Get next likely stages for current stage
    stage_data = KILL_CHAIN_STAGES.get(current_stage, {})
    next_likely = stage_data.get("next_likely", [])
    
    if not next_likely:
        return None  # End of chain or unknown stage
    
    # Calculate confidence based on chain progression
    # Higher confidence if we've seen earlier stages
    confidence = 0.5
    
    # Boost confidence for complete chain progressions
    chain_progression_patterns = [
        ["reconnaissance", "credential_access"],
        ["credential_access", "lateral_movement"],
        ["defense_evasion", "command_and_control"],
        ["collection", "exfiltration"],
    ]
    
    for pattern in chain_progression_patterns:
        if all(stage in stages_seen for stage in pattern):
            confidence += 0.15
    
    # Cap at 0.95
    confidence = min(confidence, 0.95)
    
    # Determine threat level (highest from next likely stages)
    threat_levels = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    max_threat_level = "LOW"
    for next_stage in next_likely:
        level = KILL_CHAIN_STAGES.get(next_stage, {}).get("threat_level", "LOW")
        if threat_levels.get(level, 0) > threat_levels.get(max_threat_level, 0):
            max_threat_level = level
    
    return {
        "next_stage": next_likely[0],  # Most likely
        "all_likely": next_likely,
        "confidence": confidence,
        "threat_level": max_threat_level,
    }


# ═════════════════════════════════════════════════════════════════════════════
# PREDICTION API
# ═════════════════════════════════════════════════════════════════════════════

def get_prediction(system_id: str) -> Optional[dict]:
    """
    Get active threat prediction for a system.
    
    Returns:
      - current_stage: Current attack stage
      - predicted_stage: Next likely stage
      - confidence: 0.0-1.0
      - threat_level: CRITICAL, HIGH, MEDIUM, LOW
      - recommended_actions: List of suggested responses
      - timestamp: When prediction was made
    """
    with _lock:
        pred = _predictions.get(system_id)
        
        if not pred:
            return None
        
        # Check if prediction is still recent (within chain window)
        if time.time() - pred["timestamp"] > CHAIN_WINDOW:
            return None
        
        # Add recommended actions based on predicted stage
        predicted_stage = pred["predicted_stage"]
        
        recommendations = _get_recommendations(predicted_stage)
        
        return {
            **pred,
            "recommended_actions": recommendations,
            "time_since_detection": int(time.time() - pred["timestamp"]),
        }


def _get_recommendations(predicted_stage: str) -> List[str]:
    """Get recommended actions for predicted stage."""
    recommendations = {
        "credential_access": [
            "Monitor for credential dumping tools (mimikatz, procdump)",
            "Watch for SAM/NTDS.dit access",
            "Alert on lsass.exe access attempts",
        ],
        "lateral_movement": [
            "Block SMB (445), RDP (3389) to sensitive systems",
            "Monitor for psexec.exe, wmic.exe execution",
            "Watch for remote service creation",
        ],
        "persistence": [
            "Monitor scheduled task creation (schtasks.exe)",
            "Watch for registry Run key modifications",
            "Alert on new service installations",
        ],
        "defense_evasion": [
            "Monitor for Windows Defender disable attempts",
            "Watch for event log clearing (wevtutil)",
            "Alert on PowerShell logging changes",
        ],
        "command_and_control": [
            "Block outbound connections to unknown IPs",
            "Monitor for beaconing patterns",
            "Watch for download cradles (DownloadString, IWR)",
        ],
        "exfiltration": [
            "Monitor large outbound data transfers",
            "Watch for compression tools (7z, rar)",
            "Alert on FTP/SCP/curl usage",
        ],
        "impact": [
            "CRITICAL: Block vssadmin.exe, bcdedit.exe immediately",
            "Isolate endpoint from network",
            "Take offline snapshot for forensics",
        ],
    }
    
    return recommendations.get(predicted_stage, ["Monitor system closely"])


def get_all_chains() -> Dict[str, List[dict]]:
    """Get all active attack chains across systems."""
    with _lock:
        result = {}
        now = time.time()
        
        for system_id, chain in _attack_chains.items():
            # Filter to recent entries
            recent = [entry for entry in chain if now - entry["timestamp"] < CHAIN_WINDOW]
            if recent:
                result[system_id] = recent
        
        return result


def get_system_chain(system_id: str) -> List[dict]:
    """Get attack chain for specific system."""
    with _lock:
        chain = _attack_chains.get(system_id, [])
        now = time.time()
        return [entry for entry in chain if now - entry["timestamp"] < CHAIN_WINDOW]


def clear_chain(system_id: str):
    """Clear attack chain for system (when incident is resolved)."""
    with _lock:
        if system_id in _attack_chains:
            _attack_chains[system_id].clear()
        if system_id in _predictions:
            del _predictions[system_id]


def get_stats() -> dict:
    """Return predictive scoring statistics."""
    with _lock:
        active_chains = sum(1 for chain in _attack_chains.values() if len(chain) > 0)
        active_predictions = len(_predictions)
        
        # Count by threat level
        threat_level_counts = defaultdict(int)
        for pred in _predictions.values():
            level = pred.get("threat_level", "UNKNOWN")
            threat_level_counts[level] += 1
        
        return {
            "systems_tracked": len(_attack_chains),
            "active_chains": active_chains,
            "active_predictions": active_predictions,
            "by_threat_level": dict(threat_level_counts),
            "chain_window_hours": CHAIN_WINDOW / 3600,
        }


# ═════════════════════════════════════════════════════════════════════════════
# INITIALIZATION
# ═════════════════════════════════════════════════════════════════════════════

def initialize():
    """Initialize predictive threat scoring."""
    print("[PREDICTIVE] Predictive threat scoring engine initialized")
    print(f"  Kill chain stages: {len(KILL_CHAIN_STAGES)}")
    print(f"  Tracking window: {CHAIN_WINDOW/3600:.1f} hours")
    print(f"  Pre-alert capability: Active")
