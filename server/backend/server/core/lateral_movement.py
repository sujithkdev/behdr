# server/core/lateral_movement.py — Enhanced Lateral Movement Detection
"""
PRIORITY 3 #8: Enhanced Lateral Movement Detection

Correlates events across ALL endpoints to detect attackers moving through the network.
Detects:
1. PsExec lateral movement (admin.exe spawns psexec → remote cmd.exe)
2. Pass-the-Hash attacks (NTLM relay, hash reuse)
3. Kerberos ticket abuse (Golden/Silver tickets, over-pass-the-hash)
4. WMI remote execution (wmic process call create)
5. PowerShell remoting (Enter-PSSession, Invoke-Command)
6. RDP chaining (attacker RDPs from A → B → C)

Cross-endpoint correlation:
- Timeline: Event A on Endpoint 1 → Event B on Endpoint 2 (within 30 seconds)
- Identity: Same username across multiple systems simultaneously
- Tool: Same malware hash appearing on multiple endpoints
- Campaign: Connected attack chain across 3+ systems
"""

import time
from collections import defaultdict, deque
from typing import List, Dict, Optional, Set, Tuple

# ── Cross-endpoint event tracking ─────────────────────────────────────────────

_lateral_events: List[dict] = []  # Chronological list of potential lateral movement events
_LATERAL_EVENTS_MAX = 5000  # Keep last 5000 events

_endpoint_connections: Dict[str, List[dict]] = defaultdict(list)  # system_id → [connections]
_ENDPOINT_CONN_MAX = 200  # Max connections per endpoint


# ── Event types that indicate lateral movement ────────────────────────────────

LATERAL_INDICATORS = {
    # Remote execution tools
    "psexec", "psexesvc", "paexec", "winexesvc",
    "psservice", "remcom",
    
    # Remote management
    "wmic", "wmiprvse", "winrm", "wsmprovhost",
    
    # PowerShell remoting
    "powershell -nop -w hidden", "invoke-command",
    "enter-pssession", "new-pssession",
    
    # RDP/Terminal Services
    "mstsc", "rdpclip", "tstheme",
    
    # Remote registry
    "reg.exe", "regedit",
    
    # Remote service creation
    "sc.exe", "services.exe",
}


def record_lateral_event(system_id: str, event_type: str, details: dict):
    """
    Record an event that may indicate lateral movement.
    
    Event types:
    - remote_exec: Remote command execution detected
    - smb_connection: SMB connection to admin share
    - rdp_connection: RDP session started
    - kerberos_ticket: Kerberos ticket request
    - ntlm_auth: NTLM authentication
    - wmi_exec: WMI remote execution
    - ps_remoting: PowerShell remoting
    """
    event = {
        "system_id": system_id,
        "event_type": event_type,
        "timestamp": int(time.time()),
        **details
    }
    
    _lateral_events.append(event)
    
    # Memory bound
    if len(_lateral_events) > _LATERAL_EVENTS_MAX:
        # Remove oldest 1000 events
        _lateral_events[:] = _lateral_events[-_LATERAL_EVENTS_MAX:]


def record_network_connection(system_id: str, dest_ip: str, dest_port: int, 
                              process: str, dest_system_id: str = ""):
    """
    Record outbound network connection that may be lateral movement.
    
    Tracks connections to other systems in the network for correlation.
    """
    conn = {
        "dest_ip": dest_ip,
        "dest_port": dest_port,
        "dest_system_id": dest_system_id,
        "process": process.lower(),
        "timestamp": int(time.time()),
    }
    
    _endpoint_connections[system_id].append(conn)
    
    # Memory bound
    if len(_endpoint_connections[system_id]) > _ENDPOINT_CONN_MAX:
        _endpoint_connections[system_id] = _endpoint_connections[system_id][-_ENDPOINT_CONN_MAX:]


# ── Detection: PsExec Lateral Movement ────────────────────────────────────────

def detect_psexec_lateral_movement(source_system: str, target_system: str, 
                                   username: str) -> Optional[dict]:
    """
    Detect PsExec-style lateral movement.
    
    Pattern:
    1. Source system: psexec.exe spawns → target: \\target_system
    2. Target system: (within 5 seconds) psexec service starts
    3. Target system: (within 10 seconds) cmd.exe/powershell spawned by psexec
    
    Correlation across 2 endpoints proves lateral movement.
    """
    now = int(time.time())
    
    # Find recent events on both systems
    recent_window = 30  # 30 seconds
    recent_events = [
        e for e in _lateral_events
        if now - e["timestamp"] < recent_window
        and e["system_id"] in (source_system, target_system)
    ]
    
    # Look for psexec pattern
    source_psexec = None
    target_service = None
    target_shell = None
    
    for event in recent_events:
        if event["system_id"] == source_system and event["event_type"] == "remote_exec":
            if "psexec" in event.get("process", "").lower():
                source_psexec = event
        
        if event["system_id"] == target_system:
            if event["event_type"] == "service_start" and "psexec" in event.get("service", "").lower():
                target_service = event
            
            if event["event_type"] == "process_create":
                parent = event.get("parent", "").lower()
                child = event.get("child", "").lower()
                if "psexec" in parent and child in ("cmd.exe", "powershell.exe"):
                    target_shell = event
    
    # All 3 components present = confirmed lateral movement
    if source_psexec and target_service and target_shell:
        return {
            "source_system": source_system,
            "target_system": target_system,
            "username": username,
            "risk_level": "CRITICAL",
            "risk_score": 95,
            "confidence": "HIGH",
            "reason": f"PsExec lateral movement: {source_system} → {target_system} (user: {username})",
            "technique": "T1021.002",  # Remote Services: SMB/Windows Admin Shares
            "attack_chain": [source_psexec, target_service, target_shell],
            "timestamp": now,
        }
    
    return None


# ── Detection: Pass-the-Hash ──────────────────────────────────────────────────

_ntlm_authentications: Dict[str, List[dict]] = defaultdict(list)  # username → [auth events]


def detect_pass_the_hash(username: str, source_system: str, target_system: str,
                        auth_package: str) -> Optional[dict]:
    """
    Detect Pass-the-Hash attacks.
    
    Indicators:
    - NTLM authentication (not Kerberos) to multiple systems
    - Same username authenticating from multiple sources simultaneously
    - Authentication without prior password login (hash reuse)
    - LM/NTLM v1 (old insecure protocols)
    """
    now = int(time.time())
    
    # Record this authentication
    auth_event = {
        "source_system": source_system,
        "target_system": target_system,
        "auth_package": auth_package.upper(),
        "timestamp": now,
    }
    
    _ntlm_authentications[username.lower()].append(auth_event)
    
    # Memory bound - keep last 100 auths per user
    if len(_ntlm_authentications[username.lower()]) > 100:
        _ntlm_authentications[username.lower()] = _ntlm_authentications[username.lower()][-100:]
    
    # Check for suspicious patterns
    recent_window = 300  # 5 minutes
    recent_auths = [
        a for a in _ntlm_authentications[username.lower()]
        if now - a["timestamp"] < recent_window
    ]
    
    # Pattern 1: Multiple NTLM authentications in short time
    ntlm_count = sum(1 for a in recent_auths if "NTLM" in a["auth_package"])
    
    if ntlm_count >= 5:  # 5+ NTLM auths in 5 minutes
        targets = set(a["target_system"] for a in recent_auths)
        
        return {
            "username": username,
            "source_system": source_system,
            "target_systems": list(targets),
            "risk_level": "CRITICAL",
            "risk_score": 92,
            "confidence": "HIGH",
            "reason": f"Pass-the-Hash: {username} NTLM auth to {len(targets)} systems in 5 minutes",
            "technique": "T1550.002",  # Use Alternate Authentication Material: Pass the Hash
            "timestamp": now,
        }
    
    # Pattern 2: NTLM v1 or LM authentication (insecure, rarely used legitimately)
    if auth_package.upper() in ("NTLM", "LM", "NTLM V1"):
        return {
            "username": username,
            "source_system": source_system,
            "target_system": target_system,
            "risk_level": "HIGH",
            "risk_score": 85,
            "confidence": "MEDIUM",
            "reason": f"Insecure auth protocol: {username} using {auth_package} ({source_system} → {target_system})",
            "technique": "T1550.002",
            "timestamp": now,
        }
    
    return None


# ── Detection: Kerberos Ticket Abuse ──────────────────────────────────────────

_kerberos_tickets: Dict[str, List[dict]] = defaultdict(list)  # username → [ticket requests]


def detect_kerberos_abuse(username: str, system_id: str, ticket_type: str,
                         service_name: str, encryption_type: str) -> Optional[dict]:
    """
    Detect Kerberos Golden/Silver ticket attacks and over-pass-the-hash.
    
    Indicators:
    - TGT with unusual lifetime (Golden Ticket = 10 years)
    - Unusual encryption type (RC4 instead of AES = downgrade attack)
    - TGS request without prior TGT request (Silver Ticket)
    - krbtgt service ticket (Golden Ticket forging)
    - Ticket requests from never-seen system
    """
    now = int(time.time())
    
    ticket_event = {
        "system_id": system_id,
        "ticket_type": ticket_type.upper(),  # TGT or TGS
        "service_name": service_name.lower(),
        "encryption_type": encryption_type.upper(),
        "timestamp": now,
    }
    
    _kerberos_tickets[username.lower()].append(ticket_event)
    
    # Memory bound
    if len(_kerberos_tickets[username.lower()]) > 100:
        _kerberos_tickets[username.lower()] = _kerberos_tickets[username.lower()][-100:]
    
    # Detection 1: Golden Ticket (krbtgt service)
    if "krbtgt" in service_name.lower():
        return {
            "username": username,
            "system_id": system_id,
            "risk_level": "CRITICAL",
            "risk_score": 98,
            "confidence": "HIGH",
            "reason": f"Golden Ticket: {username} requested krbtgt service ticket on {system_id}",
            "technique": "T1558.001",  # Steal or Forge Kerberos Tickets: Golden Ticket
            "timestamp": now,
        }
    
    # Detection 2: RC4 encryption (downgrade attack)
    if encryption_type.upper() in ("RC4", "RC4-HMAC", "ARCFOUR-HMAC-MD5"):
        return {
            "username": username,
            "system_id": system_id,
            "risk_level": "HIGH",
            "risk_score": 82,
            "confidence": "MEDIUM",
            "reason": f"Kerberos downgrade: {username} using RC4 encryption (likely forced downgrade)",
            "technique": "T1558",  # Steal or Forge Kerberos Tickets
            "timestamp": now,
        }
    
    # Detection 3: Silver Ticket (TGS without TGT)
    recent_window = 600  # 10 minutes
    recent_tickets = [
        t for t in _kerberos_tickets[username.lower()]
        if now - t["timestamp"] < recent_window and t["system_id"] == system_id
    ]
    
    has_tgt = any(t["ticket_type"] == "TGT" for t in recent_tickets)
    has_tgs = any(t["ticket_type"] == "TGS" for t in recent_tickets)
    
    if has_tgs and not has_tgt:  # TGS without prior TGT = forged ticket
        return {
            "username": username,
            "system_id": system_id,
            "risk_level": "CRITICAL",
            "risk_score": 94,
            "confidence": "HIGH",
            "reason": f"Silver Ticket: {username} TGS request without prior TGT on {system_id}",
            "technique": "T1558.002",  # Steal or Forge Kerberos Tickets: Silver Ticket
            "timestamp": now,
        }
    
    return None


# ── Detection: WMI Remote Execution ───────────────────────────────────────────

def detect_wmi_lateral_movement(source_system: str, target_system: str,
                                command: str, username: str) -> Optional[dict]:
    """
    Detect WMI-based lateral movement.
    
    Pattern:
    1. Source system: wmic.exe process call create
    2. Target system: wmiprvse.exe spawns suspicious process
    
    Common in APT campaigns and fileless malware.
    """
    now = int(time.time())
    
    # Look for correlated WMI events
    recent_window = 20  # 20 seconds
    recent_events = [
        e for e in _lateral_events
        if now - e["timestamp"] < recent_window
        and e["event_type"] == "wmi_exec"
    ]
    
    # Check for source→target correlation
    source_event = next(
        (e for e in recent_events 
         if e["system_id"] == source_system and e.get("target") == target_system),
        None
    )
    
    target_event = next(
        (e for e in recent_events
         if e["system_id"] == target_system and e.get("parent") == "wmiprvse.exe"),
        None
    )
    
    if source_event and target_event:
        return {
            "source_system": source_system,
            "target_system": target_system,
            "username": username,
            "risk_level": "CRITICAL",
            "risk_score": 93,
            "confidence": "HIGH",
            "reason": f"WMI lateral movement: {source_system} → {target_system} (command: {command[:50]})",
            "technique": "T1047",  # Windows Management Instrumentation
            "timestamp": now,
        }
    
    # Even without target correlation, WMI remote exec is suspicious
    if "process call create" in command.lower():
        return {
            "source_system": source_system,
            "target_system": target_system,
            "username": username,
            "risk_level": "HIGH",
            "risk_score": 80,
            "confidence": "MEDIUM",
            "reason": f"WMI remote execution attempt: {command[:60]}",
            "technique": "T1047",
            "timestamp": now,
        }
    
    return None


# ── Detection: PowerShell Remoting ────────────────────────────────────────────

def detect_powershell_remoting(source_system: str, target_system: str,
                               command: str, username: str) -> Optional[dict]:
    """
    Detect PowerShell remoting lateral movement.
    
    Commands:
    - Enter-PSSession -ComputerName target
    - Invoke-Command -ComputerName target -ScriptBlock {}
    - New-PSSession -ComputerName target
    
    Target system will show wsmprovhost.exe process.
    """
    cmd_lower = command.lower()
    
    ps_remoting_cmds = [
        "enter-pssession", "invoke-command", "new-pssession",
        "-computername", "wsmprovhost",
    ]
    
    if any(cmd in cmd_lower for cmd in ps_remoting_cmds):
        return {
            "source_system": source_system,
            "target_system": target_system,
            "username": username,
            "risk_level": "HIGH",
            "risk_score": 85,
            "confidence": "HIGH",
            "reason": f"PowerShell remoting: {source_system} → {target_system}",
            "technique": "T1021.006",  # Remote Services: Windows Remote Management
            "timestamp": int(time.time()),
        }
    
    return None


# ── Detection: RDP Chaining ───────────────────────────────────────────────────

_rdp_sessions: Dict[str, List[dict]] = defaultdict(list)  # username → [sessions]


def detect_rdp_chaining(username: str, source_ip: str, target_system: str) -> Optional[dict]:
    """
    Detect RDP chaining (attacker hops: A → B → C).
    
    Pattern:
    - User logs in via RDP to system B from A
    - Within minutes, same user RDPs from B to C
    - Chain continues: C → D → E
    
    Legitimate users rarely chain RDP sessions.
    """
    now = int(time.time())
    
    session = {
        "source_ip": source_ip,
        "target_system": target_system,
        "timestamp": now,
    }
    
    _rdp_sessions[username.lower()].append(session)
    
    # Memory bound
    if len(_rdp_sessions[username.lower()]) > 50:
        _rdp_sessions[username.lower()] = _rdp_sessions[username.lower()][-50:]
    
    # Look for chaining pattern
    recent_window = 600  # 10 minutes
    recent_sessions = [
        s for s in _rdp_sessions[username.lower()]
        if now - s["timestamp"] < recent_window
    ]
    
    # 3+ RDP sessions in 10 minutes = chaining
    if len(recent_sessions) >= 3:
        systems = [s["target_system"] for s in recent_sessions]
        
        return {
            "username": username,
            "systems": systems,
            "risk_level": "CRITICAL",
            "risk_score": 90,
            "confidence": "HIGH",
            "reason": f"RDP chaining: {username} hopped through {len(systems)} systems: {' → '.join(systems)}",
            "technique": "T1021.001",  # Remote Services: Remote Desktop Protocol
            "timestamp": now,
        }
    
    return None


# ── Correlation: Multi-System Attack Campaigns ────────────────────────────────

def detect_coordinated_attack(timeframe: int = 300) -> List[dict]:
    """
    Detect coordinated attacks across multiple endpoints.
    
    Looks for:
    - Same malware hash on 3+ systems within short time
    - Same C2 IP contacted by 3+ systems
    - Same username exhibiting malicious behavior on 3+ systems
    - Synchronized timing (attacks start within minutes)
    
    Returns list of detected campaigns.
    """
    now = int(time.time())
    campaigns = []
    
    recent_events = [
        e for e in _lateral_events
        if now - e["timestamp"] < timeframe
    ]
    
    if len(recent_events) < 10:  # Need sufficient events
        return []
    
    # Group by potential campaign identifiers
    by_malware_hash = defaultdict(set)
    by_c2_ip = defaultdict(set)
    by_username = defaultdict(set)
    
    for event in recent_events:
        system_id = event["system_id"]
        
        if "malware_hash" in event:
            by_malware_hash[event["malware_hash"]].add(system_id)
        
        if "c2_ip" in event:
            by_c2_ip[event["c2_ip"]].add(system_id)
        
        if "username" in event:
            by_username[event["username"]].add(system_id)
    
    # Campaign 1: Same malware on 3+ systems
    for malware_hash, systems in by_malware_hash.items():
        if len(systems) >= 3:
            campaigns.append({
                "campaign_type": "malware_spread",
                "identifier": malware_hash,
                "affected_systems": list(systems),
                "risk_level": "CRITICAL",
                "risk_score": 96,
                "confidence": "HIGH",
                "reason": f"Coordinated attack: Same malware on {len(systems)} systems",
                "technique": "T1570",  # Lateral Tool Transfer
                "timestamp": now,
            })
    
    # Campaign 2: Same C2 on 3+ systems
    for c2_ip, systems in by_c2_ip.items():
        if len(systems) >= 3:
            campaigns.append({
                "campaign_type": "c2_communication",
                "identifier": c2_ip,
                "affected_systems": list(systems),
                "risk_level": "CRITICAL",
                "risk_score": 94,
                "confidence": "HIGH",
                "reason": f"Coordinated attack: {len(systems)} systems contacting same C2: {c2_ip}",
                "technique": "T1071",  # Application Layer Protocol
                "timestamp": now,
            })
    
    # Campaign 3: Same compromised account on 3+ systems
    for username, systems in by_username.items():
        if len(systems) >= 4:  # Higher threshold for user activity
            campaigns.append({
                "campaign_type": "credential_reuse",
                "identifier": username,
                "affected_systems": list(systems),
                "risk_level": "CRITICAL",
                "risk_score": 91,
                "confidence": "MEDIUM",
                "reason": f"Coordinated attack: {username} active on {len(systems)} systems simultaneously",
                "technique": "T1078",  # Valid Accounts
                "timestamp": now,
            })
    
    return campaigns


# ── API: Get lateral movement timeline ────────────────────────────────────────

def get_lateral_movement_timeline(hours: int = 24) -> List[dict]:
    """Get timeline of lateral movement events for dashboard."""
    cutoff = int(time.time()) - (hours * 3600)
    
    return [
        e for e in _lateral_events
        if e["timestamp"] >= cutoff
    ]


def get_lateral_movement_stats() -> dict:
    """Get lateral movement statistics."""
    now = int(time.time())
    last_hour = [e for e in _lateral_events if now - e["timestamp"] < 3600]
    last_24h = [e for e in _lateral_events if now - e["timestamp"] < 86400]
    
    # Count by type
    types_1h = defaultdict(int)
    types_24h = defaultdict(int)
    
    for e in last_hour:
        types_1h[e["event_type"]] += 1
    
    for e in last_24h:
        types_24h[e["event_type"]] += 1
    
    # Affected systems
    systems_1h = set(e["system_id"] for e in last_hour)
    systems_24h = set(e["system_id"] for e in last_24h)
    
    return {
        "last_hour": {
            "total_events": len(last_hour),
            "by_type": dict(types_1h),
            "affected_systems": len(systems_1h),
        },
        "last_24_hours": {
            "total_events": len(last_24h),
            "by_type": dict(types_24h),
            "affected_systems": len(systems_24h),
        },
        "total_tracked_events": len(_lateral_events),
    }


# ── Initialize module ─────────────────────────────────────────────────────────

def initialize():
    """Initialize lateral movement detection module."""
    print("[LATERAL MOVEMENT] Enhanced lateral movement detection initialized")
    print("[LATERAL MOVEMENT] Correlating events across all endpoints")
    print("[LATERAL MOVEMENT] Detecting: PsExec, Pass-the-Hash, Kerberos abuse, "
          "WMI, PS Remoting, RDP chaining")
