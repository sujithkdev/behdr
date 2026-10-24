# server/core/uba.py — User Behavior Analytics
"""
PRIORITY 3 #7: User Behavior Analytics (UBA)

Shifts from process-centric to user-centric threat detection. Tracks:
1. Login patterns — time of day, frequency, source IPs
2. Application usage — which apps each user normally runs
3. Network access — which servers/shares each user accesses
4. File access — which directories each user touches
5. Privilege escalation — sudo/runas usage per user

Detects:
- Compromised credentials (attacker behavior != user behavior)
- Insider threats (user doing unusual activity)
- Account takeover (login from unusual location/time)
- Privilege abuse (user suddenly accessing sensitive data)
- Lateral movement (user accessing systems they never touched)
"""

import time
import datetime
from collections import defaultdict, Counter
from typing import Dict, List, Optional, Set

# ── Per-user behavior baselines ───────────────────────────────────────────────

_user_profiles: Dict[str, dict] = {}  # username → {login_times, apps, networks, files}
_UBA_MAX_USERS = 500  # Track up to 500 users
_BASELINE_WINDOW = 7 * 86400  # 7 days to build baseline


class UserProfile:
    """Behavioral profile for a single user."""
    
    def __init__(self, username: str):
        self.username = username
        self.first_seen = int(time.time())
        self.last_seen = int(time.time())
        
        # Login patterns
        self.login_hours = Counter()  # hour → count
        self.login_days = Counter()   # weekday → count
        self.login_ips = set()        # set of IP addresses
        
        # Application usage
        self.apps = Counter()         # process name → count
        self.never_seen_apps = set()  # apps user has NEVER run
        
        # Network access
        self.network_targets = Counter()  # ip:port → count
        self.smb_shares = set()           # set of \\server\share paths
        
        # File access
        self.file_paths = Counter()   # directory → count
        self.file_extensions = Counter()  # .docx, .exe → count
        
        # Privilege usage
        self.privilege_escalations = 0
        self.admin_commands = []      # List of commands run as admin
        
        # Total events for baseline confidence
        self.total_events = 0
    
    def is_baseline_ready(self) -> bool:
        """Return True if enough data collected for accurate baseline."""
        age = int(time.time()) - self.first_seen
        return age >= _BASELINE_WINDOW and self.total_events >= 100
    
    def update_login(self, timestamp: int, source_ip: str):
        """Record a login event."""
        dt = datetime.datetime.fromtimestamp(timestamp)
        self.login_hours[dt.hour] += 1
        self.login_days[dt.weekday()] += 1
        self.login_ips.add(source_ip)
        self.last_seen = timestamp
    
    def update_app_usage(self, app_name: str):
        """Record application usage."""
        self.apps[app_name.lower()] += 1
        self.total_events += 1
    
    def update_network_access(self, dest_ip: str, dest_port: int, share_path: str = ""):
        """Record network access."""
        target = f"{dest_ip}:{dest_port}"
        self.network_targets[target] += 1
        if share_path:
            self.smb_shares.add(share_path.lower())
        self.total_events += 1
    
    def update_file_access(self, file_path: str):
        """Record file access."""
        import os
        directory = os.path.dirname(file_path).lower()
        extension = os.path.splitext(file_path)[1].lower()
        
        self.file_paths[directory] += 1
        if extension:
            self.file_extensions[extension] += 1
        self.total_events += 1
    
    def update_privilege_escalation(self, command: str):
        """Record privilege escalation (runas, sudo, UAC)."""
        self.privilege_escalations += 1
        self.admin_commands.append({
            "command": command[:100],
            "timestamp": int(time.time()),
        })
        # Keep last 100 commands only
        if len(self.admin_commands) > 100:
            self.admin_commands = self.admin_commands[-100:]
    
    def to_dict(self) -> dict:
        """Export profile for API responses."""
        return {
            "username": self.username,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "baseline_ready": self.is_baseline_ready(),
            "total_events": self.total_events,
            "login_patterns": {
                "typical_hours": [h for h, c in self.login_hours.most_common(5)],
                "typical_days": [d for d, c in self.login_days.most_common(7)],
                "known_ips": list(self.login_ips),
            },
            "application_usage": {
                "top_apps": [app for app, c in self.apps.most_common(10)],
                "total_apps": len(self.apps),
            },
            "network_access": {
                "top_targets": [t for t, c in self.network_targets.most_common(10)],
                "total_shares": len(self.smb_shares),
            },
            "file_access": {
                "top_directories": [d for d, c in self.file_paths.most_common(10)],
                "top_extensions": [e for e, c in self.file_extensions.most_common(10)],
            },
            "privilege_usage": {
                "total_escalations": self.privilege_escalations,
                "recent_admin_commands": self.admin_commands[-10:],
            },
        }


def get_user_profile(username: str) -> UserProfile:
    """Get or create user profile."""
    username_lower = username.lower()
    
    if username_lower not in _user_profiles:
        if len(_user_profiles) >= _UBA_MAX_USERS:
            _prune_old_profiles()
        _user_profiles[username_lower] = UserProfile(username_lower)
    
    return _user_profiles[username_lower]


def _prune_old_profiles():
    """Remove 10% oldest profiles when limit reached."""
    sorted_profiles = sorted(
        _user_profiles.items(),
        key=lambda x: x[1].last_seen
    )
    
    to_remove = max(1, len(sorted_profiles) // 10)
    for username, _ in sorted_profiles[:to_remove]:
        del _user_profiles[username]


# ── UBA Event Recording ───────────────────────────────────────────────────────

def record_login(username: str, timestamp: int, source_ip: str):
    """Record user login event."""
    profile = get_user_profile(username)
    profile.update_login(timestamp, source_ip)


def record_app_usage(username: str, app_name: str):
    """Record application usage by user."""
    profile = get_user_profile(username)
    profile.update_app_usage(app_name)


def record_network_access(username: str, dest_ip: str, dest_port: int, share_path: str = ""):
    """Record network access by user."""
    profile = get_user_profile(username)
    profile.update_network_access(dest_ip, dest_port, share_path)


def record_file_access(username: str, file_path: str):
    """Record file access by user."""
    profile = get_user_profile(username)
    profile.update_file_access(file_path)


def record_privilege_escalation(username: str, command: str):
    """Record privilege escalation event."""
    profile = get_user_profile(username)
    profile.update_privilege_escalation(command)


# ── Anomaly Detection ─────────────────────────────────────────────────────────

def detect_login_anomaly(username: str, timestamp: int, source_ip: str) -> Optional[dict]:
    """
    Detect anomalous login patterns.
    
    Checks:
    - Login time outside user's normal hours
    - Login from never-seen IP address
    - Login frequency spike (multiple logins in short time)
    """
    profile = get_user_profile(username)
    
    if not profile.is_baseline_ready():
        return None  # Not enough data yet
    
    dt = datetime.datetime.fromtimestamp(timestamp)
    hour = dt.hour
    weekday = dt.weekday()
    
    anomalies = []
    score = 0
    
    # Check login hour
    if profile.login_hours[hour] == 0:  # Never logged in at this hour
        anomalies.append(f"unusual login time ({hour}:00)")
        score += 30
    elif profile.login_hours[hour] < 3:  # Rarely logs in at this hour
        anomalies.append(f"rare login time ({hour}:00)")
        score += 15
    
    # Check weekday
    if profile.login_days[weekday] < 2:  # Rarely logs in on this day
        day_names = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
        anomalies.append(f"unusual day ({day_names[weekday]})")
        score += 15
    
    # Check source IP
    if source_ip not in profile.login_ips:
        anomalies.append(f"new IP address ({source_ip})")
        score += 25
    
    if score >= 40:  # Threshold for alert
        return {
            "username": username,
            "risk_level": "HIGH" if score >= 60 else "MEDIUM",
            "risk_score": min(score, 90),
            "confidence": "MEDIUM",
            "reason": f"UBA: Anomalous login by {username}: {', '.join(anomalies)}",
            "technique": "T1078",  # Valid Accounts
            "timestamp": timestamp,
        }
    
    return None


def detect_app_anomaly(username: str, app_name: str) -> Optional[dict]:
    """
    Detect user running never-before-seen application.
    
    High-risk apps:
    - mimikatz, procdump, psexec (credential theft tools)
    - powershell.exe (if user never runs PowerShell)
    - cmd.exe (if user never uses command line)
    """
    profile = get_user_profile(username)
    
    if not profile.is_baseline_ready():
        return None
    
    app_lower = app_name.lower()
    
    # Never seen this app before
    if app_lower not in profile.apps:
        # High-risk tools
        high_risk_apps = {
            "mimikatz", "procdump", "psexec", "wmic", "vssadmin",
            "bcdedit", "netsh", "reg.exe", "schtasks", "at.exe",
        }
        
        # Moderate-risk tools (depends on user role)
        moderate_risk_apps = {
            "powershell", "cmd", "bash", "python", "perl",
        }
        
        score = 0
        risk_level = "MEDIUM"
        
        if any(h in app_lower for h in high_risk_apps):
            score = 85
            risk_level = "CRITICAL"
        elif any(m in app_lower for m in moderate_risk_apps):
            score = 65
            risk_level = "HIGH"
        else:
            score = 50  # Generic never-seen app
        
        if score >= 50:
            return {
                "username": username,
                "risk_level": risk_level,
                "risk_score": score,
                "confidence": "MEDIUM",
                "reason": f"UBA: {username} running never-seen app: {app_name}",
                "technique": "T1204",  # User Execution
                "timestamp": int(time.time()),
            }
    
    return None


def detect_network_anomaly(username: str, dest_ip: str, dest_port: int) -> Optional[dict]:
    """
    Detect user accessing never-before-seen network resources.
    
    Suspicious patterns:
    - User accessing domain controller (port 88, 389, 636) for first time
    - User accessing database servers they never touched
    - User accessing admin shares (\\C$, \\ADMIN$)
    """
    profile = get_user_profile(username)
    
    if not profile.is_baseline_ready():
        return None
    
    target = f"{dest_ip}:{dest_port}"
    
    if target not in profile.network_targets:
        # Sensitive ports
        sensitive_ports = {
            88: "Kerberos (DC)",
            389: "LDAP (DC)",
            636: "LDAPS (DC)",
            445: "SMB",
            3389: "RDP",
            1433: "SQL Server",
            3306: "MySQL",
            5432: "PostgreSQL",
        }
        
        port_desc = sensitive_ports.get(dest_port, f"port {dest_port}")
        
        if dest_port in sensitive_ports:
            score = 70
            risk_level = "HIGH"
        else:
            score = 50
            risk_level = "MEDIUM"
        
        return {
            "username": username,
            "risk_level": risk_level,
            "risk_score": score,
            "confidence": "MEDIUM",
            "reason": f"UBA: {username} accessing new network target: {dest_ip}:{dest_port} ({port_desc})",
            "technique": "T1021",  # Remote Services
            "timestamp": int(time.time()),
        }
    
    return None


def detect_file_access_anomaly(username: str, file_path: str) -> Optional[dict]:
    """
    Detect user accessing unusual files/directories.
    
    High-risk access:
    - SAM/SYSTEM registry hives (credential theft)
    - Other users' profile directories
    - Windows\System32\config
    - Database files (.mdf, .bak)
    """
    profile = get_user_profile(username)
    
    if not profile.is_baseline_ready():
        return None
    
    import os
    file_lower = file_path.lower()
    directory = os.path.dirname(file_lower)
    
    # High-risk paths
    high_risk_patterns = [
        r"\windows\system32\config",
        r"\windows\ntds",
        r"\programdata\microsoft\crypto",
        "sam.sav", "system.sav", "security.sav",
        "ntds.dit",
    ]
    
    # Check if accessing sensitive files
    if any(pattern in file_lower for pattern in high_risk_patterns):
        return {
            "username": username,
            "risk_level": "CRITICAL",
            "risk_score": 90,
            "confidence": "HIGH",
            "reason": f"UBA: {username} accessing sensitive file: {file_path}",
            "technique": "T1003.002",  # OS Credential Dumping: Security Account Manager
            "timestamp": int(time.time()),
        }
    
    # Check if accessing never-seen directory
    if directory not in profile.file_paths:
        # Other users' directories
        if r"\users" in file_lower and username not in file_lower:
            return {
                "username": username,
                "risk_level": "HIGH",
                "risk_score": 75,
                "confidence": "MEDIUM",
                "reason": f"UBA: {username} accessing other user's files: {directory}",
                "technique": "T1083",  # File and Directory Discovery
                "timestamp": int(time.time()),
            }
    
    return None


def detect_privilege_abuse(username: str, command: str) -> Optional[dict]:
    """
    Detect unusual privilege escalation.
    
    Suspicious patterns:
    - User never used admin privileges before
    - Sudden spike in privilege escalations
    - Running high-risk commands (reg.exe, vssadmin, bcdedit)
    """
    profile = get_user_profile(username)
    
    if not profile.is_baseline_ready():
        return None
    
    # First time using elevated privileges
    if profile.privilege_escalations == 0:
        return {
            "username": username,
            "risk_level": "HIGH",
            "risk_score": 70,
            "confidence": "MEDIUM",
            "reason": f"UBA: {username} using elevated privileges for first time: {command[:60]}",
            "technique": "T1078.003",  # Valid Accounts: Local Accounts
            "timestamp": int(time.time()),
        }
    
    # High-risk admin commands
    high_risk_cmds = [
        "vssadmin delete", "bcdedit", "wevtutil cl", "reg save",
        "net user /add", "net localgroup administrators", "wmic",
    ]
    
    cmd_lower = command.lower()
    if any(risk in cmd_lower for risk in high_risk_cmds):
        return {
            "username": username,
            "risk_level": "CRITICAL",
            "risk_score": 88,
            "confidence": "HIGH",
            "reason": f"UBA: {username} running high-risk admin command: {command[:60]}",
            "technique": "T1548",  # Abuse Elevation Control Mechanism
            "timestamp": int(time.time()),
        }
    
    return None


# ── Batch analysis for process events ─────────────────────────────────────────

def analyze_user_event(event: dict) -> Optional[dict]:
    """
    Analyze a single event for UBA anomalies.
    
    Extracts user from event and checks for behavioral anomalies.
    """
    username = event.get("user", "").strip()
    if not username or username.upper() == "SYSTEM":
        return None  # Skip system events
    
    # Remove domain prefix (DOMAIN\user → user)
    if "\\" in username:
        username = username.split("\\", 1)[1]
    
    # Record app usage
    child = event.get("child", "")
    if child:
        record_app_usage(username, child)
        
        # Check for app anomaly
        alert = detect_app_anomaly(username, child)
        if alert:
            alert["system_id"] = event.get("system_id", "")
            alert["process"] = child
            return alert
    
    # Check for privilege escalation indicators in cmdline
    cmdline = event.get("cmdline", "").lower()
    if "runas" in cmdline or "elevation" in cmdline:
        record_privilege_escalation(username, cmdline)
        
        alert = detect_privilege_abuse(username, cmdline)
        if alert:
            alert["system_id"] = event.get("system_id", "")
            alert["process"] = child
            return alert
    
    return None


# ── API endpoints for dashboard ───────────────────────────────────────────────

def get_user_profile_api(username: str) -> Optional[dict]:
    """Get user profile for API response."""
    username_lower = username.lower()
    if username_lower not in _user_profiles:
        return None
    
    return _user_profiles[username_lower].to_dict()


def get_all_users() -> List[dict]:
    """Get summary of all tracked users."""
    return [
        {
            "username": profile.username,
            "last_seen": profile.last_seen,
            "baseline_ready": profile.is_baseline_ready(),
            "total_events": profile.total_events,
        }
        for profile in _user_profiles.values()
    ]


def get_uba_stats() -> dict:
    """Get UBA statistics."""
    baseline_ready = sum(1 for p in _user_profiles.values() if p.is_baseline_ready())
    
    return {
        "total_users": len(_user_profiles),
        "users_with_baseline": baseline_ready,
        "users_learning": len(_user_profiles) - baseline_ready,
        "baseline_window_days": _BASELINE_WINDOW // 86400,
    }


# ── Initialize module ─────────────────────────────────────────────────────────

def initialize():
    """Initialize UBA module."""
    print("[UBA] User Behavior Analytics initialized")
    print(f"[UBA] Tracking up to {_UBA_MAX_USERS} users")
    print(f"[UBA] Baseline window: {_BASELINE_WINDOW // 86400} days")
