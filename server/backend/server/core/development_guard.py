"""Explain suspicious development-tool descendants; never authorize OS actions."""
import json
import ntpath
import re
import time
from pathlib import Path

from server.config import RULES_DIR

TOOLS = {"code.exe", "cursor.exe", "windsurf.exe", "codex.exe", "claude.exe", "code", "cursor", "codex", "claude"}
_policy = {"workspaces": [], "approved_operations": []}


def load_policy(path=None):
    global _policy
    data = json.loads(Path(path or Path(RULES_DIR) / "development_policy.json").read_text(encoding="utf-8"))
    if not isinstance(data, dict) or set(data) != {"workspaces", "approved_operations"}:
        raise ValueError("Invalid development policy structure")
    for key in data:
        if not isinstance(data[key], list) or len(data[key]) > 1000:
            raise ValueError("Invalid development policy entries")
    for row in data["workspaces"]:
        if not isinstance(row, dict) or set(row) != {"system_id", "root"} or not all(isinstance(v, str) and v for v in row.values()) or not ntpath.isabs(row["root"]):
            raise ValueError("Workspace requires a host and absolute root")
    fields = {"id", "system_id", "cwd", "exe_path", "sha256", "cmdline", "expires_at"}
    for row in data["approved_operations"]:
        if not isinstance(row, dict) or set(row) != fields:
            raise ValueError("Approval must specify exact host, cwd, executable, hash, command and expiry")
        if not all(isinstance(row[k], str) and row[k] for k in fields - {"expires_at"}):
            raise ValueError("Approval strings must be nonempty")
        if not ntpath.isabs(row["cwd"]) or not ntpath.isabs(row["exe_path"]) or not re.fullmatch(r"[a-f0-9]{64}", row["sha256"]):
            raise ValueError("Invalid approval path or hash")
        if type(row["expires_at"]) not in (int, float) or not 0 < row["expires_at"] < 2**53:
            raise ValueError("Invalid approval expiry")
    _policy = data


def within(path, root):
    if not path or not ntpath.isabs(path):
        return False
    try:
        return ntpath.commonpath([ntpath.normcase(ntpath.normpath(path)), ntpath.normcase(ntpath.normpath(root))]) == ntpath.normcase(ntpath.normpath(root))
    except ValueError:
        return False


def evaluate(event):
    ancestry = event.get("ancestors", [])
    tool = next((a for a in ancestry if a["name"].lower() in TOOLS), None)
    if event.get("child", "").lower() in TOOLS:
        tool = {"name": event["child"], "pid": event["pid"], "create_time": event.get("create_time", 0)}
    result = {"version": 1, "tool": tool, "ancestry_status": event.get("ancestry_status", "unavailable"),
              "attribution": "agent-reported process ancestry; not proof of AI authorship",
              "approved_operation": None, "findings": [], "enforcement": "observe_only", "workspace_status": "not_assessed"}
    if not tool:
        return result
    now = time.time()
    for row in _policy["approved_operations"]:
        if row["expires_at"] > now and all(event.get(k) == row[k] for k in ("system_id", "cwd", "exe_path", "sha256", "cmdline")):
            result["approved_operation"] = row["id"]
            break
    command = event.get("cmdline", "").lower().replace("/", "\\")
    findings = result["findings"]
    def add(rule, score, reason):
        findings.append({"rule_id": rule, "score": score, "reason": reason, "evidence_type": "command_line"})
    # These are visible intent indicators, not proof that an operation succeeded.
    if any(marker in command for marker in (".ssh\\", ".aws\\credentials", ".azure\\", "id_rsa", "id_ed25519", "login data", "get-secret")):
        add("DEV-CREDENTIAL-REFERENCE", 65, "Command references credential storage; investigate access intent, not confirmed file access")
    if any(marker in command for marker in ("-disablerealtimemonitoring", "-disablebehaviormonitoring", "-exclusionpath", "-exclusionprocess", "advfirewall set allprofiles state off", "auditpol \\set")):
        add("DEV-SECURITY-CHANGE", 85, "Command contains a security configuration change indicator")
    if any(marker in command for marker in ("\\currentversion\\run", "schtasks \\create", "schtasks.exe \\create", "new-service", "register-scheduledtask")):
        add("DEV-PERSISTENCE", 75, "Command contains a startup or scheduled persistence indicator")
    if ("downloadstring" in command or "invoke-webrequest" in command or "curl " in command) and any(marker in command for marker in ("invoke-expression", "iex ", "| bash", "| sh", "| powershell")):
        add("DEV-DOWNLOAD-EXECUTE", 85, "Command combines downloading content with an execution indicator")
    if any(marker in command for marker in ("-verb runas", "start-process -verb runas", "sudo ")):
        add("DEV-ELEVATION", 65, "Command requests elevated execution; authorization is unknown")
    roots = [r["root"] for r in _policy["workspaces"] if r["system_id"] == event["system_id"]]
    result["workspace_status"] = ("unconfigured" if not roots else "unavailable" if not event.get("cwd") else
                                  "inside" if any(within(event["cwd"], root) for root in roots) else "outside")
    if roots and event.get("cwd") and not any(within(event["cwd"], root) for root in roots) and not result["approved_operation"]:
        findings.append({"rule_id": "DEV-OUTSIDE-WORKSPACE", "score": 45,
                         "reason": "Process working directory is outside configured workspaces; this does not prove an out-of-workspace write",
                         "evidence_type": "working_directory"})
    return result
