"""Supported remote operations. Unsafe legacy actions are deliberately unavailable."""
import math
import re

READ_COMMANDS = {"collect_info", "get_processes", "get_network"}


def validate_command(action, params):
    if not isinstance(action, str):
        raise ValueError("action must be a string")
    if not isinstance(params, dict):
        raise ValueError("params must be an object")
    if action in READ_COMMANDS:
        if params:
            raise ValueError("This command takes no parameters")
        return
    if action != "kill_process":
        raise ValueError("Unsupported command; isolation and automatic response are disabled")
    if set(params) != {"pid", "create_time", "sha256"}:
        raise ValueError("kill_process requires exactly pid, create_time and sha256")
    pid, created, sha = params["pid"], params["create_time"], params["sha256"]
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 4 or pid >= 2**32:
        raise ValueError("Invalid process ID")
    if isinstance(created, bool) or not isinstance(created, (int, float)) or not math.isfinite(created) or created <= 0:
        raise ValueError("Invalid process creation time")
    if not isinstance(sha, str) or not re.fullmatch(r"[a-f0-9]{64}", sha):
        raise ValueError("A verified SHA-256 digest is required")
