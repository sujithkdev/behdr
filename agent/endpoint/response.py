"""Explicit, identity-checked endpoint operations. No shell command execution."""
import hashlib
import os
import platform
import socket
import psutil

PROTECTED = {"system", "registry", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe", "svchost.exe", "msmpeng.exe"}


def execute(cmd):
    action, params = cmd.get("action"), cmd.get("params", {})
    if action == "collect_info":
        return {"hostname": socket.gethostname(), "platform": platform.platform(), "cpu_count": psutil.cpu_count(), "ram_bytes": psutil.virtual_memory().total}
    if action == "get_processes":
        return [p.info for p in psutil.process_iter(["pid", "name", "create_time"])][:100]
    if action == "get_network":
        return [{"pid": c.pid, "local": list(c.laddr), "remote": list(c.raddr), "status": c.status} for c in psutil.net_connections(kind="inet")][:100]
    if action != "kill_process":
        raise ValueError("Unsupported command")
    if set(params) != {"pid", "create_time", "sha256"}:
        raise ValueError("Full process identity required")
    pid = params["pid"]
    if type(pid) is not int or pid <= 4 or pid in {os.getpid(), os.getppid()}:
        raise ValueError("Protected or invalid PID")
    process = psutil.Process(pid)
    if process.name().lower() in PROTECTED:
        raise ValueError("Protected process")
    if process.create_time() != params["create_time"]:
        raise ValueError("PID was reused; creation time does not match")
    digest = hashlib.sha256()
    with open(process.exe(), "rb") as executable:
        for chunk in iter(lambda: executable.read(65536), b""):
            digest.update(chunk)
    if digest.hexdigest() != params["sha256"]:
        raise ValueError("Executable identity does not match")
    if not process.is_running() or process.create_time() != params["create_time"]:
        raise ValueError("Process identity changed")
    # psutil's kill method also checks PID reuse before signalling.
    process.kill()
    return {"status": "terminated", "pid": pid}
