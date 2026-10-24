"""Best-effort process ancestry without reading ancestor arguments or secrets."""
import psutil


def capture(proc):
    result = {"cwd": "", "ancestors": [], "ancestry_status": "complete"}
    try:
        result["cwd"] = proc.cwd()
    except (psutil.Error, OSError):
        pass
    current, seen = proc, {proc.pid}
    try:
        for _ in range(8):
            parent = current.parent()
            if parent is None:
                return result
            if parent.pid in seen:
                result["ancestry_status"] = "incomplete"
                return result
            seen.add(parent.pid)
            with parent.oneshot():
                result["ancestors"].append({"pid": parent.pid, "create_time": parent.create_time(),
                                            "name": parent.name(), "exe_path": parent.exe()})
            current = parent
        result["ancestry_status"] = "truncated"
    except (psutil.Error, OSError):
        result["ancestry_status"] = "incomplete"
    return result
