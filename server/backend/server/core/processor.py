"""Validate process telemetry. Persistence owns deduplication after acceptance."""
import hashlib
import json
import math
import re
import time
from collections import deque

# Compatibility for the administrative cache-clear operation.
_seen_keys = set()
_seen_fifo = deque()


def valid_system_id(value):
    return isinstance(value, str) and bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", value))


def normalize(raw):
    if not isinstance(raw, dict) or not valid_system_id(raw.get("system_id")):
        raise ValueError("Invalid system_id")
    if raw.get("event") != "process_spawn":
        raise ValueError("Expected process_spawn")
    event = {"system_id": raw["system_id"], "event": "process_spawn"}
    for field in ("parent", "child"):
        value = raw.get(field)
        if not isinstance(value, str) or not value.strip() or len(value) > 260:
            raise ValueError(f"Invalid {field}")
        event[field] = value.strip().lower()
    for field in ("pid", "ppid"):
        value = raw.get(field, 0)
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 2**32:
            raise ValueError(f"Invalid {field}")
        event[field] = value
    for field in ("time", "create_time", "parent_create_time"):
        value = raw.get(field, 0)
        if isinstance(value, bool) or not isinstance(value, (float, int)) or not math.isfinite(value) or value < 0 or value > time.time() + 300:
            raise ValueError(f"Invalid {field}")
        event[field] = value
    if not event["time"]:
        raise ValueError("time required")
    for field, limit in (("cmdline", 16384), ("sha256", 64), ("exe_path", 4096), ("parent_exe_path", 4096), ("cwd", 4096), ("user", 256)):
        value = raw.get(field, "")
        if not isinstance(value, str) or len(value) > limit:
            raise ValueError(f"Invalid {field}")
        event[field] = value.strip()
    ancestors = raw.get("ancestors", [])
    if not isinstance(ancestors, list) or len(ancestors) > 8:
        raise ValueError("Invalid ancestors")
    event["ancestors"] = []
    seen = {event["pid"]}
    for ancestor in ancestors:
        if not isinstance(ancestor, dict):
            raise ValueError("Invalid ancestor")
        pid, created = ancestor.get("pid"), ancestor.get("create_time")
        if type(pid) is not int or not 0 < pid < 2**32 or pid in seen:
            raise ValueError("Invalid ancestor PID")
        if type(created) not in (int, float) or not math.isfinite(created) or not 0 < created <= time.time() + 300:
            raise ValueError("Invalid ancestor creation time")
        seen.add(pid)
        entry = {"pid": pid, "create_time": created}
        for key, bound in (("name", 260), ("exe_path", 4096)):
            value = ancestor.get(key, "")
            if not isinstance(value, str) or len(value) > bound:
                raise ValueError("Invalid ancestor text")
            entry[key] = value
        event["ancestors"].append(entry)
    if ancestors and (ancestors[0]["pid"] != event["ppid"] or ancestors[0]["create_time"] != event["parent_create_time"]):
        raise ValueError("Parent identity does not match ancestry")
    status = raw.get("ancestry_status", "unavailable")
    if status not in ("complete", "incomplete", "truncated", "unavailable"):
        raise ValueError("Invalid ancestry status")
    event["ancestry_status"] = status
    event["sha256"] = event["sha256"].lower()
    if event["sha256"] and not re.fullmatch(r"[a-f0-9]{64}", event["sha256"]):
        raise ValueError("Invalid sha256")
    identity = raw.get("event_id") or hashlib.sha256(json.dumps(event, sort_keys=True).encode()).hexdigest()
    if not isinstance(identity, str) or not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", identity):
        raise ValueError("Invalid event_id")
    event["event_id"] = identity
    for field, bound in (("source", 64), ("source_channel", 256), ("process_guid", 64), ("parent_process_guid", 64)):
        if field in raw:
            if not isinstance(raw[field], str) or len(raw[field]) > bound:
                raise ValueError(f"Invalid {field}")
            event[field] = raw[field]
    for field in ('source_record_id', 'source_event_id'):
        if field in raw:
            if type(raw[field]) is not int or raw[field] < 0:
                raise ValueError(f"Invalid {field}")
            event[field] = raw[field]
    if 'raw_source' in raw:
        if not isinstance(raw['raw_source'], dict):
            raise ValueError('Invalid raw_source')
        event['raw_source'] = raw['raw_source']
    if len(json.dumps(event, allow_nan=False).encode()) > 65536:
        raise ValueError('Event exceeds 64 KiB')
    return event


def validate(raw):
    try:
        normalize(raw)
        return True
    except ValueError:
        return False


def process(raw):
    try:
        return normalize(raw)
    except ValueError:
        return None
