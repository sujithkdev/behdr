# server/ratelimit.py — Per-identity sliding-window rate limiter
"""
Two rate-limit modes:

  rate_limit(endpoint, per_minute)
      Standard IP-based limiter for dashboard/auth endpoints.
      Key: (remote_addr, endpoint)

  rate_limit_agent(endpoint, per_minute)
      Agent endpoint limiter keyed on system_id extracted from the JSON body.
      Solves the NAT problem: all agents behind one corporate router share one
      external IP, so IP-based limiting would throttle all agents together.
      Falls back to IP if system_id is absent.

Both use a 1-minute sliding window backed by a plain dict with TTL eviction.
Zero external deps — pure Python stdlib.

Usage:
    @rate_limit("auth_login", per_minute=20)          # dashboard/auth
    @rate_limit_agent("events", per_minute=500)       # agent endpoints
"""
import time, threading
from functools import wraps
from flask import request, jsonify
from server.config import RATE_LIMIT_EVENTS, RATE_LIMIT_API

_buckets: dict = {}          # (identity_key, endpoint) → [hit_timestamps]
_lock = threading.Lock()
_WINDOW = 60.0               # 1-minute sliding window


def _check(identity: str, endpoint: str, limit: int) -> bool:
    """Return True if request is allowed, False if rate-limited."""
    key = (identity, endpoint)
    now = time.time()
    with _lock:
        if len(_buckets) >= 10000:
            stale = [k for k, v in _buckets.items() if not v or now - v[-1] >= _WINDOW]
            for old in stale:
                del _buckets[old]
            if key not in _buckets and len(_buckets) >= 10000:
                return False
        hits = _buckets.get(key, [])
        hits = [t for t in hits if now - t < _WINDOW]   # evict stale
        if len(hits) >= limit:
            _buckets[key] = hits
            return False
        hits.append(now)
        _buckets[key] = hits
        return True


def rate_limit(endpoint: str, per_minute: int = RATE_LIMIT_API):
    """
    IP-based rate limiter for dashboard/auth endpoints.
    Key: remote_addr — appropriate where all callers have distinct IPs.
    """
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            identity = request.remote_addr or "unknown"
            if not _check(identity, endpoint, per_minute):
                return jsonify({
                    "error":    "Rate limit exceeded",
                    "endpoint": endpoint,
                    "limit":    per_minute,
                    "window":   "60s",
                }), 429
            return f(*args, **kwargs)
        return wrapped
    return decorator


def rate_limit_agent(endpoint: str, per_minute: int = RATE_LIMIT_EVENTS):
    """
    system_id-based rate limiter for agent endpoints.

    Why not IP-based here:
      In enterprise environments all agents sit behind the same NAT gateway
      and share one external IP.  10 agents at 50 events/batch every 2 s
      = 250 req/s from one IP, instantly exhausting an IP-level 500/min limit.
      Keying on system_id gives each endpoint its own independent quota.

    Falls back to IP if system_id cannot be extracted from the request body,
    which prevents unauthenticated callers from bypassing limits with an
    empty body (they just get IP-bucketed instead).
    """
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            # Try to read system_id from the JSON body without consuming it.
            # Flask caches get_json() so calling it here is safe.
            identity = None
            try:
                body = request.get_json(silent=True, force=True) or {}
                if isinstance(body, dict):
                    # Events batch: {"events": [...]} — first item has system_id
                    if "system_id" in body:
                        identity = str(body["system_id"]).strip()
                    elif "events" in body and isinstance(body["events"], list):
                        first = body["events"][0] if body["events"] else {}
                        identity = str(first.get("system_id", "")).strip() or None
            except Exception:
                pass

            # Fall back to IP if system_id is missing/blank
            if not identity:
                identity = request.remote_addr or "unknown"

            if not _check(identity, endpoint, per_minute):
                return jsonify({
                    "error":    "Rate limit exceeded",
                    "endpoint": endpoint,
                    "identity": identity,
                    "limit":    per_minute,
                    "window":   "60s",
                }), 429
            return f(*args, **kwargs)
        return wrapped
    return decorator


# ── Background eviction of stale buckets (runs every 5 min) ──────────────────
def _evict():
    while True:
        time.sleep(300)
        now = time.time()
        with _lock:
            stale = [k for k, v in _buckets.items()
                     if not any(now - t < _WINDOW for t in v)]
            for k in stale:
                del _buckets[k]

