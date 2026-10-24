"""Database-backed identities, revocable sessions and host-bound agent tokens."""
import hashlib
import hmac
import re
import secrets
import sqlite3
import time
import uuid
from functools import wraps

import jwt
from flask import g, jsonify, request
from werkzeug.security import check_password_hash, generate_password_hash

from server.config import JWT_EXPIRY, JWT_SECRET
from server.database.storage import _conn, _write_lock

ROLES = {"viewer": 0, "analyst": 1, "admin": 2}


def init_auth():
    with _write_lock:
        _conn().executescript("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY, password TEXT NOT NULL,
                role TEXT NOT NULL, created INTEGER NOT NULL, version INTEGER NOT NULL DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS agent_credentials (
                system_id TEXT PRIMARY KEY, token_hash TEXT UNIQUE NOT NULL,
                created INTEGER NOT NULL, revoked INTEGER NOT NULL DEFAULT 0
            );
        """)

        c = _conn()
        if 'user_id' not in {r['name'] for r in c.execute('PRAGMA table_info(users)')}:
            c.execute('ALTER TABLE users ADD COLUMN user_id TEXT')
        for row in c.execute("SELECT username FROM users WHERE user_id IS NULL").fetchall():
            c.execute('UPDATE users SET user_id=? WHERE username=?', (uuid.uuid4().hex, row['username']))
        c.execute('CREATE UNIQUE INDEX IF NOT EXISTS user_identity ON users(user_id)')


def get_users():
    return {r["username"]: dict(r) for r in _conn().execute("SELECT * FROM users")}


def create_user(username, password, role="analyst"):
    if not isinstance(username, str) or not re.fullmatch(r"[A-Za-z0-9_.@-]{1,64}", username):
        raise ValueError("Invalid username")
    if not isinstance(role, str) or role not in ROLES or not isinstance(password, str) or not 14 <= len(password) <= 1024:
        raise ValueError("Use a valid role and a password of 14–1024 characters")
    hashed = generate_password_hash(password, method="scrypt")
    try:
        with _write_lock:
            _conn().execute("INSERT INTO users(username,password,role,created,user_id) VALUES(?,?,?,?,?)",
                            (username, hashed, role, int(time.time()), uuid.uuid4().hex))
        return True
    except sqlite3.IntegrityError:
        return False


def delete_user(username):
    with _write_lock:
        row = _conn().execute("SELECT role FROM users WHERE username=?", (username,)).fetchone()
        if not row:
            return False
        if row["role"] == "admin" and _conn().execute("SELECT COUNT(*) FROM users WHERE role='admin'").fetchone()[0] <= 1:
            return False
        return _conn().execute("DELETE FROM users WHERE username=?", (username,)).rowcount == 1


def authenticate(username, password):
    if not isinstance(username, str) or not isinstance(password, str) or len(password) > 1024:
        raise ValueError("Invalid credentials")
    row = _conn().execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if not row or not check_password_hash(row["password"], password):
        raise ValueError("Invalid credentials")
    now = int(time.time())
    claims = dict(sub=username, uid=row["user_id"], role=row["role"], ver=row["version"], iat=now,
                  exp=now + JWT_EXPIRY, iss="behedr", aud="dashboard", csrf=secrets.token_urlsafe(32))
    return row["role"], jwt.encode(claims, JWT_SECRET, algorithm="HS256")


def _decode_jwt(token):
    try:
        claims = jwt.decode(token, JWT_SECRET, algorithms=["HS256"], issuer="behedr", audience="dashboard",
                            options={"require": ["sub", "uid", "role", "ver", "iat", "exp", "csrf"]})
    except jwt.InvalidTokenError as exc:
        raise ValueError("Invalid or expired session") from exc
    row = _conn().execute("SELECT role,version,user_id FROM users WHERE username=?", (claims["sub"],)).fetchone()
    if not row or row["user_id"] != claims["uid"] or row["version"] != claims["ver"] or row["role"] != claims["role"]:
        raise ValueError("Session revoked")
    return claims


def revoke_sessions(username):
    with _write_lock:
        _conn().execute("UPDATE users SET version=version+1 WHERE username=?", (username,))


def require_jwt(min_role="viewer"):
    def decorate(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            auth = request.headers.get("Authorization", "")
            bearer = auth.startswith("Bearer ")
            token = auth[7:] if bearer else request.cookies.get("edr_session", "")
            try:
                claims = _decode_jwt(token)
            except ValueError:
                return jsonify(error="Authentication required"), 401
            if ROLES.get(claims["role"], -1) < ROLES[min_role]:
                return jsonify(error="Insufficient permissions"), 403
            if not bearer and request.method not in {"GET", "HEAD", "OPTIONS"}:
                if not hmac.compare_digest(request.headers.get("X-CSRF-Token", ""), claims["csrf"]):
                    return jsonify(error="Invalid CSRF token"), 403
            g.user, g.role, g.claims = claims["sub"], claims["role"], claims
            return fn(*args, **kwargs)
        return wrapped
    return decorate


def enroll_agent(system_id):
    from server.core.processor import valid_system_id
    if not valid_system_id(system_id):
        raise ValueError("Invalid system_id")
    token = secrets.token_urlsafe(48)
    with _write_lock:
        _conn().execute("""INSERT INTO agent_credentials VALUES(?,?,?,0)
            ON CONFLICT(system_id) DO UPDATE SET token_hash=excluded.token_hash,
            created=excluded.created,revoked=0""",
                        (system_id, hashlib.sha256(token.encode()).hexdigest(), int(time.time())))
    return token


def revoke_agent(system_id):
    with _write_lock:
        return _conn().execute("UPDATE agent_credentials SET revoked=1 WHERE system_id=?", (system_id,)).rowcount


def require_agent_key(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        digest = hashlib.sha256(request.headers.get("API-Key", "").encode()).hexdigest()
        row = _conn().execute("SELECT system_id FROM agent_credentials WHERE token_hash=? AND revoked=0", (digest,)).fetchone()
        if not row:
            return jsonify(error="Invalid agent credential"), 401
        g.agent_id = row["system_id"]
        if any(value != g.agent_id for key, value in kwargs.items() if key in {"system_id", "sid"}):
            return jsonify(error="Agent identity mismatch"), 403
        if request.method == "POST":
            body = request.get_json(silent=True)
            if not isinstance(body, dict):
                return jsonify(error="Expected a JSON object"), 400
            items = body.get("events", [body])
            if not isinstance(items, list) or not 1 <= len(items) <= 200:
                return jsonify(error="Expected 1–200 events"), 400
            if any(not isinstance(item, dict) or item.get("system_id") != g.agent_id for item in items):
                return jsonify(error="Agent identity mismatch"), 403
        return fn(*args, **kwargs)
    return wrapped
