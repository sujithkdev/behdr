"""Authenticated API for the supported single-server deployment."""
import json
import time

from flask import Blueprint, Response, g, jsonify, request, stream_with_context

from server import auth
from server.config import ENVIRONMENT, JWT_EXPIRY, OFFLINE_THRESHOLD
from server.database import storage as db
from server.ingestion import KINDS, accept, backlog, validate_event
from server.ratelimit import rate_limit

api_bp = Blueprint("api", __name__)


def body():
    return request.get_json()


def limit(default=100):
    value = int(request.args.get("limit", default))
    if not 1 <= value <= 1000:
        raise ValueError("limit must be between 1 and 1000")
    return value


@api_bp.post("/auth/login")
@rate_limit("login", per_minute=10)
def login():
    data = body()
    try:
        role, token = auth.authenticate(data.get("username"), data.get("password"))
    except ValueError:
        return jsonify(error="Invalid credentials"), 401
    claims = auth._decode_jwt(token)
    response = jsonify(username=claims["sub"], role=role, csrf=claims["csrf"])
    response.set_cookie("edr_session", token, max_age=JWT_EXPIRY, secure=ENVIRONMENT == "production", httponly=True, samesite="Strict")
    db.write_audit(claims["sub"], "login", "success", request.remote_addr)
    return response


@api_bp.get("/auth/me")
@auth.require_jwt()
def me():
    return jsonify(username=g.user, role=g.role, csrf=g.claims["csrf"])


@api_bp.post("/auth/logout")
@auth.require_jwt()
def logout():
    auth.revoke_sessions(g.user)
    response = jsonify(status="logged_out")
    response.delete_cookie("edr_session", secure=ENVIRONMENT == "production", httponly=True, samesite="Strict")
    return response


@api_bp.get("/auth/users")
@auth.require_jwt("admin")
def users():
    return jsonify(users=[{"username": key, "role": row["role"], "created": row["created"]} for key, row in auth.get_users().items()])


@api_bp.post("/auth/users")
@auth.require_jwt("admin")
def add_user():
    data = body()
    if not auth.create_user(data.get("username"), data.get("password"), data.get("role", "viewer")):
        return jsonify(error="User already exists"), 409
    db.write_audit(g.user, "create_user", data["username"], request.remote_addr)
    return jsonify(status="created"), 201


@api_bp.delete("/auth/users/<username>")
@auth.require_jwt("admin")
def delete_user(username):
    if not auth.delete_user(username):
        return jsonify(error="User not found or last administrator"), 409
    db.write_audit(g.user, "delete_user", username, request.remote_addr)
    return jsonify(status="deleted")


@api_bp.post("/api/agents/enroll")
@auth.require_jwt("admin")
def enroll():
    sid = body().get("system_id")
    token = auth.enroll_agent(sid)
    db.write_audit(g.user, "enroll_agent", sid, request.remote_addr)
    return jsonify(system_id=sid, token=token), 201


@api_bp.delete("/api/agents/<system_id>/credential")
@auth.require_jwt("admin")
def revoke(system_id):
    auth.revoke_agent(system_id)
    db.write_audit(g.user, "revoke_agent", system_id, request.remote_addr)
    return jsonify(status="revoked")


@api_bp.post("/register")
@auth.require_agent_key
def register():
    data = body()
    for key in ("hostname", "platform", "agent_ver"):
        if key in data and (not isinstance(data[key], str) or len(data[key]) > 256):
            raise ValueError(f"Invalid {key}")
    db.upsert_system({**data, "ip_address": request.remote_addr})
    return jsonify(status="registered")


@api_bp.post("/heartbeat")
@auth.require_agent_key
def heartbeat():
    health = body().get('collector_health')
    if health is not None:
        if not isinstance(health, dict):
            raise ValueError('Invalid collector_health')
        encoded = json.dumps(health, allow_nan=False)
        if len(encoded.encode()) > 8192:
            raise ValueError('Collector health exceeds 8 KiB')
        with db._write_lock:
            db._conn().execute('INSERT INTO collector_health VALUES(?,?,?) ON CONFLICT(system_id) DO UPDATE SET payload=excluded.payload,received=excluded.received',
                               (g.agent_id, encoded, time.time()))
    db.upsert_system({"system_id": g.agent_id, "ip_address": request.remote_addr})
    return jsonify(status="ok", ts=int(time.time()))


@auth.require_agent_key
def ingest():
    data = body()
    events = [validate_event(item, request.path) for item in data.get("events", [data])]
    try:
        accepted = accept(events)
    except OverflowError as exc:
        return jsonify(error=str(exc)), 503, {"Retry-After": "10"}
    return jsonify(status="accepted", accepted=accepted, processed=len(accepted))


for path in KINDS:
    api_bp.add_url_rule(path, endpoint="ingest_" + path[1:], view_func=ingest, methods=["POST"])


@api_bp.get("/commands/<system_id>")
@auth.require_agent_key
def commands(system_id):
    return jsonify(commands=db.get_pending_cmds(system_id))


@api_bp.post("/commands/result")
@auth.require_agent_key
def command_result():
    data = body()
    cid = data.get("id")
    if not isinstance(cid, str) or len(cid) != 32 or any(c not in "0123456789abcdef" for c in cid):
        raise ValueError("Invalid command ID")
    result = json.dumps(data.get("result", ""), allow_nan=False)
    if len(result) > 65536:
        raise ValueError("Command result exceeds 64 KiB")
    if not db.mark_cmd_done(cid, result, g.agent_id):
        return jsonify(error="Command not leased to this agent"), 404
    return jsonify(status="ok")


@api_bp.post("/api/command")
@auth.require_jwt("analyst")
@rate_limit("command", per_minute=30)
def command():
    from server.commands import validate_command
    data = body()
    sid, action, params = data.get("system_id"), data.get("action"), data.get("params", {})
    validate_command(action, params)
    if action == "kill_process" and g.role != "admin":
        return jsonify(error="Process termination requires an administrator"), 403
    if not db._conn().execute("SELECT 1 FROM agent_credentials WHERE system_id=? AND revoked=0", (sid,)).fetchone():
        raise ValueError("Agent is not enrolled")
    cid = db.queue_cmd(sid, action, params)
    db.write_audit(g.user, "command", json.dumps({"id": cid, **data}), request.remote_addr)
    return jsonify(status="queued", id=cid), 201


@api_bp.get("/api/commands")
@auth.require_jwt("analyst")
def command_history():
    return jsonify(commands=db.get_cmds(request.args.get("system_id"), limit()))


@api_bp.get("/api/status")
@auth.require_jwt()
def status():
    from server.core.hash_db import health_status
    from server.threatintel import health_status as ioc_health
    db.mark_stale(OFFLINE_THRESHOLD)
    collector_health = [{"system_id": r['system_id'], "received": r['received'], "sources": json.loads(r['payload'])}
                        for r in db._conn().execute('SELECT * FROM collector_health ORDER BY received DESC LIMIT 1000')]
    return jsonify(collector_health=collector_health, systems=db.get_systems_with_alert_counts(), alerts=db.get_alerts(100),
                   stats={**db.get_alert_stats(), "total_events": db.get_event_count(), "total_alerts": db.alert_count()},
                   backlog=backlog(), hash_intelligence=health_status(), ioc_intelligence=ioc_health(), capabilities={"automatic_response": False, "network_isolation": False,
                   "experimental_models": False, "deployment": "single-process", "notifications": False})


@api_bp.get('/api/operations')
@auth.require_jwt('admin')
def operations():
    from server.operations import report
    return jsonify(report())


@api_bp.get("/api/events")
@auth.require_jwt()
def events():
    return jsonify(events=db.get_events(limit(), request.args.get("system_id")))


@api_bp.get("/api/alerts")
@auth.require_jwt()
def alerts():
    return jsonify(alerts=db.get_alerts(limit(), request.args.get("system_id")))


@api_bp.get("/api/alerts/<int:alert_id>")
@auth.require_jwt()
def alert_detail(alert_id):
    alert = db.get_alert_by_id(alert_id)
    if not alert:
        return jsonify(error="Alert not found"), 404
    evidence = db._conn().execute("SELECT payload,assessment FROM telemetry WHERE system_id=? AND event_id=?",
                                  (alert["system_id"], alert["event_id"])).fetchone()
    return jsonify(alert=alert, evidence=json.loads(evidence[0]) if evidence else None,
                   assessment=json.loads(evidence[1]) if evidence else None,
                   development_assessment=json.loads(evidence[1]) if evidence else None)


@api_bp.get("/api/audit")
@auth.require_jwt("admin")
def audit():
    return jsonify(audit=db.get_audit(limit()))


@api_bp.get('/api/telemetry/<event_id>')
@auth.require_jwt()
def telemetry_detail(event_id):
    row = db._conn().execute('SELECT payload,assessment,status,received FROM telemetry WHERE system_id=? AND event_id=?',
                             (request.args.get('system_id', ''), event_id)).fetchone()
    if row is None:
        retired = db._conn().execute('SELECT retired FROM telemetry_tombstones WHERE system_id=? AND event_id=?',
                                    (request.args.get('system_id', ''), event_id)).fetchone()
        if retired:
            return jsonify(error='Telemetry retired by retention policy', retired_at=retired['retired']), 410
        return jsonify(error='Telemetry not found'), 404
    return jsonify(evidence=json.loads(row['payload']), assessment=json.loads(row['assessment']),
                   status=row['status'], received_at=row['received'])


@api_bp.get("/api/incidents")
@auth.require_jwt()
def incidents():
    from server.database.incidents import get_incidents
    return jsonify(incidents=get_incidents(request.args.get("status"), request.args.get("system_id"), limit()))


@api_bp.post("/api/incidents/<int:incident_id>/status")
@auth.require_jwt("analyst")
def incident_status(incident_id):
    from server.database.incidents import update_incident_status
    status = body().get("status")
    if status not in ("open", "investigating", "resolved", "false_positive"):
        raise ValueError("Invalid incident status")
    if not update_incident_status(incident_id, status, g.user):
        return jsonify(error="Incident not found"), 404
    db.write_audit(g.user, "incident_status", f"{incident_id}:{status}", request.remote_addr)
    return jsonify(status=status)


@api_bp.get("/api/graph/<system_id>")
@auth.require_jwt()
def graph(system_id):
    from server.core.graph import to_json
    return jsonify(to_json(system_id))


@api_bp.post("/api/alerts/<int:alert_id>/feedback")
@auth.require_jwt("analyst")
def feedback(alert_id):
    verdict, reason = body().get("verdict"), body().get("reason", "")
    if verdict not in ("true_positive", "false_positive") or not isinstance(reason, str) or len(reason) > 2000:
        raise ValueError("Invalid feedback")
    if not db.get_alert_by_id(alert_id):
        return jsonify(error="Alert not found"), 404
    with db._write_lock:
        c = db._conn()
        c.execute("BEGIN IMMEDIATE")
        try:
            c.execute("DELETE FROM alert_feedback WHERE alert_id=? AND username=?", (alert_id, g.user))
            c.execute("INSERT INTO alert_feedback(alert_id,verdict,username,reason,timestamp) VALUES(?,?,?,?,?)", (alert_id, verdict, g.user, reason, int(time.time())))
            c.commit()
        except Exception:
            c.rollback()
            raise
    db.write_audit(g.user, "feedback", f"{alert_id}:{verdict}", request.remote_addr)
    return jsonify(status="recorded", retraining=False)


@api_bp.get("/api/analysis/failures")
@auth.require_jwt("admin")
def failures():
    rows = db._conn().execute("SELECT id,system_id,event_id,attempts,error FROM telemetry WHERE status='failed' ORDER BY id LIMIT ?", (limit(),))
    return jsonify(failures=[dict(row) for row in rows])


@api_bp.post("/api/analysis/<int:job_id>/retry")
@auth.require_jwt("admin")
def retry(job_id):
    with db._write_lock:
        db._conn().execute("UPDATE telemetry SET status='pending',attempts=0,next_attempt=0 WHERE id=? AND status='failed'", (job_id,))
    db.write_audit(g.user, "retry_analysis", str(job_id), request.remote_addr)
    return jsonify(status="queued")


@api_bp.get("/health")
def health():
    return jsonify(status="ok")


@api_bp.get("/ready")
def ready():
    from server.core.recovery import STATE
    db._conn().execute("SELECT 1").fetchone()
    state = backlog()
    from server.ingestion import MAX_PENDING, worker_health
    from server.operations import storage_status
    healthy = STATE['state'] == 'ready' and state.get("pending", 0) < MAX_PENDING and storage_status()['available'] and worker_health()['healthy']
    return jsonify(status="ready" if healthy else "unavailable", recovery=STATE['state']), 200 if healthy else 503


@api_bp.get("/stream")
@auth.require_jwt()
def stream():
    # Every subscriber has its own persisted cursor. No credentials in URLs.
    cursor = int(request.headers.get("Last-Event-ID", request.args.get("after", 0)))
    username, version, expiry = g.user, g.claims["ver"], g.claims["exp"]
    def generate():
        nonlocal cursor
        # Bounded connection duration prevents endless consumption of WSGI threads.
        end = min(expiry, time.time() + 25)
        while time.time() < end:
            user = db._conn().execute("SELECT version FROM users WHERE username=?", (username,)).fetchone()
            if not user or user[0] != version:
                return
            rows = db._conn().execute("SELECT * FROM alerts WHERE id>? ORDER BY id LIMIT 100", (cursor,)).fetchall()
            for row in rows:
                cursor = row["id"]
                yield f"id: {cursor}\nevent: alert\ndata: {json.dumps(dict(row))}\n\n"
            if not rows:
                yield ": heartbeat\n\n"
                time.sleep(1)
    return Response(stream_with_context(generate()), mimetype="text/event-stream", headers={"X-Accel-Buffering": "no"})
