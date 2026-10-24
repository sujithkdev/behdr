"""Application factory. Use one process: detection context is held in memory."""
import logging

from flask import Flask, jsonify, request
from werkzeug.exceptions import HTTPException

from server.config import BACKGROUND_ENABLED, ENVIRONMENT, JWT_SECRET, validate_configuration


def create_app():
    validate_configuration()
    app = Flask(__name__)
    app.config.update(SECRET_KEY=JWT_SECRET, MAX_CONTENT_LENGTH=2 * 1024 * 1024,
                      SESSION_COOKIE_SECURE=ENVIRONMENT == "production")
    from server.database.storage import init_db
    from server.auth import init_auth
    from server.ingestion import init_inbox, start_worker
    from server.core.detector import initialize
    init_db()
    init_auth()
    init_inbox()
    initialize()
    from server.core.sigma_subset import load_catalog
    load_catalog()
    from server.core import detector
    from server.core.recovery import restore
    restore(detector._file_rules)
    from server.core.development_guard import load_policy
    load_policy()
    from server.threatintel import load_iocs
    load_iocs()
    from server.routes.api import api_bp
    from server.routes.dashboard import dash_bp
    app.register_blueprint(api_bp)
    app.register_blueprint(dash_bp)

    @app.before_request
    def validate_json():
        if request.method in {"POST", "PUT", "PATCH"}:
            if not request.is_json or not isinstance(request.get_json(silent=True), dict):
                return jsonify(error="Expected a JSON object"), 400

    @app.after_request
    def headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.errorhandler(ValueError)
    def bad_input(exc):
        return jsonify(error=str(exc)), 400

    @app.errorhandler(Exception)
    def server_error(exc):
        if isinstance(exc, HTTPException):
            return jsonify(error=exc.name), exc.code
        logging.getLogger(__name__).exception("Request failed")
        return jsonify(error="Internal server error"), 500

    if BACKGROUND_ENABLED:
        start_worker()
    return app
