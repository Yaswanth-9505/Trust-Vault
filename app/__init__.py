"""TrustVault application factory."""
import logging

from flask import Flask, jsonify, request, send_from_directory
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix

from . import audit
from .auth import csrf_protect, load_session
from .config import Config
from .db import close_db, connect, init_schema
from .errors import ApiError

log = logging.getLogger("trustvault")

CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
       "connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; "
       "frame-ancestors 'none'")


def create_app(config: Config | None = None) -> Flask:
    cfg = config or Config()
    app = Flask(__name__, static_folder="static", static_url_path="/static")
    app.config["TV"] = cfg
    app.config["MAX_CONTENT_LENGTH"] = cfg.MAX_UPLOAD_BYTES + 256 * 1024
    app.config["MAX_FORM_MEMORY_SIZE"] = 64 * 1024
    app.config["MAX_FORM_PARTS"] = 20
    app.config["JSON_SORT_KEYS"] = False
    app.config["TESTING"] = cfg.TESTING

    if cfg.TRUSTED_PROXIES:
        # Trust X-Forwarded-For / -Proto only from the number of proxies we
        # actually sit behind; otherwise a client could spoof its IP in the audit.
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=cfg.TRUSTED_PROXIES, x_proto=cfg.TRUSTED_PROXIES,
                                x_host=cfg.TRUSTED_PROXIES)

    # Create the schema on first start.
    db = connect(cfg.DATABASE_PATH)
    try:
        if db.execute("SELECT name FROM sqlite_master WHERE name='users'").fetchone() is None:
            init_schema(db)
    finally:
        db.close()

    app.before_request(load_session)
    app.before_request(csrf_protect)
    app.teardown_appcontext(close_db)

    from .routes import admin, auth_routes, documents, grants, users
    for bp in (auth_routes.bp, documents.bp, grants.bp, admin.bp, users.bp):
        app.register_blueprint(bp)

    @app.after_request
    def security_headers(resp):
        resp.headers.setdefault("Content-Security-Policy", CSP)
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        resp.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        if cfg.SECURE_COOKIES:
            resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        if request.path.startswith("/api/"):
            resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.errorhandler(ApiError)
    def handle_api_error(err: ApiError):
        audit.flush_deferred()
        return jsonify(error=err.code, message=err.message), err.status

    @app.errorhandler(HTTPException)
    def handle_http_error(err: HTTPException):
        if err.code == 413:
            return jsonify(error="too_large", message="The upload is too large."), 413
        return jsonify(error=err.name.lower().replace(" ", "_"), message=err.description), err.code

    @app.errorhandler(Exception)
    def handle_unexpected(err):
        log.exception("Unhandled error on %s %s", request.method, request.path)
        return jsonify(error="server_error", message="Something went wrong. It has been logged."), 500

    @app.get("/healthz")
    def health():
        return jsonify(status="ok")

    @app.get("/")
    def index():
        return send_from_directory(app.static_folder, "index.html")

    return app
