"""OWASP TwinLab Flask application factory."""

from __future__ import annotations

import os
import ipaddress
from pathlib import Path
from urllib.parse import urlsplit

from flask import Flask, abort, flash, g, jsonify, redirect, render_template, request, session, url_for

from . import db
from .lab_demo import LAB_DEMOS
from .lab_registry import LABS
from .workbench import ASSURANCE_ASSERTIONS, LAB_WORKBENCH, WORKBENCH_COMPONENTS


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY="OWASP-TWINLAB-DEMO-KEY-NOT-FOR-PRODUCTION",
        DATABASE=str(Path(app.instance_path) / "twinlab.sqlite3"),
        DEMO_HMAC_KEY=b"DEMO_ONLY_HMAC_KEY_A08_NOT_FOR_PRODUCTION",
        LAB_LOCAL_ONLY=True,
        LAB_ALLOW_CONTAINER_PROXY=os.environ.get("TWINLAB_ALLOW_CONTAINER_PROXY") == "1",
        LAB_RESET_ENABLED=True,
        LAB_OBSERVER_CAPABILITY="evidence-console",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
    )

    if test_config:
        app.config.update(test_config)

    os.makedirs(app.instance_path, exist_ok=True)
    db.init_app(app)

    from .modules.access_control import bp as access_control_bp
    from .modules.authentication import bp as authentication_bp
    from .modules.compact import bps as compact_bps
    from .modules.injection import bp as injection_bp
    from .modules.misconfiguration import bp as misconfiguration_bp
    from .observer import bp as observer_bp
    from .auditor import bp as auditor_bp

    app.register_blueprint(access_control_bp)
    app.register_blueprint(authentication_bp)
    for compact_bp in compact_bps:
        app.register_blueprint(compact_bp)
    app.register_blueprint(injection_bp)
    app.register_blueprint(misconfiguration_bp)
    app.register_blueprint(observer_bp)
    app.register_blueprint(auditor_bp)

    def is_loopback_request() -> bool:
        """Return True only for a directly connected IPv4/IPv6 loopback client."""

        try:
            return ipaddress.ip_address(request.remote_addr or "").is_loopback
        except ValueError:
            return False

    @app.before_request
    def enforce_local_lab_boundary() -> None:
        if not app.config["LAB_LOCAL_ONLY"]:
            return
        if is_loopback_request():
            return
        # Docker Compose is separately constrained by a 127.0.0.1 host-port
        # mapping. Its container sees the bridge gateway rather than loopback,
        # so that deployment must opt in explicitly.
        if app.config["LAB_ALLOW_CONTAINER_PROXY"]:
            return
        abort(403)

    @app.before_request
    def load_demo_actor() -> None:
        # The principal comes only from the signed Flask session fixture.
        # Caller-controlled headers must not be able to replace the identity
        # being evaluated by the access-control experiment.
        actor_name = session.get("demo_actor")
        if not actor_name:
            g.actor = None
            return
        g.actor = db.get_db().execute(
            "SELECT id, username, role FROM users WHERE username = ?", (actor_name,)
        ).fetchone()

    @app.context_processor
    def inject_global_context() -> dict:
        return {
            "labs": LABS,
            "lab_demos": LAB_DEMOS,
            "lab_workbench": LAB_WORKBENCH,
            "assurance_assertions": ASSURANCE_ASSERTIONS,
            "workbench_components": WORKBENCH_COMPONENTS,
            "current_actor": getattr(g, "actor", None),
            "local_only": app.config["LAB_LOCAL_ONLY"],
        }

    @app.get("/")
    def index():
        return render_template("index.html", title="Security Regression Workbench")

    def safe_local_next(requested_next: str, fallback: str) -> str:
        parsed_next = urlsplit(requested_next)
        if (
            parsed_next.scheme
            or parsed_next.netloc
            or not requested_next.startswith("/")
            or requested_next.startswith("//")
            or "\\" in requested_next
        ):
            return fallback
        return requested_next

    @app.post("/identity/<username>")
    def select_identity(username: str):
        user = db.get_db().execute(
            "SELECT username, role FROM users WHERE username = ?", (username,)
        ).fetchone()
        if user is None:
            abort(404)
        session["demo_actor"] = username
        if (
            request.args.get("format") == "json"
            or request.accept_mimetypes.best == "application/json"
        ):
            response = jsonify(
                {
                    "outcome": "server-side synthetic identity selected",
                    "actor": user["username"],
                    "role": user["role"],
                    "identity_source": "server_session",
                    "plane": "runner",
                }
            )
            response.headers["X-TwinLab-Plane"] = "runner"
            response.headers["Cache-Control"] = "no-store"
            return response
        requested_next = safe_local_next(request.form.get("next", ""), url_for("index"))
        response = redirect(requested_next)
        response.headers["X-TwinLab-Plane"] = "runner"
        return response

    @app.post("/identity-clear")
    def clear_identity():
        session.pop("demo_actor", None)
        if (
            request.args.get("format") == "json"
            or request.accept_mimetypes.best == "application/json"
        ):
            response = jsonify(
                {
                    "outcome": "synthetic identity context cleared",
                    "actor": None,
                    "identity_source": "server_session",
                    "plane": "runner",
                }
            )
            response.headers["X-TwinLab-Plane"] = "runner"
            response.headers["Cache-Control"] = "no-store"
            return response
        requested_next = safe_local_next(request.form.get("next", ""), url_for("index"))
        response = redirect(requested_next)
        response.headers["X-TwinLab-Plane"] = "runner"
        return response

    @app.post("/reset")
    def reset():
        if not app.config["LAB_RESET_ENABLED"] or not app.config["LAB_LOCAL_ONLY"]:
            abort(403)
        db.reset_database()
        session.clear()
        flash("Synthetic seed reset. Runtime sessions, events and state changes were cleared.")
        requested_next = safe_local_next(request.form.get("next", ""), url_for("index"))
        return redirect(requested_next)

    @app.get("/health")
    def health():
        return {"status": "ok", "scope": "localhost synthetic lab", "owasp_release": "2025"}

    return app
