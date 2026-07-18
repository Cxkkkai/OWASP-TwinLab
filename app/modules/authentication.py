from __future__ import annotations

import hashlib
import secrets
import time

from flask import Blueprint, current_app, make_response, render_template, request

from app.db import get_db, verify_demo_password
from app.lab_registry import LAB_BY_ID
from app.observer import observer_capability_required

from .common import lab_response


bp = Blueprint("a07", __name__, url_prefix="/lab/a07")
LAB = LAB_BY_ID["a07"]
COOKIE_NAME = "lab_session"
SESSION_VARIANTS = {"vulnerable", "candidate", "secure"}


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _extract_token() -> str | None:
    return request.headers.get("X-Lab-Session") or request.cookies.get(COOKIE_NAME)


@bp.get("/")
def overview():
    return render_template(
        "module.html",
        title=f"{LAB['owasp']} {LAB['name']}",
        lab=LAB,
        weakness="Session replay after incomplete logout",
        actor="Attacker who already captured one pre-logout admin token",
        asset="Admin identity and privileged dashboard",
        attack="Save the displayed lab token, log out, then replay it in X-Lab-Session.",
        root_cause="The vulnerable logout clears only the browser cookie; server state stays active.",
        control="Revoke the server-side session and validate active/expiry on every protected request.",
        vulnerable_url="/lab/a07/vulnerable/login",
        secure_url="/lab/a07/secure/login",
        legitimate_url="/lab/a07/secure/login",
        vulnerable_method="POST",
        secure_method="POST",
        legitimate_method="POST",
        vulnerable_fields={},
        secure_fields={},
        legitimate_fields={"username": "admin", "password": "demo-admin"},
        vulnerable_label="Run vulnerable logout-and-replay flow",
        secure_label="Run secure revocation-and-replay flow",
        legitimate_label="Create a fresh secure Admin session",
        setup_url=None,
        test_contract=[
            "V-positive: a fresh admin token reaches the dashboard.",
            "V-security: the old token still works after vulnerable logout.",
            "S-security: secure logout permanently revokes the old token.",
            "S-positive: a new secure login creates a different valid token.",
        ],
        extra_note="The browser now performs each login, logout and replay request separately. Only a short fingerprint is displayed; the full synthetic token remains in browser memory for the next request.",
    )


def _issue_session(user, variant: str) -> str:
    token = secrets.token_urlsafe(24)
    now = int(time.time())
    db = get_db()
    db.execute(
        "INSERT INTO sessions (token_hash, user_id, variant, active, expires_at, created_at) VALUES (?, ?, ?, 1, ?, ?)",
        (_hash_token(token), user["id"], variant, now + 900, now),
    )
    db.commit()
    return token


@bp.post("/<variant>/login")
def login(variant: str):
    if variant not in SESSION_VARIANTS:
        return lab_response(lab=LAB, variant=variant, outcome="unknown variant", data={}, status=404)
    username = request.values.get("username", "admin")
    password = request.values.get("password", "demo-admin")
    user = get_db().execute(
        "SELECT id, username, role, password_hash FROM users WHERE username = ?", (username,)
    ).fetchone()
    if user is None or not verify_demo_password(user["password_hash"], password):
        return lab_response(lab=LAB, variant=variant, outcome="invalid credentials", data={}, status=401)

    token = _issue_session(user, variant)
    response = make_response(
        lab_response(
            lab=LAB,
            variant=variant,
            outcome="fresh server-side session created",
            data={
                "username": user["username"],
                "role": user["role"],
                "lab_token": token,
                "expires_in_seconds": 900,
                "token_display_warning": "Shown only so this local replay experiment is reproducible.",
            },
        )
    )
    response.set_cookie(COOKIE_NAME, token, httponly=True, samesite="Lax", secure=False, max_age=900)
    return response


def _session_record(token: str | None, variant: str):
    if not token:
        return None
    return get_db().execute(
        """SELECT sessions.active, sessions.expires_at, users.username, users.role
           FROM sessions JOIN users ON users.id = sessions.user_id
           WHERE sessions.token_hash = ? AND sessions.variant = ?""",
        (_hash_token(token), variant),
    ).fetchone()


def _admin_decision(token: str | None, variant: str) -> tuple[str, dict, int]:
    record = _session_record(token, variant)
    now = int(time.time())
    if record is None:
        return (
            "authentication failed",
            {
                "admin_data_returned": False,
                "decision_trace": [
                    {
                        "stage": "lookup",
                        "label": "Authoritative session lookup",
                        "decision": "no matching session row",
                    }
                ],
            },
            401,
        )
    expired = record["expires_at"] <= now
    if not record["active"]:
        return (
            "authentication failed",
            {
                "admin_data_returned": False,
                "session_active": False,
                "session_expired": expired,
                "expiry_checked": variant != "candidate",
                "decision_trace": [
                    {
                        "stage": "lookup",
                        "label": "Authoritative session lookup",
                        "decision": "matching session row found",
                    },
                    {
                        "stage": "lifecycle",
                        "label": "Active-state decision",
                        "decision": "inactive session rejected",
                    },
                ],
            },
            401,
        )
    if variant != "candidate" and expired:
        return (
            "authentication failed",
            {
                "admin_data_returned": False,
                "session_active": True,
                "session_expired": True,
                "expiry_checked": True,
                "decision_trace": [
                    {
                        "stage": "lookup",
                        "label": "Authoritative session lookup",
                        "decision": "matching session row found",
                    },
                    {
                        "stage": "lifecycle",
                        "label": "Expiry decision",
                        "decision": "expired session rejected",
                    },
                ],
            },
            401,
        )
    if record["role"] != "admin":
        return (
            "authenticated but not authorized",
            {
                "admin_data_returned": False,
                "session_active": True,
                "session_expired": expired,
                "expiry_checked": variant != "candidate",
                "decision_trace": [
                    {
                        "stage": "lookup",
                        "label": "Authoritative session lookup",
                        "decision": "matching active session row found",
                    },
                    {
                        "stage": "authorization",
                        "label": "Role decision",
                        "decision": "non-Admin role rejected",
                    },
                ],
            },
            403,
        )
    return (
        "admin session accepted",
        {
            "username": record["username"],
            "admin_marker": "SYNTHETIC-ADMIN-DASHBOARD",
            "admin_data_returned": True,
            "session_active": True,
            "session_expired": expired,
            "expiry_checked": variant != "candidate",
            "decision_trace": [
                {
                    "stage": "lookup",
                    "label": "Authoritative session lookup",
                    "decision": "matching active session row found",
                },
                {
                    "stage": "lifecycle",
                    "label": "Expiry decision",
                    "decision": (
                        "candidate omitted expiry check"
                        if variant == "candidate"
                        else "session confirmed unexpired"
                    ),
                },
                {
                    "stage": "authorization",
                    "label": "Role decision",
                    "decision": "Admin role accepted",
                },
                {
                    "stage": "boundary",
                    "label": "Privileged response",
                    "decision": (
                        "Admin data returned despite expired session"
                        if expired
                        else "Admin data returned to valid session"
                    ),
                },
            ],
        },
        200,
    )


def _revoke_session(token: str | None, variant: str) -> bool:
    if not token or variant not in {"candidate", "secure"}:
        return False
    db = get_db()
    cursor = db.execute(
        "UPDATE sessions SET active = 0 WHERE token_hash = ? AND variant = ?",
        (_hash_token(token), variant),
    )
    db.commit()
    return cursor.rowcount > 0


@bp.get("/<variant>/admin")
def admin(variant: str):
    if variant not in SESSION_VARIANTS:
        return lab_response(lab=LAB, variant=variant, outcome="unknown variant", data={}, status=404)
    outcome, data, status = _admin_decision(_extract_token(), variant)
    return lab_response(lab=LAB, variant=variant, outcome=outcome, data=data, status=status)


@bp.post("/<variant>/logout")
def logout(variant: str):
    if variant not in SESSION_VARIANTS:
        return lab_response(lab=LAB, variant=variant, outcome="unknown variant", data={}, status=404)
    token = _extract_token()
    revoked = _revoke_session(token, variant)
    response = make_response("", 204)
    response.headers["X-TwinLab-Plane"] = "target"
    response.headers["X-TwinLab-Server-Session-Revoked"] = "true" if revoked else "false"
    response.delete_cookie(COOKIE_NAME)
    return response


@bp.get("/<variant>/session-state")
@observer_capability_required
def session_state(variant: str):
    """Return safe synthetic server-side session state for the replay experiment."""

    if variant not in SESSION_VARIANTS:
        return lab_response(
            lab=LAB, variant=variant, outcome="unknown variant", data={}, status=404, plane="observer"
        )
    token = _extract_token()
    if not token:
        return lab_response(
            lab=LAB,
            variant=variant,
            outcome="session token required for state inspection",
            data={"session_found": False},
            status=400,
            plane="observer",
        )
    record = _session_record(token, variant)
    if record is None:
        return lab_response(
            lab=LAB,
            variant=variant,
            outcome="session record not found",
            data={"session_found": False, "token_fingerprint": _hash_token(token)[:12]},
            status=404,
            plane="observer",
        )
    return lab_response(
        lab=LAB,
        variant=variant,
        outcome="server-side session state inspected",
        data={
            "session_found": True,
            "token_fingerprint": _hash_token(token)[:12],
            "active": bool(record["active"]),
            "expired": record["expires_at"] <= int(time.time()),
            "username": record["username"],
            "role": record["role"],
        },
        plane="observer",
    )


def observer_reset_sessions(variant: str):
    """Reset synthetic session state; exposed only by the observer blueprint."""

    if variant not in SESSION_VARIANTS:
        return lab_response(
            lab=LAB,
            variant=variant,
            outcome="unknown variant",
            data={},
            status=404,
            plane="observer",
        )
    db = get_db()
    removed = db.execute("DELETE FROM sessions WHERE variant = ?", (variant,)).rowcount
    db.commit()
    return lab_response(
        lab=LAB,
        variant=variant,
        outcome="synthetic session case reset",
        data={"sessions_removed": removed},
        plane="observer",
    )


@bp.post("/<variant>/demo")
def guided_replay_demo(variant: str):
    """Run the complete synthetic session lifecycle without exposing tokens."""

    if variant not in {"vulnerable", "secure"}:
        return lab_response(lab=LAB, variant=variant, outcome="unknown variant", data={}, status=404)
    user = get_db().execute(
        "SELECT id, username, role FROM users WHERE username = 'admin'"
    ).fetchone()
    old_token = _issue_session(user, variant)
    login_outcome, login_data, login_status = _admin_decision(old_token, variant)
    revoked = _revoke_session(old_token, variant)
    replay_outcome, replay_data, replay_status = _admin_decision(old_token, variant)
    old_state = get_db().execute(
        "SELECT active FROM sessions WHERE token_hash = ? AND variant = ?",
        (_hash_token(old_token), variant),
    ).fetchone()["active"]

    fresh_token = _issue_session(user, variant)
    fresh_outcome, fresh_data, fresh_status = _admin_decision(fresh_token, variant)
    expected_replay = 200 if variant == "vulnerable" else 401
    claim_supported = (
        login_status == 200
        and replay_status == expected_replay
        and fresh_status == 200
        and (bool(old_state) == (variant == "vulnerable"))
    )
    return lab_response(
        lab=LAB,
        variant=variant,
        outcome=(
            "old Admin token still accepted after logout"
            if variant == "vulnerable"
            else "old Admin token rejected after server-side revocation"
        ),
        data={
            "guided_flow": [
                {"step": "login", "status": login_status, "outcome": login_outcome, "admin_data_returned": login_data["admin_data_returned"]},
                {"step": "logout", "server_session_revoked": revoked},
                {"step": "replay_old_token", "status": replay_status, "outcome": replay_outcome, "admin_data_returned": replay_data["admin_data_returned"]},
                {"step": "fresh_login", "status": fresh_status, "outcome": fresh_outcome, "admin_data_returned": fresh_data["admin_data_returned"]},
            ],
            "server_session_active_after_logout": bool(old_state),
            "old_token_replay_status": replay_status,
            "fresh_token_status": fresh_status,
            "fresh_token_differs": fresh_token != old_token,
            "tokens_returned": False,
            "claim_supported": claim_supported,
        },
        plane="runner",
    )
