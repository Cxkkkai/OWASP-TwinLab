"""Capability-gated observer plane for synthetic TwinLab evidence.

Target routes model the application an attacker can reach.  Observer routes are
separate lab instrumentation used to inspect/reset synthetic server state; they
are not part of the protected TwinShop API.
"""

from __future__ import annotations

import hmac
import hashlib
import json
from functools import wraps

from flask import Blueprint, current_app, jsonify, make_response, request

from app.db import get_db


bp = Blueprint("observer", __name__, url_prefix="/observer")
OBSERVER_HEADER = "X-TwinLab-Observer"


def _rows_checksum(rows) -> str:
    canonical = json.dumps(
        [dict(row) for row in rows], sort_keys=True, separators=(",", ":")
    ).encode()
    return hashlib.sha256(canonical).hexdigest()[:16]


def observer_capability_required(view):
    """Require the fixed local evidence-console capability and label responses."""

    @wraps(view)
    def wrapped(*args, **kwargs):
        supplied = request.headers.get(OBSERVER_HEADER, "")
        expected = current_app.config["LAB_OBSERVER_CAPABILITY"]
        if not hmac.compare_digest(supplied, expected):
            response = jsonify(
                {
                    "error": "observer capability required",
                    "plane": "observer",
                    "required_header": OBSERVER_HEADER,
                }
            )
            response.status_code = 403
        else:
            response = make_response(view(*args, **kwargs))
        response.headers["X-TwinLab-Plane"] = "observer"
        response.headers["Cache-Control"] = "no-store"
        return response

    return wrapped


@bp.get("/a02/audit-event")
@observer_capability_required
def a02_audit_event():
    from app.modules.misconfiguration import secure_audit_event

    return secure_audit_event()


@bp.get("/a01/orders-state")
@observer_capability_required
def a01_orders_state():
    """Return a digest, not customer data, for the authoritative order state."""

    rows = get_db().execute(
        """SELECT id, owner_id, item, shipping_address, total_cents
           FROM orders ORDER BY id"""
    ).fetchall()
    return jsonify(
        {
            "plane": "observer",
            "asset": "orders",
            "row_count": len(rows),
            "checksum": _rows_checksum(rows),
            "raw_customer_data_returned": False,
        }
    )


@bp.get("/a05/products-state")
@observer_capability_required
def a05_products_state():
    """Return a digest and bounded counts for the catalogue state."""

    rows = get_db().execute(
        "SELECT id, name, is_public, price_cents FROM products ORDER BY id"
    ).fetchall()
    return jsonify(
        {
            "plane": "observer",
            "asset": "products",
            "row_count": len(rows),
            "public_count": sum(bool(row["is_public"]) for row in rows),
            "hidden_count": sum(not bool(row["is_public"]) for row in rows),
            "checksum": _rows_checksum(rows),
            "raw_catalogue_rows_returned": False,
        }
    )


@bp.post("/a06/<variant>/reset-case")
@observer_capability_required
def a06_reset_case(variant: str):
    from app.modules.compact import a06_reset_case as legacy_handler

    return legacy_handler(variant)


@bp.get("/a06/<variant>/state")
@observer_capability_required
def a06_state(variant: str):
    from app.modules.compact import a06_state as legacy_handler

    return legacy_handler(variant)


@bp.post("/a07/<variant>/reset-case")
@observer_capability_required
def a07_reset_case(variant: str):
    """Remove all synthetic sessions for one comparison variant."""

    from app.modules.authentication import observer_reset_sessions

    return observer_reset_sessions(variant)


@bp.get("/a07/<variant>/session-state")
@observer_capability_required
def a07_session_state(variant: str):
    from app.modules.authentication import session_state

    return session_state(variant)


@bp.post("/a07/<variant>/expire-session")
@observer_capability_required
def a07_expire_session(variant: str):
    """Move one synthetic session beyond expiry for lifecycle verification."""

    if variant not in {"vulnerable", "candidate", "secure"}:
        return jsonify({"outcome": "unknown variant", "expired": False}), 404
    token = request.headers.get("X-Lab-Session", "")
    if not token:
        return jsonify({"outcome": "session token required", "expired": False}), 400
    from app.modules.authentication import _hash_token

    db = get_db()
    cursor = db.execute(
        "UPDATE sessions SET expires_at = 0 WHERE token_hash = ? AND variant = ?",
        (_hash_token(token), variant),
    )
    db.commit()
    return jsonify(
        {
            "plane": "observer",
            "outcome": "synthetic session moved beyond expiry",
            "expired": cursor.rowcount == 1,
            "token_fingerprint": _hash_token(token)[:12],
        }
    ), (200 if cursor.rowcount == 1 else 404)


@bp.post("/a08/<variant>/reset-price")
@observer_capability_required
def a08_reset_price(variant: str):
    from app.modules.compact import a08_reset_price as legacy_handler

    return legacy_handler(variant)


@bp.get("/a08/<variant>/price-state")
@observer_capability_required
def a08_price_state(variant: str):
    from app.modules.compact import a08_price_state as legacy_handler

    return legacy_handler(variant)


@bp.post("/a09/<variant>/reset-case")
@observer_capability_required
def a09_reset_case(variant: str):
    from app.modules.compact import a09_reset_case as legacy_handler

    return legacy_handler(variant)


@bp.get("/a09/<variant>/state")
@observer_capability_required
def a09_state(variant: str):
    from app.modules.compact import a09_state as legacy_handler

    return legacy_handler(variant)
