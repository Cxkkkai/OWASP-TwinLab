from __future__ import annotations

import json
import time
import uuid

from flask import Blueprint, current_app, render_template, request

from app.db import get_db
from app.lab_registry import LAB_BY_ID
from app.observer import observer_capability_required

from .common import lab_response


bp = Blueprint("a02", __name__, url_prefix="/lab/a02")
LAB = LAB_BY_ID["a02"]
SYNTHETIC_TRACE_MARKER = "SYNTHETIC_TRACE_A02"
SYNTHETIC_PATH = "/synthetic/twinshop/orders.py"
SYNTHETIC_CONFIG_MARKER = "DEMO_ONLY_CONFIG_A02"
ERROR_POLICIES = {
    "vulnerable": {
        "name": "development-detail-to-client",
        "expose_internal_errors": True,
        "retain_minimised_operator_event": False,
    },
    "secure": {
        "name": "generic-client-correlated-operator-event",
        "expose_internal_errors": False,
        "retain_minimised_operator_event": True,
    },
    "candidate": {
        "name": "generic-body-but-diagnostic-headers",
        "expose_internal_errors": False,
        "retain_minimised_operator_event": True,
    },
}
# Backwards-compatible import name used by existing evidence helpers.
SYNTHETIC_MARKER = SYNTHETIC_CONFIG_MARKER


class ControlledLabError(RuntimeError):
    """Deterministic synthetic exception carrying only a bounded case label."""

    def __init__(self, case: str):
        super().__init__("controlled TwinLab exception")
        self.case = case


@bp.get("/")
def overview():
    return render_template(
        "module.html",
        title=f"{LAB['owasp']} {LAB['name']}",
        lab=LAB,
        weakness="CWE-209 information exposure through an unsafe error renderer",
        actor="Unauthenticated local lab visitor",
        asset="Internal paths, query shape and configuration metadata",
        attack="Send the controlled ID explode and inspect the 500 response.",
        root_cause="Development diagnostics cross the server-to-client trust boundary.",
        control="Return a generic message and correlation ID; retain only minimised diagnostics server-side.",
        vulnerable_url="/lab/a02/vulnerable/order-lookup?id=explode",
        secure_url="/lab/a02/secure/order-lookup?id=explode",
        legitimate_url="/lab/a02/secure/order-lookup?id=101",
        vulnerable_label="Expose the synthetic diagnostics",
        secure_label="Return a generic error and correlate it",
        legitimate_label="Confirm normal lookup still works",
        setup_url=None,
        test_contract=[
            "V-positive: order 101 lookup works.",
            "V-security: controlled error returns the synthetic internal marker.",
            "S-security: the same error exposes only a request ID.",
            "S-positive: valid lookup remains available and debug stays disabled.",
        ],
        extra_note="Werkzeug's interactive debugger is never enabled; the vulnerable trace is fixed synthetic text.",
    )


def _lookup_or_raise(order_id: str):
    if order_id == "explode":
        raise ControlledLabError("lookup-runtime")
    if order_id == "handler-failure":
        raise ControlledLabError("handler-failure")
    try:
        numeric_id = int(order_id)
    except ValueError as exc:
        raise ControlledLabError("invalid-identifier") from exc
    return get_db().execute(
        "SELECT id, item, total_cents FROM orders WHERE id = ?", (numeric_id,)
    ).fetchone()


@bp.get("/<variant>/order-lookup")
def lookup(variant: str):
    if variant not in {"vulnerable", "secure", "candidate"}:
        return lab_response(lab=LAB, variant=variant, outcome="unknown variant", data={}, status=404)
    order_id = request.args.get("id", "101")
    error_policy = ERROR_POLICIES[variant]
    try:
        order = _lookup_or_raise(order_id)
    except ControlledLabError as error:
        if error_policy["expose_internal_errors"]:
            return lab_response(
                lab=LAB,
                variant=variant,
                outcome="synthetic internal diagnostics exposed",
                data={
                    "synthetic_trace": SYNTHETIC_TRACE_MARKER,
                    "synthetic_path": SYNTHETIC_PATH,
                    "synthetic_sql": "SELECT * FROM orders WHERE id = <client-value>",
                    "synthetic_config": SYNTHETIC_CONFIG_MARKER,
                    "internal_details_returned": True,
                    "trace_marker_returned": True,
                    "path_marker_returned": True,
                    "config_marker_returned": True,
                    "interactive_debugger": False,
                    "error_policy": error_policy["name"],
                    "configuration_drives_response": True,
                },
                status=500,
            )
        request_id = str(uuid.uuid4())
        db = get_db()
        db.execute(
            "INSERT INTO audit_events (event_type, actor, details, request_id, created_at) VALUES (?, ?, ?, ?, ?)",
            (
                "application_error",
                "anonymous",
                json.dumps(
                    {
                        "route": "order-lookup",
                        "error_class": "RuntimeError",
                    }
                ),
                request_id,
                int(time.time()),
            ),
        )
        db.commit()
        current_app.logger.error("TwinLab controlled error request_id=%s route=order-lookup", request_id)
        response = lab_response(
            lab=LAB,
            variant=variant,
            outcome="generic error response",
            data={
                "error_code": "INTERNAL_ERROR",
                "message": "The request could not be completed.",
                "request_id": request_id,
                "internal_details_returned": False,
                "correlated_server_event": True,
                "server_event_type": "application_error",
                "server_event_details_minimised": True,
                "error_policy": error_policy["name"],
                "configuration_drives_response": True,
                "controlled_error_case": error.case,
                "decision_trace": [
                    {
                        "stage": "exception",
                        "label": "Controlled application failure",
                        "decision": error.case,
                    },
                    {
                        "stage": "body-policy",
                        "label": "Client response body",
                        "decision": "generic error and correlation ID only",
                    },
                    {
                        "stage": "header-policy",
                        "label": "Client response headers",
                        "decision": (
                            "candidate middleware adds diagnostic canaries"
                            if variant == "candidate"
                            else "no diagnostic canaries added"
                        ),
                    },
                    {
                        "stage": "operator-path",
                        "label": "Server-side event",
                        "decision": "minimised correlated event retained",
                    },
                ],
            },
            status=500,
        )
        if variant == "candidate":
            response.headers["X-TwinLab-Debug-Path"] = SYNTHETIC_PATH
            response.headers["X-TwinLab-Debug-Config"] = SYNTHETIC_CONFIG_MARKER
        return response
    if order is None:
        return lab_response(lab=LAB, variant=variant, outcome="not found", data={"requested_order": order_id}, status=404)
    return lab_response(
        lab=LAB,
        variant=variant,
        outcome="valid lookup completed",
        data={
            "order_id": order["id"],
            "order": dict(order),
            "debug_mode": bool(current_app.debug),
            "interactive_debugger": False,
            "error_policy": error_policy["name"],
            "configuration_drives_response": True,
            "decision_trace": [
                {
                    "stage": "input",
                    "label": "Order lookup input",
                    "decision": "valid numeric identifier",
                },
                {
                    "stage": "application",
                    "label": "Order lookup",
                    "decision": "normal business path completed",
                },
            ],
        },
    )


@bp.get("/secure/audit-event")
@observer_capability_required
def secure_audit_event():
    """Expose one minimised synthetic event so the client/server split is observable."""

    request_id = request.args.get("request_id", "")[:80]
    event = get_db().execute(
        """SELECT event_type, actor, details, request_id
           FROM audit_events
           WHERE request_id = ? AND event_type = 'application_error'""",
        (request_id,),
    ).fetchone()
    if event is None:
        return lab_response(
            lab=LAB,
            variant="secure",
            outcome="correlated audit event not found",
            data={"request_id": request_id, "event_found": False},
            status=404,
            plane="observer",
        )
    return lab_response(
        lab=LAB,
        variant="secure",
        outcome="minimised server event retrieved by correlation ID",
        data={
            "event_found": True,
            "event_type": event["event_type"],
            "actor": event["actor"],
            "request_id": event["request_id"],
            "event_details": json.loads(event["details"]),
            "stored_detail_keys": sorted(json.loads(event["details"]).keys()),
        },
        plane="observer",
    )
