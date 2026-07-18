from __future__ import annotations

from flask import Blueprint, g, render_template, request

from app.db import get_db
from app.lab_registry import LAB_BY_ID

from .common import lab_response


bp = Blueprint("a01", __name__, url_prefix="/lab/a01")
LAB = LAB_BY_ID["a01"]


@bp.get("/")
def overview():
    return render_template(
        "module.html",
        title=f"{LAB['owasp']} {LAB['name']}",
        lab=LAB,
        weakness="IDOR / missing object-level authorization",
        actor="Alice (authenticated customer)",
        asset="Bob's order confidentiality",
        attack="Change order ID 101 to 202 while remaining logged in as Alice.",
        root_cause="Authentication is treated as permission to access any order ID.",
        control="Constrain the database lookup by both order ID and authenticated owner ID; return 404 by default.",
        vulnerable_url="/lab/a01/vulnerable/orders/202",
        secure_url="/lab/a01/secure/orders/202",
        legitimate_url="/lab/a01/secure/orders/101",
        vulnerable_label="Show Alice receiving Bob's order 202",
        secure_label="Apply the ownership check to order 202",
        legitimate_label="Confirm Alice still receives order 101",
        setup_url="/identity/alice",
        setup_method="POST",
        setup_fields={"next": "/lab/a01/"},
        test_contract=[
            "V-positive: Alice can read order 101.",
            "V-security: Alice can read Bob's order 202.",
            "S-security: order 202 returns 404 with no Bob marker.",
            "S-positive: Alice can still read order 101.",
        ],
    )


def _actor_or_unauthorized():
    if g.actor is None:
        return None, lab_response(
            lab=LAB,
            variant="n/a",
            outcome="authentication required",
            data={"hint": "Select Alice with the workbench identity control before running the request."},
            status=401,
        )
    return g.actor, None


@bp.get("/vulnerable/orders/<int:order_id>")
def vulnerable_order(order_id: int):
    actor, error = _actor_or_unauthorized()
    if error:
        return error
    order = get_db().execute(
        """SELECT orders.id, orders.item, orders.shipping_address, orders.total_cents,
                  users.username AS owner
           FROM orders JOIN users ON users.id = orders.owner_id
           WHERE orders.id = ?""",
        (order_id,),
    ).fetchone()
    if order is None:
        return lab_response(
            lab=LAB,
            variant="vulnerable",
            outcome="not found",
            data={"requested_order": order_id},
            status=404,
        )
    return lab_response(
        lab=LAB,
        variant="vulnerable",
        outcome="order disclosed without ownership check",
        data={
            "actor": actor["username"],
            "order": dict(order),
            "authorized": order["owner"] == actor["username"],
            "object_owner": order["owner"],
            "authorization_inputs": {
                "principal": actor["username"],
                "action": "read_order",
                "requested_object": order_id,
            },
            "authorization_predicate": "orders.id = requested_order_id",
            "sensitive_data_returned": True,
        },
    )


@bp.get("/secure/orders/<int:order_id>")
def secure_order(order_id: int):
    actor, error = _actor_or_unauthorized()
    if error:
        return error
    order = get_db().execute(
        """SELECT orders.id, orders.item, orders.shipping_address, orders.total_cents,
                  users.username AS owner
           FROM orders JOIN users ON users.id = orders.owner_id
           WHERE orders.id = ? AND orders.owner_id = ?""",
        (order_id, actor["id"]),
    ).fetchone()
    if order is None:
        return lab_response(
            lab=LAB,
            variant="secure",
            outcome="denied by object ownership policy",
            data={
                "requested_order": order_id,
                "authorization_inputs": {
                    "principal": actor["username"],
                    "action": "read_order",
                    "requested_object": order_id,
                },
                "authorization_predicate": "orders.id = requested_order_id AND orders.owner_id = actor.id",
                "sensitive_data_returned": False,
            },
            status=404,
        )
    return lab_response(
        lab=LAB,
        variant="secure",
        outcome="authorized owner access",
        data={
            "actor": actor["username"],
            "order": dict(order),
            "authorized": True,
            "object_owner": order["owner"],
            "authorization_inputs": {
                "principal": actor["username"],
                "action": "read_order",
                "requested_object": order_id,
            },
            "authorization_predicate": "orders.id = requested_order_id AND orders.owner_id = actor.id",
            "sensitive_data_returned": True,
        },
    )


@bp.get("/candidate/orders/<int:order_id>")
def candidate_order(order_id: int):
    """Owner-scoped lookup with an intentionally untrusted principal source.

    This is a plausible incomplete repair used only by the bounded Auditor.  It
    demonstrates that an owner predicate is meaningless when the principal can
    be replaced by caller-controlled input.
    """

    session_actor, error = _actor_or_unauthorized()
    if error:
        return error

    requested_actor = (
        request.args.get("actor")
        or request.headers.get("X-TwinLab-Actor")
        or request.headers.get("X-Demo-Actor")
    )
    decision_actor = session_actor
    principal_source = "signed server session"
    if requested_actor:
        candidate_actor = get_db().execute(
            "SELECT id, username, role FROM users WHERE username = ?",
            (requested_actor,),
        ).fetchone()
        if candidate_actor is not None:
            decision_actor = candidate_actor
            principal_source = "caller-controlled request override"

    order = get_db().execute(
        """SELECT orders.id, orders.item, orders.shipping_address, orders.total_cents,
                  users.username AS owner
           FROM orders JOIN users ON users.id = orders.owner_id
           WHERE orders.id = ? AND orders.owner_id = ?""",
        (order_id, decision_actor["id"]),
    ).fetchone()
    trace = [
        {
            "stage": "identity",
            "label": "Signed-session principal",
            "decision": session_actor["username"],
        },
        {
            "stage": "candidate-control",
            "label": "Principal selected for owner predicate",
            "decision": f"{decision_actor['username']} from {principal_source}",
        },
        {
            "stage": "policy",
            "label": "Owner-scoped query",
            "decision": "orders.id = requested id AND owner_id = selected principal",
        },
    ]
    if order is None:
        trace.append(
            {
                "stage": "boundary",
                "label": "Customer response",
                "decision": "no order data returned",
            }
        )
        return lab_response(
            lab=LAB,
            variant="candidate",
            outcome="candidate owner predicate denied the selected principal",
            data={
                "session_actor": session_actor["username"],
                "decision_actor": decision_actor["username"],
                "principal_source": principal_source,
                "requested_order": order_id,
                "authorization_predicate": (
                    "orders.id = requested_order_id AND "
                    "orders.owner_id = selected_principal.id"
                ),
                "sensitive_data_returned": False,
                "decision_trace": trace,
            },
            status=404,
        )

    order_data = dict(order)
    leak_to_session_actor = order["owner"] != session_actor["username"]
    trace.append(
        {
            "stage": "boundary",
            "label": "Customer response",
            "decision": (
                f"{order['owner']}'s order returned to signed-session actor "
                f"{session_actor['username']}"
            ),
        }
    )
    return lab_response(
        lab=LAB,
        variant="candidate",
        outcome=(
            "caller-overridden principal caused cross-account disclosure"
            if leak_to_session_actor
            else "candidate owner access completed"
        ),
        data={
            "session_actor": session_actor["username"],
            "decision_actor": decision_actor["username"],
            "principal_source": principal_source,
            "order": order_data,
            "object_owner": order["owner"],
            "authorized_for_signed_session": not leak_to_session_actor,
            "sensitive_data_returned": True,
            "authorization_predicate": (
                "orders.id = requested_order_id AND "
                "orders.owner_id = selected_principal.id"
            ),
            "decision_trace": trace,
        },
    )
