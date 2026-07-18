from __future__ import annotations

from flask import Blueprint, render_template, request

from app.db import get_db
from app.lab_registry import LAB_BY_ID

from .common import lab_response


bp = Blueprint("a05", __name__, url_prefix="/lab/a05")
LAB = LAB_BY_ID["a05"]


@bp.get("/")
def overview():
    payload = "%25%27%20OR%201%3D1%20--"
    return render_template(
        "module.html",
        title=f"{LAB['owasp']} {LAB['name']}",
        lab=LAB,
        weakness="CWE-89 SQL injection through string-built query",
        actor="Unauthenticated local lab visitor",
        asset="Hidden product catalogue confidentiality",
        attack="Use the read-only payload %' OR 1=1 -- to alter the WHERE clause.",
        root_cause="Untrusted text is inserted into SQL code instead of bound as data.",
        control="Use a parameterized LIKE query while retaining the public-product predicate.",
        vulnerable_url=f"/lab/a05/vulnerable/search?q={payload}",
        secure_url=f"/lab/a05/secure/search?q={payload}",
        legitimate_url="/lab/a05/secure/search?q=Security",
        vulnerable_label="Let the payload change the SQL query",
        secure_label="Bind the same payload as data",
        legitimate_label="Confirm normal public search still works",
        setup_url=None,
        test_contract=[
            "V-positive: a normal term returns its public product.",
            "V-security: the payload reveals HIDDEN-PRODUCT-INTERNAL-ONLY.",
            "S-security: the identical payload is treated as text.",
            "S-positive: normal search behaviour remains available.",
        ],
    )


@bp.get("/vulnerable/search")
def vulnerable_search():
    q = request.args.get("q", "Security")
    if len(q) > 160:
        return lab_response(lab=LAB, variant="vulnerable", outcome="input rejected", data={"reason": "query too long"}, status=400)
    sql = f"SELECT id, name, price_cents, is_public FROM products WHERE is_public = 1 AND name LIKE '%{q}%' ORDER BY id"
    try:
        rows = get_db().execute(sql).fetchall()
    except Exception:
        return lab_response(
            lab=LAB,
            variant="vulnerable",
            outcome="database error",
            data={"error": "query failed; raw database details suppressed outside A02"},
            status=400,
        )
    products = [dict(row) for row in rows]
    return lab_response(
        lab=LAB,
        variant="vulnerable",
        outcome="query executed with interpolated input",
        data={
            "query": q,
            "execution_mode": "interpolated SQL text",
            "executed_statement": sql,
            "products": products,
            "result_count": len(products),
            "hidden_exposed": any(not p["is_public"] for p in products),
            "decision_trace": [
                {
                    "stage": "source",
                    "label": "Untrusted search query",
                    "decision": "accepted as application input",
                },
                {
                    "stage": "construction",
                    "label": "SQL construction",
                    "decision": "query text interpolated into SQL control structure",
                },
                {
                    "stage": "sink",
                    "label": "Catalogue query",
                    "decision": "database executes attacker-influenced statement",
                },
                {
                    "stage": "boundary",
                    "label": "Public response",
                    "decision": (
                        "hidden catalogue row returned"
                        if any(not p["is_public"] for p in products)
                        else "only public rows returned"
                    ),
                },
            ],
        },
    )


@bp.get("/candidate/search")
def candidate_search():
    """Plausible but incomplete fix used only by the bounded Auditor.

    It blocks the exact uppercase tokens in the known example.  The route stays
    read-only and intentionally demonstrates why a blacklist is not a security
    boundary.
    """

    q = request.args.get("q", "Security")
    if len(q) > 160:
        return lab_response(
            lab=LAB,
            variant="candidate",
            outcome="input rejected",
            data={"reason": "query too long", "hidden_exposed": False},
            status=400,
        )
    blocked_tokens = [token for token in ("OR", "--") if token in q]
    if blocked_tokens:
        return lab_response(
            lab=LAB,
            variant="candidate",
            outcome="known payload blocked by case-sensitive blacklist",
            data={
                "query": q,
                "execution_mode": "interpolated SQL after blacklist",
                "candidate_control": "reject exact uppercase OR and -- tokens",
                "blocked_by_candidate": True,
                "blocked_tokens": blocked_tokens,
                "products": [],
                "result_count": 0,
                "hidden_exposed": False,
                "decision_trace": [
                    {
                        "stage": "source",
                        "label": "Untrusted search query",
                        "decision": "accepted as application input",
                    },
                    {
                        "stage": "candidate-control",
                        "label": "Case-sensitive blacklist",
                        "decision": f"rejected exact tokens: {', '.join(blocked_tokens)}",
                    },
                    {
                        "stage": "boundary",
                        "label": "Public response",
                        "decision": "request rejected before catalogue query",
                    },
                ],
            },
            status=400,
        )

    sql = f"SELECT id, name, price_cents, is_public FROM products WHERE is_public = 1 AND name LIKE '%{q}%' ORDER BY id"
    try:
        rows = get_db().execute(sql).fetchall()
    except Exception:
        return lab_response(
            lab=LAB,
            variant="candidate",
            outcome="candidate query produced a database error",
            data={
                "query": q,
                "candidate_control": "reject exact uppercase OR and -- tokens",
                "blocked_by_candidate": False,
                "hidden_exposed": False,
                "decision_trace": [
                    {
                        "stage": "source",
                        "label": "Untrusted search query",
                        "decision": "accepted as application input",
                    },
                    {
                        "stage": "candidate-control",
                        "label": "Case-sensitive blacklist",
                        "decision": "allowed because exact blocked tokens were absent",
                    },
                    {
                        "stage": "sink",
                        "label": "Catalogue query",
                        "decision": "attacker-influenced SQL failed to parse",
                    },
                ],
            },
            status=400,
        )
    products = [dict(row) for row in rows]
    hidden_exposed = any(not p["is_public"] for p in products)
    return lab_response(
        lab=LAB,
        variant="candidate",
        outcome=(
            "blacklist bypass confirmed against real catalogue query"
            if hidden_exposed
            else "candidate query completed"
        ),
        data={
            "query": q,
            "execution_mode": "interpolated SQL after blacklist",
            "candidate_control": "reject exact uppercase OR and -- tokens",
            "blocked_by_candidate": False,
            "executed_statement": sql,
            "products": products,
            "result_count": len(products),
            "hidden_exposed": hidden_exposed,
            "decision_trace": [
                {
                    "stage": "source",
                    "label": "Untrusted search query",
                    "decision": "accepted as application input",
                },
                {
                    "stage": "candidate-control",
                    "label": "Case-sensitive blacklist",
                    "decision": "allowed because exact blocked tokens were absent",
                },
                {
                    "stage": "construction",
                    "label": "SQL construction",
                    "decision": "allowed input still entered SQL control structure",
                },
                {
                    "stage": "boundary",
                    "label": "Public response",
                    "decision": (
                        "hidden catalogue row returned"
                        if hidden_exposed
                        else "only public rows returned"
                    ),
                },
            ],
        },
    )


@bp.get("/secure/search")
def secure_search():
    q = request.args.get("q", "Security")
    if len(q) > 160:
        return lab_response(lab=LAB, variant="secure", outcome="input rejected", data={"reason": "query too long"}, status=400)
    rows = get_db().execute(
        "SELECT id, name, price_cents, is_public FROM products WHERE is_public = 1 AND name LIKE ? ORDER BY id",
        (f"%{q}%",),
    ).fetchall()
    products = [dict(row) for row in rows]
    return lab_response(
        lab=LAB,
        variant="secure",
        outcome="input bound as data",
        data={
            "query": q,
            "execution_mode": "parameterized statement",
            "statement_template": "SELECT id, name, price_cents, is_public FROM products WHERE is_public = 1 AND name LIKE ? ORDER BY id",
            "bound_parameter": f"%{q}%",
            "products": products,
            "result_count": len(products),
            "hidden_exposed": False,
            "decision_trace": [
                {
                    "stage": "source",
                    "label": "Untrusted search query",
                    "decision": "accepted as application input",
                },
                {
                    "stage": "construction",
                    "label": "Parameterized statement",
                    "decision": "query remains a bound data value",
                },
                {
                    "stage": "sink",
                    "label": "Catalogue query",
                    "decision": "database executes a fixed SQL structure",
                },
                {
                    "stage": "boundary",
                    "label": "Public response",
                    "decision": "hidden catalogue predicate remains enforced",
                },
            ],
        },
    )
