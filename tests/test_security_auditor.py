from __future__ import annotations

from urllib.parse import quote

from app.auditor_contracts import validate_auditor_contracts
from app.db import get_db
from app.modules.misconfiguration import SYNTHETIC_CONFIG_MARKER, SYNTHETIC_PATH


OBSERVER_HEADERS = {"X-TwinLab-Observer": "evidence-console"}


def _login(json_post, variant: str) -> str:
    response = json_post(
        f"/lab/a07/{variant}/login",
        data={"username": "admin", "password": "demo-admin"},
    )
    assert response.status_code == 200
    return response.json["lab_token"]


def test_auditor_contract_manifest_is_valid_and_bounded(client):
    manifest = validate_auditor_contracts()
    assert list(manifest) == ["a05", "a07", "a01", "a02"]
    assert {contract["explorer"]["kind"] for contract in manifest.values()} == {
        "grammar",
        "state",
        "policy",
        "boundary",
    }
    assert all(contract["bounded_claim"] for contract in manifest.values())
    assert all(
        set(contract["attack"])
        == {
            "objective",
            "capability",
            "known_path",
            "manipulation",
            "success",
        }
        for contract in manifest.values()
    )

    page = client.get("/auditor/")
    assert page.status_code == 200
    text = page.get_data(as_text=True)
    # The template is added with the user-facing Auditor UI in the next patch;
    # this route-level assertion keeps the blueprint contract explicit.
    assert "Security Control Auditor" in text
    assert "Live attack reconstruction" in text
    assert "Actual attacker execution" in text

    response = client.get("/auditor/contracts")
    assert response.status_code == 200
    assert list(response.json["contracts"]) == ["a01", "a02", "a05", "a07"]
    assert response.headers["X-TwinLab-Plane"] == "runner"


def test_a05_candidate_passes_known_baseline_but_mutation_finds_real_bypass(json_get):
    known = "%' OR 1=1 --"
    bypass = "%' oR 1=1 /*"

    baseline = json_get(f"/lab/a05/candidate/search?q={quote(known, safe='')}")
    candidate = json_get(f"/lab/a05/candidate/search?q={quote(bypass, safe='')}")
    robust = json_get(f"/lab/a05/secure/search?q={quote(bypass, safe='')}")
    legitimate = json_get("/lab/a05/candidate/search?q=Security")

    assert baseline.status_code == 400
    assert baseline.json["blocked_by_candidate"] is True
    assert baseline.json["hidden_exposed"] is False
    assert legitimate.status_code == 200
    assert legitimate.json["hidden_exposed"] is False
    assert candidate.status_code == 200
    assert candidate.json["blocked_by_candidate"] is False
    assert candidate.json["hidden_exposed"] is True
    assert any(
        product["name"] == "HIDDEN-PRODUCT-INTERNAL-ONLY"
        for product in candidate.json["products"]
    )
    assert robust.status_code == 200
    assert robust.json["hidden_exposed"] is False
    assert candidate.json["decision_trace"][-1]["stage"] == "boundary"


def test_a01_candidate_owner_check_passes_baseline_but_trusts_actor_override(
    client, json_get
):
    client.post("/identity/alice")
    baseline = json_get("/lab/a01/candidate/orders/202")
    bypass = json_get(
        "/lab/a01/candidate/orders/202",
        headers={"X-TwinLab-Actor": "bob"},
    )
    robust = json_get(
        "/lab/a01/secure/orders/202",
        headers={"X-TwinLab-Actor": "bob"},
    )
    legitimate = json_get("/lab/a01/candidate/orders/101")

    assert baseline.status_code == 404
    assert legitimate.status_code == 200
    assert bypass.status_code == 200
    assert bypass.json["session_actor"] == "alice"
    assert bypass.json["decision_actor"] == "bob"
    assert bypass.json["principal_source"] == "caller-controlled request override"
    assert bypass.json["object_owner"] == "bob"
    assert bypass.json["authorized_for_signed_session"] is False
    assert robust.status_code == 404
    assert robust.json["sensitive_data_returned"] is False


def test_a02_candidate_passes_body_only_check_but_leaks_across_header_boundary(
    json_get,
):
    candidate = json_get("/lab/a02/candidate/order-lookup?id=explode")
    robust = json_get("/lab/a02/secure/order-lookup?id=explode")
    legitimate = json_get("/lab/a02/candidate/order-lookup?id=101")

    assert candidate.status_code == robust.status_code == 500
    assert candidate.json["internal_details_returned"] is False
    assert SYNTHETIC_PATH not in candidate.get_data(as_text=True)
    assert SYNTHETIC_CONFIG_MARKER not in candidate.get_data(as_text=True)
    assert candidate.headers["X-TwinLab-Debug-Path"] == SYNTHETIC_PATH
    assert candidate.headers["X-TwinLab-Debug-Config"] == SYNTHETIC_CONFIG_MARKER
    assert "X-TwinLab-Debug-Path" not in robust.headers
    assert "X-TwinLab-Debug-Config" not in robust.headers
    assert robust.json["internal_details_returned"] is False
    assert legitimate.status_code == 200


def test_a02_candidate_still_retains_minimised_correlated_operator_event(json_get):
    candidate = json_get("/lab/a02/candidate/order-lookup?id=handler-failure")
    event = json_get(
        f"/observer/a02/audit-event?request_id={candidate.json['request_id']}",
        headers=OBSERVER_HEADERS,
    )
    assert event.status_code == 200
    assert event.json["stored_detail_keys"] == ["error_class", "route"]
    assert event.json["event_details"] == {
        "error_class": "RuntimeError",
        "route": "order-lookup",
    }


def test_a07_candidate_passes_logout_baseline_but_omits_expiry_decision(
    json_get, json_post
):
    baseline_token = _login(json_post, "candidate")
    logout = json_post(
        "/lab/a07/candidate/logout",
        headers={"X-Lab-Session": baseline_token},
    )
    replay = json_get(
        "/lab/a07/candidate/admin",
        headers={"X-Lab-Session": baseline_token},
    )
    assert logout.status_code == 204
    assert logout.headers["X-TwinLab-Server-Session-Revoked"] == "true"
    assert replay.status_code == 401

    candidate_token = _login(json_post, "candidate")
    expired = json_post(
        "/observer/a07/candidate/expire-session",
        headers={**OBSERVER_HEADERS, "X-Lab-Session": candidate_token},
    )
    candidate_access = json_get(
        "/lab/a07/candidate/admin",
        headers={"X-Lab-Session": candidate_token},
    )
    assert expired.status_code == 200
    assert candidate_access.status_code == 200
    assert candidate_access.json["admin_data_returned"] is True
    assert candidate_access.json["session_expired"] is True
    assert candidate_access.json["expiry_checked"] is False

    secure_token = _login(json_post, "secure")
    json_post(
        "/observer/a07/secure/expire-session",
        headers={**OBSERVER_HEADERS, "X-Lab-Session": secure_token},
    )
    secure_access = json_get(
        "/lab/a07/secure/admin",
        headers={"X-Lab-Session": secure_token},
    )
    assert secure_access.status_code == 401
    assert secure_access.json["admin_data_returned"] is False
    assert secure_access.json["expiry_checked"] is True


def test_session_schema_isolates_candidate_variant(app):
    with app.app_context():
        schema = get_db().execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='sessions'"
        ).fetchone()["sql"]
    assert "'candidate'" in schema
