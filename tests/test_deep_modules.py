from __future__ import annotations

import hashlib
import time

from app.db import get_db, verify_demo_password
from app.modules.misconfiguration import (
    SYNTHETIC_CONFIG_MARKER,
    SYNTHETIC_PATH,
    SYNTHETIC_TRACE_MARKER,
)


OBSERVER_HEADERS = {"X-TwinLab-Observer": "evidence-console"}


def test_shared_login_store_uses_slow_salted_password_hashes(app):
    with app.app_context():
        rows = get_db().execute(
            "SELECT username, password_hash FROM users ORDER BY id"
        ).fetchall()
    hashes = {row["username"]: row["password_hash"] for row in rows}
    assert all(value.startswith(("scrypt:", "pbkdf2:sha256:")) for value in hashes.values())
    assert len(set(hashes.values())) == 3
    assert verify_demo_password(hashes["admin"], "demo-admin") is True
    assert verify_demo_password(hashes["admin"], "wrong") is False


def test_a01_vulnerable_legitimate_owner_access(client, json_get):
    client.post("/identity/alice")
    response = json_get("/lab/a01/vulnerable/orders/101")
    assert response.status_code == 200
    assert response.json["order"]["owner"] == "alice"
    assert response.json["authorized"] is True


def test_a01_vulnerable_idor_exposes_bob_order(client, json_get):
    client.post("/identity/alice")
    response = json_get("/lab/a01/vulnerable/orders/202")
    assert response.status_code == 200
    assert response.json["order"]["owner"] == "bob"
    assert response.json["authorized"] is False
    assert response.json["object_owner"] == "bob"
    assert response.json["sensitive_data_returned"] is True
    assert response.json["authorization_inputs"] == {
        "principal": "alice",
        "action": "read_order",
        "requested_object": 202,
    }
    assert response.json["authorization_predicate"] == "orders.id = requested_order_id"


def test_a01_secure_blocks_idor_without_bob_marker(client, json_get):
    client.post("/identity/alice")
    response = json_get("/lab/a01/secure/orders/202")
    assert response.status_code == 404
    assert response.json["sensitive_data_returned"] is False
    assert "orders.owner_id = actor.id" in response.json["authorization_predicate"]
    assert b"Fiction Avenue" not in response.data
    assert b'"owner":"bob"' not in response.data


def test_a01_secure_preserves_owner_access(client, json_get):
    client.post("/identity/alice")
    response = json_get("/lab/a01/secure/orders/101")
    assert response.status_code == 200
    assert response.json["order"]["owner"] == "alice"


def test_a01_requires_an_actor(json_get):
    response = json_get("/lab/a01/secure/orders/101")
    assert response.status_code == 401


def test_a01_ignores_caller_controlled_actor_header(client, json_get):
    client.post("/identity/alice")
    response = json_get(
        "/lab/a01/secure/orders/202", headers={"X-Demo-Actor": "bob"}
    )
    assert response.status_code == 404
    assert response.json["authorization_inputs"]["principal"] == "alice"


def test_a05_normal_search_is_equivalent(json_get):
    vulnerable = json_get("/lab/a05/vulnerable/search?q=Security")
    secure = json_get("/lab/a05/secure/search?q=Security")
    assert vulnerable.status_code == secure.status_code == 200
    assert [p["name"] for p in vulnerable.json["products"]] == [p["name"] for p in secure.json["products"]]
    assert vulnerable.json["hidden_exposed"] is False
    assert secure.json["hidden_exposed"] is False


def test_a05_read_only_sqli_exposes_hidden_product_only_in_vulnerable(app, json_get):
    payload = "%25%27%20OR%201%3D1%20--"
    with app.app_context():
        before = [tuple(row) for row in get_db().execute("SELECT id, name, is_public, price_cents FROM products ORDER BY id")]
    vulnerable = json_get(f"/lab/a05/vulnerable/search?q={payload}")
    secure = json_get(f"/lab/a05/secure/search?q={payload}")
    assert vulnerable.status_code == secure.status_code == 200
    assert vulnerable.json["hidden_exposed"] is True
    assert vulnerable.json["execution_mode"] == "interpolated SQL text"
    assert "OR 1=1" in vulnerable.json["executed_statement"]
    assert any(product["name"] == "HIDDEN-PRODUCT-INTERNAL-ONLY" for product in vulnerable.json["products"])
    assert secure.json["hidden_exposed"] is False
    assert secure.json["execution_mode"] == "parameterized statement"
    assert "LIKE ?" in secure.json["statement_template"]
    assert secure.json["bound_parameter"] == "%%' OR 1=1 --%"
    assert secure.json["products"] == []
    with app.app_context():
        after = [tuple(row) for row in get_db().execute("SELECT id, name, is_public, price_cents FROM products ORDER BY id")]
    assert after == before


def test_a05_secure_rejects_excessively_long_query(json_get):
    response = json_get("/lab/a05/secure/search?q=" + "x" * 161)
    assert response.status_code == 400
    assert "sql" not in response.get_data(as_text=True).lower()


def _login(json_post, variant: str, username: str = "admin", password: str = "demo-admin") -> str:
    response = json_post(
        f"/lab/a07/{variant}/login",
        data={"username": username, "password": password},
    )
    assert response.status_code == 200
    return response.json["lab_token"]


def test_a07_fresh_admin_sessions_work_in_both_variants(json_get, json_post):
    for variant in ("vulnerable", "secure"):
        token = _login(json_post, variant)
        response = json_get(f"/lab/a07/{variant}/admin", headers={"X-Lab-Session": token})
        assert response.status_code == 200
        assert response.json["admin_marker"] == "SYNTHETIC-ADMIN-DASHBOARD"


def test_a07_vulnerable_logout_allows_old_token_replay(app, json_get, json_post):
    token = _login(json_post, "vulnerable")
    logout = json_post("/lab/a07/vulnerable/logout", headers={"X-Lab-Session": token})
    replay = json_get("/lab/a07/vulnerable/admin", headers={"X-Lab-Session": token})
    assert logout.status_code == 204
    assert logout.headers["X-TwinLab-Server-Session-Revoked"] == "false"
    assert replay.status_code == 200
    assert replay.json["admin_data_returned"] is True
    with app.app_context():
        active = get_db().execute(
            "SELECT active FROM sessions WHERE token_hash = ?",
            (hashlib.sha256(token.encode()).hexdigest(),),
        ).fetchone()[0]
    assert active == 1


def test_a07_secure_logout_revokes_old_token_and_new_login_works(app, json_get, json_post):
    old_token = _login(json_post, "secure")
    logout = json_post("/lab/a07/secure/logout", headers={"X-Lab-Session": old_token})
    replay = json_get("/lab/a07/secure/admin", headers={"X-Lab-Session": old_token})
    new_token = _login(json_post, "secure")
    fresh = json_get("/lab/a07/secure/admin", headers={"X-Lab-Session": new_token})
    assert logout.status_code == 204
    assert logout.headers["X-TwinLab-Server-Session-Revoked"] == "true"
    assert replay.status_code == 401
    assert replay.json["admin_data_returned"] is False
    assert new_token != old_token
    assert fresh.status_code == 200
    with app.app_context():
        active = get_db().execute(
            "SELECT active FROM sessions WHERE token_hash = ?",
            (hashlib.sha256(old_token.encode()).hexdigest(),),
        ).fetchone()[0]
    assert active == 0


def test_a07_session_state_endpoint_makes_revocation_row_observable(json_get, json_post):
    vulnerable_token = _login(json_post, "vulnerable")
    json_post("/lab/a07/vulnerable/logout", headers={"X-Lab-Session": vulnerable_token})
    vulnerable_state = json_get(
        "/observer/a07/vulnerable/session-state",
        headers={**OBSERVER_HEADERS, "X-Lab-Session": vulnerable_token},
    )
    secure_token = _login(json_post, "secure")
    json_post("/lab/a07/secure/logout", headers={"X-Lab-Session": secure_token})
    secure_state = json_get(
        "/observer/a07/secure/session-state",
        headers={**OBSERVER_HEADERS, "X-Lab-Session": secure_token},
    )
    assert vulnerable_state.status_code == secure_state.status_code == 200
    assert vulnerable_state.json["active"] is True
    assert secure_state.json["active"] is False
    assert len(vulnerable_state.json["token_fingerprint"]) == 12
    assert len(secure_state.json["token_fingerprint"]) == 12


def test_a07_guided_flows_show_complete_replay_contrast_without_returning_tokens(json_post):
    vulnerable = json_post("/lab/a07/vulnerable/demo")
    secure = json_post("/lab/a07/secure/demo")
    assert vulnerable.status_code == secure.status_code == 200
    assert vulnerable.json["old_token_replay_status"] == 200
    assert vulnerable.json["server_session_active_after_logout"] is True
    assert secure.json["old_token_replay_status"] == 401
    assert secure.json["server_session_active_after_logout"] is False
    assert vulnerable.json["fresh_token_status"] == secure.json["fresh_token_status"] == 200
    assert vulnerable.json["claim_supported"] is True
    assert secure.json["claim_supported"] is True
    for response in (vulnerable, secure):
        assert response.json["tokens_returned"] is False
        assert "lab_token" not in response.get_data(as_text=True)


def test_a07_random_expired_and_customer_tokens_fail(app, json_get, json_post):
    random_response = json_get("/lab/a07/secure/admin", headers={"X-Lab-Session": "not-a-session"})
    customer_token = _login(json_post, "secure", username="alice", password="alice-demo")
    customer_response = json_get("/lab/a07/secure/admin", headers={"X-Lab-Session": customer_token})
    expired_token = _login(json_post, "secure")
    with app.app_context():
        get_db().execute(
            "UPDATE sessions SET expires_at = ? WHERE token_hash = ?",
            (int(time.time()) - 1, hashlib.sha256(expired_token.encode()).hexdigest()),
        )
        get_db().commit()
    expired_response = json_get("/lab/a07/secure/admin", headers={"X-Lab-Session": expired_token})
    assert random_response.status_code == 401
    assert customer_response.status_code == 403
    assert expired_response.status_code == 401


def test_a02_valid_lookup_works_and_debug_is_disabled(json_get):
    for variant in ("vulnerable", "secure"):
        response = json_get(f"/lab/a02/{variant}/order-lookup?id=101")
        assert response.status_code == 200
        assert response.json["order"]["id"] == 101
        assert response.json["debug_mode"] is False
        assert response.json["interactive_debugger"] is False


def test_a02_vulnerable_error_discloses_only_synthetic_marker(json_get, client):
    response = json_get("/lab/a02/vulnerable/order-lookup?id=explode")
    assert response.status_code == 500
    assert response.json["synthetic_trace"] == SYNTHETIC_TRACE_MARKER
    assert response.json["synthetic_path"] == SYNTHETIC_PATH
    assert response.json["synthetic_config"] == SYNTHETIC_CONFIG_MARKER
    assert response.json["internal_details_returned"] is True
    assert response.json["trace_marker_returned"] is True
    assert response.json["path_marker_returned"] is True
    assert response.json["config_marker_returned"] is True
    assert response.json["interactive_debugger"] is False
    html_response = client.get("/lab/a02/vulnerable/order-lookup?id=explode")
    html = html_response.get_data(as_text=True)
    assert html_response.status_code == 500
    assert "Internal details returned" in html
    assert "Synthetic trace returned" in html
    assert "Synthetic path returned" in html
    assert "Synthetic config marker returned" in html


def test_a02_secure_error_is_generic_but_correlated(app, json_get, caplog):
    response = json_get("/lab/a02/secure/order-lookup?id=explode")
    body = response.get_data(as_text=True)
    assert response.status_code == 500
    assert response.json["internal_details_returned"] is False
    assert response.json["error_code"] == "INTERNAL_ERROR"
    assert response.json["request_id"]
    assert response.json["correlated_server_event"] is True
    assert response.json["server_event_type"] == "application_error"
    assert response.json["server_event_details_minimised"] is True
    assert SYNTHETIC_CONFIG_MARKER not in body
    assert SYNTHETIC_TRACE_MARKER not in body
    assert SYNTHETIC_PATH not in body
    with app.app_context():
        event = get_db().execute(
            "SELECT event_type, request_id, details FROM audit_events WHERE event_type = 'application_error'"
        ).fetchone()
    assert event["request_id"] == response.json["request_id"]
    assert "lab-api-key" not in event["details"]
    assert response.json["request_id"] in caplog.text
    visible_event = json_get(
        f"/observer/a02/audit-event?request_id={response.json['request_id']}",
        headers=OBSERVER_HEADERS,
    )
    assert visible_event.status_code == 200
    assert visible_event.json["event_found"] is True
    assert visible_event.json["event_type"] == "application_error"
    assert visible_event.json["event_details"] == {
        "route": "order-lookup",
        "error_class": "RuntimeError",
    }
    assert visible_event.json["stored_detail_keys"] == ["error_class", "route"]
