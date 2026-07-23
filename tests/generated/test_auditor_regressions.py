"""Generated from confirmed bounded Auditor counterexamples."""

from urllib.parse import quote


def test_generated_a05_counterexample(json_get):
    payload = "%' oR 1=1 /*"
    response = json_get("/lab/a05/secure/search?q=" + quote(payload, safe=""))
    assert response.status_code == 200
    assert response.json["hidden_exposed"] is False


def test_generated_a01_principal_override_is_ignored(client, json_get):
    client.post("/identity/alice")
    response = json_get(
        "/lab/a01/secure/orders/202",
        headers={"X-TwinLab-Actor": 'bob'},
    )
    assert response.status_code == 404
    assert response.json["sensitive_data_returned"] is False


def test_generated_a02_response_boundary_has_no_canary(json_get):
    response = json_get("/lab/a02/secure/order-lookup?id=explode")
    assert "X-TwinLab-Debug-Path" not in response.headers
    assert "X-TwinLab-Debug-Config" not in response.headers


def test_generated_a07_expired_session_is_rejected(json_get, json_post):
    login = json_post(
        "/lab/a07/secure/login",
        data={"username": "admin", "password": "demo-admin"},
    )
    token = login.json["lab_token"]
    json_post(
        "/observer/a07/secure/expire-session",
        headers={
            "X-TwinLab-Observer": "evidence-console",
            "X-Lab-Session": token,
        },
    )
    response = json_get(
        "/lab/a07/secure/admin",
        headers={"X-Lab-Session": token},
    )
    assert response.status_code == 401
    assert response.json["admin_data_returned"] is False
