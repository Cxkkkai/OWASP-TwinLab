from __future__ import annotations

import hashlib
import hmac
import json
import re
import sqlite3

import pytest

from app import create_app
from app.db import get_db
from app.modules.compact import TRUSTED_SHA256
from app.trusted_manifest import TRUSTED_A03_MANIFEST


OBSERVER_HEADERS = {"X-TwinLab-Observer": "evidence-console"}


def _select_identity(client, username: str) -> None:
    response = client.post(f"/identity/{username}", data={"next": "/"})
    assert response.status_code == 302


def test_a03_trusted_repository_is_accepted_by_both_variants(json_get):
    for variant in ("vulnerable", "secure"):
        response = json_get(f"/lab/a03/{variant}/verify?repository=trusted")
        assert response.status_code == 200
        assert response.json["accepted"] is True
        assert response.json["selected_version"] == "2.4.1"
        assert response.json["contains_untrusted_marker"] is False


def test_a03_floating_latest_selects_unreviewed_but_secure_stays_pinned(json_get):
    vulnerable = json_get("/lab/a03/vulnerable/verify?repository=newer")
    secure = json_get("/lab/a03/secure/verify?repository=newer")
    assert vulnerable.status_code == 200
    assert vulnerable.json["accepted"] is True
    assert vulnerable.json["selection_policy"] == "floating-latest"
    assert vulnerable.json["selected_version"] == "2.4.2"
    assert vulnerable.json["contains_untrusted_marker"] is True
    assert secure.status_code == 200
    assert secure.json["accepted"] is True
    assert secure.json["selection_policy"] == "trusted-manifest-pin"
    assert secure.json["selected_version"] == "2.4.1"
    assert secure.json["contains_untrusted_marker"] is False


def test_a03_secure_rejects_modified_bytes_at_the_pinned_version(json_get):
    response = json_get("/lab/a03/secure/verify?repository=pinned-tamper")
    assert response.status_code == 422
    assert response.json["accepted"] is False
    assert response.json["actual_sha256"] != response.json["expected_sha256"]
    assert response.json["expected_sha256"] == TRUSTED_SHA256 == TRUSTED_A03_MANIFEST["sha256"]
    assert response.json["digest_match"] is False
    assert len(response.json["expected_digest_fingerprint"]) == 12
    assert len(response.json["actual_digest_fingerprint"]) == 12


def _a04_compare(json_post, variant: str, candidate: str):
    return json_post(
        f"/lab/a04/{variant}/compare",
        data={"password": "correct-horse", "candidate": candidate},
    )


def test_a04_vulnerable_correct_candidate_verifies(json_post):
    response = _a04_compare(json_post, "vulnerable", "correct-horse")
    assert response.status_code == 200
    assert response.json["candidate_verified"] is True


def test_a04_unsalted_hashes_match_but_random_salted_scrypt_values_do_not(json_post):
    vulnerable = _a04_compare(json_post, "vulnerable", "correct-horse")
    secure = _a04_compare(json_post, "secure", "correct-horse")
    assert vulnerable.status_code == secure.status_code == 200
    assert vulnerable.json["hashes_equal"] is True
    assert vulnerable.json["alice_record_fingerprint"] == vulnerable.json["bob_record_fingerprint"]
    assert vulnerable.json["unique_salt_per_account"] is False
    assert secure.json["hashes_equal"] is False
    assert secure.json["alice_record_fingerprint"] != secure.json["bob_record_fingerprint"]
    assert len(secure.json["alice_record_fingerprint"]) == 12
    assert len(secure.json["bob_record_fingerprint"]) == 12
    assert secure.json["unique_salt_per_account"] is True
    assert secure.json["salt_lengths"] == [16, 16]
    assert "scrypt" in secure.json["algorithm"]
    assert secure.json["sensitive_record_values_returned"] is False
    assert "alice_hash" not in secure.json and "bob_hash" not in secure.json
    serialized = secure.get_data(as_text=True).lower()
    assert "correct-horse" not in serialized
    assert re.search(r"\b[0-9a-f]{64}\b", serialized) is None


def test_a04_secure_verification_preserves_legitimate_path(json_post):
    accepted = _a04_compare(json_post, "secure", "correct-horse")
    rejected = _a04_compare(json_post, "secure", "wrong")
    assert accepted.status_code == rejected.status_code == 200
    assert accepted.json["candidate_verified"] is True
    assert rejected.json["candidate_verified"] is False


def _apply_coupon(json_post, variant: str, actor: str):
    return json_post(
        f"/lab/a06/{variant}/apply",
        data={"actor": actor, "coupon": "WELCOME10"},
    )


def test_a06_vulnerable_allows_coupon_replay(app, client, json_post):
    _select_identity(client, "alice")
    first = _apply_coupon(json_post, "vulnerable", "alice")
    second = _apply_coupon(json_post, "vulnerable", "alice")
    assert first.status_code == second.status_code == 201
    assert first.json["redemption_number"] == 1
    assert second.json["redemption_number"] == 2
    assert second.json["accepted"] is True
    with app.app_context():
        assert get_db().execute(
            "SELECT COUNT(*) FROM coupon_uses WHERE user_id = 1 AND variant = 'vulnerable'"
        ).fetchone()[0] == 2


def test_a06_secure_atomic_invariant_blocks_replay_but_preserves_other_user(app, client, json_post):
    _select_identity(client, "alice")
    first = _apply_coupon(json_post, "secure", "alice")
    replay = _apply_coupon(json_post, "secure", "alice")
    _select_identity(client, "bob")
    bob = _apply_coupon(json_post, "secure", "bob")
    assert first.status_code == 201 and first.json["accepted"] is True
    assert replay.status_code == 409 and replay.json["accepted"] is False
    assert bob.status_code == 201 and bob.json["accepted"] is True
    with app.app_context():
        db = get_db()
        assert db.execute(
            "SELECT COUNT(*) FROM coupon_uses WHERE user_id = 1 AND variant = 'secure'"
        ).fetchone()[0] == 1
        with pytest.raises(sqlite3.IntegrityError):
            db.execute(
                "INSERT INTO coupon_uses (user_id, coupon_code, variant, used_at) VALUES (1, 'WELCOME10', 'secure', 0)"
            )
        db.rollback()


def test_a06_guided_flows_make_first_use_and_replay_visible_in_one_result(client, json_post):
    _select_identity(client, "alice")
    vulnerable = json_post("/lab/a06/vulnerable/demo")
    secure = json_post("/lab/a06/secure/demo")
    assert vulnerable.status_code == secure.status_code == 200
    assert vulnerable.json["first_use_status"] == secure.json["first_use_status"] == 201
    assert vulnerable.json["replay_status"] == 201
    assert vulnerable.json["replay_blocked"] is False
    assert secure.json["replay_status"] == 409
    assert secure.json["replay_blocked"] is True
    assert vulnerable.json["claim_supported"] is True
    assert secure.json["claim_supported"] is True
    _select_identity(client, "bob")
    first_bob = json_post("/lab/a06/secure/legitimate")
    repeated_bob_demo = json_post("/lab/a06/secure/legitimate")
    assert first_bob.status_code == repeated_bob_demo.status_code == 201


def test_a06_direct_runner_endpoints_show_database_state(client, json_get, json_post):
    _select_identity(client, "alice")
    json_post(
        "/observer/a06/vulnerable/reset-case",
        data={"subject": "alice", "coupon": "WELCOME10"},
        headers=OBSERVER_HEADERS,
    )
    _apply_coupon(json_post, "vulnerable", "alice")
    _apply_coupon(json_post, "vulnerable", "alice")
    vulnerable_state = json_get(
        "/observer/a06/vulnerable/state?subject=alice&coupon=WELCOME10",
        headers=OBSERVER_HEADERS,
    )
    json_post(
        "/observer/a06/secure/reset-case",
        data={"subject": "alice", "coupon": "WELCOME10"},
        headers=OBSERVER_HEADERS,
    )
    _apply_coupon(json_post, "secure", "alice")
    secure_replay = _apply_coupon(json_post, "secure", "alice")
    secure_state = json_get(
        "/observer/a06/secure/state?subject=alice&coupon=WELCOME10",
        headers=OBSERVER_HEADERS,
    )
    assert vulnerable_state.json["use_count"] == 2
    assert vulnerable_state.json["database_unique_invariant"] is False
    assert secure_replay.status_code == 409
    assert secure_state.json["use_count"] == 1
    assert secure_state.json["database_unique_invariant"] is True


def test_a06_target_uses_signed_session_identity_and_ignores_actor_field(app, client, json_post):
    _select_identity(client, "alice")
    response = _apply_coupon(json_post, "secure", "bob")
    assert response.status_code == 201
    assert response.json["actor"] == "alice"
    assert response.json["identity_source"] == "server_session"
    assert response.json["request_actor_ignored"] is True
    with app.app_context():
        db = get_db()
        assert db.execute(
            "SELECT COUNT(*) FROM coupon_uses WHERE user_id = 1 AND variant = 'secure'"
        ).fetchone()[0] == 1
        assert db.execute(
            "SELECT COUNT(*) FROM coupon_uses WHERE user_id = 2 AND variant = 'secure'"
        ).fetchone()[0] == 0


def test_a06_target_requires_a_signed_session_even_if_actor_is_submitted(json_post):
    response = _apply_coupon(json_post, "secure", "alice")
    assert response.status_code == 401
    assert response.json["authenticated"] is False


def _price_signature(key: bytes, raw_body: bytes) -> str:
    return "sha256=" + hmac.new(key, raw_body, hashlib.sha256).hexdigest()


def _post_price(client, variant: str, raw_body: bytes, signature: str | None = None):
    headers = {"Content-Type": "application/json"}
    if signature is not None:
        headers["X-TwinLab-Signature"] = signature
    return client.post(
        f"/lab/a08/{variant}/price-update?format=json",
        data=raw_body,
        headers=headers,
    )


def test_a08_vulnerable_legitimate_unsigned_update_succeeds(app, client):
    body = b'{"product_id":1,"price_cents":5100}'
    response = _post_price(client, "vulnerable", body)
    assert response.status_code == 204
    with app.app_context():
        assert get_db().execute("SELECT price_cents FROM products WHERE id = 1").fetchone()[0] == 5100


def test_a08_vulnerable_accepts_tampered_raw_message(app, client):
    trusted = b'{"product_id":1,"price_cents":4900}'
    tampered = b'{"product_id":1,"price_cents":100}'
    stale_signature = _price_signature(app.config["DEMO_HMAC_KEY"], trusted)
    response = _post_price(client, "vulnerable", tampered, stale_signature)
    assert response.status_code == 204
    with app.app_context():
        assert get_db().execute("SELECT price_cents FROM products WHERE id = 1").fetchone()[0] == 100


def test_a08_secure_rejects_missing_and_byte_modified_signatures_without_state_change(app, client):
    trusted = b'{"product_id":1,"price_cents":4900}'
    tampered = b'{"product_id":1,"price_cents":100}'
    stale_signature = _price_signature(app.config["DEMO_HMAC_KEY"], trusted)
    missing = _post_price(client, "secure", tampered)
    modified = _post_price(client, "secure", tampered, stale_signature)
    whitespace_modified = _post_price(
        client,
        "secure",
        b'{"product_id": 1,"price_cents":4900}',
        stale_signature,
    )
    assert [missing.status_code, modified.status_code, whitespace_modified.status_code] == [401, 401, 401]
    assert all(response.json["accepted"] is False for response in (missing, modified, whitespace_modified))
    with app.app_context():
        db = get_db()
        assert db.execute("SELECT price_cents FROM products WHERE id = 1").fetchone()[0] == 4900
        serialized = " ".join(
            row["details"]
            for row in db.execute(
                "SELECT details FROM audit_events WHERE event_type = 'price_integrity_failed'"
            ).fetchall()
        )
    assert stale_signature not in serialized
    assert app.config["DEMO_HMAC_KEY"].decode() not in serialized
    response_bodies = " ".join(
        response.get_data(as_text=True) for response in (missing, modified, whitespace_modified)
    )
    assert stale_signature not in response_bodies
    assert app.config["DEMO_HMAC_KEY"].decode() not in response_bodies


def test_a08_secure_exact_raw_body_signature_updates_and_returns_204(app, client):
    body = b'{"product_id":1,"price_cents":5100}'
    signature = _price_signature(app.config["DEMO_HMAC_KEY"], body)
    response = _post_price(client, "secure", body, signature)
    assert response.status_code == 204
    assert response.data == b""
    with app.app_context():
        db = get_db()
        assert db.execute("SELECT price_cents FROM products WHERE id = 1").fetchone()[0] == 5100
        event = db.execute(
            "SELECT details FROM audit_events WHERE event_type = 'price_integrity_verified'"
        ).fetchone()
    assert signature not in event["details"]


def test_a08_ui_demos_are_isolated_and_show_the_price_state(app, json_post):
    vulnerable = json_post(
        "/lab/a08/vulnerable/demo", data={"case": "tampered"}
    )
    assert vulnerable.status_code == 200
    assert vulnerable.json["before_price_cents"] == 4900
    assert vulnerable.json["after_price_cents"] == 100
    assert vulnerable.json["state_changed"] is True

    controlled = json_post(
        "/lab/a08/secure/demo", data={"case": "tampered"}
    )
    assert controlled.status_code == 401
    assert controlled.json["before_price_cents"] == 4900
    assert controlled.json["after_price_cents"] == 4900
    assert controlled.json["state_changed"] is False

    legitimate = json_post(
        "/lab/a08/secure/demo", data={"case": "valid"}
    )
    assert legitimate.status_code == 200
    assert legitimate.json["api_status"] == 204
    assert legitimate.json["before_price_cents"] == 4900
    assert legitimate.json["after_price_cents"] == 5100
    assert legitimate.json["state_changed"] is True

    with app.app_context():
        assert get_db().execute(
            "SELECT price_cents FROM products WHERE id = 1"
        ).fetchone()[0] == 5100


def test_a08_direct_runner_reset_update_and_state_endpoints(app, client, json_get, json_post):
    reset = json_post("/observer/a08/secure/reset-price", headers=OBSERVER_HEADERS)
    assert reset.json["price_cents"] == 4900
    trusted = b'{"product_id":1,"price_cents":5100}'
    tampered = b'{"product_id":1,"price_cents":100}'
    stale_signature = _price_signature(app.config["DEMO_HMAC_KEY"], trusted)
    rejected = _post_price(client, "secure", tampered, stale_signature)
    state = json_get("/observer/a08/secure/price-state", headers=OBSERVER_HEADERS)
    assert rejected.status_code == 401
    assert state.json["price_cents"] == 4900


class FakeClock:
    def __init__(self, value: int = 1_000):
        self.value = value

    def __call__(self) -> int:
        return self.value


def _a09_login(json_post, variant: str, password: str):
    return json_post(
        f"/lab/a09/{variant}/login",
        data={"username": "admin", "password": password},
    )


def test_a09_vulnerable_valid_login_is_preserved(app, json_post):
    response = _a09_login(json_post, "vulnerable", "demo-admin")
    assert response.status_code == 200
    assert response.json["authenticated"] is True
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM audit_events").fetchone()[0] == 0


def test_a09_vulnerable_failures_return_401_but_leave_no_signal(app, json_post):
    responses = [_a09_login(json_post, "vulnerable", "DEMO_WRONG_PASSWORD") for _ in range(3)]
    assert all(response.status_code == 401 for response in responses)
    assert responses[-1].json["failure_event_count"] == 0
    assert responses[-1].json["alert_count"] == 0
    with app.app_context():
        db = get_db()
        assert db.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 0


def test_a09_secure_threshold_is_zero_zero_one_and_events_are_minimised(app, json_post):
    clock = FakeClock()
    app.config["A09_CLOCK"] = clock
    responses = []
    for _ in range(3):
        responses.append(_a09_login(json_post, "secure", "DEMO_WRONG_PASSWORD"))
        clock.value += 10
    assert all(response.status_code == 401 for response in responses)
    assert [response.json["alert_count"] for response in responses] == [0, 0, 1]
    assert [response.json["failure_event_count"] for response in responses] == [1, 2, 3]
    with app.app_context():
        db = get_db()
        rows = db.execute(
            "SELECT event_type, actor, details, request_id FROM audit_events ORDER BY id"
        ).fetchall()
        alerts = db.execute("SELECT alert_type, actor, event_count FROM alerts").fetchall()
    assert len(rows) == 3
    assert len(alerts) == 1
    assert tuple(alerts[0]) == ("AUTH_FAILURE_THRESHOLD", "admin", 3)
    for row in rows:
        details = json.loads(row["details"])
        assert row["event_type"] == details["event_type"] == "AUTH_FAILURE"
        assert row["actor"] == details["subject"] == "admin"
        assert row["request_id"] == details["request_id"]
        assert details["source_id"] == "synthetic-local-source"
        assert details["outcome"] == "failure"
        assert set(details) == {
            "timestamp",
            "event_type",
            "subject",
            "source_id",
            "outcome",
            "request_id",
            "comparison_run_id",
        }
        serialized = row["details"].lower()
        assert "demo_wrong_password" not in serialized
        assert "password" not in serialized
        assert "cookie" not in serialized
        assert "token" not in serialized


def test_a09_secure_failure_window_expires_using_fake_clock(app, json_post):
    clock = FakeClock()
    app.config["A09_CLOCK"] = clock
    for _ in range(2):
        response = _a09_login(json_post, "secure", "DEMO_WRONG_PASSWORD")
        assert response.json["alert_count"] == 0
        clock.value += 10
    clock.value += 61
    after_window = _a09_login(json_post, "secure", "DEMO_WRONG_PASSWORD")
    assert after_window.status_code == 401
    assert after_window.json["alert_count"] == 0
    _a09_login(json_post, "secure", "DEMO_WRONG_PASSWORD")
    threshold = _a09_login(json_post, "secure", "DEMO_WRONG_PASSWORD")
    assert threshold.json["alert_count"] == 1


def test_a09_secure_valid_login_emits_success_without_failure_alert(app, json_post):
    clock = FakeClock()
    app.config["A09_CLOCK"] = clock
    response = _a09_login(json_post, "secure", "demo-admin")
    assert response.status_code == 200
    assert response.json["authenticated"] is True
    with app.app_context():
        db = get_db()
        event = db.execute("SELECT event_type, details FROM audit_events").fetchone()
        assert event["event_type"] == "AUTH_SUCCESS"
        assert json.loads(event["details"])["outcome"] == "success"
        assert db.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 0


def test_a09_guided_flows_make_detection_sequence_visible_in_one_result(json_post):
    vulnerable = json_post("/lab/a09/vulnerable/demo")
    secure = json_post("/lab/a09/secure/demo")
    assert vulnerable.status_code == secure.status_code == 200
    assert [step["failure_event_count"] for step in vulnerable.json["guided_flow"]] == [0, 0, 0]
    assert [step["alert_count"] for step in vulnerable.json["guided_flow"]] == [0, 0, 0]
    assert [step["failure_event_count"] for step in secure.json["guided_flow"]] == [1, 2, 3]
    assert [step["alert_count"] for step in secure.json["guided_flow"]] == [0, 0, 1]
    assert vulnerable.json["valid_login"]["status"] == secure.json["valid_login"]["status"] == 200
    assert vulnerable.json["passwords_or_tokens_logged"] is False
    assert secure.json["passwords_or_tokens_logged"] is False
    assert vulnerable.json["claim_supported"] is True
    assert secure.json["claim_supported"] is True


def test_a09_direct_runner_state_lists_three_events_and_one_alert(json_get, json_post):
    json_post(
        "/observer/a09/secure/reset-case",
        data={"username": "admin"},
        headers=OBSERVER_HEADERS,
    )
    for _ in range(3):
        _a09_login(json_post, "secure", "DEMO_WRONG_PASSWORD")
    state = json_get(
        "/observer/a09/secure/state?username=admin", headers=OBSERVER_HEADERS
    )
    assert state.status_code == 200
    assert state.json["auth_failure_count"] == 3
    assert state.json["alert_count"] == 1
    assert [event["event_type"] for event in state.json["events"]] == [
        "AUTH_FAILURE",
        "AUTH_FAILURE",
        "AUTH_FAILURE",
    ]
    assert state.json["alerts"] == [
        {"alert_type": "AUTH_FAILURE_THRESHOLD", "event_count": 3}
    ]
    assert state.json["passwords_or_tokens_logged"] is False


def test_a09_telemetry_is_isolated_by_comparison_run_id(json_get, json_post):
    for _ in range(1):
        json_post(
            "/lab/a09/secure/login",
            data={
                "username": "admin",
                "password": "DEMO_WRONG_PASSWORD",
                "comparison_run_id": "run-alpha",
            },
        )
    for _ in range(3):
        json_post(
            "/lab/a09/secure/login",
            data={
                "username": "admin",
                "password": "DEMO_WRONG_PASSWORD",
                "comparison_run_id": "run-beta",
            },
        )
    alpha = json_get(
        "/observer/a09/secure/state?username=admin&comparison_run_id=run-alpha",
        headers=OBSERVER_HEADERS,
    )
    beta = json_get(
        "/observer/a09/secure/state?username=admin&comparison_run_id=run-beta",
        headers=OBSERVER_HEADERS,
    )
    assert (alpha.json["auth_failure_count"], alpha.json["alert_count"]) == (1, 0)
    assert (beta.json["auth_failure_count"], beta.json["alert_count"]) == (3, 1)


def test_a09_state_excludes_other_variants_and_system_audit_events(app, json_get, json_post):
    json_get("/lab/a02/secure/order-lookup?id=explode")
    json_post(
        "/lab/a09/secure/login",
        data={
            "username": "admin",
            "password": "DEMO_WRONG_PASSWORD",
            "comparison_run_id": "variant-scope",
        },
    )
    secure = json_get(
        "/observer/a09/secure/state?username=admin&comparison_run_id=variant-scope",
        headers=OBSERVER_HEADERS,
    )
    vulnerable = json_get(
        "/observer/a09/vulnerable/state?username=admin&comparison_run_id=variant-scope",
        headers=OBSERVER_HEADERS,
    )
    assert secure.json["auth_failure_count"] == 1
    assert vulnerable.json["event_count"] == 0
    with app.app_context():
        scopes = get_db().execute(
            "SELECT DISTINCT variant, comparison_run_id FROM audit_events ORDER BY variant"
        ).fetchall()
    assert {(row["variant"], row["comparison_run_id"]) for row in scopes} == {
        ("secure", "variant-scope"),
        ("system", "default"),
    }


def test_a10_fail_open_vs_fail_closed_on_same_exception_for_alice(client, json_get):
    _select_identity(client, "alice")
    vulnerable = json_get("/lab/a10/vulnerable/export?simulate=error&actor=admin")
    secure = json_get("/lab/a10/secure/export?simulate=error&actor=admin")
    assert vulnerable.status_code == 200
    assert vulnerable.json["actor"] == "alice"
    assert vulnerable.json["export_returned"] is True
    assert vulnerable.json["fail_open"] is True
    assert vulnerable.json["policy_result"] == "exception"
    assert vulnerable.json["fallback_decision"] == "allow"
    assert vulnerable.json["request_actor_ignored"] is True
    assert vulnerable.json["role"] == "customer"
    assert secure.status_code == 503
    assert secure.json["export_returned"] is False
    assert secure.json["policy_result"] == "exception"
    assert secure.json["fallback_decision"] == "deny"
    secure_body = secure.get_data(as_text=True)
    assert "SYNTHETIC-CUSTOMER-EXPORT" not in secure_body
    assert "ConnectionError" not in secure_body
    assert "controlled synthetic policy-service failure" not in secure_body
    assert "traceback" not in secure_body.lower()


def test_a10_explicit_admin_allow_preserves_legitimate_export_in_both_variants(client, json_get):
    _select_identity(client, "admin")
    for variant in ("vulnerable", "secure"):
        response = json_get(f"/lab/a10/{variant}/export?simulate=ok&actor=admin")
        assert response.status_code == 200
        assert response.json["actor"] == "admin"
        assert response.json["role"] == "admin"
        assert response.json["export_marker"] == "SYNTHETIC-CUSTOMER-EXPORT"


def test_a10_healthy_policy_denies_alice(client, json_get):
    _select_identity(client, "alice")
    response = json_get("/lab/a10/secure/export?simulate=ok&actor=admin")
    assert response.status_code == 403
    assert response.json["access_granted"] is False
    assert response.json["export_returned"] is False
    assert "SYNTHETIC-CUSTOMER-EXPORT" not in response.get_data(as_text=True)


def test_a10_query_actor_cannot_authenticate_an_unauthenticated_caller(json_get):
    response = json_get("/lab/a10/secure/export?simulate=ok&actor=admin")
    assert response.status_code == 401
    assert response.json["authenticated"] is False
    assert response.json["export_returned"] is False
    assert response.json["plane"] == "target"
    assert response.headers["X-TwinLab-Plane"] == "target"


def test_observer_endpoints_require_capability_and_label_the_plane(json_get):
    denied = json_get("/observer/a09/secure/state?username=admin")
    assert denied.status_code == 403
    assert denied.headers["X-TwinLab-Plane"] == "observer"
    allowed = json_get(
        "/observer/a09/secure/state?username=admin", headers=OBSERVER_HEADERS
    )
    assert allowed.status_code == 200
    assert allowed.json["plane"] == "observer"
    assert allowed.headers["X-TwinLab-Plane"] == "observer"
    legacy_denied = json_get("/lab/a09/secure/state?username=admin")
    assert legacy_denied.status_code == 403
    assert legacy_denied.headers["X-TwinLab-Plane"] == "observer"


def test_existing_telemetry_schema_is_migrated_without_a_destructive_reset(tmp_path):
    database = tmp_path / "legacy-twinlab.sqlite3"
    connection = sqlite3.connect(database)
    connection.executescript(
        """
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            role TEXT NOT NULL,
            password_hash TEXT NOT NULL
        );
        INSERT INTO users VALUES (1, 'alice', 'customer',
            '0000000000000000000000000000000000000000000000000000000000000000');
        CREATE TABLE orders (
            id INTEGER PRIMARY KEY,
            owner_id INTEGER NOT NULL,
            item TEXT NOT NULL,
            shipping_address TEXT NOT NULL,
            total_cents INTEGER NOT NULL
        );
        CREATE TABLE products (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            is_public INTEGER NOT NULL,
            price_cents INTEGER NOT NULL
        );
        CREATE TABLE sessions (
            token_hash TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            variant TEXT NOT NULL,
            active INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            created_at INTEGER NOT NULL
        );
        CREATE TABLE coupon_uses (
            user_id INTEGER NOT NULL,
            coupon_code TEXT NOT NULL,
            variant TEXT NOT NULL,
            used_at INTEGER NOT NULL
        );
        CREATE TABLE audit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            actor TEXT NOT NULL,
            details TEXT NOT NULL,
            request_id TEXT NOT NULL,
            created_at INTEGER NOT NULL
        );
        INSERT INTO audit_events
            (event_type, actor, details, request_id, created_at)
            VALUES ('legacy_event', 'alice', '{}', 'legacy-request', 1);
        CREATE TABLE alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_type TEXT NOT NULL,
            actor TEXT NOT NULL,
            event_count INTEGER NOT NULL,
            created_at INTEGER NOT NULL
        );
        """
    )
    connection.commit()
    connection.close()

    migrated_app = create_app({"TESTING": True, "DATABASE": str(database)})
    with migrated_app.app_context():
        db = get_db()
        audit_columns = {
            row["name"] for row in db.execute("PRAGMA table_info(audit_events)").fetchall()
        }
        alert_columns = {
            row["name"] for row in db.execute("PRAGMA table_info(alerts)").fetchall()
        }
        legacy_event = db.execute(
            "SELECT variant, comparison_run_id FROM audit_events WHERE request_id = 'legacy-request'"
        ).fetchone()
        password_hash = db.execute(
            "SELECT password_hash FROM users WHERE username = 'alice'"
        ).fetchone()["password_hash"]
    assert {"variant", "comparison_run_id"}.issubset(audit_columns)
    assert {"variant", "comparison_run_id"}.issubset(alert_columns)
    assert tuple(legacy_event) == ("system", "default")
    assert password_hash.startswith(("scrypt:", "pbkdf2:sha256:"))
