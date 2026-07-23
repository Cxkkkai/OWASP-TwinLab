from __future__ import annotations

import html
import json
import re
import runpy

import pytest

from app import create_app
from app.db import get_db
from app.lab_demo import LAB_DEMOS
from app.lab_registry import LABS
from app.workbench import LAB_WORKBENCH


CANONICAL_OWASP_2025 = {
    "a01": "Broken Access Control",
    "a02": "Security Misconfiguration",
    "a03": "Software Supply Chain Failures",
    "a04": "Cryptographic Failures",
    "a05": "Injection",
    "a06": "Insecure Design",
    "a07": "Authentication Failures",
    "a08": "Software or Data Integrity Failures",
    "a09": "Security Logging and Alerting Failures",
    "a10": "Mishandling of Exceptional Conditions",
}


def test_index_contains_all_ten_owasp_2025_categories(client):
    response = client.get("/")
    text = response.get_data(as_text=True)
    assert response.status_code == 200
    assert "intentionally vulnerable" in text.lower()
    assert "localhost" in text.lower()
    for lab in LABS:
        assert lab["owasp"] in text
        assert lab["name"] in text


def test_registry_matches_independent_canonical_2025_map():
    assert {lab["id"]: lab["name"] for lab in LABS} == CANONICAL_OWASP_2025
    assert [lab["owasp"] for lab in LABS] == [f"A{i:02d}:2025" for i in range(1, 11)]


def test_registry_contains_complete_course_linked_analysis_and_contracts():
    expected_sections = {"what", "why", "how", "learning", "boundary"}
    expected_contract_ids = {"v_positive", "v_security", "s_security", "s_positive"}
    for lab in LABS:
        analysis = lab["analysis"]
        assert set(analysis) == expected_sections, lab["id"]
        for key in (
            "actor",
            "asset",
            "precondition",
            "weakness",
            "mechanism",
            "failed_decision",
            "attack_technique",
            "trust_boundary",
        ):
            assert analysis["what"][key], (lab["id"], key)
        for key in ("security_property", "likelihood", "threat_chain", "impact", "if_unfixed"):
            assert analysis["why"][key], (lab["id"], key)
        for key in ("control", "why_it_works", "comparison", "observed_change", "legitimate_check"):
            assert analysis["how"][key], (lab["id"], key)
        for key in (
            "before",
            "after",
            "mistake",
            "correction",
            "redo",
            "course_topic",
            "course_source",
        ):
            assert analysis["learning"][key], (lab["id"], key)
        assert analysis["learning"]["before"].startswith("I ")
        assert analysis["learning"]["after"].startswith("I ")
        assert analysis["boundary"]["supports"]
        assert analysis["boundary"]["does_not_prove"]
        assert analysis["boundary"]["residual_risks"]
        assert {case["id"] for case in lab["contract"]} == expected_contract_ids
        assert all(case["expected"] and case["oracle"] for case in lab["contract"])
        if lab["depth"] == "Deep":
            assert len(lab["deep_dive"]["attack_chain"]) >= 4
            for key in ("insufficient_fix", "control_choice", "evidence_reading", "tradeoff"):
                assert lab["deep_dive"][key], (lab["id"], key)
        else:
            assert "deep_dive" not in lab

    assert [lab["id"] for lab in LABS if lab["depth"] == "Deep"] == ["a01", "a02", "a05", "a07"]
    assert len([lab for lab in LABS if lab["depth"] == "Compact"]) == 6


def test_every_module_overview_renders(client):
    for lab in LABS:
        response = client.get(f"/lab/{lab['id']}/")
        assert response.status_code == 200, lab["id"]
        text = response.get_data(as_text=True)
        assert lab["owasp"] in text
        assert lab["name"] in text
        assert "Actor capability" in text
        assert "Protected asset" in text
        assert "Security invariant" in text
        assert "Abuse action" in text
        assert "Executable experiment verdict" in text
        assert "Vulnerability reproduced" in text
        assert "Target control effective" in text
        assert "Authoritative state safe" in text
        assert "Legitimate use preserved" in text
        assert "Implementation inspector" in text
        assert "Vulnerable code" in text
        assert "Controlled code" in text
        assert "Run complete comparison" in text
        assert "Replay with control" in text
        assert "Verify intended use" in text
        assert "Equivalent-condition rule" in text
        assert "Request, response and observer trace" in text
        assert "Vulnerable" in text
        assert "Controlled" in text
        assert (
            "Deep investigation" if lab["depth"] == "Deep" else "Compact check"
        ) in text
        assert "What did I learn?" not in text
        assert "Why is this a real security threat?" not in text
        assert "Course connection:" not in text
        assert "Trust boundary crossed:" not in text
        assert 'id="analysis-what"' not in text
        assert 'id="analysis-learning"' not in text


def test_every_module_exposes_an_operational_attacker_journey(client):
    for lab in LABS:
        lab_id = lab["id"]
        journey = LAB_WORKBENCH[lab_id]["attack_execution"]
        assert journey is LAB_WORKBENCH[lab_id]["attacker_journey"]
        for key in (
            "objective",
            "starting_position",
            "hypothesis",
            "baseline",
            "manipulation",
            "failed_server_decision",
            "failed_decision",
            "payoff",
            "obtained_effect",
        ):
            assert journey[key], (lab_id, key)

        minimum_steps = 3 if lab["depth"] == "Deep" else 2
        assert len(journey["steps"]) >= minimum_steps
        page_text = client.get(f"/lab/{lab_id}/").get_data(as_text=True)
        config = _runner_config(page_text)
        vulnerable_step_ids = {
            step["id"] for step in config["runs"]["vulnerable"]["steps"]
        }
        for step in journey["steps"]:
            assert step["id"] and step["action"] and step["expected_signal"]
            if step["evidence_step"] is None:
                assert step["evidence_path"] is None
                assert step["evidence"] is None
            else:
                assert step["evidence_step"] in vulnerable_step_ids, (
                    lab_id,
                    step["evidence_step"],
                )
                assert step["evidence_path"]
                assert step["evidence"].startswith(
                    f"steps.{step['evidence_step']}."
                )

        text = html.unescape(page_text)
        assert 'data-adversary-execution' in text
        assert 'data-run-adversary' in text
        assert "Attacker hypothesis" in text
        assert "Failed decision" in text
        assert "Obtained effect" in text
        assert "Controlled interception" in text
        assert journey["objective"] in text
        assert journey["hypothesis"] in text
        assert journey["failed_decision"] in text
        assert journey["obtained_effect"] in text
        for step in journey["steps"]:
            assert step["action"] in text
            assert step["expected_signal"] in text

        # The attack path is a first-class product surface, not another
        # disclosure hidden behind the request/response details element.
        assert text.index("data-adversary-execution") < text.index(
            'class="experiment-runner'
        )


def test_deep_attack_paths_make_the_decisive_manipulation_visible(client):
    a01 = html.unescape(client.get("/lab/a01/").get_data(as_text=True))
    assert "Alice's 101" in a01 and "Bob's 202" in a01
    assert "/lab/a01/vulnerable/orders/202" in a01

    a02 = html.unescape(client.get("/lab/a02/").get_data(as_text=True))
    assert "id=explode" in a02
    assert "filesystem path" in a02 and "customer-facing response" in a02

    a05 = html.unescape(client.get("/lab/a05/").get_data(as_text=True))
    assert "%' OR 1=1 --" in a05
    assert "quote exits the string" in a05
    assert "attacker-supplied SQL structure" in a05

    a07 = html.unescape(client.get("/lab/a07/").get_data(as_text=True))
    assert "captured pre-logout Admin token" in a07
    assert "Replay Old Token" in a07
    assert "server session remains active=true" in a07


def test_report_analysis_is_not_exposed_as_product_pages(client):
    assert client.get("/learning").status_code == 404
    assert client.get("/journey").status_code == 404
    index_text = client.get("/").get_data(as_text=True)
    assert "Course learning map" not in index_text
    assert "Project journey" not in index_text
    assert "What did I learn?" not in index_text


def test_html_result_presents_observed_output_without_report_analysis(client):
    client.post("/identity/alice", data={"next": "/lab/a01/"})
    response = client.get("/lab/a01/vulnerable/orders/202")
    text = response.get_data(as_text=True)
    assert response.status_code == 200
    assert "HTTP 200" in text
    assert "VULNERABLE" in text
    assert "Observed output" in text
    assert "Authorization decision" in text
    assert "Returned object owner" in text
    assert "Sensitive data returned" in text
    assert "Raw response" in text
    assert "What did I learn?" not in text
    assert "Course:" not in text
    assert "Trust boundary:" not in text
    assert 'id="result-analysis-what"' not in text
    assert "order disclosed without ownership check" in text


def test_controlled_result_uses_the_same_user_facing_label_as_the_module(client):
    client.post("/identity/alice", data={"next": "/lab/a01/"})
    text = client.get("/lab/a01/secure/orders/202").get_data(as_text=True)
    assert "CONTROLLED" in text
    assert ">SECURE<" not in text


def test_health_endpoint_states_scope_and_release(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json == {"status": "ok", "scope": "localhost synthetic lab", "owasp_release": "2025"}


def test_reset_restores_seed_and_clears_runtime_state(app, client, json_post):
    client.post("/identity/alice", data={"next": "/"})
    json_post(
        "/lab/a06/vulnerable/apply",
        data={"actor": "alice", "coupon": "WELCOME10"},
    )
    response = client.post("/reset")
    assert response.status_code == 302
    with app.app_context():
        db = get_db()
        assert db.execute("SELECT COUNT(*) FROM coupon_uses").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0
        assert db.execute("SELECT price_cents FROM products WHERE id = 1").fetchone()[0] == 4900


def test_reset_returns_to_safe_local_module_and_rejects_external_next(client):
    local = client.post("/reset", data={"next": "/lab/a05/"})
    assert local.status_code == 302
    assert local.headers["Location"].endswith("/lab/a05/")
    external = client.post("/reset", data={"next": "https://example.com/redirect"})
    assert external.status_code == 302
    assert external.headers["Location"].endswith("/")


def test_run_script_calls_flask_with_loopback_and_debug_disabled(monkeypatch):
    captured = {}

    def fake_run(_app, **kwargs):
        captured.update(kwargs)

    monkeypatch.setattr("flask.Flask.run", fake_run)
    runpy.run_path("run.py", run_name="__main__")
    assert captured == {
        "host": "127.0.0.1",
        "port": 5000,
        "debug": False,
        "use_reloader": False,
    }


def test_application_rejects_non_loopback_clients(client):
    assert client.get("/health", environ_overrides={"REMOTE_ADDR": "127.0.0.1"}).status_code == 200
    assert client.get("/health", environ_overrides={"REMOTE_ADDR": "::1"}).status_code == 200
    assert client.get("/health", environ_overrides={"REMOTE_ADDR": "198.51.100.25"}).status_code == 403
    assert client.post("/reset", environ_overrides={"REMOTE_ADDR": "198.51.100.25"}).status_code == 403


def test_identity_selection_is_post_only_and_rejects_external_next(client):
    assert client.get("/identity/alice").status_code == 405
    local = client.post("/identity/alice", data={"next": "/lab/a01/"})
    assert local.status_code == 302
    assert local.headers["Location"].endswith("/lab/a01/")
    external = client.post("/identity/alice", data={"next": "https://example.com/phish"})
    assert external.status_code == 302
    assert external.headers["Location"].endswith("/")
    for unsafe_next in ("//example.com/phish", "/\\\\example.com/phish"):
        rejected = client.post("/identity/alice", data={"next": unsafe_next})
        assert rejected.status_code == 302
        assert rejected.headers["Location"].endswith("/")


def test_identity_context_can_be_cleared_after_an_assurance_run(client):
    selected = client.post("/identity/alice?format=json")
    assert selected.json["actor"] == "alice"
    assert selected.json["plane"] == "runner"
    assert selected.headers["X-TwinLab-Plane"] == "runner"
    cleared = client.post("/identity-clear?format=json")
    assert cleared.status_code == 200
    assert cleared.json["actor"] is None
    assert cleared.headers["X-TwinLab-Plane"] == "runner"
    assert client.get("/lab/a01/secure/orders/101?format=json").status_code == 401


def test_state_changing_lab_routes_reject_get(client):
    for path in (
        "/lab/a04/vulnerable/compare",
        "/lab/a06/vulnerable/apply",
        "/lab/a07/vulnerable/login",
        "/lab/a07/vulnerable/logout",
        "/lab/a08/vulnerable/price-update",
        "/lab/a09/vulnerable/login",
    ):
        assert client.get(path).status_code == 405, path


def test_reset_is_disabled_if_local_only_mode_is_disabled(app, client):
    app.config["LAB_LOCAL_ONLY"] = False
    assert client.post("/reset").status_code == 403


def test_non_testing_app_refuses_to_reset_an_arbitrary_database_path(tmp_path):
    with pytest.raises(RuntimeError, match="dedicated TwinLab instance path"):
        create_app({"DATABASE": str(tmp_path / "not-the-lab.sqlite3")})


def test_route_map_contains_every_canonical_overview_and_pair(app):
    rules = {rule.rule for rule in app.url_map.iter_rules()}
    for lab_id in CANONICAL_OWASP_2025:
        assert f"/lab/{lab_id}/" in rules
        module_rules = {rule for rule in rules if rule.startswith(f"/lab/{lab_id}/")}
        assert any("vulnerable" in rule or "<variant>" in rule for rule in module_rules)
        assert any("secure" in rule or "<variant>" in rule for rule in module_rules)


def _runner_config(page_text: str) -> dict:
    match = re.search(
        r'<script id="lab-runner-config" type="application/json">\s*(.*?)\s*</script>',
        page_text,
        re.DOTALL,
    )
    assert match
    return json.loads(html.unescape(match.group(1)))


def _with_json_format(path: str) -> str:
    return f"{path}{'&' if '?' in path else '?'}format=json"


def _resolve_runner_value(value, runtime):
    if isinstance(value, str):
        return re.sub(
            r"\{\{([a-zA-Z0-9_]+)\}\}",
            lambda match: str(runtime[match.group(1)]),
            value,
        )
    if isinstance(value, dict):
        return {key: _resolve_runner_value(item, runtime) for key, item in value.items()}
    if isinstance(value, list):
        return [_resolve_runner_value(item, runtime) for item in value]
    return value


def test_every_runner_action_rendered_by_module_pages_reaches_its_endpoint(client):
    observed_actions = 0
    for lab_id in CANONICAL_OWASP_2025:
        page = client.get(f"/lab/{lab_id}/")
        config = _runner_config(page.get_data(as_text=True))
        if config["setup"]:
            setup = config["setup"]
            response = client.open(
                setup["url"],
                method=setup["method"],
                data=setup["fields"],
            )
            assert response.status_code not in {404, 405}
        runtime = {}
        for run in config["runs"].values():
            for unresolved_step in run["steps"]:
                step = _resolve_runner_value(unresolved_step, runtime)
                headers = {"Accept": "application/json", **step.get("headers", {})}
                request_kwargs = {
                    "method": step["method"],
                    "headers": headers,
                }
                if "raw_body" in step:
                    request_kwargs["data"] = step["raw_body"]
                else:
                    request_kwargs["data"] = step.get("fields", {})
                response = client.open(_with_json_format(step["url"]), **request_kwargs)
                assert response.status_code != 405, (lab_id, step["url"])
                assert response.status_code == 204 or response.is_json, (lab_id, step["url"])
                if response.is_json:
                    for runtime_name, response_path in step.get("capture", {}).items():
                        value = response.json
                        for part in response_path.split("."):
                            value = value[part]
                        runtime[runtime_name] = value
                observed_actions += 1
    # The executable contract currently contains 90 real target/observer actions.
    # Keeping this explicit makes an accidentally deleted evidence step visible.
    assert observed_actions == 90


def test_a04_paired_ui_uses_the_same_attack_candidate(client):
    config = _runner_config(client.get("/lab/a04/").get_data(as_text=True))
    assert config["runs"]["vulnerable"]["steps"][0]["fields"]["candidate"] == "wrong-password"
    assert config["runs"]["controlled"]["steps"][0]["fields"]["candidate"] == "wrong-password"
    assert config["runs"]["legitimate"]["steps"][0]["fields"]["candidate"] == "correct-horse"


def test_runner_specs_cover_ten_real_source_comparisons():
    assert set(LAB_DEMOS) == set(CANONICAL_OWASP_2025)
    for lab_id, demo in LAB_DEMOS.items():
        assert demo["request"] and demo["replay_request"] and demo["input_lock"]
        expected_steps = 4 if demo["depth"] == "deep" else 2
        assert len(demo["steps"]) == expected_steps, lab_id
        assert set(demo["observations"]) == {"vulnerable", "controlled", "legitimate"}
        for variant in ("vulnerable_code", "controlled_code"):
            excerpt = demo[variant]
            source = open(excerpt["file"], encoding="utf-8").read()
            assert excerpt["start_anchor"] in source, (lab_id, variant)
            assert excerpt["end_anchor"] in source, (lab_id, variant)
            assert excerpt["lines"], (lab_id, variant)
            assert any(line["focus"] for line in excerpt["lines"]), (lab_id, variant)


def test_normal_use_pages_surface_operational_results(client):
    a02 = client.get("/lab/a02/secure/order-lookup?id=101").get_data(as_text=True)
    assert "Order ID" in a02 and ">101<" in a02

    a05 = client.get("/lab/a05/secure/search?q=Security").get_data(as_text=True)
    assert "Results returned" in a05 and ">1<" in a05

    client.post("/identity/bob", data={"next": "/"})
    a06 = client.post("/lab/a06/secure/legitimate").get_data(as_text=True)
    assert "Actor" in a06 and "bob" in a06
    assert "Redemption number" in a06 and "Discount percent" in a06

    a07 = client.post(
        "/lab/a07/secure/login",
        data={"username": "admin", "password": "demo-admin"},
    ).get_data(as_text=True)
    assert "Username" in a07 and "admin" in a07
    assert "Role" in a07 and "Session lifetime" in a07

    a09 = client.post(
        "/lab/a09/secure/login",
        data={"username": "admin", "password": "demo-admin"},
    ).get_data(as_text=True)
    assert "Authenticated" in a09 and "Subject" in a09 and "Role" in a09
