from __future__ import annotations

import html
import json
import re
from pathlib import Path

from app.lab_registry import LABS


CHECK_IDS = {
    "vulnerability_reproduced",
    "control_effective",
    "authoritative_state_safe",
    "legitimate_use_preserved",
}
SUPPORTED_OPERATORS = {
    "equals",
    "not_equals",
    "truthy",
    "falsy",
    "in",
    "unchanged",
    "changed",
}


def _suite_manifest(page_text: str) -> dict:
    match = re.search(
        r'<script id="assurance-suite-manifest" type="application/json">\s*(.*?)\s*</script>',
        page_text,
        re.DOTALL,
    )
    assert match
    return json.loads(html.unescape(match.group(1)))


def test_index_renders_real_ten_by_four_assurance_matrix(client):
    response = client.get("/")
    text = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "Full assurance suite" in text
    assert "Run all 10 checks" in text
    assert "Download evidence JSON" in text
    assert 'src="/static/assurance-suite.js"' in text
    assert text.count("data-suite-row=") == 10
    assert text.count("data-suite-cell=") == 40


def test_suite_manifest_has_all_modules_and_four_acceptance_claims(client):
    manifest = _suite_manifest(client.get("/").get_data(as_text=True))

    assert [module["id"] for module in manifest["modules"]] == [lab["id"] for lab in LABS]
    for module in manifest["modules"]:
        assert module["url"] == f"/lab/{module['id']}/"
        assertions = [
            assertion
            for phase_assertions in module["assertions"].values()
            for assertion in phase_assertions
        ]
        assert {assertion["id"] for assertion in assertions} == CHECK_IDS
        assert {assertion["operator"] for assertion in assertions} <= SUPPORTED_OPERATORS
        assert all(assertion["path"] and assertion["label"] for assertion in assertions)


def test_suite_engine_requires_evidence_and_sanitises_secrets():
    source = Path("app/static/assurance-suite.js").read_text(encoding="utf-8")

    for operator in SUPPORTED_OPERATORS:
        assert f'case "{operator}"' in source
    assert "No assertion was supplied" in source
    assert 'return "[redacted]"' in source
    assert "X-TwinLab-Observer" not in source
    assert "config.assertions" in source
    assert "run.assertions" in source
    assert "comparison_run_id" in source
    assert "response.status !== 204" in source
    assert "format=json" not in source
