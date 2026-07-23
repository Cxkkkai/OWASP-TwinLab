from __future__ import annotations

import html
import json
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from app.lab_registry import LABS


def _runner_config(page_text: str) -> dict:
    match = re.search(
        r'<script id="lab-runner-config" type="application/json">\s*(.*?)\s*</script>',
        page_text,
        re.DOTALL,
    )
    assert match
    return json.loads(html.unescape(match.group(1)))


def _value_at_path(value, path):
    for part in str(path).split("."):
        if value is None or part not in value:
            return None
        value = value[part]
    return value


def _resolve(value, runtime):
    if isinstance(value, str):
        return re.sub(
            r"\{\{([a-zA-Z0-9_]+)\}\}",
            lambda match: str(runtime[match.group(1)]),
            value,
        )
    if isinstance(value, list):
        return [_resolve(item, runtime) for item in value]
    if isinstance(value, dict):
        return {key: _resolve(item, runtime) for key, item in value.items()}
    return value


def _experiment_url(raw_url: str, run_id: str) -> str:
    split = urlsplit(raw_url)
    query = dict(parse_qsl(split.query, keep_blank_values=True))
    query.update(format="json", comparison_run_id=run_id)
    return urlunsplit((split.scheme, split.netloc, split.path, urlencode(query), split.fragment))


def _execute_run(client, run: dict, run_id: str) -> dict:
    runtime = {}
    steps = {}
    for unresolved in run["steps"]:
        step = _resolve(unresolved, runtime)
        headers = {"Accept": "application/json", "X-TwinLab-Run-Id": run_id, **step.get("headers", {})}
        request_kwargs = {"method": step.get("method", "GET"), "headers": headers}
        if "raw_body" in step:
            request_kwargs["data"] = step["raw_body"]
        else:
            request_kwargs["data"] = step.get("fields", {})
        response = client.open(_experiment_url(step["url"], run_id), **request_kwargs)
        payload = response.get_json(silent=True) or {}
        response_headers = {key.lower(): value for key, value in response.headers.items()}
        steps[step["id"]] = {
            "status": response.status_code,
            "headers": response_headers,
            "payload": payload,
        }
        for runtime_name, response_path in step.get("capture", {}).items():
            captured = _value_at_path(payload, response_path)
            assert captured is not None, (step["id"], response_path)
            runtime[runtime_name] = captured

    selected = steps[run.get("summary_step") or step["id"]]
    return {
        **selected["payload"],
        "http_status": selected["status"],
        "response_headers": selected["headers"],
        "steps": steps,
    }


def _assertion_passes(assertion: dict, record: dict) -> bool:
    operator = assertion["operator"]
    if operator in {"changed", "unchanged"}:
        assert isinstance(assertion["path"], list) and len(assertion["path"]) == 2
        before = _value_at_path(record, assertion["path"][0])
        after = _value_at_path(record, assertion["path"][1])
        assert before is not None and after is not None
        return (before != after) if operator == "changed" else (before == after)

    actual = _value_at_path(record, assertion["path"])
    assert actual is not None, (assertion["id"], assertion["path"])
    expected = assertion.get("expected")
    return {
        "equals": actual == expected,
        "not_equals": actual != expected,
        "truthy": bool(actual),
        "falsy": not actual,
        "in": actual in expected if isinstance(expected, list) else False,
    }[operator]


def test_every_rendered_experiment_produces_four_passing_executable_claims(client):
    for lab_id in (lab["id"] for lab in LABS):
        config = _runner_config(client.get(f"/lab/{lab_id}/").get_data(as_text=True))
        if config["setup"]:
            setup = config["setup"]
            response = client.open(setup["url"], method=setup["method"], data=setup["fields"])
            assert response.status_code < 400

        results_by_id: dict[str, list[bool]] = {}
        for phase in ("vulnerable", "controlled", "legitimate"):
            record = _execute_run(client, config["runs"][phase], f"test-{lab_id}")
            for assertion in config["assertions"][phase]:
                results_by_id.setdefault(assertion["id"], []).append(_assertion_passes(assertion, record))

        assert set(results_by_id) == {
            "vulnerability_reproduced",
            "control_effective",
            "authoritative_state_safe",
            "legitimate_use_preserved",
        }
        assert all(all(results) for results in results_by_id.values()), lab_id
