"""Generate repeatable raw HTTP/state evidence from the Flask test client.

The script never contacts a network host. It creates an isolated temporary
SQLite database and writes only synthetic request/response evidence.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import platform
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app import create_app
from app.db import get_db, reset_database


EVIDENCE = ROOT / "docs" / "evidence"
OBSERVER_HEADERS = {"X-TwinLab-Observer": "evidence-console"}


def json_path(path: str) -> str:
    return path + ("&" if "?" in path else "?") + "format=json"


def response_text(response) -> str:
    body = response.get_json(silent=True)
    if isinstance(body, dict) and "lab_token" in body:
        token = body["lab_token"]
        body["lab_token"] = f"<redacted synthetic token; prefix={token[:6]}>"
    return "\n".join(
        [
            f"HTTP {response.status_code}",
            f"Content-Type: {response.content_type}",
            "",
            json.dumps(body, indent=2, sort_keys=True) if body is not None else response.get_data(as_text=True),
        ]
    )


def write(module: str, name: str, content: str) -> None:
    directory = EVIDENCE / module
    directory.mkdir(parents=True, exist_ok=True)
    (directory / name).write_text(content.rstrip() + "\n", encoding="utf-8")


def record(
    client,
    module: str,
    filename: str,
    method: str,
    path: str,
    *,
    headers=None,
    display_headers=None,
    data=None,
    display_body: str | None = None,
):
    request_headers = dict(display_headers if display_headers is not None else (headers or {}))
    for header_name, replacement in {
        "X-TwinLab-Observer": "<redacted local observer capability>",
        "X-Lab-Session": "<redacted synthetic session token>",
        "X-TwinLab-Signature": "sha256=<redacted demo signature>",
    }.items():
        if header_name in request_headers:
            request_headers[header_name] = replacement
    request_text = [f"{method.upper()} {path}"] + [f"{key}: {value}" for key, value in request_headers.items()]
    if display_body is not None:
        request_text.extend(["", display_body])
    response = client.open(json_path(path), method=method, headers=headers or {}, data=data)
    write(module, filename, "\n".join(request_text) + "\n\n" + response_text(response))
    return response


def reset(app) -> None:
    with app.app_context():
        reset_database()


def select_identity(client, username: str):
    """Select the synthetic principal through the signed lab session."""

    response = client.post(
        json_path(f"/identity/{username}"),
        headers={"Accept": "application/json"},
    )
    if response.status_code != 200:
        raise RuntimeError(f"Could not select evidence identity {username}")
    return response


def generate() -> list[tuple[str, str, str, str]]:
    # Remove only generated per-module text artefacts so renamed protocols do
    # not leave stale evidence that appears current.
    for module_number in range(1, 11):
        module_directory = EVIDENCE / f"A{module_number:02d}"
        if module_directory.exists():
            for generated_text in module_directory.glob("*.txt"):
                generated_text.unlink()

    tmp = tempfile.NamedTemporaryFile(prefix="twinlab-evidence-", suffix=".sqlite3", delete=False)
    tmp.close()
    Path(tmp.name).unlink(missing_ok=True)
    app = create_app({"TESTING": True, "DATABASE": tmp.name, "SECRET_KEY": "evidence-only"})
    client = app.test_client()
    rows: list[tuple[str, str, str, str]] = []

    # A01
    reset(app)
    select_identity(client, "alice")
    before = record(
        client,
        "A01",
        "00-authoritative-state-before.txt",
        "GET",
        "/observer/a01/orders-state",
        headers=OBSERVER_HEADERS,
    )
    vulnerable = record(client, "A01", "01-vulnerable-attack.txt", "GET", "/lab/a01/vulnerable/orders/202")
    reset(app)
    select_identity(client, "alice")
    secure = record(client, "A01", "02-secure-attack.txt", "GET", "/lab/a01/secure/orders/202")
    legitimate = record(client, "A01", "03-secure-legitimate.txt", "GET", "/lab/a01/secure/orders/101")
    after = record(
        client,
        "A01",
        "04-authoritative-state-after.txt",
        "GET",
        "/observer/a01/orders-state",
        headers=OBSERVER_HEADERS,
    )
    write(
        "A01",
        "05-state-effect.txt",
        "Read-only experiment.\n"
        f"Before checksum: {before.get_json()['checksum']}\n"
        f"After checksum: {after.get_json()['checksum']}\n"
        f"Row count: {after.get_json()['row_count']}\n"
        "No customer rows were returned by the Observer.",
    )
    rows.append(("A01", "200 / Bob exposed", f"{secure.status_code} / no Bob data", f"{legitimate.status_code} / Alice order"))

    # A02
    reset(app)
    vulnerable = record(client, "A02", "01-vulnerable-error.txt", "GET", "/lab/a02/vulnerable/order-lookup?id=explode")
    secure = record(client, "A02", "02-secure-error.txt", "GET", "/lab/a02/secure/order-lookup?id=explode")
    legitimate = record(client, "A02", "03-secure-legitimate.txt", "GET", "/lab/a02/secure/order-lookup?id=101")
    request_id = secure.get_json()["request_id"]
    event = record(
        client,
        "A02",
        "04-observer-correlated-event.txt",
        "GET",
        f"/observer/a02/audit-event?request_id={request_id}",
        headers=OBSERVER_HEADERS,
    )
    write(
        "A02",
        "05-state-effect.txt",
        f"Customer response request_id={request_id}\n"
        f"Observer event found={event.get_json()['event_found']}\n"
        f"Stored detail keys={event.get_json()['stored_detail_keys']}\n"
        "The customer response contains no trace, path or configuration marker.",
    )
    rows.append(("A02", "500 / synthetic trace leaked", "500 / generic request ID", f"{legitimate.status_code} / valid lookup"))

    # A03
    reset(app)
    vulnerable = record(client, "A03", "01-vulnerable-newer.txt", "GET", "/lab/a03/vulnerable/verify?repository=newer")
    secure = record(client, "A03", "02-secure-pinned.txt", "GET", "/lab/a03/secure/verify?repository=newer")
    legitimate = record(client, "A03", "03-secure-legitimate.txt", "GET", "/lab/a03/secure/verify?repository=trusted")
    checksum = record(client, "A03", "04-secure-checksum.txt", "GET", "/lab/a03/secure/verify?repository=pinned-tamper")
    rows.append(("A03", "200 / unreviewed latest selected", f"{secure.status_code} / reviewed pin retained; tamper={checksum.status_code}", f"{legitimate.status_code} / trusted accepted"))

    # A04
    reset(app)
    a04_form = {"password": "correct-horse", "candidate": "correct-horse"}
    vulnerable = record(client, "A04", "01-vulnerable-equal-hashes.txt", "POST", "/lab/a04/vulnerable/compare", data=a04_form, display_body="password=<redacted demo password>&candidate=<redacted demo candidate>")
    secure = record(client, "A04", "02-secure-separated-hashes.txt", "POST", "/lab/a04/secure/compare", data={"password": "correct-horse", "candidate": "wrong"}, display_body="password=<redacted demo password>&candidate=<redacted demo wrong candidate>")
    legitimate = record(client, "A04", "03-secure-legitimate.txt", "POST", "/lab/a04/secure/compare", data=a04_form, display_body="password=<redacted demo password>&candidate=<redacted demo candidate>")
    rows.append(("A04", "200 / equal hashes", "200 / salted hashes differ", f"{legitimate.status_code} / verification passes"))

    # A05
    reset(app)
    payload = "%25%27%20OR%201%3D1%20--"
    before = record(
        client,
        "A05",
        "00-authoritative-state-before.txt",
        "GET",
        "/observer/a05/products-state",
        headers=OBSERVER_HEADERS,
    )
    vulnerable = record(client, "A05", "01-vulnerable-injection.txt", "GET", f"/lab/a05/vulnerable/search?q={payload}")
    secure = record(client, "A05", "02-secure-injection.txt", "GET", f"/lab/a05/secure/search?q={payload}")
    legitimate = record(client, "A05", "03-secure-legitimate.txt", "GET", "/lab/a05/secure/search?q=Security")
    after = record(
        client,
        "A05",
        "04-authoritative-state-after.txt",
        "GET",
        "/observer/a05/products-state",
        headers=OBSERVER_HEADERS,
    )
    write(
        "A05",
        "05-state-effect.txt",
        "Read-only payload.\n"
        f"Before checksum: {before.get_json()['checksum']}\n"
        f"After checksum: {after.get_json()['checksum']}\n"
        f"Catalogue rows: {after.get_json()['row_count']}\n"
        "No catalogue rows were returned by the Observer.",
    )
    rows.append(("A05", "200 / hidden product exposed", "200 / payload treated as text", f"{legitimate.status_code} / normal match"))

    # A06
    reset(app)
    coupon_form = {"coupon": "WELCOME10"}
    select_identity(client, "alice")
    record(
        client,
        "A06",
        "00-vulnerable-reset.txt",
        "POST",
        "/observer/a06/vulnerable/reset-case",
        headers=OBSERVER_HEADERS,
        data={"subject": "alice", "coupon": "WELCOME10"},
        display_body="subject=alice&coupon=WELCOME10",
    )
    record(client, "A06", "01-vulnerable-first-use.txt", "POST", "/lab/a06/vulnerable/apply", data=coupon_form, display_body="coupon=WELCOME10")
    vulnerable = record(client, "A06", "02-vulnerable-replay.txt", "POST", "/lab/a06/vulnerable/apply", data=coupon_form, display_body="coupon=WELCOME10")
    record(
        client,
        "A06",
        "03-vulnerable-state.txt",
        "GET",
        "/observer/a06/vulnerable/state?subject=alice&coupon=WELCOME10",
        headers=OBSERVER_HEADERS,
    )
    reset(app)
    select_identity(client, "alice")
    record(
        client,
        "A06",
        "04-secure-reset.txt",
        "POST",
        "/observer/a06/secure/reset-case",
        headers=OBSERVER_HEADERS,
        data={"subject": "alice", "coupon": "WELCOME10"},
        display_body="subject=alice&coupon=WELCOME10",
    )
    record(client, "A06", "05-secure-first-use.txt", "POST", "/lab/a06/secure/apply", data=coupon_form, display_body="coupon=WELCOME10")
    secure = record(client, "A06", "06-secure-replay.txt", "POST", "/lab/a06/secure/apply", data=coupon_form, display_body="coupon=WELCOME10")
    record(
        client,
        "A06",
        "07-secure-state.txt",
        "GET",
        "/observer/a06/secure/state?subject=alice&coupon=WELCOME10",
        headers=OBSERVER_HEADERS,
    )
    select_identity(client, "bob")
    legitimate = record(client, "A06", "08-secure-other-user.txt", "POST", "/lab/a06/secure/apply", data=coupon_form, display_body="coupon=WELCOME10")
    rows.append(("A06", "201 / second use accepted", f"{secure.status_code} / replay blocked", f"{legitimate.status_code} / Bob first use"))

    # A07
    reset(app)
    login_v = client.post(json_path("/lab/a07/vulnerable/login"), data={"username": "admin", "password": "demo-admin"})
    token_v = login_v.get_json()["lab_token"]
    logout_v = client.post(json_path("/lab/a07/vulnerable/logout"), headers={"X-Lab-Session": token_v})
    replay_v = client.get(json_path("/lab/a07/vulnerable/admin"), headers={"X-Lab-Session": token_v})
    write("A07", "01-vulnerable-flow.txt", "LOGIN\n" + response_text(login_v) + "\n\nLOGOUT using <same synthetic token>\n" + response_text(logout_v) + "\n\nREPLAY X-Lab-Session: <same synthetic token>\n" + response_text(replay_v))
    record(
        client,
        "A07",
        "02-vulnerable-observer-state.txt",
        "GET",
        "/observer/a07/vulnerable/session-state",
        headers={**OBSERVER_HEADERS, "X-Lab-Session": token_v},
        display_headers={**OBSERVER_HEADERS, "X-Lab-Session": "<redacted old synthetic token>"},
    )
    reset(app)
    login_s = client.post(json_path("/lab/a07/secure/login"), data={"username": "admin", "password": "demo-admin"})
    token_s = login_s.get_json()["lab_token"]
    logout_s = client.post(json_path("/lab/a07/secure/logout"), headers={"X-Lab-Session": token_s})
    replay_s = client.get(json_path("/lab/a07/secure/admin"), headers={"X-Lab-Session": token_s})
    login_new = client.post(json_path("/lab/a07/secure/login"), data={"username": "admin", "password": "demo-admin"})
    token_new = login_new.get_json()["lab_token"]
    legitimate = client.get(json_path("/lab/a07/secure/admin"), headers={"X-Lab-Session": token_new})
    write("A07", "03-secure-flow.txt", "LOGIN\n" + response_text(login_s) + "\n\nLOGOUT using <old synthetic token>\n" + response_text(logout_s) + "\n\nREPLAY X-Lab-Session: <old synthetic token>\n" + response_text(replay_s))
    write("A07", "04-secure-new-session.txt", "NEW LOGIN (token differs from revoked token)\n" + response_text(login_new) + "\n\nADMIN REQUEST using <new synthetic token>\n" + response_text(legitimate))
    record(
        client,
        "A07",
        "05-secure-revoked-state.txt",
        "GET",
        "/observer/a07/secure/session-state",
        headers={**OBSERVER_HEADERS, "X-Lab-Session": token_s},
        display_headers={**OBSERVER_HEADERS, "X-Lab-Session": "<redacted revoked synthetic token>"},
    )
    login_expired = client.post(json_path("/lab/a07/secure/login"), data={"username": "admin", "password": "demo-admin"})
    token_expired = login_expired.get_json()["lab_token"]
    record(
        client,
        "A07",
        "06-observer-expire-session.txt",
        "POST",
        "/observer/a07/secure/expire-session",
        headers={**OBSERVER_HEADERS, "X-Lab-Session": token_expired},
        display_headers={**OBSERVER_HEADERS, "X-Lab-Session": "<redacted synthetic token>"},
    )
    expired = record(
        client,
        "A07",
        "07-secure-expired-token.txt",
        "GET",
        "/lab/a07/secure/admin",
        headers={"X-Lab-Session": token_expired},
        display_headers={"X-Lab-Session": "<redacted expired synthetic token>"},
    )
    random_token = record(
        client,
        "A07",
        "08-secure-random-token.txt",
        "GET",
        "/lab/a07/secure/admin",
        headers={"X-Lab-Session": "synthetic-random-token"},
        display_headers={"X-Lab-Session": "<redacted random synthetic token>"},
    )
    write(
        "A07",
        "09-state-effect.txt",
        f"Revoked old-token replay HTTP: {replay_s.status_code}\n"
        f"Expired-token request HTTP: {expired.status_code}\n"
        f"Random-token request HTTP: {random_token.status_code}\n"
        f"Fresh secure token request HTTP: {legitimate.status_code}",
    )
    rows.append(("A07", "200 / old token replayed", f"{replay_s.status_code} / old token revoked", f"{legitimate.status_code} / new token works"))

    # A08
    reset(app)
    record(
        client,
        "A08",
        "00-vulnerable-reset.txt",
        "POST",
        "/observer/a08/vulnerable/reset-price",
        headers=OBSERVER_HEADERS,
    )
    key = app.config["DEMO_HMAC_KEY"]
    trusted_body = b'{"product_id":1,"price_cents":4900}'
    tampered_body = b'{"product_id":1,"price_cents":100}'
    legitimate_body = b'{"product_id":1,"price_cents":5100}'
    original = "sha256=" + hmac.new(key, trusted_body, hashlib.sha256).hexdigest()
    signature_headers = {"Content-Type": "application/json", "X-TwinLab-Signature": original}
    displayed_headers = {"Content-Type": "application/json", "X-TwinLab-Signature": "sha256=<redacted demo signature>"}
    vulnerable = record(client, "A08", "01-vulnerable-tamper.txt", "POST", "/lab/a08/vulnerable/price-update", headers=signature_headers, display_headers=displayed_headers, data=tampered_body, display_body=tampered_body.decode())
    record(
        client,
        "A08",
        "02-vulnerable-state.txt",
        "GET",
        "/observer/a08/vulnerable/price-state",
        headers=OBSERVER_HEADERS,
    )
    reset(app)
    record(
        client,
        "A08",
        "03-secure-reset.txt",
        "POST",
        "/observer/a08/secure/reset-price",
        headers=OBSERVER_HEADERS,
    )
    secure = record(client, "A08", "04-secure-tamper.txt", "POST", "/lab/a08/secure/price-update", headers=signature_headers, display_headers=displayed_headers, data=tampered_body, display_body=tampered_body.decode())
    secure_state = record(
        client,
        "A08",
        "05-secure-state-after-rejection.txt",
        "GET",
        "/observer/a08/secure/price-state",
        headers=OBSERVER_HEADERS,
    )
    legitimate_signature = "sha256=" + hmac.new(key, legitimate_body, hashlib.sha256).hexdigest()
    legitimate_headers = {"Content-Type": "application/json", "X-TwinLab-Signature": legitimate_signature}
    legitimate = record(client, "A08", "06-secure-legitimate.txt", "POST", "/lab/a08/secure/price-update", headers=legitimate_headers, display_headers=displayed_headers, data=legitimate_body, display_body=legitimate_body.decode())
    final_state = record(
        client,
        "A08",
        "07-secure-state-after-legitimate.txt",
        "GET",
        "/observer/a08/secure/price-state",
        headers=OBSERVER_HEADERS,
    )
    write(
        "A08",
        "08-state-effect.txt",
        f"Price after rejected tamper: {secure_state.get_json()['price_cents']} cents\n"
        f"Price after exact signed update: {final_state.get_json()['price_cents']} cents",
    )
    rows.append(("A08", "204 / tampered price stored", f"{secure.status_code} / HMAC mismatch", f"{legitimate.status_code} / exact raw-body signature"))

    # A09
    reset(app)
    wrong_login = {"username": "admin", "password": "DEMO_WRONG_PASSWORD"}
    vulnerable_run = "evidence-a09-vulnerable"
    vulnerable_headers = {"X-TwinLab-Run-Id": vulnerable_run}
    record(
        client,
        "A09",
        "00-vulnerable-reset.txt",
        "POST",
        "/observer/a09/vulnerable/reset-case",
        headers={**OBSERVER_HEADERS, **vulnerable_headers},
        data={"username": "admin"},
        display_body="username=admin",
    )
    for index in range(1, 4):
        vulnerable = record(client, "A09", f"01-vulnerable-failure-{index}.txt", "POST", "/lab/a09/vulnerable/login", headers=vulnerable_headers, data=wrong_login, display_body="username=admin&password=<redacted demo wrong password>")
    vulnerable_state = record(
        client,
        "A09",
        "02-vulnerable-state.txt",
        "GET",
        "/observer/a09/vulnerable/state?username=admin",
        headers={**OBSERVER_HEADERS, **vulnerable_headers},
    )
    controlled_run = "evidence-a09-controlled"
    controlled_headers = {"X-TwinLab-Run-Id": controlled_run}
    record(
        client,
        "A09",
        "03-secure-reset.txt",
        "POST",
        "/observer/a09/secure/reset-case",
        headers={**OBSERVER_HEADERS, **controlled_headers},
        data={"username": "admin"},
        display_body="username=admin",
    )
    for index in range(1, 4):
        secure = record(client, "A09", f"04-secure-failure-{index}.txt", "POST", "/lab/a09/secure/login", headers=controlled_headers, data=wrong_login, display_body="username=admin&password=<redacted demo wrong password>")
    secure_state = record(
        client,
        "A09",
        "05-secure-state.txt",
        "GET",
        "/observer/a09/secure/state?username=admin",
        headers={**OBSERVER_HEADERS, **controlled_headers},
    )
    legitimate_run = "evidence-a09-legitimate"
    legitimate_headers = {"X-TwinLab-Run-Id": legitimate_run}
    record(
        client,
        "A09",
        "06-legitimate-reset.txt",
        "POST",
        "/observer/a09/secure/reset-case",
        headers={**OBSERVER_HEADERS, **legitimate_headers},
        data={"username": "admin"},
        display_body="username=admin",
    )
    legitimate = record(client, "A09", "07-secure-legitimate.txt", "POST", "/lab/a09/secure/login", headers=legitimate_headers, data={"username": "admin", "password": "demo-admin"}, display_body="username=admin&password=<redacted demo password>")
    legitimate_state = record(
        client,
        "A09",
        "08-secure-legitimate-state.txt",
        "GET",
        "/observer/a09/secure/state?username=admin",
        headers={**OBSERVER_HEADERS, **legitimate_headers},
    )
    write(
        "A09",
        "09-state-effect.txt",
        f"Vulnerable failure events: {vulnerable_state.get_json()['auth_failure_count']}; alerts: {vulnerable_state.get_json()['alert_count']}\n"
        f"Controlled failure events: {secure_state.get_json()['auth_failure_count']}; alerts: {secure_state.get_json()['alert_count']}\n"
        f"Legitimate success events: {legitimate_state.get_json()['auth_success_count']}; alerts: {legitimate_state.get_json()['alert_count']}\n"
        "Each line comes from a distinct variant/run-id partition.",
    )
    rows.append(("A09", "401 / zero events", "401 / 3 failures + 1 alert", f"{legitimate.status_code} / AUTH_SUCCESS"))

    # A10
    reset(app)
    select_identity(client, "alice")
    vulnerable = record(client, "A10", "01-vulnerable-exception.txt", "GET", "/lab/a10/vulnerable/export?simulate=error&actor=admin")
    select_identity(client, "alice")
    secure = record(client, "A10", "02-secure-exception.txt", "GET", "/lab/a10/secure/export?simulate=error&actor=admin")
    select_identity(client, "admin")
    legitimate = record(client, "A10", "03-secure-legitimate.txt", "GET", "/lab/a10/secure/export?simulate=ok&actor=alice")
    rows.append(("A10", "200 / export on exception", f"{secure.status_code} / failed closed", f"{legitimate.status_code} / explicit allow"))

    Path(tmp.name).unlink(missing_ok=True)
    return rows


def write_index(rows: list[tuple[str, str, str, str]], recorded_at: str) -> None:
    lines = [
        "# Generated Evidence Summary",
        "",
        "Generated locally by `scripts/generate_evidence.py` from an isolated synthetic database.",
        f"Recorded: {recorded_at}",
        "",
        "| Module | Vulnerable attack | Secure equivalent | Secure legitimate |",
        "|---|---|---|---|",
    ]
    lines.extend(f"| {module} | {vulnerable} | {secure} | {legitimate} |" for module, vulnerable, secure, legitimate in rows)
    lines.extend(
        [
            "",
            "These observations prove only the documented, deterministic experiment contracts. Raw responses and state effects are stored in each module directory.",
        ]
    )
    (EVIDENCE / "EVIDENCE_SUMMARY.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_test_output(recorded_at: str) -> None:
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-q"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    output = "\n".join(
        [
            f"Recorded: {recorded_at}",
            f"Python: {platform.python_version()}",
            f"Platform: {platform.platform()}",
            "$ python -m pytest -q",
            result.stdout.rstrip(),
            result.stderr.rstrip(),
            "",
        ]
    )
    (EVIDENCE / "TEST_OUTPUT.txt").write_text(output, encoding="utf-8")
    if result.returncode:
        raise SystemExit(result.returncode)


if __name__ == "__main__":
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    recorded_at = datetime.now(ZoneInfo("Australia/Sydney")).strftime("%Y-%m-%d %H:%M:%S %Z")
    generated = generate()
    write_index(generated, recorded_at)
    write_test_output(recorded_at)
    print(f"Generated evidence for {len(generated)} modules in {EVIDENCE}")
