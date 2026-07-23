"""Presentation metadata for the executable TwinLab experiment runner.

This module deliberately contains only lab-operational information: the exact
request being replayed, the real implementation excerpt, and the response
fields that act as evidence.  Report-style What/Why/How analysis remains in the
report data model and is not rendered into the product UI.
"""

from __future__ import annotations

from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _excerpt(
    source: str,
    start_anchor: str,
    end_anchor: str,
    *,
    focus: tuple[str, ...],
    tone: str,
    after: str | None = None,
) -> dict:
    """Return a numbered excerpt copied from the running source file."""

    path = PROJECT_ROOT / source
    lines = path.read_text(encoding="utf-8").splitlines()
    search_from = 0
    if after is not None:
        search_from = next(
            index for index, line in enumerate(lines) if after in line
        )
    start = next(
        index
        for index, line in enumerate(lines[search_from:], start=search_from)
        if start_anchor in line
    )
    end = next(
        index
        for index, line in enumerate(lines[start:], start=start)
        if end_anchor in line
    )
    return {
        "file": source,
        "line": start + 1,
        "start_anchor": start_anchor,
        "end_anchor": end_anchor,
        "lines": [
            {
                "number": index + 1,
                "text": lines[index],
                "focus": tone if any(marker in lines[index] for marker in focus) else "",
            }
            for index in range(start, end + 1)
        ],
    }


LAB_DEMOS = {
    "a01": {
        "depth": "deep",
        "actor": "Alice · authenticated customer",
        "target": "Bob's order 202",
        "technique": "Change one object identifier",
        "impact": "Bob's item, address and order value cross into Alice's response; repeating the ID change could disclose other customers' records.",
        "input_lock": "Actor Alice and order ID 202 stay fixed for both attack runs.",
        "request": "POST /identity/alice\nGET /lab/a01/vulnerable/orders/202",
        "replay_request": "POST /identity/alice\nGET /lab/a01/secure/orders/202",
        "steps": [
            "Prepare Alice's ordinary customer identity.",
            "Replace Alice's order ID 101 with Bob's ID 202.",
            "Send the request to the vulnerable lookup.",
            "Inspect the returned owner and sensitive-data decision.",
        ],
        "failure": "The database lookup uses the browser-controlled order ID but not Alice's owner ID.",
        "control": "The controlled lookup requires the order ID and the authenticated owner ID in one query.",
        "vulnerable_code": _excerpt(
            "app/modules/access_control.py",
            '@bp.get("/vulnerable/orders/<int:order_id>")',
            "        (order_id,),",
            focus=("WHERE orders.id = ?", "(order_id,),"),
            tone="bad",
        ),
        "controlled_code": _excerpt(
            "app/modules/access_control.py",
            '@bp.get("/secure/orders/<int:order_id>")',
            '        (order_id, actor["id"]),',
            focus=("orders.owner_id = ?", 'actor["id"]'),
            tone="good",
        ),
        "observations": {
            "vulnerable": [
                {"key": "authorized", "label": "Authorized"},
                {"key": "object_owner", "label": "Returned owner"},
                {"key": "authorization_predicate", "label": "Authorization predicate"},
                {"key": "sensitive_data_returned", "label": "Sensitive data returned"},
                {"key": "order.shipping_address", "label": "Leaked address"},
            ],
            "controlled": [
                {"key": "sensitive_data_returned", "label": "Sensitive data returned"},
                {"key": "requested_order", "label": "Requested order"},
                {"key": "authorization_predicate", "label": "Authorization predicate"},
            ],
            "legitimate": [
                {"key": "authorized", "label": "Authorized"},
                {"key": "object_owner", "label": "Returned owner"},
                {"key": "sensitive_data_returned", "label": "Sensitive data returned"},
            ],
        },
    },
    "a02": {
        "depth": "deep",
        "actor": "Unauthenticated caller",
        "target": "Client-facing error boundary",
        "technique": "Trigger a controlled exception",
        "impact": "Internal paths, query shape and configuration markers reduce attacker uncertainty and can guide more targeted follow-up attacks.",
        "input_lock": "The value id=explode is replayed without modification.",
        "request": "GET /lab/a02/vulnerable/order-lookup?id=explode",
        "replay_request": "GET /lab/a02/secure/order-lookup?id=explode",
        "steps": [
            "Submit the controlled identifier explode.",
            "Reach the same RuntimeError in both implementations.",
            "Inspect which diagnostic fields cross into the client response.",
            "Verify that the controlled response keeps a server-side correlation ID.",
        ],
        "failure": "The vulnerable renderer serializes operator-only trace, path, SQL and configuration details.",
        "control": "The controlled renderer returns a generic error and stores one minimised correlated event.",
        "vulnerable_code": _excerpt(
            "app/modules/misconfiguration.py",
            '        if error_policy["expose_internal_errors"]:',
            '                    "configuration_drives_response": True,',
            focus=("synthetic_trace", "synthetic_path", "synthetic_sql", "synthetic_config", "internal_details_returned"),
            tone="bad",
        ),
        "controlled_code": _excerpt(
            "app/modules/misconfiguration.py",
            "        request_id = str(uuid.uuid4())",
            '                "server_event_details_minimised": True,',
            focus=("request_id =", "INSERT INTO audit_events", '"error_code"', '"message"', '"internal_details_returned": False', '"correlated_server_event"'),
            tone="good",
        ),
        "observations": {
            "vulnerable": [
                {"key": "internal_details_returned", "label": "Internal details returned"},
                {"key": "synthetic_trace", "label": "Trace marker"},
                {"key": "synthetic_path", "label": "Internal path"},
                {"key": "synthetic_config", "label": "Configuration marker"},
            ],
            "controlled": [
                {"key": "internal_details_returned", "label": "Internal details returned"},
                {"key": "error_code", "label": "Client error code"},
                {"key": "request_id", "label": "Correlation ID"},
                {"key": "correlated_server_event", "label": "Server event stored"},
            ],
            "legitimate": [
                {"key": "order_id", "label": "Order ID"},
                {"key": "debug_mode", "label": "Debug mode"},
                {"key": "interactive_debugger", "label": "Interactive debugger"},
            ],
        },
    },
    "a03": {
        "depth": "compact",
        "actor": "Synthetic build process",
        "target": "Dependency artefact",
        "technique": "Publish a newer unreviewed version",
        "impact": "An unreviewed package can enter the build and execute with the application's build or runtime privileges.",
        "input_lock": "Repository state newer is used for both selections.",
        "request": "GET /lab/a03/vulnerable/verify?repository=newer",
        "replay_request": "GET /lab/a03/secure/verify?repository=newer",
        "steps": [
            "Expose trusted 2.4.1 and unreviewed 2.4.2 in the repository.",
            "Compare floating-latest selection with the reviewed manifest pin.",
        ],
        "failure": "Floating latest selects a package by version ordering without a trusted digest.",
        "control": "The reviewed manifest fixes the version and verifies the selected bytes with SHA-256.",
        "vulnerable_code": _excerpt(
            "app/modules/compact.py",
            '    selected_version = max(repository) if variant == "vulnerable" else TRUSTED_VERSION',
            "    contains_untrusted_marker = b\"UNTRUSTED_ARTIFACT_A03\" in artefact",
            focus=("max(repository)", 'variant == "vulnerable"'),
            tone="bad",
            after="def a03_verify",
        ),
        "controlled_code": _excerpt(
            "app/modules/compact.py",
            '    selected_version = max(repository) if variant == "vulnerable" else TRUSTED_VERSION',
            "    accepted = variant == \"vulnerable\" or hmac.compare_digest(actual, TRUSTED_SHA256)",
            focus=("TRUSTED_VERSION", "TRUSTED_SHA256", "compare_digest"),
            tone="good",
            after="def a03_verify",
        ),
        "observations": {
            "vulnerable": [
                {"key": "selection_policy", "label": "Selection policy"},
                {"key": "selected_version", "label": "Selected version"},
                {"key": "contains_untrusted_marker", "label": "Unreviewed marker selected"},
                {"key": "accepted", "label": "Accepted"},
            ],
            "controlled": [
                {"key": "selection_policy", "label": "Selection policy"},
                {"key": "selected_version", "label": "Selected version"},
                {"key": "contains_untrusted_marker", "label": "Unreviewed marker selected"},
                {"key": "accepted", "label": "Accepted"},
            ],
            "legitimate": [
                {"key": "selected_version", "label": "Selected version"},
                {"key": "accepted", "label": "Digest accepted"},
            ],
        },
    },
    "a04": {
        "depth": "compact",
        "actor": "Offline credential-record observer",
        "target": "Alice and Bob's password records",
        "technique": "Compare equal-password records",
        "impact": "Equal records reveal password reuse and a fast hash makes each offline password guess cheap to test across accounts.",
        "input_lock": "Both attack runs use password=correct-horse and candidate=wrong-password.",
        "request": "POST /lab/a04/vulnerable/compare\npassword=correct-horse&candidate=wrong-password",
        "replay_request": "POST /lab/a04/secure/compare\npassword=correct-horse&candidate=wrong-password",
        "steps": [
            "Create two synthetic records from the same password.",
            "Compare whether the stored representations are equal.",
        ],
        "failure": "Fast unsalted SHA-256 creates identical records for identical passwords.",
        "control": "Each account gets a unique random salt and a memory-hard scrypt derivation.",
        "vulnerable_code": _excerpt(
            "app/modules/compact.py",
            '    if variant == "vulnerable":',
            "        salt_lengths = [0, 0]",
            focus=("hashlib.sha256", "salt_lengths = [0, 0]"),
            tone="bad",
            after="def a04_compare",
        ),
        "controlled_code": _excerpt(
            "app/modules/compact.py",
            "        alice_salt = secrets.token_bytes(16)",
            "        salt_lengths = [len(alice_salt), len(bob_salt)]",
            focus=("secrets.token_bytes(16)", "_scrypt", "compare_digest"),
            tone="good",
            after="def a04_compare",
        ),
        "observations": {
            "vulnerable": [
                {"key": "algorithm", "label": "Algorithm"},
                {"key": "hashes_equal", "label": "Records equal"},
                {"key": "alice_record_fingerprint", "label": "Alice record"},
                {"key": "bob_record_fingerprint", "label": "Bob record"},
            ],
            "controlled": [
                {"key": "algorithm", "label": "Algorithm"},
                {"key": "hashes_equal", "label": "Records equal"},
                {"key": "alice_record_fingerprint", "label": "Alice record"},
                {"key": "bob_record_fingerprint", "label": "Bob record"},
            ],
            "legitimate": [
                {"key": "algorithm", "label": "Algorithm"},
                {"key": "candidate_verified", "label": "Correct candidate verified"},
            ],
        },
    },
    "a05": {
        "depth": "deep",
        "actor": "Unauthenticated caller",
        "target": "Hidden product catalogue rows",
        "technique": "Boolean SQL injection",
        "impact": "A public search returns an internal-only catalogue row; the same code/data confusion can threaten confidentiality and database integrity.",
        "input_lock": "The payload %' OR 1=1 -- is replayed byte-for-byte.",
        "request": "GET /lab/a05/vulnerable/search?q=%25%27%20OR%201%3D1%20--\nDecoded q: %' OR 1=1 --",
        "replay_request": "GET /lab/a05/secure/search?q=%25%27%20OR%201%3D1%20--\nDecoded q: %' OR 1=1 --",
        "steps": [
            "Place a quote into the search term to leave the intended string literal.",
            "Add OR 1=1 so the WHERE expression becomes true.",
            "Use -- to remove the remainder of the intended predicate.",
            "Compare whether the hidden product marker reaches the response.",
        ],
        "failure": "The f-string mixes untrusted text with SQL syntax before the database parses it.",
        "control": "A placeholder sends the same payload as one data value, leaving the SQL structure fixed.",
        "vulnerable_code": _excerpt(
            "app/modules/injection.py",
            '    sql = f"SELECT id, name, price_cents, is_public FROM products',
            "        rows = get_db().execute(sql).fetchall()",
            focus=("sql = f", "execute(sql)"),
            tone="bad",
        ),
        "controlled_code": _excerpt(
            "app/modules/injection.py",
            '@bp.get("/secure/search")',
            "    ).fetchall()",
            focus=("LIKE ?", '(f"%{q}%",)'),
            tone="good",
        ),
        "observations": {
            "vulnerable": [
                {"key": "query", "label": "Submitted payload"},
                {"key": "execution_mode", "label": "Execution mode"},
                {"key": "executed_statement", "label": "Effective SQL"},
                {"key": "result_count", "label": "Rows returned"},
                {"key": "hidden_exposed", "label": "Hidden row exposed"},
                {"key": "products.3.name", "label": "Hidden marker"},
            ],
            "controlled": [
                {"key": "query", "label": "Same payload"},
                {"key": "execution_mode", "label": "Execution mode"},
                {"key": "statement_template", "label": "SQL template"},
                {"key": "bound_parameter", "label": "Bound value"},
                {"key": "result_count", "label": "Rows returned"},
                {"key": "hidden_exposed", "label": "Hidden row exposed"},
            ],
            "legitimate": [
                {"key": "query", "label": "Search term"},
                {"key": "result_count", "label": "Rows returned"},
                {"key": "hidden_exposed", "label": "Hidden row exposed"},
            ],
        },
    },
    "a06": {
        "depth": "compact",
        "actor": "Alice · authenticated customer",
        "target": "WELCOME10 one-use rule",
        "technique": "Replay the same valid coupon",
        "impact": "One customer can receive repeated discounts, violating price integrity and consuming promotion budget beyond the intended rule.",
        "input_lock": "The signed server-side identity Alice and coupon WELCOME10 stay fixed while the coupon request is submitted twice.",
        "request": "POST /identity/alice\nPOST /lab/a06/vulnerable/apply × 2\ncoupon=WELCOME10\nThen inspect Observer state",
        "replay_request": "POST /identity/alice\nPOST /lab/a06/secure/apply × 2\ncoupon=WELCOME10\nThen inspect Observer state",
        "steps": [
            "Apply Alice's valid welcome coupon once.",
            "Replay the identical customer-and-coupon pair.",
        ],
        "failure": "The vulnerable path records another use without enforcing a one-use business invariant.",
        "control": "The controlled path checks redemption atomically and the database also rejects duplicates.",
        "vulnerable_code": _excerpt(
            "app/modules/compact.py",
            "    try:",
            "    current = previous + 1",
            focus=("INSERT INTO coupon_uses", "current = previous + 1"),
            tone="bad",
            after="def _apply_coupon_once",
        ),
        "controlled_code": _excerpt(
            "app/modules/compact.py",
            '    if variant == "secure":',
            '            "one-use database invariant blocked coupon replay",',
            focus=('BEGIN IMMEDIATE', 'if variant == "secure" and previous', "db.rollback()", "except sqlite3.IntegrityError"),
            tone="good",
            after="def _apply_coupon_once",
        ),
        "observations": {
            "vulnerable": [
                {"key": "first_use_status", "label": "First use HTTP"},
                {"key": "replay_status", "label": "Replay HTTP"},
                {"key": "replay_blocked", "label": "Replay blocked"},
                {"key": "claim_supported", "label": "Expected trace observed"},
            ],
            "controlled": [
                {"key": "first_use_status", "label": "First use HTTP"},
                {"key": "replay_status", "label": "Replay HTTP"},
                {"key": "replay_blocked", "label": "Replay blocked"},
                {"key": "claim_supported", "label": "Expected trace observed"},
            ],
            "legitimate": [
                {"key": "actor", "label": "Independent actor"},
                {"key": "accepted", "label": "First use accepted"},
                {"key": "redemption_number", "label": "Redemption number"},
                {"key": "discount_percent", "label": "Discount percent"},
            ],
        },
    },
    "a07": {
        "depth": "deep",
        "actor": "Holder of a captured pre-logout Admin token",
        "target": "Admin session after logout",
        "technique": "Replay an old bearer token",
        "impact": "A copied Admin token can retain privileged dashboard access after the user believes logout ended the session.",
        "input_lock": "Each path runs login → logout → replay old token → fresh login.",
        "request": "POST /lab/a07/vulnerable/login\nPOST /lab/a07/vulnerable/logout\nGET /lab/a07/vulnerable/admin\nX-Lab-Session: <captured-old-token>",
        "replay_request": "POST /lab/a07/secure/login\nPOST /lab/a07/secure/logout\nGET /lab/a07/secure/admin\nX-Lab-Session: <captured-old-token>",
        "steps": [
            "Create a valid synthetic Admin session and retain its old token.",
            "Log out and clear the browser cookie.",
            "Replay the retained token directly against the Admin endpoint.",
            "Create a fresh session to verify that legitimate login still works.",
        ],
        "failure": "Vulnerable logout clears client state but deliberately skips server-side revocation.",
        "control": "Controlled logout marks the matching server session inactive; every Admin request checks that state.",
        "vulnerable_code": _excerpt(
            "app/modules/authentication.py",
            '    if not token or variant not in {"candidate", "secure"}:',
            "        return False",
            focus=('variant not in {"candidate", "secure"}', "return False"),
            tone="bad",
            after="def _revoke_session",
        ),
        "controlled_code": _excerpt(
            "app/modules/authentication.py",
            "    cursor = db.execute(",
            "    return cursor.rowcount > 0",
            focus=("UPDATE sessions SET active = 0", "db.commit()", "cursor.rowcount"),
            tone="good",
            after="def _revoke_session",
        ),
        "observations": {
            "vulnerable": [
                {"key": "server_session_active_after_logout", "label": "Old session active"},
                {"key": "old_token_replay_status", "label": "Old-token replay HTTP"},
                {"key": "fresh_token_status", "label": "Fresh-token HTTP"},
                {"key": "claim_supported", "label": "Expected lifecycle observed"},
            ],
            "controlled": [
                {"key": "server_session_active_after_logout", "label": "Old session active"},
                {"key": "old_token_replay_status", "label": "Old-token replay HTTP"},
                {"key": "fresh_token_status", "label": "Fresh-token HTTP"},
                {"key": "claim_supported", "label": "Expected lifecycle observed"},
            ],
            "legitimate": [
                {"key": "username", "label": "Username"},
                {"key": "role", "label": "Role"},
                {"key": "expires_in_seconds", "label": "Session lifetime"},
            ],
        },
    },
    "a08": {
        "depth": "compact",
        "actor": "Caller modifying a price message",
        "target": "Product 1 price state",
        "technique": "Change signed bytes and replay the old signature",
        "impact": "A modified message changes a 4900-cent product to 100 cents, directly violating stored price integrity.",
        "input_lock": "Both attack runs submit price 100 with the signature made for price 5100.",
        "request": "POST /lab/a08/vulnerable/price-update\nX-TwinLab-Signature: <signature for 5100 body>\nBody: {\"product_id\":1,\"price_cents\":100}",
        "replay_request": "POST /lab/a08/secure/price-update\nX-TwinLab-Signature: <same stale signature>\nBody: {\"product_id\":1,\"price_cents\":100}",
        "steps": [
            "Keep the signature for the intended 5100-cent message.",
            "Submit modified 100-cent bytes and observe the stored price.",
        ],
        "failure": "The vulnerable branch computes integrity but updates state even when the signature is invalid.",
        "control": "The controlled branch rejects invalid bytes before parsing or updating the product.",
        "vulnerable_code": _excerpt(
            "app/modules/compact.py",
            "    expected_signature = _price_signature(raw_body)",
            '    if variant == "secure" and not integrity_valid:',
            focus=('if variant == "secure" and not integrity_valid',),
            tone="bad",
            after="def _process_price_update",
        ),
        "controlled_code": _excerpt(
            "app/modules/compact.py",
            '    if variant == "secure" and not integrity_valid:',
            "            401,",
            focus=('not integrity_valid', '"decision": "reject"', '"accepted": False', "401"),
            tone="good",
            after="def _process_price_update",
        ),
        "observations": {
            "vulnerable": [
                {"key": "integrity_valid", "label": "Signature valid"},
                {"key": "accepted", "label": "Update accepted"},
                {"key": "before_price_cents", "label": "Price before"},
                {"key": "after_price_cents", "label": "Price after"},
            ],
            "controlled": [
                {"key": "integrity_valid", "label": "Signature valid"},
                {"key": "accepted", "label": "Update accepted"},
                {"key": "before_price_cents", "label": "Price before"},
                {"key": "after_price_cents", "label": "Price after"},
            ],
            "legitimate": [
                {"key": "integrity_valid", "label": "Signature valid"},
                {"key": "accepted", "label": "Update accepted"},
                {"key": "after_price_cents", "label": "Price after"},
                {"key": "api_status", "label": "Protected API HTTP"},
            ],
        },
    },
    "a09": {
        "depth": "compact",
        "actor": "Synthetic source targeting Admin",
        "target": "Authentication monitoring",
        "technique": "Three failures inside 60 seconds",
        "impact": "Repeated attacks leave no investigation trail or alert, delaying detection and incident response.",
        "input_lock": "Both runs submit the same wrong Admin credentials three times through the real login endpoint.",
        "request": "POST /lab/a09/vulnerable/login × 3\nusername=admin&password=DEMO_WRONG_PASSWORD",
        "replay_request": "POST /lab/a09/secure/login × 3\nusername=admin&password=DEMO_WRONG_PASSWORD",
        "steps": [
            "Submit three failed Admin logins from one synthetic source.",
            "Compare event and threshold-alert counts after each attempt.",
        ],
        "failure": "The vulnerable branch returns 401 without emitting or correlating a security event.",
        "control": "The controlled branch writes minimised AUTH_FAILURE events and alerts once at 3/60s.",
        "vulnerable_code": _excerpt(
            "app/modules/compact.py",
            "    return (",
            '        "login failed with no security signal" if variant == "vulnerable" else "login failed and structured event recorded",',
            focus=('"login failed with no security signal"', 'variant == "vulnerable"'),
            tone="bad",
            after="    alert_count = db.execute(",
        ),
        "controlled_code": _excerpt(
            "app/modules/compact.py",
            "        window_start = now - A09_WINDOW_SECONDS",
            "        db.commit()",
            focus=("A09_WINDOW_SECONDS", "failure_count =", "failure_count >= A09_THRESHOLD", '"AUTH_FAILURE_THRESHOLD"'),
            tone="good",
            after="def _process_a09_login",
        ),
        "observations": {
            "vulnerable": [
                {"key": "failure_event_count", "label": "Failure events"},
                {"key": "alert_count", "label": "Alerts"},
                {"key": "claim_supported", "label": "Expected trace observed"},
            ],
            "controlled": [
                {"key": "failure_event_count", "label": "Failure events"},
                {"key": "alert_count", "label": "Alerts"},
                {"key": "claim_supported", "label": "Expected trace observed"},
            ],
            "legitimate": [
                {"key": "authenticated", "label": "Authenticated"},
                {"key": "subject", "label": "Subject"},
                {"key": "role", "label": "Role"},
            ],
        },
    },
    "a10": {
        "depth": "compact",
        "actor": "Alice · non-admin customer",
        "target": "Admin-only customer export",
        "technique": "Trigger the policy dependency exception",
        "impact": "A non-admin receives the protected customer export precisely when the authorization dependency is unavailable.",
        "input_lock": "The server-side identity remains Alice and simulate=error is replayed unchanged; actor=admin is deliberately injected and ignored.",
        "request": "POST /identity/alice\nGET /lab/a10/vulnerable/export?simulate=error&actor=admin",
        "replay_request": "POST /identity/alice\nGET /lab/a10/secure/export?simulate=error&actor=admin",
        "steps": [
            "Trigger the same controlled policy-service failure for Alice.",
            "Compare whether an unknown decision releases the export.",
        ],
        "failure": "The exception handler substitutes allowed=True when authorization is unknown.",
        "control": "The controlled handler fails closed with 503 and returns no protected export.",
        "vulnerable_code": _excerpt(
            "app/modules/compact.py",
            "    except ConnectionError:",
            "            allowed = True",
            focus=("allowed = True",),
            tone="bad",
            after="def a10_export",
        ),
        "controlled_code": _excerpt(
            "app/modules/compact.py",
            "        else:",
            "                status=503,",
            focus=('"access_granted": False', '"export_returned": False', "status=503"),
            tone="good",
            after="def a10_export",
        ),
        "observations": {
            "vulnerable": [
                {"key": "actor", "label": "Actor"},
                {"key": "policy_result", "label": "Policy result"},
                {"key": "fallback_decision", "label": "Fallback decision"},
                {"key": "access_granted", "label": "Access granted"},
                {"key": "export_returned", "label": "Export returned"},
            ],
            "controlled": [
                {"key": "actor", "label": "Actor"},
                {"key": "policy_result", "label": "Policy result"},
                {"key": "fallback_decision", "label": "Fallback decision"},
                {"key": "access_granted", "label": "Access granted"},
                {"key": "export_returned", "label": "Export returned"},
            ],
            "legitimate": [
                {"key": "actor", "label": "Actor"},
                {"key": "access_granted", "label": "Access granted"},
                {"key": "export_returned", "label": "Export returned"},
                {"key": "export_marker", "label": "Export marker"},
            ],
        },
    },
}


def _step(
    step_id: str,
    label: str,
    url: str,
    *,
    method: str = "GET",
    fields: dict | None = None,
    headers: dict | None = None,
    raw_body: str | None = None,
    observations: list[dict] | None = None,
    capture: dict | None = None,
) -> dict:
    step = {
        "id": step_id,
        "label": label,
        "url": url,
        "method": method,
        "fields": fields or {},
        "headers": headers or {},
        "observations": observations or [],
        "capture": capture or {},
    }
    if raw_body is not None:
        step["raw_body"] = raw_body
    return step


def _run(summary_step: str, observations: list[dict], *steps: dict) -> dict:
    return {
        "summary_step": summary_step,
        "observations": observations,
        "steps": list(steps),
    }


# These sequences are executed by the browser one request at a time.  The old
# guided endpoints remain for regression/evidence compatibility, but the UI no
# longer uses them as black boxes.
OBSERVER_HEADERS = {"X-TwinLab-Observer": "evidence-console"}


def _state_step(step_id: str, label: str, url: str, observations: list[dict]) -> dict:
    return _step(
        step_id,
        label,
        url,
        headers=OBSERVER_HEADERS,
        observations=observations,
    )


LAB_DEMOS["a01"]["runs"] = {
    "vulnerable": _run(
        "attack",
        LAB_DEMOS["a01"]["observations"]["vulnerable"],
        _state_step(
            "before",
            "Record the authoritative order-state digest",
            "/observer/a01/orders-state",
            [
                {"key": "row_count", "label": "Order rows"},
                {"key": "checksum", "label": "State digest before"},
            ],
        ),
        _step(
            "attack",
            "Open Bob's order while Alice is selected",
            "/lab/a01/vulnerable/orders/202",
            observations=LAB_DEMOS["a01"]["observations"]["vulnerable"],
        ),
        _state_step(
            "after",
            "Confirm the read did not modify the order database",
            "/observer/a01/orders-state",
            [
                {"key": "checksum", "label": "State digest after"},
                {"key": "raw_customer_data_returned", "label": "Raw customer data returned"},
            ],
        ),
    ),
    "controlled": _run(
        "attack",
        LAB_DEMOS["a01"]["observations"]["controlled"],
        _state_step(
            "before",
            "Record the same authoritative order state",
            "/observer/a01/orders-state",
            [{"key": "checksum", "label": "State digest before"}],
        ),
        _step(
            "attack",
            "Replay Bob's order ID against ownership enforcement",
            "/lab/a01/secure/orders/202",
            observations=LAB_DEMOS["a01"]["observations"]["controlled"],
        ),
        _state_step(
            "after",
            "Verify the authoritative order state is unchanged",
            "/observer/a01/orders-state",
            [{"key": "checksum", "label": "State digest after"}],
        ),
    ),
    "legitimate": _run(
        "request",
        LAB_DEMOS["a01"]["observations"]["legitimate"],
        _step(
            "request",
            "Open Alice's own order 101",
            "/lab/a01/secure/orders/101",
            observations=LAB_DEMOS["a01"]["observations"]["legitimate"],
        ),
    ),
}


LAB_DEMOS["a04"]["runs"] = {
    "vulnerable": _run(
        "compare",
        LAB_DEMOS["a04"]["observations"]["vulnerable"],
        _step(
            "compare",
            "Compare equal-password SHA-256 records",
            "/lab/a04/vulnerable/compare",
            method="POST",
            fields={"password": "correct-horse", "candidate": "wrong-password"},
            observations=LAB_DEMOS["a04"]["observations"]["vulnerable"],
        ),
    ),
    "controlled": _run(
        "compare",
        LAB_DEMOS["a04"]["observations"]["controlled"],
        _step(
            "compare",
            "Compare independently salted scrypt records",
            "/lab/a04/secure/compare",
            method="POST",
            fields={"password": "correct-horse", "candidate": "wrong-password"},
            observations=LAB_DEMOS["a04"]["observations"]["controlled"],
        ),
    ),
    "legitimate": _run(
        "compare",
        LAB_DEMOS["a04"]["observations"]["legitimate"],
        _step(
            "compare",
            "Verify the correct password against the controlled record",
            "/lab/a04/secure/compare",
            method="POST",
            fields={"password": "correct-horse", "candidate": "correct-horse"},
            observations=LAB_DEMOS["a04"]["observations"]["legitimate"],
        ),
    ),
}


LAB_DEMOS["a05"]["runs"] = {
    "vulnerable": _run(
        "attack",
        LAB_DEMOS["a05"]["observations"]["vulnerable"],
        _state_step(
            "before",
            "Record the authoritative catalogue digest",
            "/observer/a05/products-state",
            [
                {"key": "hidden_count", "label": "Internal rows"},
                {"key": "checksum", "label": "State digest before"},
            ],
        ),
        _step(
            "attack",
            "Submit the SQL control/data confusion payload",
            "/lab/a05/vulnerable/search?q=%25%27%20OR%201%3D1%20--",
            observations=LAB_DEMOS["a05"]["observations"]["vulnerable"],
        ),
        _state_step(
            "after",
            "Confirm the read-only payload did not modify catalogue state",
            "/observer/a05/products-state",
            [{"key": "checksum", "label": "State digest after"}],
        ),
    ),
    "controlled": _run(
        "attack",
        LAB_DEMOS["a05"]["observations"]["controlled"],
        _state_step(
            "before",
            "Record the same authoritative catalogue state",
            "/observer/a05/products-state",
            [{"key": "checksum", "label": "State digest before"}],
        ),
        _step(
            "attack",
            "Bind the identical payload as one search value",
            "/lab/a05/secure/search?q=%25%27%20OR%201%3D1%20--",
            observations=LAB_DEMOS["a05"]["observations"]["controlled"],
        ),
        _state_step(
            "after",
            "Verify the catalogue state remains unchanged",
            "/observer/a05/products-state",
            [{"key": "checksum", "label": "State digest after"}],
        ),
    ),
    "legitimate": _run(
        "request",
        LAB_DEMOS["a05"]["observations"]["legitimate"],
        _step(
            "request",
            "Search normally for Security",
            "/lab/a05/secure/search?q=Security",
            observations=LAB_DEMOS["a05"]["observations"]["legitimate"],
        ),
    ),
}


LAB_DEMOS["a10"]["runs"] = {
    "vulnerable": _run(
        "attack",
        LAB_DEMOS["a10"]["observations"]["vulnerable"],
        _step(
            "identity",
            "Select non-admin Alice in server-side lab identity state",
            "/identity/alice?format=json",
            method="POST",
            observations=[
                {"key": "actor", "label": "Server-side actor"},
                {"key": "role", "label": "Role"},
            ],
        ),
        _step(
            "attack",
            "Trigger the policy exception and attempt an actor-field spoof",
            "/lab/a10/vulnerable/export?simulate=error&actor=admin",
            observations=LAB_DEMOS["a10"]["observations"]["vulnerable"] + [
                {"key": "request_actor_ignored", "label": "Request actor ignored"}
            ],
        ),
    ),
    "controlled": _run(
        "attack",
        LAB_DEMOS["a10"]["observations"]["controlled"],
        _step(
            "identity",
            "Keep Alice as the server-side lab identity",
            "/identity/alice?format=json",
            method="POST",
        ),
        _step(
            "attack",
            "Replay the dependency failure against fail-closed handling",
            "/lab/a10/secure/export?simulate=error&actor=admin",
            observations=LAB_DEMOS["a10"]["observations"]["controlled"] + [
                {"key": "request_actor_ignored", "label": "Request actor ignored"}
            ],
        ),
    ),
    "legitimate": _run(
        "request",
        LAB_DEMOS["a10"]["observations"]["legitimate"],
        _step(
            "identity",
            "Select Admin in server-side lab identity state",
            "/identity/admin?format=json",
            method="POST",
            observations=[{"key": "actor", "label": "Server-side actor"}],
        ),
        _step(
            "request",
            "Confirm a healthy explicit Admin allow",
            "/lab/a10/secure/export?simulate=ok&actor=alice",
            observations=LAB_DEMOS["a10"]["observations"]["legitimate"] + [
                {"key": "request_actor_ignored", "label": "Request actor ignored"}
            ],
        ),
    ),
}


LAB_DEMOS["a02"]["runs"] = {
    "vulnerable": _run(
        "error",
        LAB_DEMOS["a02"]["observations"]["vulnerable"],
        _step(
            "error",
            "Trigger the exposed error response",
            "/lab/a02/vulnerable/order-lookup?id=explode",
            observations=LAB_DEMOS["a02"]["observations"]["vulnerable"],
        ),
        _step(
            "invalid_format",
            "Reach the same configured renderer through an invalid identifier",
            "/lab/a02/vulnerable/order-lookup?id=bad-format",
            observations=[
                {"key": "internal_details_returned", "label": "Internal details returned"},
                {"key": "error_policy", "label": "Configured error policy"},
            ],
        ),
    ),
    "controlled": _run(
        "error",
        LAB_DEMOS["a02"]["observations"]["controlled"],
        _step(
            "error",
            "Replay the same failing lookup",
            "/lab/a02/secure/order-lookup?id=explode",
            observations=LAB_DEMOS["a02"]["observations"]["controlled"],
            capture={"request_id": "request_id"},
        ),
        _step(
            "audit",
            "Inspect the correlated event through the observer plane",
            "/observer/a02/audit-event?request_id={{request_id}}",
            headers=OBSERVER_HEADERS,
            observations=[
                {"key": "event_found", "label": "Event found"},
                {"key": "event_type", "label": "Event type"},
                {"key": "event_details.route", "label": "Stored route"},
                {"key": "stored_detail_keys", "label": "Stored detail keys"},
            ],
        ),
        _step(
            "invalid_format",
            "Trigger a second exception entry point under the same policy",
            "/lab/a02/secure/order-lookup?id=bad-format",
            capture={"request_id_2": "request_id"},
            observations=[
                {"key": "internal_details_returned", "label": "Internal details returned"},
                {"key": "error_policy", "label": "Configured error policy"},
            ],
        ),
        _step(
            "audit_2",
            "Confirm the second entry point is also correlated in the observer plane",
            "/observer/a02/audit-event?request_id={{request_id_2}}",
            headers=OBSERVER_HEADERS,
            observations=[
                {"key": "event_found", "label": "Event found"},
                {"key": "stored_detail_keys", "label": "Stored detail keys"},
            ],
        ),
    ),
    "legitimate": _run(
        "lookup",
        LAB_DEMOS["a02"]["observations"]["legitimate"],
        _step(
            "lookup",
            "Run a valid order lookup",
            "/lab/a02/secure/order-lookup?id=101",
            observations=LAB_DEMOS["a02"]["observations"]["legitimate"],
        ),
    ),
}


LAB_DEMOS["a03"]["runs"] = {
    "vulnerable": _run(
        "newer",
        LAB_DEMOS["a03"]["observations"]["vulnerable"],
        _step(
            "newer",
            "Select from a repository containing unreviewed 2.4.2",
            "/lab/a03/vulnerable/verify?repository=newer",
            observations=LAB_DEMOS["a03"]["observations"]["vulnerable"],
        ),
    ),
    "controlled": _run(
        "newer",
        LAB_DEMOS["a03"]["observations"]["controlled"],
        _step(
            "newer",
            "Replay the same newer repository state",
            "/lab/a03/secure/verify?repository=newer",
            observations=LAB_DEMOS["a03"]["observations"]["controlled"],
        ),
        _step(
            "digest_tamper",
            "Modify the bytes at the pinned version",
            "/lab/a03/secure/verify?repository=pinned-tamper",
            observations=[
                {"key": "accepted", "label": "Tampered bytes accepted"},
                {"key": "digest_match", "label": "Digest matches manifest"},
                {"key": "expected_digest_fingerprint", "label": "Expected digest"},
                {"key": "actual_digest_fingerprint", "label": "Actual digest"},
            ],
        ),
    ),
    "legitimate": _run(
        "trusted",
        LAB_DEMOS["a03"]["observations"]["legitimate"],
        _step(
            "trusted",
            "Verify the reviewed pinned artefact",
            "/lab/a03/secure/verify?repository=trusted",
            observations=LAB_DEMOS["a03"]["observations"]["legitimate"],
        ),
    ),
}


def _coupon_sequence(variant: str, actor: str = "alice") -> dict:
    coupon_fields = {"coupon": "WELCOME10"}
    return _run(
        "state",
        [
            {"key": "steps.first.status", "label": "First-use HTTP"},
            {"key": "steps.replay.status", "label": "Replay HTTP"},
            {"key": "steps.replay.payload.accepted", "label": "Replay accepted"},
            {"key": "use_count", "label": "Stored redemptions"},
        ],
        _step(
            "identity",
            f"Select {actor} as the server-side synthetic customer",
            f"/identity/{actor}?format=json",
            method="POST",
            observations=[
                {"key": "actor", "label": "Server-side actor"},
                {"key": "identity_source", "label": "Identity source"},
            ],
        ),
        _step(
            "reset",
            f"Reset {actor}'s synthetic coupon state",
            f"/observer/a06/{variant}/reset-case",
            method="POST",
            fields={"subject": actor, "coupon": "WELCOME10"},
            headers=OBSERVER_HEADERS,
            observations=[{"key": "use_count", "label": "Uses before experiment"}],
        ),
        _step(
            "first",
            "Submit the valid coupon once",
            f"/lab/a06/{variant}/apply",
            method="POST",
            fields=coupon_fields,
            observations=[
                {"key": "accepted", "label": "Accepted"},
                {"key": "redemption_number", "label": "Redemption number"},
            ],
        ),
        _step(
            "replay",
            "Replay the identical coupon request",
            f"/lab/a06/{variant}/apply",
            method="POST",
            fields=coupon_fields,
            observations=[
                {"key": "accepted", "label": "Accepted"},
                {"key": "redemption_number", "label": "Redemption number"},
                {"key": "previous_uses", "label": "Previous uses"},
            ],
        ),
        _step(
            "state",
            "Inspect the stored redemption records",
            f"/observer/a06/{variant}/state?subject={actor}&coupon=WELCOME10",
            headers=OBSERVER_HEADERS,
            observations=[
                {"key": "use_count", "label": "Stored redemptions"},
                {"key": "database_unique_invariant", "label": "Unique invariant"},
            ],
        ),
    )


LAB_DEMOS["a06"]["runs"] = {
    "vulnerable": _coupon_sequence("vulnerable"),
    "controlled": _coupon_sequence("secure"),
    "legitimate": _run(
        "state",
        [
            {"key": "steps.first.status", "label": "First-use HTTP"},
            {"key": "steps.first.payload.accepted", "label": "First use accepted"},
            {"key": "use_count", "label": "Stored redemptions"},
            {"key": "actor", "label": "Independent actor"},
        ],
        _step(
            "identity",
            "Select Bob as an independent eligible customer",
            "/identity/bob?format=json",
            method="POST",
            observations=[{"key": "actor", "label": "Server-side actor"}],
        ),
        _step(
            "reset",
            "Reset Bob's synthetic coupon state",
            "/observer/a06/secure/reset-case",
            method="POST",
            fields={"subject": "bob", "coupon": "WELCOME10"},
            headers=OBSERVER_HEADERS,
            observations=[{"key": "use_count", "label": "Uses before experiment"}],
        ),
        _step(
            "first",
            "Submit Bob's valid first coupon use",
            "/lab/a06/secure/apply",
            method="POST",
            fields={"coupon": "WELCOME10"},
            observations=[
                {"key": "accepted", "label": "Accepted"},
                {"key": "redemption_number", "label": "Redemption number"},
                {"key": "discount_percent", "label": "Discount percent"},
            ],
        ),
        _step(
            "state",
            "Inspect Bob's stored redemption state",
            "/observer/a06/secure/state?subject=bob&coupon=WELCOME10",
            headers=OBSERVER_HEADERS,
            observations=[
                {"key": "actor", "label": "Actor"},
                {"key": "use_count", "label": "Stored redemptions"},
            ],
        ),
    ),
}


def _session_sequence(variant: str) -> dict:
    token_header = {"X-Lab-Session": "{{old_token}}"}
    steps = [
        _step(
            "login",
            "Create and capture a synthetic Admin token",
            f"/lab/a07/{variant}/login",
            method="POST",
            fields={"username": "admin", "password": "demo-admin"},
            observations=[
                {"key": "username", "label": "Username"},
                {"key": "role", "label": "Role"},
                {"key": "lab_token", "label": "Captured token"},
            ],
            capture={"old_token": "lab_token"},
        ),
        _step(
            "before_logout",
            "Confirm the captured token works before logout",
            f"/lab/a07/{variant}/admin",
            headers=token_header,
            observations=[{"key": "admin_data_returned", "label": "Admin data returned"}],
        ),
        _step(
            "logout",
            "Log out with the captured token",
            f"/lab/a07/{variant}/logout",
            method="POST",
            headers=token_header,
            observations=[
                {"key": "http_status", "label": "Logout HTTP"},
                {"key": "response_headers.x-twinlab-server-session-revoked", "label": "Server state revoked"},
            ],
        ),
        _step(
            "state",
            "Inspect the old token through the observer plane",
            f"/observer/a07/{variant}/session-state",
            headers={**token_header, **OBSERVER_HEADERS},
            observations=[
                {"key": "token_fingerprint", "label": "Token fingerprint"},
                {"key": "active", "label": "Session active"},
                {"key": "expired", "label": "Expired"},
            ],
        ),
        _step(
            "replay",
            "Replay the old token after logout",
            f"/lab/a07/{variant}/admin",
            headers=token_header,
            observations=[
                {"key": "admin_data_returned", "label": "Admin data returned"},
                {"key": "admin_marker", "label": "Admin marker"},
            ],
        ),
        _step(
            "fresh_login",
            "Create a different fresh Admin token",
            f"/lab/a07/{variant}/login",
            method="POST",
            fields={"username": "admin", "password": "demo-admin"},
            observations=[{"key": "lab_token", "label": "Fresh token"}],
            capture={"fresh_token": "lab_token"},
        ),
        _step(
            "fresh_admin",
            "Use the fresh token on the Admin endpoint",
            f"/lab/a07/{variant}/admin",
            headers={"X-Lab-Session": "{{fresh_token}}"},
            observations=[{"key": "admin_data_returned", "label": "Admin data returned"}],
        ),
    ]
    if variant == "secure":
        steps.extend(
            [
                _step(
                    "expiry_login",
                    "Create a session for the expiry decision",
                    "/lab/a07/secure/login",
                    method="POST",
                    fields={"username": "admin", "password": "demo-admin"},
                    capture={"expiry_token": "lab_token"},
                ),
                _step(
                    "expire",
                    "Move that synthetic session beyond expiry in the observer plane",
                    "/observer/a07/secure/expire-session",
                    method="POST",
                    headers={
                        "X-Lab-Session": "{{expiry_token}}",
                        **OBSERVER_HEADERS,
                    },
                    observations=[{"key": "expired", "label": "Expiry applied"}],
                ),
                _step(
                    "expired_admin",
                    "Present the expired token to the protected endpoint",
                    "/lab/a07/secure/admin",
                    headers={"X-Lab-Session": "{{expiry_token}}"},
                    observations=[{"key": "admin_data_returned", "label": "Admin data returned"}],
                ),
                _step(
                    "random_admin",
                    "Present a token with no authoritative session row",
                    "/lab/a07/secure/admin",
                    headers={"X-Lab-Session": "synthetic-random-token-not-issued"},
                    observations=[{"key": "admin_data_returned", "label": "Admin data returned"}],
                ),
            ]
        )
    return _run(
        "replay",
        [
            {"key": "steps.logout.headers.x-twinlab-server-session-revoked", "label": "Server session revoked"},
            {"key": "steps.state.payload.active", "label": "Old session active"},
            {"key": "steps.replay.status", "label": "Replay HTTP"},
            {"key": "steps.replay.payload.admin_data_returned", "label": "Admin data returned"},
            {"key": "steps.fresh_admin.status", "label": "Fresh session HTTP"},
        ],
        *steps,
    )


LAB_DEMOS["a07"]["runs"] = {
    "vulnerable": _session_sequence("vulnerable"),
    "controlled": _session_sequence("secure"),
    "legitimate": _run(
        "admin",
        [
            {"key": "username", "label": "Username"},
            {"key": "admin_data_returned", "label": "Admin data returned"},
            {"key": "steps.login.payload.expires_in_seconds", "label": "Session lifetime"},
        ],
        _step(
            "login",
            "Create a fresh controlled Admin session",
            "/lab/a07/secure/login",
            method="POST",
            fields={"username": "admin", "password": "demo-admin"},
            observations=[
                {"key": "username", "label": "Username"},
                {"key": "role", "label": "Role"},
                {"key": "lab_token", "label": "Fresh token"},
            ],
            capture={"fresh_token": "lab_token"},
        ),
        _step(
            "admin",
            "Use the fresh token on the Admin endpoint",
            "/lab/a07/secure/admin",
            headers={"X-Lab-Session": "{{fresh_token}}"},
            observations=[
                {"key": "username", "label": "Username"},
                {"key": "admin_data_returned", "label": "Admin data returned"},
            ],
        ),
    ),
}


def _auth_failure_sequence(variant: str) -> dict:
    wrong = {"username": "admin", "password": "DEMO_WRONG_PASSWORD"}
    return _run(
        "state",
        [
            {"key": "steps.failure_1.status", "label": "Attempt 1 HTTP"},
            {"key": "steps.failure_2.status", "label": "Attempt 2 HTTP"},
            {"key": "steps.failure_3.status", "label": "Attempt 3 HTTP"},
            {"key": "auth_failure_count", "label": "Stored failure events"},
            {"key": "alert_count", "label": "Threshold alerts"},
        ],
        _step(
            "reset",
            "Reset the synthetic Admin telemetry",
            f"/observer/a09/{variant}/reset-case",
            method="POST",
            fields={"username": "admin"},
            headers=OBSERVER_HEADERS,
            observations=[
                {"key": "event_count", "label": "Events before"},
                {"key": "alert_count", "label": "Alerts before"},
            ],
        ),
        *[
            _step(
                f"failure_{attempt}",
                f"Submit wrong Admin password — attempt {attempt}",
                f"/lab/a09/{variant}/login",
                method="POST",
                fields=wrong,
                observations=[
                    {"key": "authenticated", "label": "Authenticated"},
                    {"key": "failure_event_count", "label": "Failure events"},
                    {"key": "alert_count", "label": "Alerts"},
                ],
            )
            for attempt in range(1, 4)
        ],
        _step(
            "state",
            "Inspect stored events and alerts",
            f"/observer/a09/{variant}/state?username=admin",
            headers=OBSERVER_HEADERS,
            observations=[
                {"key": "auth_failure_count", "label": "Failure events"},
                {"key": "alert_count", "label": "Threshold alerts"},
                {"key": "passwords_or_tokens_logged", "label": "Secrets logged"},
            ],
        ),
    )


LAB_DEMOS["a09"]["runs"] = {
    "vulnerable": _auth_failure_sequence("vulnerable"),
    "controlled": _auth_failure_sequence("secure"),
    "legitimate": _run(
        "login",
        [
            {"key": "authenticated", "label": "Authenticated"},
            {"key": "subject", "label": "Subject"},
            {"key": "role", "label": "Role"},
            {"key": "steps.state.payload.auth_success_count", "label": "Success events"},
        ],
        _step(
            "reset",
            "Reset the synthetic Admin telemetry",
            "/observer/a09/secure/reset-case",
            method="POST",
            fields={"username": "admin"},
            headers=OBSERVER_HEADERS,
        ),
        _step(
            "login",
            "Submit the valid Admin credentials",
            "/lab/a09/secure/login",
            method="POST",
            fields={"username": "admin", "password": "demo-admin"},
            observations=[
                {"key": "authenticated", "label": "Authenticated"},
                {"key": "subject", "label": "Subject"},
                {"key": "role", "label": "Role"},
            ],
        ),
        _step(
            "state",
            "Inspect the stored success event",
            "/observer/a09/secure/state?username=admin",
            headers=OBSERVER_HEADERS,
            observations=[
                {"key": "auth_success_count", "label": "Success events"},
                {"key": "alert_count", "label": "Failure alerts"},
            ],
        ),
    ),
}
