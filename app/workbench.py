"""Operational product metadata for the TwinShop security workbench.

This is deliberately not report-style teaching content.  It defines the
experiment contract the running product needs: who acts, which asset is in
scope, the invariant being tested, the concrete abuse action, and the narrow
claim boundary for the executable proof.
"""

from __future__ import annotations


WORKBENCH_COMPONENTS = [
    {
        "id": "storefront",
        "name": "Customer storefront",
        "description": "Search, orders and coupon operations initiated by a customer browser.",
        "labs": ["a01", "a05", "a06"],
        "boundary": "Browser input crosses into server-side authorization and data decisions.",
    },
    {
        "id": "identity",
        "name": "Identity & session service",
        "description": "Credential verification, session creation, logout and privileged access.",
        "labs": ["a04", "a07", "a09"],
        "boundary": "Identity evidence must be established and mediated by the server.",
    },
    {
        "id": "operations",
        "name": "Operations boundary",
        "description": "Error handling, audit records and exceptional authorization decisions.",
        "labs": ["a02", "a10"],
        "boundary": "Customer responses are separated from operator-only evidence and policy state.",
    },
    {
        "id": "delivery",
        "name": "Software & data delivery",
        "description": "Package selection and integrity-protected administrative messages.",
        "labs": ["a03", "a08"],
        "boundary": "Untrusted artefacts and messages must be verified before use.",
    },
]


LAB_WORKBENCH = {
    "a01": {
        "component": "Customer storefront · Orders",
        "actor_capability": "Alice has a valid customer session and can choose an order identifier.",
        "asset": "Order ownership, shipping address and order value",
        "invariant": "A customer may read or update only an order they own.",
        "abuse_action": "Replace Alice's order ID 101 with Bob's ID 202.",
        "observed_effect": "The vulnerable read returns Bob's order; the controlled read returns no order data.",
        "supported_claim": "Object ownership is enforced for the demonstrated order operations.",
        "not_tested": "It does not prove authorization is correct for every TwinShop resource or action.",
        "input": {"name": "order_id", "label": "Order ID", "value": "202", "type": "number"},
    },
    "a02": {
        "component": "Operations boundary · Error policy",
        "actor_capability": "An unauthenticated caller can submit an invalid order lookup value.",
        "asset": "Internal paths, query shape and configuration metadata",
        "invariant": "Operator diagnostics must not cross into a customer response.",
        "abuse_action": "Trigger the controlled error using lookup value explode.",
        "observed_effect": "The vulnerable response exposes fixed internal markers; the controlled response returns a correlation ID only.",
        "supported_claim": "The demonstrated error policy separates client output from minimised operator evidence.",
        "not_tested": "It does not enable a live debugger or claim that every framework error path is covered.",
        "input": {"name": "lookup_id", "label": "Lookup value", "value": "explode", "type": "text"},
    },
    "a03": {
        "component": "Software delivery · Package selection",
        "actor_capability": "A publisher can place a newer artefact in the synthetic repository.",
        "asset": "Reviewed dependency bytes",
        "invariant": "Only the reviewed version and digest may enter the build.",
        "abuse_action": "Add unreviewed version 2.4.2 and modify the pinned artefact bytes.",
        "observed_effect": "Floating latest accepts the unreviewed artefact; the manifest pin and digest reject changed bytes.",
        "supported_claim": "Version selection and byte integrity are enforced for the inert local artefacts.",
        "not_tested": "No package is installed or executed; provenance, SBOM and signing are outside this compact check.",
    },
    "a04": {
        "component": "Identity service · Credential records",
        "actor_capability": "An offline observer can compare two synthetic password records.",
        "asset": "Password secrecy and cross-account unlinkability",
        "invariant": "Equal passwords must not create equal reusable stored records.",
        "abuse_action": "Compare Alice and Bob records created from the same password.",
        "observed_effect": "Unsalted SHA-256 records match; independently salted scrypt records differ and still verify correctly.",
        "supported_claim": "The demonstrated record construction removes direct equality leakage and adds KDF cost.",
        "not_tested": "This is not a persistent production credential lifecycle or a cracking benchmark.",
    },
    "a05": {
        "component": "Customer storefront · Product search",
        "actor_capability": "Any visitor can control the public product search term.",
        "asset": "Internal-only catalogue rows",
        "invariant": "Search input remains data and cannot change the SQL program.",
        "abuse_action": "Submit %' OR 1=1 -- in the product search field.",
        "observed_effect": "The interpolated query returns the hidden product; the bound query treats the payload as text.",
        "supported_claim": "The demonstrated value injection is prevented by parameter binding while normal search remains available.",
        "not_tested": "The check is read-only and does not prove every query or dynamic identifier is safe.",
        "input": {"name": "search_query", "label": "Search query", "value": "%' OR 1=1 --", "type": "text"},
    },
    "a06": {
        "component": "Customer storefront · Promotion policy",
        "actor_capability": "An authenticated eligible customer can replay a valid coupon request.",
        "asset": "Order price integrity and promotion budget",
        "invariant": "WELCOME10 is redeemable at most once per eligible customer.",
        "abuse_action": "Submit the same coupon twice for the same server-side customer identity.",
        "observed_effect": "The vulnerable path stores two uses; the controlled transaction and database invariant retain one.",
        "supported_claim": "The demonstrated one-use invariant survives sequential replay for the synthetic database.",
        "not_tested": "Payment, distributed concurrency and the full checkout lifecycle are outside this compact check.",
    },
    "a07": {
        "component": "Identity service · Session lifecycle",
        "actor_capability": "An attacker already holds one captured pre-logout Admin token.",
        "asset": "Privileged Admin session",
        "invariant": "Logout and expiry make an old token unusable at every protected request.",
        "abuse_action": "Replay the captured token after logout, then compare random, expired and fresh tokens.",
        "observed_effect": "Client-only logout leaves the old session usable; server revocation rejects it while a fresh session works.",
        "supported_claim": "The demonstrated protected endpoint completely mediates active, revoked and fresh session state.",
        "not_tested": "Token theft prevention, browser compromise and distributed session stores are outside this lab.",
    },
    "a08": {
        "component": "Data delivery · Price update",
        "actor_capability": "A caller can alter message bytes while retaining an old signature.",
        "asset": "Stored product price",
        "invariant": "Price state changes only after exact-body integrity verification.",
        "abuse_action": "Change the signed 5100-cent message to 100 cents and replay its stale signature.",
        "observed_effect": "The vulnerable branch stores 100; the controlled branch rejects the bytes and retains 4900.",
        "supported_claim": "The demonstrated HMAC gate binds acceptance to the exact request bytes.",
        "not_tested": "Freshness, replay prevention, key rotation and publisher authorization remain outside this compact check.",
    },
    "a09": {
        "component": "Identity service · Security telemetry",
        "actor_capability": "One synthetic source can submit repeated incorrect Admin credentials.",
        "asset": "Authentication investigation trail and threshold signal",
        "invariant": "Three failures inside 60 seconds produce minimised events and one alert without logging secrets.",
        "abuse_action": "Submit the same wrong Admin password three times.",
        "observed_effect": "The vulnerable path remains silent; the controlled path stores three events and one threshold alert.",
        "supported_claim": "The local rolling-window rule produces the demonstrated trace and alert without secret fields.",
        "not_tested": "This is not a distributed SIEM, SOC workflow or measured incident-response improvement.",
    },
    "a10": {
        "component": "Operations boundary · Authorization dependency",
        "actor_capability": "Authenticated Alice can trigger a controlled policy-service exception.",
        "asset": "Admin-only customer export",
        "invariant": "An unknown authorization decision never releases protected data.",
        "abuse_action": "Trigger the same policy dependency failure as non-admin Alice.",
        "observed_effect": "Fail-open releases the export; fail-closed returns 503 with no export while healthy Admin access remains available.",
        "supported_claim": "The demonstrated exception path fails closed and derives the actor from server-side lab identity state.",
        "not_tested": "The compact policy service is local and does not model retries, caching or a production identity provider.",
    },
}


# Product-runtime attack narratives.  These are execution plans, not report
# sections: each step can be rendered as an action and then bound to the
# corresponding response captured by the vulnerable runner.  ``evidence_path``
# is relative to that step record (for example ``payload.object_owner`` or
# ``status``); conceptual setup steps deliberately use ``None``.
ATTACKER_JOURNEYS = {
    "a01": {
        "objective": "Read Bob's order 202 while authenticated only as Alice.",
        "starting_position": "Alice has an ordinary customer session and knows that her own order is 101.",
        "hypothesis": "The order route may treat a valid login as sufficient and look up whichever order ID appears in the URL.",
        "steps": [
            {
                "id": "establish_actor",
                "action": "Keep the server-side identity set to Alice; do not obtain Bob's credentials or session.",
                "expected_signal": "The request context identifies Alice as a customer.",
                "evidence_step": None,
                "evidence_path": None,
            },
            {
                "id": "record_target_state",
                "action": "Record the order-store digest, then change the browser-controlled order ID from Alice's 101 to Bob's 202.",
                "expected_signal": "Order 202 exists in the authoritative store before the read attempt.",
                "evidence_step": "before",
                "evidence_path": "payload.row_count",
            },
            {
                "id": "request_foreign_order",
                "action": "Send GET /lab/a01/vulnerable/orders/202 using Alice's active identity.",
                "expected_signal": "HTTP 200 returns an order whose owner is Bob even though the requester is Alice.",
                "evidence_step": "attack",
                "evidence_path": "payload.object_owner",
            },
            {
                "id": "confirm_disclosure",
                "action": "Inspect the response for the authorization decision and customer fields.",
                "expected_signal": "authorized=false while sensitive_data_returned=true, including Bob's shipping address.",
                "evidence_step": "attack",
                "evidence_path": "payload.sensitive_data_returned",
            },
        ],
        "failed_server_decision": "The server selects an order by order_id alone after authentication; it never includes Alice's owner_id in the authorization predicate.",
        "payoff": "Bob's item, address and order value are disclosed, and changing IDs could repeat the disclosure across other customers.",
    },
    "a02": {
        "objective": "Extract operator-only diagnostics through the public order-lookup error boundary.",
        "starting_position": "No account is required; the caller can supply the public id query parameter.",
        "hypothesis": "A predictable invalid value may reach an exception renderer that serializes internal debugging material into the client response.",
        "steps": [
            {
                "id": "trigger_runtime_error",
                "action": "Send GET /lab/a02/vulnerable/order-lookup?id=explode.",
                "expected_signal": "The client receives an error response with internal_details_returned=true.",
                "evidence_step": "error",
                "evidence_path": "payload.internal_details_returned",
            },
            {
                "id": "collect_diagnostics",
                "action": "Inspect the returned body for trace, filesystem path, SQL-shape and configuration markers.",
                "expected_signal": "Operator-only diagnostic fields are visible in the customer-facing response.",
                "evidence_step": "error",
                "evidence_path": "payload.synthetic_path",
            },
            {
                "id": "test_second_entry",
                "action": "Send the different malformed value id=bad-format through the same public route.",
                "expected_signal": "The second exception path applies the same exposed error policy.",
                "evidence_step": "invalid_format",
                "evidence_path": "payload.internal_details_returned",
            },
        ],
        "failed_server_decision": "The exception handler uses internal diagnostic data as the client error representation instead of separating customer output from operator evidence.",
        "payoff": "The attacker learns internal paths, query shape and configuration markers that reduce uncertainty for targeted follow-up attacks.",
    },
    "a03": {
        "objective": "Cause the synthetic build to select an unreviewed dependency artefact.",
        "starting_position": "The attacker can publish version 2.4.2 beside the reviewed 2.4.1 artefact in the local repository model.",
        "hypothesis": "A floating-latest policy will prefer the higher version without checking the reviewed version or digest.",
        "steps": [
            {
                "id": "publish_newer",
                "action": "Place the newer unreviewed 2.4.2 artefact in the repository state.",
                "expected_signal": "Both 2.4.1 and 2.4.2 are available to dependency selection.",
                "evidence_step": None,
                "evidence_path": None,
            },
            {
                "id": "invoke_build_selection",
                "action": "Run the vulnerable verifier against repository=newer.",
                "expected_signal": "The floating policy selects version 2.4.2.",
                "evidence_step": "newer",
                "evidence_path": "payload.selected_version",
            },
            {
                "id": "confirm_unreviewed_bytes",
                "action": "Inspect the selected artefact marker and acceptance decision.",
                "expected_signal": "contains_untrusted_marker=true and the artefact is accepted.",
                "evidence_step": "newer",
                "evidence_path": "payload.contains_untrusted_marker",
            },
        ],
        "failed_server_decision": "The build trusts version ordering as its selection and trust decision, with no reviewed manifest pin or digest comparison.",
        "payoff": "Unreviewed bytes enter the build boundary with the privileges later granted to the dependency.",
    },
    "a04": {
        "objective": "Identify accounts sharing a password and make offline password guesses cheap to compare.",
        "starting_position": "The attacker has obtained two synthetic stored credential records but not the plaintext passwords.",
        "hypothesis": "A fast unsalted digest will produce the same reusable record whenever two accounts use the same password.",
        "steps": [
            {
                "id": "create_records",
                "action": "Create Alice and Bob records from the same synthetic password through the vulnerable comparison.",
                "expected_signal": "Both records report SHA-256 with zero-length salts.",
                "evidence_step": "compare",
                "evidence_path": "payload.algorithm",
            },
            {
                "id": "compare_records",
                "action": "Compare the two stored record fingerprints byte-for-byte.",
                "expected_signal": "hashes_equal=true reveals that Alice and Bob reused the same password.",
                "evidence_step": "compare",
                "evidence_path": "payload.hashes_equal",
            },
        ],
        "failed_server_decision": "Credential storage applies a deterministic fast hash without a unique per-account salt or a password-specific KDF.",
        "payoff": "One comparison links password reuse across accounts, and each offline password guess can be tested quickly against every matching record.",
    },
    "a05": {
        "objective": "Make the public product search return an internal-only catalogue row.",
        "starting_position": "The attacker is unauthenticated and controls only the q value of the public search request.",
        "hypothesis": "If q is interpolated into SQL before parsing, a quote can end the intended string and inject a true WHERE expression.",
        "steps": [
            {
                "id": "map_catalogue",
                "action": "Record that the authoritative catalogue contains at least one hidden row before running the search.",
                "expected_signal": "The observer reports an internal row that should never appear in public results.",
                "evidence_step": "before",
                "evidence_path": "payload.hidden_count",
            },
            {
                "id": "construct_payload",
                "action": "Build the search value %' OR 1=1 --: the quote exits the string, OR 1=1 makes the predicate true, and -- comments out the remainder.",
                "expected_signal": "The exact payload is ready to be sent as one q parameter.",
                "evidence_step": None,
                "evidence_path": None,
            },
            {
                "id": "execute_injection",
                "action": "Send the payload to /lab/a05/vulnerable/search and inspect the effective SQL.",
                "expected_signal": "The executed statement contains attacker-supplied SQL structure rather than one bound value.",
                "evidence_step": "attack",
                "evidence_path": "payload.executed_statement",
            },
            {
                "id": "confirm_hidden_result",
                "action": "Inspect the returned products for the internal-only marker.",
                "expected_signal": "hidden_exposed=true and the private catalogue row crosses into the response.",
                "evidence_step": "attack",
                "evidence_path": "payload.hidden_exposed",
            },
        ],
        "failed_server_decision": "The server concatenates untrusted q text into the SQL program before the database parses it.",
        "payoff": "The attacker reads internal catalogue data; the same code/data confusion pattern can threaten other database confidentiality or integrity.",
    },
    "a06": {
        "objective": "Redeem the one-use WELCOME10 promotion more than once as Alice.",
        "starting_position": "Alice is an eligible authenticated customer with a valid first-use coupon request.",
        "hypothesis": "If redemption is recorded without an atomic one-use invariant, an identical replay will be treated as another valid use.",
        "steps": [
            {
                "id": "first_redemption",
                "action": "Submit Alice's valid WELCOME10 request once.",
                "expected_signal": "The first request is accepted with HTTP 201.",
                "evidence_step": "first",
                "evidence_path": "status",
            },
            {
                "id": "replay_redemption",
                "action": "Submit the identical customer-and-coupon request a second time.",
                "expected_signal": "The vulnerable endpoint accepts the replay with another HTTP 201.",
                "evidence_step": "replay",
                "evidence_path": "status",
            },
            {
                "id": "inspect_redemptions",
                "action": "Read the authoritative coupon-use state after both requests.",
                "expected_signal": "Two redemption records exist for Alice and WELCOME10.",
                "evidence_step": "state",
                "evidence_path": "payload.use_count",
            },
        ],
        "failed_server_decision": "The server inserts another use without atomically checking or enforcing uniqueness for the customer-and-coupon pair.",
        "payoff": "The attacker receives repeated discounts and consumes promotion budget beyond the intended one-use rule.",
    },
    "a07": {
        "objective": "Keep using privileged Admin access after the real Admin has logged out.",
        "starting_position": "The attacker already possesses one valid Admin bearer token captured before logout.",
        "hypothesis": "Logout may remove only browser state while leaving the matching server-side session active.",
        "steps": [
            {
                "id": "capture_token",
                "action": "Create an Admin session and retain the issued token independently of the browser cookie.",
                "expected_signal": "The login succeeds and returns a token that can be replayed directly.",
                "evidence_step": "login",
                "evidence_path": "payload.lab_token",
            },
            {
                "id": "prove_privilege",
                "action": "Present the captured token to the protected Admin endpoint before logout.",
                "expected_signal": "HTTP 200 returns the Admin marker, proving the captured token carries privilege.",
                "evidence_step": "before_logout",
                "evidence_path": "payload.admin_data_returned",
            },
            {
                "id": "logout_and_check_state",
                "action": "Log out, then inspect the captured token's authoritative session row.",
                "expected_signal": "The browser-side logout completes but the vulnerable server session remains active=true.",
                "evidence_step": "state",
                "evidence_path": "payload.active",
            },
            {
                "id": "replay_old_token",
                "action": "Send the retained pre-logout token directly to the Admin endpoint.",
                "expected_signal": "HTTP 200 still returns admin_data_returned=true after logout.",
                "evidence_step": "replay",
                "evidence_path": "payload.admin_data_returned",
            },
        ],
        "failed_server_decision": "Vulnerable logout clears client state but does not revoke the server session, and the protected endpoint continues to accept that active token.",
        "payoff": "The attacker preserves privileged Admin access after the user believes the session has ended.",
    },
    "a08": {
        "objective": "Change product 1 from 4900 cents to 100 cents using a signature created for different bytes.",
        "starting_position": "The attacker can intercept a valid signed 5100-cent message and alter its body while retaining the old signature.",
        "hypothesis": "The update path may compute integrity but still mutate price state when verification fails.",
        "steps": [
            {
                "id": "establish_price",
                "action": "Reset and record product 1 at 4900 cents.",
                "expected_signal": "The authoritative starting price is 4900.",
                "evidence_step": "reset",
                "evidence_path": "payload.price_cents",
            },
            {
                "id": "submit_tampered_message",
                "action": "Replace the signed 5100-cent body with 100-cent bytes and submit it with the stale signature.",
                "expected_signal": "integrity_valid=false but the vulnerable update is still accepted.",
                "evidence_step": "update",
                "evidence_path": "payload.accepted",
            },
            {
                "id": "confirm_price_change",
                "action": "Read the authoritative product state after the rejected-integrity decision.",
                "expected_signal": "The stored price is now 100 cents.",
                "evidence_step": "state",
                "evidence_path": "payload.price_cents",
            },
        ],
        "failed_server_decision": "The server calculates that the signature is invalid but does not use that result as a mandatory gate before parsing and updating state.",
        "payoff": "The attacker directly violates price integrity and can purchase or expose goods at an unauthorized value.",
    },
    "a09": {
        "objective": "Make repeated Admin password attempts without creating an investigation trail or threshold alert.",
        "starting_position": "The unauthenticated attacker can reach the Admin login endpoint from one synthetic source.",
        "hypothesis": "Failed authentication may return 401 without recording a structured security event.",
        "steps": [
            {
                "id": "clear_baseline",
                "action": "Start with zero synthetic Admin failure events and alerts.",
                "expected_signal": "The monitoring state is empty before the attempt sequence.",
                "evidence_step": "reset",
                "evidence_path": "payload.event_count",
            },
            {
                "id": "repeat_failures",
                "action": "Submit the same wrong Admin password three times inside 60 seconds.",
                "expected_signal": "Each login returns 401, but the vulnerable path emits no security signal.",
                "evidence_step": "failure_3",
                "evidence_path": "status",
            },
            {
                "id": "inspect_telemetry",
                "action": "Inspect stored authentication events and threshold alerts after the third failure.",
                "expected_signal": "auth_failure_count=0 and alert_count=0.",
                "evidence_step": "state",
                "evidence_path": "payload.auth_failure_count",
            },
        ],
        "failed_server_decision": "The login handler treats a 401 response as the complete failure outcome and omits the minimised event needed for correlation and alerting.",
        "payoff": "Password attacks remain invisible in the demonstrated telemetry, delaying detection and investigation.",
    },
    "a10": {
        "objective": "Obtain the Admin-only customer export while authenticated only as Alice.",
        "starting_position": "Alice has a valid non-admin session and can trigger the synthetic authorization-policy dependency failure.",
        "hypothesis": "The exception path may replace an unknown authorization result with allow.",
        "steps": [
            {
                "id": "establish_non_admin",
                "action": "Select Alice as the signed server-side identity and optionally send actor=admin as an ignored spoof field.",
                "expected_signal": "The authoritative actor remains Alice with the customer role.",
                "evidence_step": "identity",
                "evidence_path": "payload.actor",
            },
            {
                "id": "trigger_policy_failure",
                "action": "Request /lab/a10/vulnerable/export?simulate=error&actor=admin.",
                "expected_signal": "The policy result is unknown, but fallback_decision=allow.",
                "evidence_step": "attack",
                "evidence_path": "payload.fallback_decision",
            },
            {
                "id": "confirm_export",
                "action": "Inspect whether the protected export crossed to the non-admin response.",
                "expected_signal": "access_granted=true and export_returned=true for Alice.",
                "evidence_step": "attack",
                "evidence_path": "payload.export_returned",
            },
        ],
        "failed_server_decision": "The authorization exception handler substitutes allowed=true when the policy service cannot provide a decision.",
        "payoff": "A non-admin receives the protected customer export precisely when the authorization dependency is unavailable.",
    },
}

for _lab_id, _attacker_journey in ATTACKER_JOURNEYS.items():
    # ``attack_execution`` is the UI-facing alias.  The additional names keep
    # the card schema terse while the fuller attacker-journey vocabulary
    # remains available to other consumers.
    _attacker_journey["baseline"] = _attacker_journey["starting_position"]
    _attacker_journey["manipulation"] = LAB_WORKBENCH[_lab_id]["abuse_action"]
    _attacker_journey["failed_decision"] = _attacker_journey["failed_server_decision"]
    _attacker_journey["obtained_effect"] = _attacker_journey["payoff"]
    for _journey_step in _attacker_journey["steps"]:
        if _journey_step["evidence_step"] and _journey_step["evidence_path"]:
            _journey_step["evidence"] = (
                f"steps.{_journey_step['evidence_step']}."
                f"{_journey_step['evidence_path']}"
            )
        else:
            _journey_step["evidence"] = None
    LAB_WORKBENCH[_lab_id]["attacker_journey"] = _attacker_journey
    LAB_WORKBENCH[_lab_id]["attack_execution"] = _attacker_journey


# Machine-readable checks consumed by the browser runner.  Paths are resolved
# against a phase summary, which includes the selected response and every step
# under ``steps.<step_id>``.  Multiple checks with the same id are ANDed.
ASSURANCE_ASSERTIONS = {
    "a01": {
        "vulnerable": [
            {"id": "vulnerability_reproduced", "label": "Cross-owner order disclosed", "path": "sensitive_data_returned", "operator": "equals", "expected": True},
            {"id": "vulnerability_reproduced", "label": "Returned object is not Alice's", "path": "authorized", "operator": "equals", "expected": False},
        ],
        "controlled": [
            {"id": "control_effective", "label": "Cross-owner data withheld", "path": "sensitive_data_returned", "operator": "equals", "expected": False},
            {"id": "authoritative_state_safe", "label": "Order database unchanged", "path": ["steps.before.payload.checksum", "steps.after.payload.checksum"], "operator": "unchanged"},
        ],
        "legitimate": [
            {"id": "legitimate_use_preserved", "label": "Alice can still read order 101", "path": "authorized", "operator": "equals", "expected": True},
        ],
    },
    "a02": {
        "vulnerable": [
            {"id": "vulnerability_reproduced", "label": "Internal diagnostics crossed to client", "path": "internal_details_returned", "operator": "equals", "expected": True},
        ],
        "controlled": [
            {"id": "control_effective", "label": "Client diagnostics removed", "path": "internal_details_returned", "operator": "equals", "expected": False},
            {"id": "authoritative_state_safe", "label": "Minimised operator event retained", "path": "steps.audit.payload.event_found", "operator": "equals", "expected": True},
            {"id": "authoritative_state_safe", "label": "Second error entry point also correlated", "path": "steps.audit_2.payload.event_found", "operator": "equals", "expected": True},
        ],
        "legitimate": [
            {"id": "legitimate_use_preserved", "label": "Valid order lookup still works", "path": "http_status", "operator": "equals", "expected": 200},
        ],
    },
    "a03": {
        "vulnerable": [
            {"id": "vulnerability_reproduced", "label": "Unreviewed newer artefact selected", "path": "contains_untrusted_marker", "operator": "equals", "expected": True},
        ],
        "controlled": [
            {"id": "control_effective", "label": "Reviewed version stays selected", "path": "contains_untrusted_marker", "operator": "equals", "expected": False},
            {"id": "authoritative_state_safe", "label": "Changed pinned bytes rejected", "path": "steps.digest_tamper.payload.accepted", "operator": "equals", "expected": False},
        ],
        "legitimate": [
            {"id": "legitimate_use_preserved", "label": "Reviewed artefact accepted", "path": "accepted", "operator": "equals", "expected": True},
        ],
    },
    "a04": {
        "vulnerable": [
            {"id": "vulnerability_reproduced", "label": "Equal passwords create equal records", "path": "hashes_equal", "operator": "equals", "expected": True},
        ],
        "controlled": [
            {"id": "control_effective", "label": "Per-account records differ", "path": "hashes_equal", "operator": "equals", "expected": False},
            {"id": "authoritative_state_safe", "label": "Sensitive record values remain server-side", "path": "sensitive_record_values_returned", "operator": "equals", "expected": False},
        ],
        "legitimate": [
            {"id": "legitimate_use_preserved", "label": "Correct password still verifies", "path": "candidate_verified", "operator": "equals", "expected": True},
        ],
    },
    "a05": {
        "vulnerable": [
            {"id": "vulnerability_reproduced", "label": "Internal-only product exposed", "path": "hidden_exposed", "operator": "equals", "expected": True},
        ],
        "controlled": [
            {"id": "control_effective", "label": "Payload remains a bound value", "path": "hidden_exposed", "operator": "equals", "expected": False},
            {"id": "authoritative_state_safe", "label": "Product database unchanged", "path": ["steps.before.payload.checksum", "steps.after.payload.checksum"], "operator": "unchanged"},
        ],
        "legitimate": [
            {"id": "legitimate_use_preserved", "label": "Normal public search still works", "path": "result_count", "operator": "equals", "expected": 1},
        ],
    },
    "a06": {
        "vulnerable": [
            {"id": "vulnerability_reproduced", "label": "Coupon replay accepted", "path": "steps.replay.status", "operator": "equals", "expected": 201},
        ],
        "controlled": [
            {"id": "control_effective", "label": "Coupon replay rejected", "path": "steps.replay.status", "operator": "equals", "expected": 409},
            {"id": "authoritative_state_safe", "label": "Only one redemption stored", "path": "use_count", "operator": "equals", "expected": 1},
        ],
        "legitimate": [
            {"id": "legitimate_use_preserved", "label": "Independent eligible customer succeeds", "path": "steps.first.status", "operator": "equals", "expected": 201},
        ],
    },
    "a07": {
        "vulnerable": [
            {"id": "vulnerability_reproduced", "label": "Old token works after logout", "path": "steps.replay.status", "operator": "equals", "expected": 200},
        ],
        "controlled": [
            {"id": "control_effective", "label": "Revoked token rejected", "path": "steps.replay.status", "operator": "equals", "expected": 401},
            {"id": "control_effective", "label": "Expired token rejected", "path": "steps.expired_admin.status", "operator": "equals", "expected": 401},
            {"id": "control_effective", "label": "Unknown token rejected", "path": "steps.random_admin.status", "operator": "equals", "expected": 401},
            {"id": "authoritative_state_safe", "label": "Server session marked inactive", "path": "steps.state.payload.active", "operator": "equals", "expected": False},
        ],
        "legitimate": [
            {"id": "legitimate_use_preserved", "label": "Fresh Admin session succeeds", "path": "http_status", "operator": "equals", "expected": 200},
        ],
    },
    "a08": {
        "vulnerable": [
            {"id": "vulnerability_reproduced", "label": "Tampered price stored", "path": "price_cents", "operator": "equals", "expected": 100},
        ],
        "controlled": [
            {"id": "control_effective", "label": "Tampered message rejected", "path": "steps.update.status", "operator": "equals", "expected": 401},
            {"id": "authoritative_state_safe", "label": "Stored price remains 4900", "path": "price_cents", "operator": "equals", "expected": 4900},
        ],
        "legitimate": [
            {"id": "legitimate_use_preserved", "label": "Valid signed update accepted", "path": "steps.update.status", "operator": "equals", "expected": 204},
        ],
    },
    "a09": {
        "vulnerable": [
            {"id": "vulnerability_reproduced", "label": "Repeated failures leave no events", "path": "auth_failure_count", "operator": "equals", "expected": 0},
        ],
        "controlled": [
            {"id": "control_effective", "label": "Threshold alert produced", "path": "alert_count", "operator": "equals", "expected": 1},
            {"id": "authoritative_state_safe", "label": "Secrets excluded from telemetry", "path": "passwords_or_tokens_logged", "operator": "equals", "expected": False},
        ],
        "legitimate": [
            {"id": "legitimate_use_preserved", "label": "Valid Admin login succeeds", "path": "authenticated", "operator": "equals", "expected": True},
        ],
    },
    "a10": {
        "vulnerable": [
            {"id": "vulnerability_reproduced", "label": "Unknown decision releases export", "path": "export_returned", "operator": "equals", "expected": True},
        ],
        "controlled": [
            {"id": "control_effective", "label": "Unknown decision fails closed", "path": "export_returned", "operator": "equals", "expected": False},
            {"id": "authoritative_state_safe", "label": "Access remains denied", "path": "access_granted", "operator": "equals", "expected": False},
        ],
        "legitimate": [
            {"id": "legitimate_use_preserved", "label": "Authenticated Admin export succeeds", "path": "export_returned", "operator": "equals", "expected": True},
        ],
    },
}
