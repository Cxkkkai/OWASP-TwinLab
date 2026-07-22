"""Executable contracts for the counterexample-guided control auditor.

The contracts deliberately describe a bounded, local experiment.  They are not
claims that TwinLab can scan arbitrary applications or prove production safety.
"""

from __future__ import annotations

from copy import deepcopy


AUDITOR_CONTRACTS = {
    "a05": {
        "id": "a05",
        "owasp": "A05:2025",
        "name": "Injection",
        "title": "Can a blacklist survive equivalent SQL syntax?",
        "invariant": "Every product returned by public search must have is_public=true.",
        "candidate": {
            "name": "Case-sensitive keyword blacklist",
            "summary": "Reject the exact uppercase OR and -- tokens used by the known demonstration payload.",
            "baseline_reason": "The known payload is rejected and normal search still works.",
        },
        "attack": {
            "objective": "Make public search return the internal-only catalogue row.",
            "capability": "The attacker can supply the public search value but cannot change server code or database rows.",
            "known_path": "Submit the original demonstration input and observe the Candidate reject it.",
            "manipulation": "Preserve the boolean meaning while changing keyword case, whitespace and comment syntax.",
            "success": "The Candidate returns a product whose is_public flag is false.",
        },
        "explorer": {
            "kind": "grammar",
            "name": "Bounded SQL boolean grammar",
            "dimensions": ["keyword case", "whitespace", "comment form", "equivalent tautology"],
            "case_limit": 28,
            "seed": "a05-grammar-v1",
        },
        "oracle": {
            "forbidden": "A response contains a product with is_public=false.",
            "legitimate": "The normal query Security still returns its public product.",
        },
        "bounded_claim": (
            "The result covers the displayed read-only SQLite grammar corpus. "
            "No counterexample result is a proof that every query in another application is safe."
        ),
    },
    "a07": {
        "id": "a07",
        "owasp": "A07:2025",
        "name": "Authentication Failures",
        "title": "Does a repaired logout cover the whole session lifecycle?",
        "invariant": "An inactive or expired session must never authorise Admin data.",
        "candidate": {
            "name": "Revocation checked, expiry omitted",
            "summary": "Logout revokes the session and Admin access checks active state, but the expiry decision is missing.",
            "baseline_reason": "The original login → logout → replay test is correctly rejected.",
        },
        "attack": {
            "objective": "Use a no-longer-valid session to retrieve Admin data.",
            "capability": "The attacker holds a synthetic Admin session token issued before the lifecycle transition.",
            "known_path": "Login, logout and replay the old token; the Candidate correctly rejects it.",
            "manipulation": "Replace logout with an authoritative expiry transition, then replay the still-active token.",
            "success": "Admin data is returned even though the authoritative session is expired.",
        },
        "explorer": {
            "kind": "state",
            "name": "Bounded explicit-state session explorer",
            "dimensions": ["logout transition", "expiry transition", "privileged access"],
            "max_depth": 3,
            "seed": "a07-state-v1",
        },
        "oracle": {
            "forbidden": "Admin data is returned after a session has been revoked or expired.",
            "legitimate": "A fresh, active and unexpired Admin session remains usable.",
        },
        "bounded_claim": (
            "The explorer covers the displayed lifecycle actions to depth three. "
            "It does not prove token theft prevention, fixation defence or distributed-session correctness."
        ),
    },
    "a01": {
        "id": "a01",
        "owasp": "A01:2025",
        "name": "Broken Access Control",
        "title": "Is the owner check using an authoritative principal?",
        "invariant": "The signed-session customer may read only an order they own.",
        "candidate": {
            "name": "Owner predicate with a caller-overridable principal",
            "summary": "The query includes owner_id, but a request actor can replace the signed-session principal used by the predicate.",
            "baseline_reason": "Without an actor override, Alice is denied Bob's order.",
        },
        "attack": {
            "objective": "Read Bob's order while the signed application session is still Alice.",
            "capability": "Alice can choose an order ID and add caller-controlled query or header values.",
            "known_path": "Request Bob's order with no actor override; the Candidate owner predicate denies it.",
            "manipulation": "Supply Bob as the request actor so the predicate uses a different principal source.",
            "success": "Bob's order is returned to a request whose signed session remains Alice.",
        },
        "explorer": {
            "kind": "policy",
            "name": "Principal-source and object policy explorer",
            "dimensions": ["signed session", "query actor", "header actor", "requested object"],
            "case_limit": 3,
            "seed": "a01-policy-v1",
        },
        "oracle": {
            "forbidden": "Bob's order data is returned to Alice's signed session.",
            "legitimate": "Alice can still read order 101.",
        },
        "bounded_claim": (
            "The matrix covers the displayed synthetic identities, principal sources and two orders. "
            "It does not establish application-wide authorisation correctness."
        ),
    },
    "a02": {
        "id": "a02",
        "owasp": "A02:2025",
        "name": "Security Misconfiguration",
        "title": "Did the fix secure the whole response boundary?",
        "invariant": "Internal diagnostic canaries must not cross any client-visible response channel.",
        "candidate": {
            "name": "Generic body with diagnostic response headers",
            "summary": "The JSON body is generic, but a middleware-style header still exposes internal diagnostic canaries.",
            "baseline_reason": "A body-only check sees a generic error and reports no leak.",
        },
        "attack": {
            "objective": "Recover an internal diagnostic marker from a client-visible error response.",
            "capability": "An unauthenticated visitor can trigger the controlled synthetic failure and inspect the full HTTP response.",
            "known_path": "Inspect only the generic JSON body; the Candidate appears to disclose nothing.",
            "manipulation": "Inspect every response channel, including diagnostic headers, across several failure inputs.",
            "success": "A synthetic internal canary is visible outside the server boundary.",
        },
        "explorer": {
            "kind": "boundary",
            "name": "Multi-channel error canary scanner",
            "dimensions": ["body", "headers", "cookies", "redirect location", "operator event"],
            "case_limit": 3,
            "seed": "a02-boundary-v1",
        },
        "oracle": {
            "forbidden": "A synthetic path, trace or configuration marker appears in a client-visible channel.",
            "legitimate": "A normal order lookup works and a minimised correlated event remains available.",
        },
        "bounded_claim": (
            "The scanner covers the displayed controlled error cases and HTTP response channels. "
            "It does not inspect framework or infrastructure paths outside this synthetic app."
        ),
    },
}


def validate_auditor_contracts(contracts: dict | None = None) -> dict:
    """Validate and return a defensive copy of the public contract manifest."""

    manifest = deepcopy(contracts or AUDITOR_CONTRACTS)
    required = {
        "id",
        "owasp",
        "name",
        "title",
        "invariant",
        "candidate",
        "attack",
        "explorer",
        "oracle",
        "bounded_claim",
    }
    if list(manifest) != ["a05", "a07", "a01", "a02"]:
        raise ValueError("Auditor contracts must keep the presentation order A05, A07, A01, A02.")
    for module_id, contract in manifest.items():
        missing = required - set(contract)
        if missing:
            raise ValueError(f"{module_id} contract missing fields: {sorted(missing)}")
        if contract["id"] != module_id:
            raise ValueError(f"{module_id} contract id does not match its key.")
        if contract["explorer"].get("kind") not in {"grammar", "state", "policy", "boundary"}:
            raise ValueError(f"{module_id} has an unsupported explorer kind.")
        if not contract["bounded_claim"].strip():
            raise ValueError(f"{module_id} requires an explicit bounded claim.")
        if not contract["candidate"].get("baseline_reason"):
            raise ValueError(f"{module_id} requires a baseline-pass explanation.")
        if set(contract["attack"]) != {
            "objective",
            "capability",
            "known_path",
            "manipulation",
            "success",
        }:
            raise ValueError(f"{module_id} requires a complete attack narrative contract.")
    return manifest
