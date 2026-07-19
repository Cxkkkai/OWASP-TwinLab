"""Six compact but executable OWASP Top 10:2025 comparison experiments."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sqlite3
import time
import uuid

from flask import Blueprint, current_app, render_template, request, session
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from app.db import get_db, verify_demo_password
from app.lab_registry import LAB_BY_ID
from app.observer import observer_capability_required
from app.trusted_manifest import TRUSTED_A03_MANIFEST

from .common import lab_response


def _module_page(lab_id: str, **context):
    lab = LAB_BY_ID[lab_id]
    defaults = {
        "title": f"{lab['owasp']} {lab['name']}",
        "lab": lab,
        "setup_url": None,
        "extra_note": None,
    }
    defaults.update(context)
    return render_template("module.html", **defaults)


def _server_session_actor():
    """Return the actor selected in the signed lab session, never request data.

    The identity selector is an explicit local-lab fixture. Target endpoints use
    this server-side context so an ``actor`` query/form field cannot change the
    authorization principal for the request being evaluated.
    """

    actor_name = session.get("demo_actor")
    if not actor_name:
        return None
    return get_db().execute(
        "SELECT id, username, role FROM users WHERE username = ?", (actor_name,)
    ).fetchone()


def _authentication_required(lab, variant: str):
    return lab_response(
        lab=lab,
        variant=variant,
        outcome="authenticated lab identity required",
        data={
            "authenticated": False,
            "identity_source": "server_session",
            "access_granted": False,
        },
        status=401,
    )


# A03 — Software Supply Chain Failures
a03 = Blueprint("a03", __name__, url_prefix="/lab/a03")
A03 = LAB_BY_ID["a03"]
TRUSTED_VERSION = "2.4.1"
UNREVIEWED_VERSION = "2.4.2"
TRUSTED_ARTIFACT = b"acme-widget-2.4.1|synthetic-local-package"
UNREVIEWED_ARTIFACT = b"acme-widget-2.4.2|UNTRUSTED_ARTIFACT_A03"
TAMPERED_PINNED_ARTIFACT = TRUSTED_ARTIFACT + b"|tampered"
TRUSTED_SHA256 = TRUSTED_A03_MANIFEST["sha256"]


@a03.get("/", endpoint="overview")
def a03_overview():
    return _module_page(
        "a03",
        weakness="Unpinned dependency plus missing artefact integrity verification",
        actor="Local build process consuming a synthetic package artefact",
        asset="Build and dependency integrity",
        attack="Substitute a tampered local artefact while retaining the expected package name.",
        root_cause="The vulnerable manifest asks for latest and trusts origin/name without a digest.",
        control="Pin version 2.4.1 and compare SHA-256 with the separate reviewed lab manifest.",
        vulnerable_url="/lab/a03/vulnerable/verify?repository=newer",
        secure_url="/lab/a03/secure/verify?repository=newer",
        legitimate_url="/lab/a03/secure/verify?repository=trusted",
        vulnerable_label="Let floating latest select the newer artefact",
        secure_label="Keep the reviewed version pinned",
        legitimate_label="Verify the reviewed artefact",
        test_contract=[
            "V-positive: the reviewed artefact is accepted when it is the only version.",
            "V-security: floating latest selects an unreviewed newer artefact.",
            "S-security: the same repository state remains pinned to the reviewed version.",
            "S-positive: the pinned trusted artefact is accepted.",
        ],
        extra_note="The expected SHA-256 is a fixed value in a separate reviewed lab manifest. The pinned-tamper case verifies that changed repository bytes fail that comparison.",
    )


@a03.get("/<variant>/verify")
def a03_verify(variant: str):
    if variant not in {"vulnerable", "secure"}:
        return lab_response(lab=A03, variant=variant, outcome="unknown variant", data={}, status=404)
    repository_state = request.args.get("repository", "trusted")
    if repository_state not in {"trusted", "newer", "pinned-tamper"}:
        return lab_response(
            lab=A03,
            variant=variant,
            outcome="unknown synthetic repository state",
            data={"accepted": False},
            status=400,
        )

    repository = {TRUSTED_VERSION: TRUSTED_ARTIFACT}
    if repository_state == "newer":
        repository[UNREVIEWED_VERSION] = UNREVIEWED_ARTIFACT
    elif repository_state == "pinned-tamper":
        repository[TRUSTED_VERSION] = TAMPERED_PINNED_ARTIFACT

    selected_version = max(repository) if variant == "vulnerable" else TRUSTED_VERSION
    artefact = repository[selected_version]
    actual = hashlib.sha256(artefact).hexdigest()
    accepted = variant == "vulnerable" or hmac.compare_digest(actual, TRUSTED_SHA256)
    contains_untrusted_marker = b"UNTRUSTED_ARTIFACT_A03" in artefact
    if not accepted:
        outcome = "pinned artefact digest mismatch blocked"
    elif contains_untrusted_marker:
        outcome = "floating latest accepted an unreviewed artefact"
    else:
        outcome = "reviewed pinned artefact verified" if variant == "secure" else "artefact accepted without a trusted manifest"
    return lab_response(
        lab=A03,
        variant=variant,
        outcome=outcome,
        data={
            "repository_state": repository_state,
            "selection_policy": "floating-latest" if variant == "vulnerable" else "trusted-manifest-pin",
            "selected_version": selected_version,
            "expected_sha256": None if variant == "vulnerable" else TRUSTED_SHA256,
            "actual_sha256": actual,
            "expected_digest_fingerprint": None if variant == "vulnerable" else TRUSTED_SHA256[:12],
            "actual_digest_fingerprint": actual[:12],
            "digest_match": None if variant == "vulnerable" else hmac.compare_digest(actual, TRUSTED_SHA256),
            "contains_untrusted_marker": contains_untrusted_marker,
            "accepted": accepted,
        },
        status=200 if accepted else 422,
    )


# A04 — Cryptographic Failures
a04 = Blueprint("a04", __name__, url_prefix="/lab/a04")
A04 = LAB_BY_ID["a04"]


def _scrypt(password: str, salt: bytes) -> str:
    # OWASP's published minimum-equivalent scrypt profiles include this
    # 16 MiB / p=5 combination.  Keeping the parameters explicit makes the
    # educational record self-describing and avoids implying that the old
    # p=1 demonstration profile was production guidance.
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=5)
    return kdf.derive(password.encode()).hex()


@a04.get("/", endpoint="overview")
def a04_overview():
    return _module_page(
        "a04",
        weakness="Fast, unsalted password hashing reveals password reuse",
        actor="Offline observer comparing two synthetic credential records",
        asset="Password confidentiality and account separation",
        attack="Compare Alice and Bob's hashes when both use the lab password correct-horse.",
        root_cause="Plain SHA-256 is fast and deterministic; there is no per-user salt or cost.",
        control="Use a unique public salt per account and the memory-hard scrypt password KDF.",
        vulnerable_url="/lab/a04/vulnerable/compare",
        secure_url="/lab/a04/secure/compare",
        legitimate_url="/lab/a04/secure/compare",
        vulnerable_method="POST",
        secure_method="POST",
        legitimate_method="POST",
        vulnerable_fields={"password": "correct-horse", "candidate": "wrong-password"},
        secure_fields={"password": "correct-horse", "candidate": "wrong-password"},
        legitimate_fields={"password": "correct-horse", "candidate": "correct-horse"},
        vulnerable_label="Show equal unsalted password records",
        secure_label="Show unique salted scrypt records",
        legitimate_label="Verify the correct password still works",
        test_contract=[
            "V-positive: the correct candidate verifies.",
            "V-security: equal passwords produce equal hashes across accounts.",
            "S-security: unique salts produce different stored values.",
            "S-positive: scrypt verification still accepts the correct candidate.",
        ],
        extra_note="Only booleans, KDF parameters and salt lengths are returned; plaintext, salts and derived values stay out of the response.",
    )


@a04.post("/<variant>/compare")
def a04_compare(variant: str):
    if variant not in {"vulnerable", "secure"}:
        return lab_response(lab=A04, variant=variant, outcome="unknown variant", data={}, status=404)
    password = request.form.get("password", "correct-horse")[:80]
    candidate = request.form.get("candidate", password)[:80]
    if variant == "vulnerable":
        alice_hash = hashlib.sha256(password.encode()).hexdigest()
        bob_hash = hashlib.sha256(password.encode()).hexdigest()
        candidate_hash = hashlib.sha256(candidate.encode()).hexdigest()
        verified = hmac.compare_digest(candidate_hash, alice_hash)
        algorithm = "SHA-256 (single fast hash)"
        salt_lengths = [0, 0]
    else:
        alice_salt = secrets.token_bytes(16)
        bob_salt = secrets.token_bytes(16)
        while bob_salt == alice_salt:
            bob_salt = secrets.token_bytes(16)
        alice_hash = _scrypt(password, alice_salt)
        bob_hash = _scrypt(password, bob_salt)
        candidate_hash = _scrypt(candidate, alice_salt)
        verified = hmac.compare_digest(candidate_hash, alice_hash)
        algorithm = "scrypt n=16384 r=8 p=5"
        salt_lengths = [len(alice_salt), len(bob_salt)]
    return lab_response(
        lab=A04,
        variant=variant,
        outcome="cross-account hashes reveal password equality" if alice_hash == bob_hash else "unique salts separate equal passwords",
        data={
            "algorithm": algorithm,
            "unique_salt_per_account": variant == "secure",
            "salt_lengths": salt_lengths,
            "record_fields": ["algorithm", "n", "r", "p", "salt", "derived_key"] if variant == "secure" else ["digest"],
            "hashes_equal": alice_hash == bob_hash,
            "alice_record_fingerprint": alice_hash[:12],
            "bob_record_fingerprint": bob_hash[:12],
            "candidate_verified": verified,
            "sensitive_record_values_returned": False,
        },
    )


# A06 — Insecure Design
a06 = Blueprint("a06", __name__, url_prefix="/lab/a06")
A06 = LAB_BY_ID["a06"]


@a06.get("/", endpoint="overview")
def a06_overview():
    return _module_page(
        "a06",
        weakness="Missing one-use business invariant for WELCOME10",
        actor="Authenticated synthetic customer Alice",
        asset="Order pricing integrity and promotion budget",
        attack="Submit the same valid welcome coupon twice for the same customer.",
        root_cause="The design validates coupon syntax but never models prior redemption.",
        control="Check server-side redemption state before applying the discount and record successful use.",
        vulnerable_url="/lab/a06/vulnerable/apply",
        secure_url="/lab/a06/secure/apply",
        legitimate_url="/lab/a06/secure/legitimate",
        vulnerable_method="POST",
        secure_method="POST",
        legitimate_method="POST",
        vulnerable_fields={},
        secure_fields={},
        legitimate_fields={},
        vulnerable_label="Run two vulnerable coupon uses",
        secure_label="Run two secure coupon uses",
        legitimate_label="Confirm Bob's independent first use",
        test_contract=[
            "V-positive: Alice's first valid coupon is accepted.",
            "V-security: Alice's second use is also accepted.",
            "S-security: Alice's second secure use is rejected.",
            "S-positive: another eligible user can use the coupon once.",
        ],
    )


@a06.post("/<variant>/apply")
def a06_apply(variant: str):
    if variant not in {"vulnerable", "secure"}:
        return lab_response(lab=A06, variant=variant, outcome="unknown variant", data={}, status=404)
    actor = _server_session_actor()
    if actor is None:
        return _authentication_required(A06, variant)
    actor_name = actor["username"]
    coupon = request.values.get("coupon", "WELCOME10").upper()
    outcome, data, status = _apply_coupon_once(variant, actor_name, coupon)
    data.update(
        {
            "actor": actor_name,
            "identity_source": "server_session",
            "request_actor_ignored": "actor" in request.values,
        }
    )
    return lab_response(lab=A06, variant=variant, outcome=outcome, data=data, status=status)


@a06.post("/<variant>/reset-case")
@observer_capability_required
def a06_reset_case(variant: str):
    if variant not in {"vulnerable", "secure"}:
        return lab_response(
            lab=A06, variant=variant, outcome="unknown variant", data={}, status=404, plane="observer"
        )
    actor_name = request.values.get("subject", request.values.get("actor", "alice"))[:40]
    coupon = request.values.get("coupon", "WELCOME10").upper()[:40]
    db = get_db()
    user = db.execute("SELECT id FROM users WHERE username = ?", (actor_name,)).fetchone()
    if user is None:
        return lab_response(
            lab=A06, variant=variant, outcome="unknown observer subject", data={}, status=404, plane="observer"
        )
    db.execute(
        "DELETE FROM coupon_uses WHERE user_id = ? AND coupon_code = ? AND variant = ?",
        (user["id"], coupon, variant),
    )
    db.commit()
    return lab_response(
        lab=A06,
        variant=variant,
        outcome="synthetic coupon case reset",
        data={"actor": actor_name, "subject": actor_name, "coupon": coupon, "use_count": 0},
        plane="observer",
    )


@a06.get("/<variant>/state")
@observer_capability_required
def a06_state(variant: str):
    if variant not in {"vulnerable", "secure"}:
        return lab_response(
            lab=A06, variant=variant, outcome="unknown variant", data={}, status=404, plane="observer"
        )
    actor_name = request.args.get("subject", request.args.get("actor", "alice"))[:40]
    coupon = request.args.get("coupon", "WELCOME10").upper()[:40]
    db = get_db()
    user = db.execute("SELECT id FROM users WHERE username = ?", (actor_name,)).fetchone()
    if user is None:
        return lab_response(
            lab=A06, variant=variant, outcome="unknown observer subject", data={}, status=404, plane="observer"
        )
    rows = db.execute(
        """SELECT used_at FROM coupon_uses
           WHERE user_id = ? AND coupon_code = ? AND variant = ? ORDER BY used_at""",
        (user["id"], coupon, variant),
    ).fetchall()
    return lab_response(
        lab=A06,
        variant=variant,
        outcome="coupon redemption state inspected",
        data={
            "actor": actor_name,
            "subject": actor_name,
            "coupon": coupon,
            "use_count": len(rows),
            "redemptions": [
                {"redemption_number": index + 1, "stored": True}
                for index, _row in enumerate(rows)
            ],
            "database_unique_invariant": variant == "secure",
        },
        plane="observer",
    )


def _apply_coupon_once(variant: str, actor_name: str, coupon: str) -> tuple[str, dict, int]:
    db = get_db()
    user = db.execute("SELECT id, username FROM users WHERE username = ?", (actor_name,)).fetchone()
    if user is None or coupon != "WELCOME10":
        return "invalid customer or coupon", {"accepted": False}, 400
    if variant == "secure":
        db.execute("BEGIN IMMEDIATE")
    previous = db.execute(
        "SELECT COUNT(*) FROM coupon_uses WHERE user_id = ? AND coupon_code = ? AND variant = ?",
        (user["id"], coupon, variant),
    ).fetchone()[0]
    if variant == "secure" and previous:
        db.rollback()
        return (
            "one-use invariant blocked coupon replay",
            {"actor": actor_name, "coupon": coupon, "previous_uses": previous, "accepted": False},
            409,
        )
    try:
        db.execute(
            "INSERT INTO coupon_uses (user_id, coupon_code, variant, used_at) VALUES (?, ?, ?, ?)",
            (user["id"], coupon, variant, int(time.time())),
        )
    except sqlite3.IntegrityError:
        db.rollback()
        return (
            "one-use database invariant blocked coupon replay",
            {"actor": actor_name, "coupon": coupon, "accepted": False},
            409,
        )
    db.commit()
    current = previous + 1
    return (
        "discount applied",
        {"actor": actor_name, "coupon": coupon, "redemption_number": current, "accepted": True, "discount_percent": 10},
        201,
    )


@a06.post("/secure/legitimate")
def a06_secure_legitimate_demo():
    """Repeatably exercise a valid first use for the signed-session actor."""

    actor = _server_session_actor()
    if actor is None:
        return _authentication_required(A06, "secure")
    db = get_db()
    db.execute(
        "DELETE FROM coupon_uses WHERE user_id = ? AND coupon_code = 'WELCOME10' AND variant = 'secure'",
        (actor["id"],),
    )
    db.commit()
    outcome, data, status = _apply_coupon_once("secure", actor["username"], "WELCOME10")
    data["identity_source"] = "server_session"
    return lab_response(lab=A06, variant="secure", outcome=outcome, data=data, status=status)


@a06.post("/<variant>/demo")
def a06_guided_replay_demo(variant: str):
    """Run a deterministic first-use and replay pair for one synthetic user."""

    if variant not in {"vulnerable", "secure"}:
        return lab_response(lab=A06, variant=variant, outcome="unknown variant", data={}, status=404)
    actor = _server_session_actor()
    if actor is None:
        return _authentication_required(A06, variant)
    db = get_db()
    db.execute(
        "DELETE FROM coupon_uses WHERE user_id = ? AND coupon_code = 'WELCOME10' AND variant = ?",
        (actor["id"], variant),
    )
    db.commit()
    actor_name = actor["username"]
    first_outcome, first_data, first_status = _apply_coupon_once(variant, actor_name, "WELCOME10")
    second_outcome, second_data, second_status = _apply_coupon_once(variant, actor_name, "WELCOME10")
    expected_second = 201 if variant == "vulnerable" else 409
    return lab_response(
        lab=A06,
        variant=variant,
        outcome=(
            "coupon replay accepted a second time"
            if variant == "vulnerable"
            else "one-use invariant rejected coupon replay"
        ),
        data={
            "guided_flow": [
                {"step": "first_use", "status": first_status, "outcome": first_outcome, **first_data},
                {"step": "replay", "status": second_status, "outcome": second_outcome, **second_data},
            ],
            "first_use_status": first_status,
            "replay_status": second_status,
            "replay_blocked": second_status == 409,
            "actor": actor_name,
            "identity_source": "server_session",
            "claim_supported": first_status == 201 and second_status == expected_second,
        },
        plane="runner",
    )


# A08 — Software or Data Integrity Failures
a08 = Blueprint("a08", __name__, url_prefix="/lab/a08")
A08 = LAB_BY_ID["a08"]


def _price_signature(raw_body: bytes) -> str:
    digest = hmac.new(current_app.config["DEMO_HMAC_KEY"], raw_body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


@a08.get("/", endpoint="overview")
def a08_overview():
    trusted_body = '{"product_id":1,"price_cents":5100}'
    tampered_body = '{"product_id":1,"price_cents":100}'
    trusted_signature = _price_signature(trusted_body.encode())

    def price_sequence(variant: str, body: str, signature: str, label: str) -> dict:
        return {
            "summary_step": "state",
            "observations": [
                {"key": "steps.update.status", "label": "Update HTTP"},
                {"key": "steps.update.payload.integrity_valid", "label": "Signature valid"},
                {"key": "steps.update.payload.accepted", "label": "Update accepted"},
                {"key": "price_cents", "label": "Stored price"},
            ],
            "steps": [
                {
                    "id": "reset",
                    "label": "Reset product 1 to 4900 cents",
                    "url": f"/observer/a08/{variant}/reset-price",
                    "method": "POST",
                    "fields": {},
                    "headers": {"X-TwinLab-Observer": "evidence-console"},
                    "observations": [{"key": "price_cents", "label": "Starting price"}],
                    "capture": {},
                },
                {
                    "id": "update",
                    "label": label,
                    "url": f"/lab/a08/{variant}/price-update",
                    "method": "POST",
                    "fields": {},
                    "headers": {
                        "Content-Type": "application/json",
                        "X-TwinLab-Signature": signature,
                    },
                    "raw_body": body,
                    "observations": [
                        {"key": "http_status", "label": "HTTP status"},
                        {"key": "integrity_valid", "label": "Signature valid"},
                        {"key": "accepted", "label": "Accepted"},
                    ],
                    "capture": {},
                },
                {
                    "id": "state",
                    "label": "Read the stored product price",
                    "url": f"/observer/a08/{variant}/price-state",
                    "method": "GET",
                    "fields": {},
                    "headers": {"X-TwinLab-Observer": "evidence-console"},
                    "observations": [
                        {"key": "product_id", "label": "Product"},
                        {"key": "price_cents", "label": "Stored price"},
                    ],
                    "capture": {},
                },
            ],
        }

    runner_runs = {
        "vulnerable": price_sequence(
            "vulnerable",
            tampered_body,
            trusted_signature,
            "Send 100-cent bytes with the stale 5100-cent signature",
        ),
        "controlled": price_sequence(
            "secure",
            tampered_body,
            trusted_signature,
            "Replay the identical tampered bytes and stale signature",
        ),
        "legitimate": price_sequence(
            "secure",
            trusted_body,
            trusted_signature,
            "Send the exact body covered by the signature",
        ),
    }
    return _module_page(
        "a08",
        weakness="A client-controlled price update has no authenticity/integrity binding",
        actor="Local caller who can modify product_id, price and signature fields",
        asset="Synthetic product price integrity",
        attack="Change 4900 cents to 100 cents while replaying the original signature.",
        root_cause="The vulnerable route trusts mutable client data without verifying provenance.",
        control="Verify an HMAC over the exact product ID and intended price before updating state.",
        vulnerable_url="/lab/a08/vulnerable/price-update",
        secure_url="/lab/a08/secure/price-update",
        legitimate_url="/lab/a08/secure/price-update",
        vulnerable_method="POST",
        secure_method="POST",
        legitimate_method="POST",
        vulnerable_fields={"case": "tampered"},
        secure_fields={"case": "tampered"},
        legitimate_fields={"case": "valid"},
        vulnerable_label="Accept the tampered price message",
        secure_label="Reject the same tampered bytes",
        legitimate_label="Accept an exact HMAC-authenticated message",
        runner_runs=runner_runs,
        test_contract=[
            "V-positive: an intended price update is accepted.",
            "V-security: a modified price is accepted with a stale signature.",
            "S-security: the identical tampered message is rejected.",
            "S-positive: an exact signed message is accepted.",
        ],
        extra_note="The runner sends the exact raw JSON bytes to the protected API. Signature values are shown only as fingerprints; the demo key is synthetic and not a production secret.",
    )


def _record_price_event(event_type: str, request_id: str, details: dict) -> None:
    db = get_db()
    db.execute(
        "INSERT INTO audit_events (event_type, actor, details, request_id, created_at) VALUES (?, ?, ?, ?, ?)",
        (event_type, "synthetic-publisher", json.dumps(details, sort_keys=True), request_id, int(time.time())),
    )
    db.commit()


def _process_price_update(variant: str, raw_body: bytes, supplied_signature: str):
    if variant not in {"vulnerable", "secure"}:
        return "unknown variant", {"accepted": False}, 404

    expected_signature = _price_signature(raw_body)
    integrity_valid = hmac.compare_digest(supplied_signature, expected_signature)
    request_id = str(uuid.uuid4())
    if variant == "secure" and not integrity_valid:
        _record_price_event(
            "price_integrity_failed",
            request_id,
            {"decision": "reject", "reason": "invalid_or_missing_signature"},
        )
        return (
            "integrity verification failed",
            {"accepted": False, "integrity_valid": False, "request_id": request_id},
            401,
        )

    try:
        payload = json.loads(raw_body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return "invalid JSON body", {"accepted": False}, 400
    if not isinstance(payload, dict) or set(payload) != {"product_id", "price_cents"}:
        return "invalid price-update schema", {"accepted": False}, 400
    product_id = payload["product_id"]
    price_cents = payload["price_cents"]
    if type(product_id) is not int or type(price_cents) is not int:
        return "invalid numeric input", {"accepted": False}, 400
    if price_cents < 1 or price_cents > 1_000_000:
        return "price outside lab policy", {"accepted": False}, 400
    db = get_db()
    product = db.execute("SELECT price_cents FROM products WHERE id = ?", (product_id,)).fetchone()
    if product is None:
        return "product not found", {"accepted": False}, 404
    before = product["price_cents"]
    db.execute("UPDATE products SET price_cents = ? WHERE id = ?", (price_cents, product_id))
    db.commit()
    if variant == "secure":
        _record_price_event(
            "price_integrity_verified",
            request_id,
            {"decision": "accept", "product_id": product_id, "price_cents": price_cents},
        )
    return (
        "price state updated without integrity proof" if not integrity_valid else "signed price state updated",
        {
            "product_id": product_id,
            "before_price_cents": before,
            "after_price_cents": price_cents,
            "integrity_valid": integrity_valid,
            "accepted": True,
            "request_id": request_id,
        },
        204,
    )


@a08.post("/<variant>/price-update")
def a08_price_update(variant: str):
    if request.mimetype != "application/json":
        return lab_response(
            lab=A08,
            variant=variant,
            outcome="JSON body required",
            data={"accepted": False},
            status=415,
        )
    outcome, data, status = _process_price_update(
        variant,
        request.get_data(cache=True),
        request.headers.get("X-TwinLab-Signature", ""),
    )
    if status == 204:
        return "", 204, {"X-TwinLab-Plane": "target"}
    return lab_response(lab=A08, variant=variant, outcome=outcome, data=data, status=status)


@a08.post("/<variant>/reset-price")
@observer_capability_required
def a08_reset_price(variant: str):
    if variant not in {"vulnerable", "secure"}:
        return lab_response(
            lab=A08, variant=variant, outcome="unknown variant", data={}, status=404, plane="observer"
        )
    db = get_db()
    db.execute("UPDATE products SET price_cents = 4900 WHERE id = 1")
    db.commit()
    return lab_response(
        lab=A08,
        variant=variant,
        outcome="synthetic product price reset",
        data={"product_id": 1, "price_cents": 4900},
        plane="observer",
    )


@a08.get("/<variant>/price-state")
@observer_capability_required
def a08_price_state(variant: str):
    if variant not in {"vulnerable", "secure"}:
        return lab_response(
            lab=A08, variant=variant, outcome="unknown variant", data={}, status=404, plane="observer"
        )
    product = get_db().execute(
        "SELECT id, name, price_cents FROM products WHERE id = 1"
    ).fetchone()
    return lab_response(
        lab=A08,
        variant=variant,
        outcome="stored product price inspected",
        data={"product_id": product["id"], "product_name": product["name"], "price_cents": product["price_cents"]},
        plane="observer",
    )


@a08.post("/<variant>/demo")
def a08_demo(variant: str):
    # Each UI demo starts from the same synthetic price so clicking the
    # vulnerable path cannot contaminate the later controlled comparison.
    db = get_db()
    db.execute("UPDATE products SET price_cents = 4900 WHERE id = 1")
    db.commit()

    trusted_body = b'{"product_id":1,"price_cents":5100}'
    tampered_body = b'{"product_id":1,"price_cents":100}'
    case = request.form.get("case", "tampered")
    if case not in {"tampered", "valid"}:
        return lab_response(lab=A08, variant=variant, outcome="unknown demo case", data={}, status=400)
    raw_body = trusted_body if case == "valid" else tampered_body
    supplied_signature = _price_signature(trusted_body)
    outcome, data, status = _process_price_update(variant, raw_body, supplied_signature)
    final_price = get_db().execute(
        "SELECT price_cents FROM products WHERE id = 1"
    ).fetchone()["price_cents"]
    return lab_response(
        lab=A08,
        variant=variant,
        outcome=outcome,
        data={
            **data,
            "before_price_cents": 4900,
            "after_price_cents": final_price,
            "state_changed": final_price != 4900,
            "demo_wrapper": True,
            "api_status": status,
        },
        status=200 if status == 204 else status,
        plane="runner",
    )


# A09 — Security Logging and Alerting Failures
a09 = Blueprint("a09", __name__, url_prefix="/lab/a09")
A09 = LAB_BY_ID["a09"]
A09_SOURCE_ID = "synthetic-local-source"
A09_WINDOW_SECONDS = 60
A09_THRESHOLD = 3


@a09.get("/", endpoint="overview")
def a09_overview():
    return _module_page(
        "a09",
        weakness="Repeated authentication failures are neither recorded nor correlated",
        actor="Synthetic source repeatedly submitting a wrong password for Admin",
        asset="Detection capability and incident-response evidence",
        attack="Submit three failed logins for the same subject/source inside 60 seconds.",
        root_cause="The vulnerable path returns 401 but produces no security-relevant telemetry.",
        control="Emit minimised structured auth events and one alert at a three-failure, 60-second threshold.",
        vulnerable_url="/lab/a09/vulnerable/login",
        secure_url="/lab/a09/secure/login",
        legitimate_url="/lab/a09/secure/login",
        vulnerable_method="POST",
        secure_method="POST",
        legitimate_method="POST",
        vulnerable_fields={},
        secure_fields={},
        legitimate_fields={"username": "admin", "password": "demo-admin"},
        vulnerable_label="Run three invisible failed logins",
        secure_label="Run three measured failed logins",
        legitimate_label="Confirm valid login records success",
        test_contract=[
            "V-positive: valid vulnerable login still succeeds.",
            "V-security: three failed logins return 401 but leave event/alert counts at zero.",
            "S-security: failures one and two do not alert; failure three creates exactly one alert.",
            "S-positive: valid secure login emits AUTH_SUCCESS and no failure alert.",
        ],
        extra_note="The browser sends three separate login requests and then reads the stored event/alert state. Tests also inject a fake clock to verify the 60-second window.",
    )


def _a09_now() -> int:
    clock = current_app.config.get("A09_CLOCK", time.time)
    return int(clock())


def _a09_comparison_run_id() -> str:
    raw_value = (
        request.values.get("comparison_run_id")
        or request.headers.get("X-TwinLab-Run-Id")
        or "default"
    ).strip()
    return (raw_value or "default")[:64]


def _a09_event_details(
    *,
    timestamp: int,
    event_type: str,
    subject: str,
    outcome: str,
    request_id: str,
    comparison_run_id: str,
) -> str:
    return json.dumps(
        {
            "timestamp": timestamp,
            "event_type": event_type,
            "subject": subject,
            "source_id": A09_SOURCE_ID,
            "outcome": outcome,
            "request_id": request_id,
            "comparison_run_id": comparison_run_id,
        },
        sort_keys=True,
    )


@a09.post("/<variant>/login")
def a09_login(variant: str):
    if variant not in {"vulnerable", "secure"}:
        return lab_response(lab=A09, variant=variant, outcome="unknown variant", data={}, status=404)
    subject = request.form.get("username", "admin")[:40]
    password = request.form.get("password", "")[:100]
    outcome, data, status = _process_a09_login(
        variant, subject, password, _a09_comparison_run_id()
    )
    return lab_response(lab=A09, variant=variant, outcome=outcome, data=data, status=status)


@a09.post("/<variant>/reset-case")
@observer_capability_required
def a09_reset_case(variant: str):
    if variant not in {"vulnerable", "secure"}:
        return lab_response(
            lab=A09, variant=variant, outcome="unknown variant", data={}, status=404, plane="observer"
        )
    subject = request.values.get("username", "admin")[:40]
    comparison_run_id = _a09_comparison_run_id()
    db = get_db()
    db.execute(
        """DELETE FROM audit_events
           WHERE actor = ? AND variant = ? AND comparison_run_id = ?
             AND event_type IN ('AUTH_FAILURE', 'AUTH_SUCCESS')""",
        (subject, variant, comparison_run_id),
    )
    db.execute(
        """DELETE FROM alerts
           WHERE actor = ? AND variant = ? AND comparison_run_id = ?
             AND alert_type = 'AUTH_FAILURE_THRESHOLD'""",
        (subject, variant, comparison_run_id),
    )
    db.commit()
    return lab_response(
        lab=A09,
        variant=variant,
        outcome="synthetic authentication telemetry reset",
        data={
            "subject": subject,
            "comparison_run_id": comparison_run_id,
            "event_count": 0,
            "alert_count": 0,
        },
        plane="observer",
    )


@a09.get("/<variant>/state")
@observer_capability_required
def a09_state(variant: str):
    if variant not in {"vulnerable", "secure"}:
        return lab_response(
            lab=A09, variant=variant, outcome="unknown variant", data={}, status=404, plane="observer"
        )
    subject = request.args.get("username", "admin")[:40]
    comparison_run_id = _a09_comparison_run_id()
    db = get_db()
    events = db.execute(
        """SELECT event_type, details, request_id FROM audit_events
           WHERE actor = ? AND variant = ? AND comparison_run_id = ?
             AND event_type IN ('AUTH_FAILURE', 'AUTH_SUCCESS') ORDER BY id""",
        (subject, variant, comparison_run_id),
    ).fetchall()
    alerts = db.execute(
        """SELECT alert_type, event_count FROM alerts
           WHERE actor = ? AND variant = ? AND comparison_run_id = ?
             AND alert_type = 'AUTH_FAILURE_THRESHOLD' ORDER BY id""",
        (subject, variant, comparison_run_id),
    ).fetchall()
    event_records = [
        {
            "event_type": row["event_type"],
            "outcome": json.loads(row["details"])["outcome"],
            "source_id": json.loads(row["details"])["source_id"],
            "request_id": row["request_id"],
        }
        for row in events
    ]
    return lab_response(
        lab=A09,
        variant=variant,
        outcome="authentication telemetry state inspected",
        data={
            "subject": subject,
            "comparison_run_id": comparison_run_id,
            "event_count": len(event_records),
            "auth_failure_count": sum(event["event_type"] == "AUTH_FAILURE" for event in event_records),
            "auth_success_count": sum(event["event_type"] == "AUTH_SUCCESS" for event in event_records),
            "alert_count": len(alerts),
            "events": event_records,
            "alerts": [dict(row) for row in alerts],
            "passwords_or_tokens_logged": False,
        },
        plane="observer",
    )


def _process_a09_login(
    variant: str, subject: str, password: str, comparison_run_id: str
) -> tuple[str, dict, int]:
    db = get_db()
    user = db.execute(
        "SELECT username, role, password_hash FROM users WHERE username = ?", (subject,)
    ).fetchone()
    authenticated = user is not None and verify_demo_password(user["password_hash"], password)
    request_id = str(uuid.uuid4())
    now = _a09_now()

    if authenticated:
        if variant == "secure":
            db.execute(
                """INSERT INTO audit_events
                   (event_type, actor, details, request_id, created_at, variant, comparison_run_id)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    "AUTH_SUCCESS",
                    subject,
                    _a09_event_details(
                        timestamp=now,
                        event_type="AUTH_SUCCESS",
                        subject=subject,
                        outcome="success",
                        request_id=request_id,
                        comparison_run_id=comparison_run_id,
                    ),
                    request_id,
                    now,
                    variant,
                    comparison_run_id,
                ),
            )
            db.commit()
        return (
            "synthetic login accepted",
            {
                "authenticated": True,
                "subject": subject,
                "role": user["role"],
                "request_id": request_id,
                "comparison_run_id": comparison_run_id,
            },
            200,
        )

    if variant == "secure":
        db.execute(
            """INSERT INTO audit_events
               (event_type, actor, details, request_id, created_at, variant, comparison_run_id)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                "AUTH_FAILURE",
                subject,
                _a09_event_details(
                    timestamp=now,
                    event_type="AUTH_FAILURE",
                    subject=subject,
                    outcome="failure",
                    request_id=request_id,
                    comparison_run_id=comparison_run_id,
                ),
                request_id,
                now,
                variant,
                comparison_run_id,
            ),
        )
        window_start = now - A09_WINDOW_SECONDS
        failure_count = db.execute(
            """SELECT COUNT(*) FROM audit_events
               WHERE event_type = 'AUTH_FAILURE' AND actor = ?
                 AND variant = ? AND comparison_run_id = ?
                 AND created_at >= ? AND created_at <= ?""",
            (subject, variant, comparison_run_id, window_start, now),
        ).fetchone()[0]
        existing_alert = db.execute(
            """SELECT COUNT(*) FROM alerts
               WHERE alert_type = 'AUTH_FAILURE_THRESHOLD' AND actor = ?
                 AND variant = ? AND comparison_run_id = ?
                 AND created_at >= ? AND created_at <= ?""",
            (subject, variant, comparison_run_id, window_start, now),
        ).fetchone()[0]
        if failure_count >= A09_THRESHOLD and existing_alert == 0:
            db.execute(
                """INSERT INTO alerts
                   (alert_type, actor, event_count, created_at, variant, comparison_run_id)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    "AUTH_FAILURE_THRESHOLD",
                    subject,
                    failure_count,
                    now,
                    variant,
                    comparison_run_id,
                ),
            )
        db.commit()

    audit_count = db.execute(
        """SELECT COUNT(*) FROM audit_events
           WHERE event_type = 'AUTH_FAILURE' AND actor = ?
             AND variant = ? AND comparison_run_id = ?""",
        (subject, variant, comparison_run_id),
    ).fetchone()[0]
    alert_count = db.execute(
        """SELECT COUNT(*) FROM alerts
           WHERE alert_type = 'AUTH_FAILURE_THRESHOLD' AND actor = ?
             AND variant = ? AND comparison_run_id = ?""",
        (subject, variant, comparison_run_id),
    ).fetchone()[0]
    return (
        "login failed with no security signal" if variant == "vulnerable" else "login failed and structured event recorded",
        {
            "authenticated": False,
            "subject": subject,
            "source_id": A09_SOURCE_ID,
            "request_id": request_id if variant == "secure" else None,
            "comparison_run_id": comparison_run_id,
            "failure_event_count": audit_count,
            "alert_count": alert_count,
        },
        401,
    )


@a09.post("/<variant>/demo")
def a09_guided_detection_demo(variant: str):
    """Run three controlled failures and one legitimate login as one readable flow."""

    if variant not in {"vulnerable", "secure"}:
        return lab_response(lab=A09, variant=variant, outcome="unknown variant", data={}, status=404)
    comparison_run_id = f"guided-{uuid.uuid4()}"

    attempts = []
    for attempt_number in range(1, 4):
        attempt_outcome, attempt_data, attempt_status = _process_a09_login(
            variant, "admin", "DEMO_WRONG_PASSWORD", comparison_run_id
        )
        attempts.append(
            {
                "attempt": attempt_number,
                "status": attempt_status,
                "outcome": attempt_outcome,
                "failure_event_count": attempt_data["failure_event_count"],
                "alert_count": attempt_data["alert_count"],
            }
        )
    valid_outcome, valid_data, valid_status = _process_a09_login(
        variant, "admin", "demo-admin", comparison_run_id
    )
    expected_events = 0 if variant == "vulnerable" else 3
    expected_alerts = 0 if variant == "vulnerable" else 1
    return lab_response(
        lab=A09,
        variant=variant,
        outcome=(
            "three failed logins remained invisible"
            if variant == "vulnerable"
            else "third failed login created the threshold alert"
        ),
        data={
            "guided_flow": attempts,
            "failure_event_count": attempts[-1]["failure_event_count"],
            "alert_count": attempts[-1]["alert_count"],
            "comparison_run_id": comparison_run_id,
            "valid_login": {
                "status": valid_status,
                "outcome": valid_outcome,
                "authenticated": valid_data["authenticated"],
            },
            "passwords_or_tokens_logged": False,
            "claim_supported": (
                attempts[-1]["failure_event_count"] == expected_events
                and attempts[-1]["alert_count"] == expected_alerts
                and valid_status == 200
            ),
        },
        plane="runner",
    )


# A10 — Mishandling of Exceptional Conditions
a10 = Blueprint("a10", __name__, url_prefix="/lab/a10")
A10 = LAB_BY_ID["a10"]


@a10.get("/", endpoint="overview")
def a10_overview():
    return _module_page(
        "a10",
        weakness="Authorization dependency exception handled as allow (fail open)",
        actor="Alice requesting an admin-only synthetic export; Admin is the legitimate actor",
        asset="Export confidentiality and authorization availability",
        attack="Trigger a controlled policy-service error during the authorization decision.",
        root_cause="A broad exception handler substitutes True when the decision is unknown.",
        control="Fail closed, return 503, and avoid releasing the protected result when authorization cannot be established.",
        vulnerable_url="/lab/a10/vulnerable/export?simulate=error&actor=alice",
        secure_url="/lab/a10/secure/export?simulate=error&actor=alice",
        legitimate_url="/lab/a10/secure/export?simulate=ok&actor=admin",
        vulnerable_label="Treat the policy error as allow",
        secure_label="Fail closed on the same policy error",
        legitimate_label="Confirm a healthy explicit Admin allow",
        test_contract=[
            "V-positive: a healthy explicit Admin allow returns the export.",
            "V-security: Alice receives the export when the policy dependency errors.",
            "S-security: the same error returns 503 with no export marker.",
            "S-positive: healthy Admin allow succeeds and healthy Alice is denied.",
        ],
    )


def _policy_decision(simulate: str, role: str) -> bool:
    if simulate == "error":
        raise ConnectionError("controlled synthetic policy-service failure")
    return simulate == "ok" and role == "admin"


@a10.get("/<variant>/export")
def a10_export(variant: str):
    if variant not in {"vulnerable", "secure"}:
        return lab_response(lab=A10, variant=variant, outcome="unknown variant", data={}, status=404)
    simulate = request.args.get("simulate", "ok")
    session_actor = _server_session_actor()
    if session_actor is None:
        return lab_response(
            lab=A10,
            variant=variant,
            outcome="authenticated lab identity required",
            data={
                "authenticated": False,
                "identity_source": "server_session",
                "access_granted": False,
                "export_returned": False,
            },
            status=401,
        )
    actor = session_actor["username"]
    identity_evidence = {
        "authenticated": True,
        "identity_source": "server_session",
        "role": session_actor["role"],
        "request_actor_ignored": "actor" in request.args,
    }
    try:
        allowed = _policy_decision(simulate, session_actor["role"])
    except ConnectionError:
        if variant == "vulnerable":
            allowed = True
            policy_result = "exception"
            fallback_decision = "allow"
        else:
            return lab_response(
                lab=A10,
                variant=variant,
                outcome="authorization unavailable; failed closed",
                data={
                    "actor": actor,
                    "policy_result": "exception",
                    "fallback_decision": "deny",
                    "access_granted": False,
                    "export_returned": False,
                    "retryable": True,
                    **identity_evidence,
                },
                status=503,
            )
    else:
        policy_result = "explicit_allow" if allowed else "explicit_deny"
        fallback_decision = "not_used"
    if not allowed:
        return lab_response(
            lab=A10,
            variant=variant,
            outcome="policy denied access",
            data={
                "actor": actor,
                "policy_result": policy_result,
                "fallback_decision": fallback_decision,
                "access_granted": False,
                "export_returned": False,
                **identity_evidence,
            },
            status=403,
        )
    return lab_response(
        lab=A10,
        variant=variant,
        outcome="protected export returned after explicit allow" if simulate == "ok" else "dependency failure incorrectly treated as allow",
        data={
            "actor": actor,
            "policy_result": policy_result,
            "fallback_decision": fallback_decision,
            "access_granted": True,
            "export_returned": True,
            "export_marker": "SYNTHETIC-CUSTOMER-EXPORT",
            "fail_open": simulate == "error",
            **identity_evidence,
        },
    )


bps = [a03, a04, a06, a08, a09, a10]
