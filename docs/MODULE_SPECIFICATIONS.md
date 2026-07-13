# OWASP TwinLab Module Specifications

Baseline: [OWASP Top 10:2025](https://owasp.org/Top10/2025/0x00_2025-Introduction/)

System: TwinShop localhost-only synthetic lab

## 1. Common executable contract

Every module uses the same four assurance questions:

1. Does ordinary use work before the attack?
2. Does the defined vulnerable business effect occur?
3. Does the controlled path prevent that effect or handle it safely?
4. Does legitimate use still work after the control?

The browser executes Vulnerable, controlled and legitimate phases and derives
four verdicts from actual response or state paths:

| Verdict | Required meaning |
|---|---|
| `vulnerability_reproduced` | The declared unsafe business effect occurred |
| `control_effective` | The equivalent controlled request was blocked or made safe |
| `authoritative_state_safe` | Database, session or telemetry state satisfies the invariant |
| `legitimate_use_preserved` | The control did not pass by deleting the feature |

An assertion fails if its evidence path is absent, its comparison operator is
unknown or its actual value does not match the contract. Multiple conditions
with one identifier are combined with logical AND.

## 2. Shared identities and fixtures

| Fixture | Purpose |
|---|---|
| Alice | Ordinary customer and actor in ownership or business-rule experiments |
| Bob | Separate customer and owner of a different object |
| Admin | Synthetic privileged identity for session and export experiments |
| Eve | Synthetic actor for offline comparison, tampering and repeated failures |
| Publisher | Synthetic artefact or update source |
| Order 101 | Alice's legitimate order |
| Order 202 | Bob's protected order |
| Public product | Legitimate A05 search and A08 price target |
| Hidden product | Marker that must not cross the public A05 response boundary |
| `WELCOME10` | Synthetic one-use promotion |

Reset restores deterministic business identifiers and state, but values that
should be random, such as session tokens and salts, are not reused.

## 3. Module contracts

### A01 Broken Access Control - cross-owner order read

- Actor: authenticated Alice
- Asset: confidentiality of Bob's order
- Invariant: a customer may read only an order they own
- Vulnerable decision: authentication is treated as sufficient, and the caller
  selects any order identifier
- Vulnerable effect: Alice receives Bob's record
- Robust control: derive the principal from the signed server-side session and
  include ownership in the object lookup
- Legitimate counterexample: Alice can still read order 101
- Oracle: target response status and protected owner/address markers
- Boundary: the experiment covers one read route, not write access or every
  object endpoint

### A02 Security Misconfiguration - diagnostic disclosure

- Actor: unauthenticated local caller
- Asset: confidentiality of internal paths, query shape and configuration data
- Invariant: customer responses must not contain operator diagnostics
- Vulnerable decision: a failure renderer sends synthetic internal details to
  the client
- Vulnerable effect: fixed diagnostic canaries cross the response boundary
- Robust control: return a generic error reference and store only a correlated,
  minimal operator event
- Legitimate counterexample: a valid lookup still returns public business data
- Oracle: scan the full response body and headers for every controlled canary
- Boundary: the lab does not enable an interactive debugger or expose real
  secrets

### A03 Software Supply Chain Failures - unreviewed latest artefact

- Actor: synthetic publisher
- Asset: integrity of accepted dependency bytes
- Invariant: only the reviewed version and independently trusted digest may be
  accepted
- Vulnerable decision: newest plausible artefact is treated as approved
- Robust control: pin the reviewed version and compare bytes with a digest held
  in a separate trusted manifest
- Legitimate counterexample: the reviewed pinned bytes remain accepted
- Oracle: selected version and checksum result
- Boundary: no registry access, installation or code execution occurs

### A04 Cryptographic Failures - comparable password records

- Actor: offline observer of synthetic records
- Asset: password verifier confidentiality and resistance to direct comparison
- Invariant: equal passwords must not produce equal stored records
- Vulnerable decision: fast unsalted SHA-256 is used as a password verifier
- Robust control: independent random salts and scrypt
- Legitimate counterexample: the correct synthetic password still verifies
- Oracle: equality of returned record representations and verification result
- Boundary: this is not a cracking benchmark or credential migration design

### A05 Injection - public catalogue search

- Actor: unauthenticated visitor controlling the search term
- Asset: confidentiality of the internal catalogue
- Invariant: non-public rows must never cross the public response boundary
- Vulnerable decision: the search term is concatenated into SQL
- Vulnerable effect: a non-public marker is returned
- Robust control: fixed SQL structure and parameter binding
- Legitimate counterexample: an ordinary public search still works
- Oracle: hidden marker in the target response plus unchanged catalogue
  checksum
- Boundary: the experiment is read-only and does not use stacked statements

### A06 Insecure Design - one-use promotion

- Actor: authenticated eligible customer
- Asset: integrity of the promotion rule
- Invariant: one customer may redeem the promotion no more than once
- Vulnerable decision: each plausible request is accepted without authoritative
  prior-use enforcement
- Robust control: server-side identity, one transaction and a database
  uniqueness rule
- Legitimate counterexample: another eligible customer can use the promotion
  once
- Oracle: response outcome and authoritative redemption rows
- Boundary: sequential replay only; payment and distributed concurrency are out
  of scope

### A07 Authentication Failures - session replay

- Actor: holder of one synthetic pre-logout Admin token
- Asset: privileged Admin session
- Invariant: Admin data requires an existing, active, unexpired Admin session
- Vulnerable decision: token presence is treated as sufficient
- Vulnerable effect: the old token remains useful after logout
- Robust control: check existence, active state, expiry and role on every
  protected request
- Legitimate counterexample: a fresh valid Admin session still works
- Oracle: protected response plus authoritative session row
- Boundary: the lab does not model token theft, MFA or a production identity
  provider

### A08 Software or Data Integrity Failures - tampered price message

- Actor: caller able to change message bytes while retaining an old signature
- Asset: integrity of the synthetic product price
- Invariant: state may change only for an authentic, unchanged message
- Vulnerable decision: valid JSON is treated as authentic
- Robust control: verify HMAC over exact raw bytes before parsing and mutation
- Legitimate counterexample: a correctly signed update succeeds
- Oracle: target outcome followed by authoritative price state
- Boundary: freshness, replay prevention and key rotation are not modelled

### A09 Security Logging and Alerting Failures - invisible login failures

- Actor: one synthetic source submitting repeated incorrect Admin credentials
- Asset: investigation evidence and threshold signal
- Invariant: repeated relevant failures must produce minimal events and a
  run-scoped alert
- Vulnerable decision: returning `401` is treated as complete handling
- Robust control: structured minimal events and a rolling three-in-sixty-second
  threshold
- Legitimate counterexample: successful login remains available and produces
  the expected event
- Oracle: event and alert counts filtered by variant and comparison run
- Boundary: no external SIEM, notification or response workflow is claimed

### A10 Mishandling of Exceptional Conditions - policy failure

- Actor: authenticated Alice triggering a controlled policy exception
- Asset: confidentiality of a synthetic customer export
- Invariant: only an explicit allow decision may release the export
- Vulnerable decision: dependency failure is converted into allow
- Robust control: fail closed and return a safe service-unavailable response
- Legitimate counterexample: healthy authorised Admin export still works
- Oracle: response status and absence or presence of the export marker
- Boundary: the policy service and export are deterministic local fixtures

## 4. Deep-module Candidate controls

The four deep modules also contain a Candidate implementation. It must use a
recognisable defensive idea, preserve normal use and pass the original known
demonstration. It is deliberately incomplete so that a bounded explorer can
test whether the apparent fix enforces the actual invariant.

| Module | Candidate defect | Explorer | Confirmed forbidden effect | Robust difference |
|---|---|---|---|---|
| A01 | Owner predicate uses a caller-selected principal when present | Principal-source policy matrix | Signed Alice receives Bob's order | Principal comes only from the signed session |
| A02 | Body is generic but another response channel is not checked | Full response-boundary scan | Internal canary crosses a client-visible channel | Every client channel follows the generic policy |
| A05 | Exact-token blacklist blocks only the rehearsed payload | Bounded SQL grammar corpus | Hidden product crosses the public boundary | Input is bound as data |
| A07 | Active state and role are checked, but expiry is omitted | Bounded session-state search | Expired session receives Admin data | Every lifecycle condition is enforced |

For each confirmed case, the Auditor:

1. records the known baseline;
2. shows the changed attack strategy;
3. checks a property-specific oracle on the real target or authoritative state;
4. replays the same case against the Robust path;
5. preserves one legitimate business case; and
6. retains the counterexample as a Robust regression test.

See [AUDITOR_SPECIFICATION.md](AUDITOR_SPECIFICATION.md) for the bounded search
models and claim limits.

## 5. Safety requirements

- The direct runner binds only to `127.0.0.1`.
- Flask debug mode, the interactive debugger and the reloader remain disabled.
- Every identity, record, password, token, package, key, event and path is
  synthetic.
- A03 does not contact a registry or execute package bytes.
- A05 is read-only and uses only the disposable local database.
- A09 does not send external alerts.
- A10 does not call a real policy service.
- Observer capabilities, tokens, signatures and passwords are redacted from
  displayed or exported evidence.

## 6. Verification

```bash
.venv/bin/python -m pytest -q
node --test tests/js/*.test.js
```

The current verified state records 91 Python tests and 15 browser-logic tests
passing. The ten-module assurance runner executes 90 target or observer actions
and resolves 40 executable assertion cells. The Auditor evaluates 36 bounded
case definitions across its four models.

These numbers describe the frozen synthetic contracts. They are not a
production security score, formal proof or OWASP compliance result.

