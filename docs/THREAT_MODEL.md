# TwinShop Threat Model

## 1. System and research question

TwinShop is a localhost-only Flask and SQLite teaching application. Each
experiment fixes an actor capability, protected asset, business goal and abuse
action. It then changes one security decision between a deliberately Vulnerable
path and a controlled path.

The main question is not whether the page looks secure. It is whether moving a
trust decision away from caller-controlled input, an unsafe default or missing
state produces an observable security improvement without breaking legitimate
use.

Each comparison checks:

1. the defined vulnerable effect is actually observed;
2. the control changes that effect;
3. authoritative database, session or telemetry state satisfies the invariant;
4. legitimate use remains available.

## 2. Protected assets

- Confidentiality of orders, customer exports and the internal catalogue
- Integrity of product prices, promotion rules, dependency bytes and audit data
- Password verifiers, Admin identity and server-side session state
- Confidentiality of internal diagnostic and configuration details
- Evidence needed to investigate authentication failures
- Availability of legitimate customer and administrator workflows

All records, identities, credentials, packages, keys and consequences are
synthetic.

## 3. Actors and starting capabilities

| Actor | Starting capability | Explicitly excluded capability |
|---|---|---|
| Unauthenticated local caller | Can change local query, form, header and body values | Cannot directly edit server files or database rows |
| Alice | Has an ordinary customer identity established in the signed lab session | Cannot replace that identity with an `actor` parameter or header |
| Bob | Has a separate customer identity and owns different records | Does not share Alice's identity |
| Admin | Has a synthetic privileged identity or credential flow | Does not represent a production administrator |
| Token holder | Holds one synthetic Admin token issued before a lifecycle transition | The lab does not model how the token was stolen |
| Publisher or update source | Can provide synthetic artefact or message bytes | Cannot access a real registry, webhook or build system |
| Local operator | Can start, reset and inspect the lab | The observer capability is instrumentation, not production authentication |

## 4. Planes and trust boundaries

### Target plane

`/lab/...` contains the behaviour under test. A security conclusion must come
from its business response or resulting authoritative mutation. Target routes
do not use the observer to make business authorisation decisions.

### Observer plane

`/observer/...` is local experiment instrumentation. It requires the fixed
`X-TwinLab-Observer` capability and labels responses as the observer plane. It
is used for reset, checksums and bounded state inspection. The capability is
redacted from displayed traces and is not a production authentication design.

### Verdict plane

The browser runner calculates assertions from actual response and state paths.
Missing evidence, an unknown comparison operator or a mismatched value fails
the assertion. Conditions sharing one assertion identifier are combined with
logical AND. A fresh comparison run identifier prevents state from another run
from satisfying A09 telemetry checks.

### Core boundaries

1. Browser input to Flask: every caller-controlled value is untrusted.
2. Signed identity to protected action: authentication does not imply
   authorisation.
3. Application data to SQL interpreter: values must not alter statement
   structure.
4. Bearer token to session store: possession does not imply active, unexpired
   and authorised state.
5. Exception to client response: operator diagnostics must not cross the
   customer response boundary.
6. Artefact or message bytes to trusted state: identity and integrity must be
   verified before acceptance or mutation.
7. Security outcome to event store: relevant failures must become visible
   without storing passwords, tokens or unnecessary personal data.
8. Target to observer: business behaviour and experiment instrumentation remain
   separate.

## 5. Module-level failed decisions

| ID | Vulnerable decision | Controlled decision | Demonstrated scope |
|---|---|---|---|
| A01 | A logged-in user plus a caller-selected order ID is treated as sufficient authority | Object lookup binds the server-side principal to ownership | One read-only order route |
| A02 | Internal diagnostics can cross into a client error response | Generic client error and correlated minimal operator event are separated | Two controlled error inputs |
| A03 | The newest plausible artefact is treated as reviewed | A reviewed version and independently held digest are required | Inert local bytes |
| A04 | A fast deterministic hash is treated as an adequate password record | Independent salts and a slow password KDF are used | Synthetic password records |
| A05 | Search input can become SQL grammar | Statement structure is fixed and input is bound as one value | Read-only SQLite search |
| A06 | Every plausible coupon request is independently accepted | Server identity, a transaction and a database uniqueness rule enforce one use | Sequential replay |
| A07 | A token that was once valid remains sufficient after logout or expiry | Existence, active state, expiry and role are checked at every protected use | Local session store |
| A08 | Valid JSON is treated as authentic and unchanged | HMAC over exact raw bytes is checked before parsing and mutation | Integrity and authenticity, not freshness |
| A09 | Returning `401` is treated as complete handling | Minimal events and a run-scoped rolling threshold create an observable signal | Local three-in-sixty-second rule |
| A10 | Policy-service failure is converted into allow | Only an explicit policy allow releases the synthetic export | Deterministic local exception |

## 6. State isolation

- A01, A06 and A10 identities come from the signed Flask lab session.
- A09 events and alerts include both variant and comparison run identifiers.
- A07 observer actions can move a synthetic session into an expired state; the
  target route independently evaluates it.
- A01 and A05 checksums show whether authoritative tables changed. Disclosure
  itself is measured at the target response boundary.
- A08 combines the target result with a later state read so that a rejected
  message cannot be counted as safe if it still changed the price.

## 7. Assumptions

- The caller can edit local request values and request order.
- Object identifiers, routes and controlled trigger values may be known.
- The defined attacker cannot directly modify source files or SQLite records.
- The public demonstration signing key is not a production secret.
- The operator performs an explicit reset when required.
- Each controlled path addresses only the stated synthetic scenario.
- Localhost containment is a laboratory boundary, not a production network
  architecture.

## 8. Out of scope

- Production TLS, reverse proxies, CSRF and distributed authorisation
- Package signing, provenance and SBOM processing
- Credential migration, pepper management and MFA
- Multi-node coupon races and payment processing
- HMAC freshness, replay protection and key rotation
- SIEM ingestion, SOC workflow and external alert delivery
- Resilience of a real external policy service
- A malicious local operator or compromised host

The strongest supported claim is that the frozen paired scenarios and stated
state invariants execute as specified. The project does not claim that the
application is production-ready, formally verified or OWASP compliant.

