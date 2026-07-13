# Ethics and Safety Boundary

## Authorized scope

OWASP TwinLab runs only on a computer controlled by the operator. It uses a fictional shop, synthetic identities and deterministic local SQLite records. The project does not scan, probe, crawl or contact school systems, public sites, third-party APIs, registries or other people.

## Technical safeguards

- `run.py` binds Flask to `127.0.0.1` with debug and reloader disabled, and the application rejects non-loopback client addresses by default.
- `compose.yaml` publishes `127.0.0.1:5000:5000`; the container's internal `0.0.0.0` listener is not published publicly and its bridge-address exception requires an explicit environment opt-in.
- The UI permanently labels the project as intentionally vulnerable and local-only.
- Target routes remain under `/lab/...`. Reset and state-inspection instrumentation is separated under `/observer/...`, requires a fixed local capability and labels its responses as the observer plane. The capability is a lab boundary, not a production authentication claim.
- A01, A06 and A10 derive the actor from a Flask signed lab session; caller-supplied actor headers/query/form values cannot authenticate or replace that principal in the defined experiment. The repository's demo signing key is not a production secret, so this fixture is not a claim about production identity security.
- The injection payload is read-only and operates only on the bundled synthetic SQLite database.
- A02 never enables Werkzeug's debugger. Its “trace”, path, SQL and config marker are hard-coded fictional strings.
- A03 compares two in-memory byte strings. It does not fetch or execute a dependency.
- A04 derives only bounded synthetic records, uses random salts in the secure comparison and returns no plaintext, salt, digest or derived-key values.
- A06 changes only synthetic coupon-use rows; its secure path has a database one-use invariant and no cart, payment or external service.
- A07 uses only synthetic sessions; full tokens are redacted from browser trace/evidence export, and expiry manipulation exists only in the observer plane.
- A08 uses an explicitly labelled non-secret demonstration key and changes only a local fictional price.
- A09 records only timestamp, event type, fictional subject/source, outcome, request ID, variant and comparison run ID; it stores alerts locally, isolates runs and sends no external notification.
- A10 returns only a fixed read-only export marker and calls no external policy or customer-data service.
- Reset is POST-only, is disabled outside local-only mode, refuses non-test database paths other than the dedicated TwinLab instance database, and removes all runtime sessions, mutable demonstrations and audit/alert records.

## Prohibited use

Do not expose this application to a LAN or the internet. Do not copy its vulnerable routes into a real application. Do not apply its inputs to systems without explicit authorization. Do not replace the seed with real personal data, credentials or production secrets.

## Claim boundary

The secure comparison paths implement narrowly defined controls for narrowly defined scenarios. They are not production-ready and do not establish OWASP compliance. The strongest defensible claim is: under the documented seed, preconditions and requests, the automated tests observe the intended vulnerable outcome, the secure control changes that outcome, and the legitimate secure path remains functional.
