# Security Control Auditor specification

## Purpose

The Auditor is the challenge extension to the existing OWASP TwinLab product.
It does not replace the ten-module vulnerable/controlled comparison promised in
the proposal. It investigates a harder question inside the four Deep modules:

> Can a plausible patch pass the known demonstration and still violate the
> underlying security invariant?

Each Deep module therefore has three real target implementations:

1. `vulnerable`: reproduces the original defect;
2. `candidate`: a plausible incomplete patch that passes the known baseline;
3. `secure`: the controlled implementation used as the robust comparison.

The candidate is not a straw-man that simply does nothing. It contains a
recognisable defensive idea, preserves normal use and passes the original
example. The Auditor must find a different, bounded counterexample.

## Executable contract

Every contract contains:

- the protected invariant;
- the candidate control and its known baseline;
- a deterministic explorer with an explicit case limit and seed;
- an oracle for a forbidden observation;
- a robust implementation used for differential replay;
- a legitimate-use check;
- a bounded claim that states what the result does not prove.

The browser UI and automated tests read the same contract manifest from the
Flask application and exercise the same target routes.

## Four bounded investigations

| Module | Candidate that passes the known example | Explorer | Counterexample oracle | Robust control |
|---|---|---|---|---|
| A05 Injection | Case-sensitive blocklist rejects the original uppercase keyword/comment form | 28-case SQL syntax grammar over keyword case, spacing, comment and equivalent condition | A non-public catalogue row crosses the public response boundary | Fixed SQL structure plus parameter binding |
| A07 Authentication Failures | Logout revokes the old server session, so the original logout/replay test passes | Depth-three state sequences over login, logout/expiry and Admin access | Admin data is returned for an inactive or expired authoritative session | Existence, active, expiry and role checked on every protected request |
| A01 Broken Access Control | Query includes an owner predicate when no override is supplied | Three-case principal-source policy matrix | Signed Alice receives Bob's order | Principal comes only from the signed server session and is joined to object ownership |
| A02 Security Misconfiguration | Error body is generic and passes a body-only scan | Three controlled failure inputs scanned across body and response headers | A synthetic internal canary crosses any client-visible channel | Generic response plus correlated, minimised operator event |

## Audit lifecycle

1. Run the known baseline against the candidate.
2. Keep legitimate use available.
3. Enumerate the documented bounded search space.
4. Evaluate the forbidden-observation oracle on actual HTTP responses and
   authoritative observer state.
5. Select the smallest confirmed counterexample in the displayed corpus.
6. Reconstruct the attack as five visible steps: starting capability, known
   probe, changed strategy, Candidate decision and protected business effect.
   Every observed step contains evidence from the current run.
7. Replay that case across vulnerable, candidate and robust implementations.
8. Display the runtime decision provenance returned by the target.
9. Display a three-step Robust replay: same case, invariant result and
   legitimate-business counterexample.
10. Generate a regression test for the robust implementation.
11. Aggregate the four seeded defects into a mutation score.

The UI never invents a green verdict. A result is displayed only after the
corresponding target/observer requests have completed.

## Verification

Run:

```bash
.venv/bin/python -m pytest -q tests/test_security_auditor.py tests/generated/test_auditor_regressions.py
node --test tests/js/auditor-core.test.js
```

The Python tests use an isolated Flask test client and temporary SQLite
database. They do not open a network connection. Confirmed counterexamples are
retained as four generated Robust regression tests in `tests/generated/`.
Browser-logic tests check counterexample selection, attack reconstruction,
evidence redaction and mutation-score aggregation.

## Claim boundary

The Auditor is a deterministic counterexample-guided control checker for four
declared TwinShop contracts. It is not:

- a generic vulnerability scanner;
- formal proof of security;
- complete enumeration of SQL, authentication, policy or error behaviour;
- a production penetration test;
- evidence that the whole application is OWASP compliant.

Its result supports a narrower and defensible claim: within each displayed
bounded model, a plausible candidate passes the original example, the Auditor
finds and replays a real violating case, and the robust control preserves both
the invariant and legitimate use.
