# OWASP TwinLab

OWASP TwinLab is a localhost-only Flask and SQLite security engineering lab.
It contains one bounded, executable experiment for each OWASP Top 10:2025
category. Four modules are investigated in depth and six provide compact
regression comparisons.

The project is intentionally vulnerable. It is a teaching artefact, not a
production application, scanner, compliance checker or target for deployment.
All identities, records, credentials, artefacts, keys and logs are synthetic.

## Project contribution

Each original module compares:

1. normal business use;
2. a deliberately vulnerable result;
3. a controlled result; and
4. preserved legitimate use.

The four deep modules—A01, A02, A05 and A07—also include a Security Control
Auditor. A plausible but incomplete Candidate control first passes the known
demonstration. A bounded explorer then changes the attack strategy, checks a
property-specific oracle against the actual route or authoritative state, and
replays the discovered counterexample against the Robust control.

The four explorers use different models:

| Module | Bounded model | Main security question |
|---|---|---|
| A01 Broken Access Control | principal-source policy matrix | Is the authorised principal derived from an authoritative source? |
| A02 Security Misconfiguration | response-boundary channel scan | Can sensitive diagnostic information cross another response channel? |
| A05 Injection | input-grammar corpus | Does user input remain data rather than changing SQL structure? |
| A07 Authentication Failures | session-state transition search | Does every privileged request enforce the complete session lifecycle? |

The remaining modules cover bounded examples of supply-chain trust, password
record design, one-time business rules, message integrity, security logging and
fail-closed exception handling.

## Safety boundary

- Run only on a computer you control.
- The direct runner binds to `127.0.0.1`.
- Do not change the application to listen on a public or LAN interface.
- Flask debug mode, the interactive debugger and the reloader remain disabled.
- Do not replace synthetic inputs with real personal, credential or customer
  data.
- A05 is a read-only experiment; A03 does not download or execute packages;
  A02 exposes only fixed synthetic diagnostic material.
- The fixed demo key and local observer capability are laboratory fixtures, not
  production authentication mechanisms.

See [docs/ETHICS_AND_SAFETY.md](docs/ETHICS_AND_SAFETY.md) and
[SECURITY.md](SECURITY.md) before running the lab.

## Requirements

- Python 3.9 or later
- Node.js for the browser-logic tests
- Docker is optional

## Run locally

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.lock
.venv/bin/python run.py
```

Open <http://127.0.0.1:5000>. The ten-module workbench is on the home page and
the challenge extension is at <http://127.0.0.1:5000/auditor/>.

Reset the synthetic database:

```bash
.venv/bin/python scripts/reset_lab.py
```

Optional Docker route:

```bash
docker compose up --build
```

The Compose configuration also publishes only on `127.0.0.1:5000`.

## Verify

```bash
.venv/bin/python -m pytest -q
node --test tests/js/*.test.js
```

The current verified project state records:

- 91 Python tests passing;
- 15 browser-logic tests passing;
- 90 target/observer actions across the ten-module assurance run;
- 40/40 executable assurance assertions;
- 36 bounded Auditor cases; and
- four confirmed Candidate counterexamples replayed successfully against the
  Robust controls.

The Auditor's 100% mutation score means that its four deliberately seeded
Candidate defects were detected. It is not a production security score.

## Repository map

```text
app/                  Flask application, UI and executable security contracts
tests/                Python and browser-logic regression tests
scripts/              Evidence generator and synthetic database reset command
docs/                 Specifications, safety notes and selected evidence
requirements.lock     Frozen Python dependencies
run.py                Loopback-only development runner
compose.yaml          Optional loopback-only container route
```

Useful technical documents:

- [Module specifications](docs/MODULE_SPECIFICATIONS.md)
- [Auditor specification](docs/AUDITOR_SPECIFICATION.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Selected execution evidence](docs/evidence/README.md)

## Claim boundary

TwinLab demonstrates selected security decisions inside a disposable,
localhost-only teaching environment. Passing its tests does not establish
production readiness, formal correctness, OWASP compliance, protection against
every CWE in a category or independent reproduction.
