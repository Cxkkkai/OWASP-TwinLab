# Selected execution evidence

This directory contains the small evidence subset needed to check the principal
claims made in the project report:

- `TEST_OUTPUT.txt` records the frozen Python test result: 91 tests passed.
- `AUDITOR/A01_counterexample.json` records the access-control counterexample.
- `AUDITOR/A02_counterexample.json` records the response-channel counterexample.
- `AUDITOR/A05_counterexample.json` records the injection-filter counterexample.
- `AUDITOR/A07_counterexample.json` records the session-lifecycle counterexample.
- `AUDITOR/mutation_score.json` summarises the four seeded Candidate defects and
  the Robust-control replay results.

The complete 77-file raw response and state package is submitted separately as
Supporting Materials. It is intentionally not duplicated in this repository.

To regenerate the full local evidence package from the current source:

```bash
.venv/bin/python scripts/generate_evidence.py
```

The generator uses Flask's isolated test client, a temporary SQLite database and
synthetic data. It does not send network traffic. The resulting files document
bounded laboratory behaviour; they are not evidence of production security.
