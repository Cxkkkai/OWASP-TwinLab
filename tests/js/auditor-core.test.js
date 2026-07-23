const test = require("node:test");
const assert = require("node:assert/strict");

const auditor = require("../../app/static/auditor-core.js");


test("SQL mutation corpus is deterministic and contains a blacklist bypass", () => {
  const first = auditor.buildSqlMutationCorpus(28);
  const second = auditor.buildSqlMutationCorpus(28);
  assert.deepEqual(first, second);
  assert.equal(first[0], "%' OR 1=1 --");
  assert.ok(first.includes("%' oR 1=1 /*"));
  assert.equal(first.length, 28);
});


test("shortest counterexample is selected only from confirmed violations", () => {
  const selected = auditor.chooseShortestCounterexample(
    [
      { input: "longer counterexample", oracle_violation: true },
      { input: "safe", oracle_violation: false },
      { input: "short", oracle_violation: true },
    ],
    (item) => item.oracle_violation,
  );
  assert.equal(selected.input, "short");
});


test("canary scanner covers body and every response header", () => {
  const hits = auditor.scanCanaries(
    {
      bodyText: '{"message":"generic"}',
      headers: {
        "x-twinlab-debug-path": "/synthetic/twinshop/orders.py",
        "content-type": "application/json",
      },
    },
    ["/synthetic/twinshop/orders.py", "DEMO_ONLY_CONFIG_A02"],
  );
  assert.deepEqual(hits, [
    {
      channel: "header:x-twinlab-debug-path",
      canary: "/synthetic/twinshop/orders.py",
    },
  ]);
});


test("mutation summary is derived from actual per-module outcomes", () => {
  const summary = auditor.summariseAuditResults([
    {
      baseline_passed: true,
      counterexample_found: true,
      robust_control_holds: true,
      legitimate_use_preserved: true,
    },
    {
      baseline_passed: true,
      counterexample_found: false,
      robust_control_holds: true,
      legitimate_use_preserved: false,
    },
  ]);
  assert.deepEqual(summary, {
    total_seeded_defects: 2,
    detected_seeded_defects: 1,
    baseline_passed: 2,
    robust_controls_held: 2,
    legitimate_uses_preserved: 1,
    mutation_score_percent: 50,
  });
});


test("evidence redaction removes bearer material but retains fingerprints", () => {
  const redacted = auditor.redactEvidence({
    lab_token: "secret",
    password: "demo-admin",
    token_fingerprint: "123456789abc",
    nested: { token: "other-secret" },
  });
  assert.deepEqual(redacted, {
    lab_token: "[REDACTED]",
    password: "[REDACTED]",
    token_fingerprint: "123456789abc",
    nested: { token: "[REDACTED]" },
  });
});


test("confirmed counterexamples produce readable regression tests", () => {
  const generated = auditor.buildRegressionTest("a05", {
    input: "%' oR 1=1 /*",
  });
  assert.match(generated, /test_generated_a05_counterexample/);
  assert.match(generated, /quote\(payload/);
  assert.match(generated, /hidden_exposed/);
});


test("confirmed results reconstruct a five-step attacker execution path", () => {
  const shared = {
    baseline_passed: true,
    actual_replay_confirmed: true,
    robust_control_holds: true,
    legitimate_use_preserved: true,
    provenance: [
      { decision: "input accepted" },
      { decision: "candidate decision recorded" },
    ],
  };
  const fixtures = {
    a05: {
      ...shared,
      counterexample: {
        input: "bounded mutation",
        candidate_http: 200,
        hidden_product_returned: true,
      },
    },
    a07: {
      ...shared,
      counterexample: {
        sequence: ["login", "expire", "Admin access"],
        candidate_http: 200,
        expiry_checked: false,
        authoritative_state: {
          active: true,
          expired: true,
          token_fingerprint: "123456789abc",
        },
      },
    },
    a01: {
      ...shared,
      counterexample: {
        input: "actor override",
        candidate_http: 200,
        request_actor: "bob",
        signed_session: "alice",
        returned_owner: "bob",
      },
    },
    a02: {
      ...shared,
      counterexample: {
        input: "controlled failure",
        candidate_http: 500,
        channels: [{ channel: "header:synthetic", canary: "fixed-marker" }],
      },
    },
  };
  for (const [moduleId, result] of Object.entries(fixtures)) {
    const story = auditor.buildAttackStory(moduleId, result);
    assert.equal(story.steps.length, 5);
    assert.equal(story.replay.length, 3);
    assert.ok(story.steps.every((step) => step.action && step.evidence));
  }
});


test("session attack reconstruction exposes only a fingerprint", () => {
  const story = auditor.buildAttackStory("a07", {
    baseline_passed: true,
    actual_replay_confirmed: true,
    robust_control_holds: true,
    legitimate_use_preserved: true,
    counterexample: {
      sequence: ["login", "expire", "Admin access"],
      candidate_http: 200,
      expiry_checked: false,
      authoritative_state: {
        active: true,
        expired: true,
        token_fingerprint: "123456789abc",
      },
    },
  });
  const serialised = JSON.stringify(story);
  assert.match(serialised, /123456789abc/);
  assert.doesNotMatch(serialised, /lab_token|demo-admin/);
});
