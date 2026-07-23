"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const runner = require("../../app/static/lab-runner.js");

test("assertion operators require present evidence and compare explicit values", () => {
  const record = {
    allowed: false,
    status: 401,
    role: "customer",
    steps: { before: { payload: { count: 1 } }, after: { payload: { count: 2 } } },
  };

  assert.equal(runner.evaluateAssertion({ id: "a", path: "allowed", operator: "falsy" }, record).passed, true);
  assert.equal(runner.evaluateAssertion({ id: "b", path: "status", operator: "equals", expected: 401 }, record).passed, true);
  assert.equal(runner.evaluateAssertion({ id: "c", path: "role", operator: "in", expected: ["customer", "admin"] }, record).passed, true);
  assert.equal(runner.evaluateAssertion({ id: "d", path: "missing", operator: "falsy" }, record).passed, false);
  assert.equal(runner.evaluateAssertion({ id: "e", path: "missing", operator: "not_equals", expected: true }, record).passed, false);
});

test("changed and unchanged assertions compare two authoritative evidence paths", () => {
  const record = {
    steps: {
      before: { payload: { price: 4900, checksum: "abc" } },
      after: { payload: { price: 100, checksum: "abc" } },
    },
  };

  const changed = runner.evaluateAssertion({
    id: "state_changed",
    path: ["steps.before.payload.price", "steps.after.payload.price"],
    operator: "changed",
  }, record);
  const unchanged = runner.evaluateAssertion({
    id: "state_safe",
    path: "steps.after.payload.checksum",
    operator: "unchanged",
    expected: { path: "steps.before.payload.checksum" },
  }, record);

  assert.equal(changed.passed, true);
  assert.deepEqual(changed.evidence, { before: 4900, after: 100 });
  assert.equal(unchanged.passed, true);
});

test("A08 HTTP 204 outcome is derived from the later authoritative state read", () => {
  const results = [
    { id: "reset", status: 200, headers: {}, payload: { price_cents: 4900 } },
    { id: "update", status: 204, headers: {}, payload: { outcome: "request completed with no response body" } },
    { id: "state", status: 200, headers: {}, payload: { price_cents: 100, outcome: "stored product price inspected" } },
  ];
  const run = { summary_step: "state", observations: [] };
  const assertions = [{
    id: "vulnerability_reproduced",
    label: "Tampered price reached stored state",
    path: "steps.update.payload.accepted",
    operator: "equals",
    expected: true,
  }];

  const summary = runner.buildSummary(run, results, "run-a08", assertions, "vulnerable");

  assert.equal(summary.record.steps.update.payload.accepted, true);
  assert.equal(summary.record.steps.update.payload.before_price_cents, 4900);
  assert.equal(summary.record.steps.update.payload.after_price_cents, 100);
  assert.equal(summary.assertions[0].passed, true);
});

test("input control replaces only targeted steps and URL-encodes attacker input", () => {
  const step = { id: "attack", url: "/orders/{{input}}", method: "GET" };
  const untouched = { id: "legitimate", url: "/orders/101", method: "GET" };
  const control = {
    name: "input",
    type: "path",
    target_steps: ["vulnerable.attack"],
    placeholder: "{{input}}",
  };

  assert.equal(
    runner.applyInputControl(step, control, "202/../../admin", "vulnerable").url,
    "/orders/202%2F..%2F..%2Fadmin"
  );
  assert.deepEqual(runner.applyInputControl(untouched, control, "202", "legitimate"), untouched);
});

test("downstream invalidation and run-id checks prevent mixed comparisons", () => {
  const summaries = {
    vulnerable: { runId: "run-1" },
    controlled: { runId: "run-1" },
    legitimate: { runId: "run-1" },
  };
  assert.equal(runner.summariesShareRun(summaries, runner.PHASES, "run-1"), true);

  runner.invalidateSummaries(summaries, runner.PHASES, 1);
  assert.deepEqual(Object.keys(summaries), ["vulnerable"]);
  summaries.controlled = { runId: "run-2" };
  summaries.legitimate = { runId: "run-2" };
  assert.equal(runner.summariesShareRun(summaries, runner.PHASES, "run-2"), false);
});

test("multiple clauses with one contract id are ANDed, not overwritten", () => {
  const grouped = runner.aggregateAssertionResults([
    { id: "control_effective", label: "Data withheld", passed: true, evidence: false },
    { id: "control_effective", label: "Expired token rejected", passed: false, evidence: 200 },
  ]);

  assert.equal(grouped.control_effective.passed, false);
  assert.equal(grouped.control_effective.evidence.length, 2);
});

test("attacker journey evidence binds a visible step to its real response", () => {
  const result = {
    id: "attack",
    status: 200,
    request: "GET /lab/a01/vulnerable/orders/202",
    payload: {
      outcome: "order returned without object ownership enforcement",
      object_owner: "bob",
      sensitive_data_returned: true,
    },
  };

  const evidence = runner.attackEvidenceForStep(result, "payload.object_owner");
  assert.deepEqual(evidence, {
    stepId: "attack",
    status: 200,
    outcome: "order returned without object ownership enforcement",
    value: "bob",
    request: "GET /lab/a01/vulnerable/orders/202",
  });

  assert.equal(
    runner.attackEvidenceForStep(result, "payload.missing").value,
    undefined
  );
});
