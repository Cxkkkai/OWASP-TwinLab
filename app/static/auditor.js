(function securityControlAuditor() {
  "use strict";

  const manifestNode = document.getElementById("auditor-manifest");
  if (!manifestNode || !globalThis.TwinLabAuditorCore) return;

  const manifest = JSON.parse(manifestNode.textContent);
  const core = globalThis.TwinLabAuditorCore;
  const moduleOrder = manifest.module_order;
  const baselineByModule = new Map();
  const resultByModule = new Map();
  let selectedModule = moduleOrder[0];
  let busy = false;

  const elements = {
    moduleButtons: [...document.querySelectorAll("[data-auditor-module]")],
    baselineButton: document.querySelector("[data-auditor-baseline]"),
    auditButton: document.querySelector("[data-auditor-audit]"),
    runAllButton: document.querySelector("[data-auditor-run-all]"),
    downloadButton: document.querySelector("[data-auditor-download]"),
    status: document.querySelector("[data-auditor-status]"),
    contractId: document.querySelector("[data-contract-id]"),
    contractTitle: document.querySelector("[data-contract-title]"),
    contractInvariant: document.querySelector("[data-contract-invariant]"),
    candidateName: document.querySelector("[data-candidate-name]"),
    candidateSummary: document.querySelector("[data-candidate-summary]"),
    explorerName: document.querySelector("[data-explorer-name]"),
    explorerDimensions: document.querySelector("[data-explorer-dimensions]"),
    oracleForbidden: document.querySelector("[data-oracle-forbidden]"),
    boundedClaim: document.querySelector("[data-bounded-claim]"),
    baselineBadge: document.querySelector("[data-baseline-badge]"),
    baselineSummary: document.querySelector("[data-baseline-summary]"),
    baselineEvidence: document.querySelector("[data-baseline-evidence]"),
    counterexampleBadge: document.querySelector("[data-counterexample-badge]"),
    counterexampleSummary: document.querySelector("[data-counterexample-summary]"),
    counterexampleValue: document.querySelector("[data-counterexample-value]"),
    robustBadge: document.querySelector("[data-robust-badge]"),
    robustSummary: document.querySelector("[data-robust-summary]"),
    robustEvidence: document.querySelector("[data-robust-evidence]"),
    metricCases: document.querySelector("[data-metric-cases]"),
    metricTime: document.querySelector("[data-metric-time]"),
    metricReplay: document.querySelector("[data-metric-replay]"),
    metricLegitimate: document.querySelector("[data-metric-legitimate]"),
    attackStoryState: document.querySelector("[data-attack-story-state]"),
    attackObjective: document.querySelector("[data-attack-objective]"),
    attackCapability: document.querySelector("[data-attack-capability]"),
    attackManipulation: document.querySelector("[data-attack-manipulation]"),
    attackSuccess: document.querySelector("[data-attack-success]"),
    attackFlow: document.querySelector("[data-attack-flow]"),
    robustReplay: document.querySelector("[data-robust-replay]"),
    replayFlow: document.querySelector("[data-replay-flow]"),
    provenanceSection: document.querySelector(".auditor-provenance"),
    provenanceFlow: document.querySelector("[data-provenance-flow]"),
    caseTableSection: document.querySelector(".auditor-case-table"),
    caseTableBody: document.querySelector("[data-case-table-body]"),
    caseTableCaption: document.querySelector("[data-case-table-caption]"),
    regressionSection: document.querySelector(".auditor-regression"),
    regressionTest: document.querySelector("[data-regression-test]"),
    copyTest: document.querySelector("[data-copy-test]"),
    rawEvidence: document.querySelector("[data-raw-evidence]"),
    summarySection: document.querySelector("[data-auditor-summary]"),
    summaryScore: document.querySelector("[data-summary-score]"),
    summaryTotal: document.querySelector("[data-summary-total]"),
    summaryBaseline: document.querySelector("[data-summary-baseline]"),
    summaryDetected: document.querySelector("[data-summary-detected]"),
    summaryRobust: document.querySelector("[data-summary-robust]"),
  };

  const canaries = [
    "SYNTHETIC_TRACE_A02",
    "/synthetic/twinshop/orders.py",
    "DEMO_ONLY_CONFIG_A02",
    "SELECT * FROM orders WHERE id = <client-value>",
  ];

  function runId(moduleId) {
    const random = Math.random().toString(16).slice(2, 10);
    return `auditor-${moduleId}-${Date.now()}-${random}`;
  }

  async function requestJson(url, options = {}) {
    const headers = {
      Accept: "application/json",
      ...(options.headers || {}),
    };
    const response = await fetch(url, {
      ...options,
      headers,
      credentials: "same-origin",
    });
    const bodyText = await response.text();
    let body = {};
    if (bodyText) {
      try {
        body = JSON.parse(bodyText);
      } catch (_error) {
        body = { non_json_body: bodyText };
      }
    }
    const responseHeaders = {};
    response.headers.forEach((value, key) => {
      responseHeaders[key] = value;
    });
    return {
      url,
      method: options.method || "GET",
      status: response.status,
      ok: response.ok,
      body,
      bodyText,
      headers: responseHeaders,
    };
  }

  function observerOptions(options = {}) {
    return {
      ...options,
      headers: {
        ...(options.headers || {}),
        [manifest.observer_header]: manifest.observer_capability,
      },
    };
  }

  async function selectIdentity(username) {
    return requestJson(`/identity/${encodeURIComponent(username)}`, {
      method: "POST",
    });
  }

  async function restoreInitialIdentity() {
    if (manifest.initial_actor) {
      await selectIdentity(manifest.initial_actor);
    } else {
      await requestJson("/identity-clear", { method: "POST" });
    }
  }

  function query(path, name, value) {
    const joiner = path.includes("?") ? "&" : "?";
    return `${path}${joiner}${encodeURIComponent(name)}=${encodeURIComponent(value)}`;
  }

  function traceOf(response) {
    return Array.isArray(response?.body?.decision_trace)
      ? response.body.decision_trace
      : [];
  }

  function evidence(label, value) {
    return { label, value: String(value) };
  }

  async function baselineA05() {
    const known = "%' OR 1=1 --";
    const attack = await requestJson(query("/lab/a05/candidate/search", "q", known));
    const legitimate = await requestJson(
      query("/lab/a05/candidate/search", "q", "Security"),
    );
    const passed =
      attack.status === 400 &&
      attack.body.blocked_by_candidate === true &&
      attack.body.hidden_exposed === false &&
      legitimate.status === 200 &&
      legitimate.body.hidden_exposed === false;
    return {
      module_id: "a05",
      passed,
      summary: passed
        ? "The exact known payload is rejected and normal public search remains available."
        : "The candidate did not satisfy its known baseline.",
      evidence: [
        evidence("Known payload HTTP", attack.status),
        evidence("Known payload blocked", attack.body.blocked_by_candidate === true),
        evidence("Normal search HTTP", legitimate.status),
      ],
      known_case: known,
    };
  }

  async function auditA05(baseline) {
    const started = performance.now();
    const id = runId("a05");
    const contract = manifest.contracts.a05;
    const corpus = core.buildSqlMutationCorpus(contract.explorer.case_limit);
    const before = await requestJson(
      "/observer/a05/products-state",
      observerOptions(),
    );
    const cases = [];
    let firstCounterexampleAt = null;
    for (const input of corpus) {
      const path = (variant) => query(`/lab/a05/${variant}/search`, "q", input);
      const vulnerable = await requestJson(path("vulnerable"));
      const candidate = await requestJson(path("candidate"));
      const robust = await requestJson(path("secure"));
      const candidateViolation =
        candidate.status === 200 && candidate.body.hidden_exposed === true;
      if (candidateViolation && firstCounterexampleAt === null) {
        firstCounterexampleAt = performance.now() - started;
      }
      cases.push({
        label: input,
        input,
        vulnerable: {
          status: vulnerable.status,
          violation: vulnerable.body.hidden_exposed === true,
        },
        candidate: {
          status: candidate.status,
          violation: candidateViolation,
          blocked: candidate.body.blocked_by_candidate === true,
          response: candidate,
        },
        robust: {
          status: robust.status,
          violation: robust.body.hidden_exposed === true,
        },
        oracle_violation: candidateViolation,
      });
    }
    const counterexample = core.chooseShortestCounterexample(
      cases,
      (item) => item.oracle_violation,
    );
    const after = await requestJson(
      "/observer/a05/products-state",
      observerOptions(),
    );
    const legitimate = await requestJson(
      query("/lab/a05/secure/search", "q", "Security"),
    );
    const robustHolds = cases.every((item) => !item.robust.violation);
    const stateUnchanged =
      before.body.checksum && before.body.checksum === after.body.checksum;
    const legitimatePreserved =
      legitimate.status === 200 &&
      legitimate.body.hidden_exposed === false &&
      legitimate.body.result_count >= 1;
    const confirmed = Boolean(
      counterexample &&
        counterexample.candidate.response.body.hidden_exposed === true &&
        counterexample.candidate.response.body.products.some(
          (product) => product.name === "HIDDEN-PRODUCT-INTERNAL-ONLY",
        ),
    );
    return {
      module_id: "a05",
      run_id: id,
      contract_seed: contract.explorer.seed,
      baseline_passed: baseline.passed,
      baseline,
      counterexample_found: Boolean(counterexample),
      counterexample: counterexample
        ? {
            input: counterexample.input,
            candidate_http: counterexample.candidate.status,
            hidden_product_returned: confirmed,
            minimisation: "shortest confirmed input in the displayed bounded corpus",
          }
        : null,
      robust_control_holds: robustHolds && stateUnchanged,
      legitimate_use_preserved: legitimatePreserved,
      actual_replay_confirmed: confirmed,
      cases_executed: corpus.length,
      time_to_counterexample_ms:
        firstCounterexampleAt === null ? null : Math.round(firstCounterexampleAt),
      elapsed_ms: Math.round(performance.now() - started),
      case_results: cases.map(({ candidate, ...item }) => ({
        ...item,
        candidate: {
          status: candidate.status,
          violation: candidate.violation,
          blocked: candidate.blocked,
        },
      })),
      provenance: counterexample
        ? traceOf(counterexample.candidate.response)
        : [],
      authoritative_state: {
        checksum_before: before.body.checksum,
        checksum_after: after.body.checksum,
        unchanged: stateUnchanged,
      },
      regression_test: core.buildRegressionTest("a05", counterexample),
      bounded_claim: contract.bounded_claim,
    };
  }

  async function baselineA01() {
    await selectIdentity("alice");
    try {
      const attack = await requestJson("/lab/a01/candidate/orders/202");
      const legitimate = await requestJson("/lab/a01/candidate/orders/101");
      const passed =
        attack.status === 404 &&
        attack.body.sensitive_data_returned === false &&
        legitimate.status === 200 &&
        legitimate.body.object_owner === "alice";
      return {
        module_id: "a01",
        passed,
        summary: passed
          ? "With no caller override, the owner predicate denies Alice access to Bob's order."
          : "The candidate did not satisfy its known owner-check baseline.",
        evidence: [
          evidence("Alice → Bob order", attack.status),
          evidence("Sensitive data returned", attack.body.sensitive_data_returned),
          evidence("Alice → own order", legitimate.status),
        ],
      };
    } finally {
      await restoreInitialIdentity();
    }
  }

  async function auditA01(baseline) {
    const started = performance.now();
    const contract = manifest.contracts.a01;
    const id = runId("a01");
    const definitions = [
      { label: "No actor override", input: "none", headers: {}, suffix: "" },
      {
        label: "Header actor = bob",
        input: "X-TwinLab-Actor: bob",
        request_actor: "bob",
        headers: { "X-TwinLab-Actor": "bob" },
        suffix: "",
      },
      {
        label: "Query actor = bob",
        input: "actor=bob",
        request_actor: "bob",
        headers: {},
        suffix: "?actor=bob",
      },
    ];
    const cases = [];
    let firstCounterexampleAt = null;
    await selectIdentity("alice");
    try {
      for (const definition of definitions) {
        const options = { headers: definition.headers };
        const vulnerable = await requestJson(
          `/lab/a01/vulnerable/orders/202${definition.suffix}`,
          options,
        );
        const candidate = await requestJson(
          `/lab/a01/candidate/orders/202${definition.suffix}`,
          options,
        );
        const robust = await requestJson(
          `/lab/a01/secure/orders/202${definition.suffix}`,
          options,
        );
        const candidateViolation =
          candidate.status === 200 &&
          candidate.body.session_actor === "alice" &&
          candidate.body.object_owner === "bob";
        if (candidateViolation && firstCounterexampleAt === null) {
          firstCounterexampleAt = performance.now() - started;
        }
        cases.push({
          ...definition,
          vulnerable: {
            status: vulnerable.status,
            violation: vulnerable.body.object_owner === "bob",
          },
          candidate: {
            status: candidate.status,
            violation: candidateViolation,
            response: candidate,
          },
          robust: {
            status: robust.status,
            violation: robust.body.sensitive_data_returned === true,
          },
          oracle_violation: candidateViolation,
        });
      }
      const counterexample = core.chooseShortestCounterexample(
        cases,
        (item) => item.oracle_violation,
      );
      const legitimate = await requestJson("/lab/a01/secure/orders/101");
      const robustHolds = cases.every((item) => !item.robust.violation);
      const legitimatePreserved =
        legitimate.status === 200 && legitimate.body.object_owner === "alice";
      return {
        module_id: "a01",
        run_id: id,
        contract_seed: contract.explorer.seed,
        baseline_passed: baseline.passed,
        baseline,
        counterexample_found: Boolean(counterexample),
        counterexample: counterexample
          ? {
              input: counterexample.input,
              request_actor: counterexample.request_actor,
              candidate_http: counterexample.candidate.status,
              returned_owner:
                counterexample.candidate.response.body.object_owner,
              signed_session:
                counterexample.candidate.response.body.session_actor,
              minimisation: "smallest principal-source manipulation in the policy matrix",
            }
          : null,
        robust_control_holds: robustHolds,
        legitimate_use_preserved: legitimatePreserved,
        actual_replay_confirmed: Boolean(counterexample),
        cases_executed: cases.length,
        time_to_counterexample_ms:
          firstCounterexampleAt === null ? null : Math.round(firstCounterexampleAt),
        elapsed_ms: Math.round(performance.now() - started),
        case_results: cases.map(({ candidate, headers, suffix, ...item }) => ({
          ...item,
          candidate: {
            status: candidate.status,
            violation: candidate.violation,
          },
        })),
        provenance: counterexample
          ? traceOf(counterexample.candidate.response)
          : [],
        regression_test: core.buildRegressionTest("a01", counterexample),
        bounded_claim: contract.bounded_claim,
      };
    } finally {
      await restoreInitialIdentity();
    }
  }

  async function baselineA02() {
    const attack = await requestJson(
      "/lab/a02/candidate/order-lookup?id=explode",
    );
    const bodyOnlyHits = core.scanCanaries(
      { bodyText: attack.bodyText, headers: {} },
      canaries,
    );
    const legitimate = await requestJson(
      "/lab/a02/candidate/order-lookup?id=101",
    );
    const passed =
      attack.status === 500 &&
      attack.body.internal_details_returned === false &&
      bodyOnlyHits.length === 0 &&
      legitimate.status === 200;
    return {
      module_id: "a02",
      passed,
      summary: passed
        ? "A body-only check sees a generic error and the normal lookup still works."
        : "The candidate did not satisfy its body-only baseline.",
      evidence: [
        evidence("Error HTTP", attack.status),
        evidence("Body canary hits", bodyOnlyHits.length),
        evidence("Normal lookup HTTP", legitimate.status),
      ],
    };
  }

  async function auditA02(baseline) {
    const started = performance.now();
    const contract = manifest.contracts.a02;
    const id = runId("a02");
    const inputs = ["explode", "not-a-number", "handler-failure"];
    const cases = [];
    let firstCounterexampleAt = null;
    for (const input of inputs) {
      const path = (variant) =>
        query(`/lab/a02/${variant}/order-lookup`, "id", input);
      const vulnerable = await requestJson(path("vulnerable"));
      const candidate = await requestJson(path("candidate"));
      const robust = await requestJson(path("secure"));
      const vulnerableHits = core.scanCanaries(vulnerable, canaries);
      const candidateHits = core.scanCanaries(candidate, canaries);
      const robustHits = core.scanCanaries(robust, canaries);
      if (candidateHits.length && firstCounterexampleAt === null) {
        firstCounterexampleAt = performance.now() - started;
      }
      cases.push({
        label: input,
        input,
        vulnerable: {
          status: vulnerable.status,
          violation: vulnerableHits.length > 0,
          hits: vulnerableHits,
        },
        candidate: {
          status: candidate.status,
          violation: candidateHits.length > 0,
          hits: candidateHits,
          response: candidate,
        },
        robust: {
          status: robust.status,
          violation: robustHits.length > 0,
          hits: robustHits,
          response: robust,
        },
        oracle_violation: candidateHits.length > 0,
      });
    }
    const counterexample = core.chooseShortestCounterexample(
      cases,
      (item) => item.oracle_violation,
    );
    let observerEvent = null;
    if (counterexample?.candidate.response.body.request_id) {
      observerEvent = await requestJson(
        query(
          "/observer/a02/audit-event",
          "request_id",
          counterexample.candidate.response.body.request_id,
        ),
        observerOptions(),
      );
    }
    const legitimate = await requestJson(
      "/lab/a02/secure/order-lookup?id=101",
    );
    const robustHolds = cases.every((item) => !item.robust.violation);
    const eventMinimised =
      observerEvent?.status === 200 &&
      JSON.stringify(observerEvent.body.stored_detail_keys) ===
        JSON.stringify(["error_class", "route"]);
    return {
      module_id: "a02",
      run_id: id,
      contract_seed: contract.explorer.seed,
      baseline_passed: baseline.passed,
      baseline,
      counterexample_found: Boolean(counterexample),
      counterexample: counterexample
        ? {
            input: counterexample.input,
            candidate_http: counterexample.candidate.status,
            channels: counterexample.candidate.hits,
            minimisation: "shortest controlled failure input with a client-visible canary",
          }
        : null,
      robust_control_holds: robustHolds && eventMinimised,
      legitimate_use_preserved: legitimate.status === 200,
      actual_replay_confirmed: Boolean(counterexample),
      cases_executed: cases.length,
      time_to_counterexample_ms:
        firstCounterexampleAt === null ? null : Math.round(firstCounterexampleAt),
      elapsed_ms: Math.round(performance.now() - started),
      case_results: cases.map(({ candidate, robust, ...item }) => ({
        ...item,
        candidate: {
          status: candidate.status,
          violation: candidate.violation,
          hits: candidate.hits,
        },
        robust: {
          status: robust.status,
          violation: robust.violation,
        },
      })),
      provenance: counterexample
        ? traceOf(counterexample.candidate.response)
        : [],
      correlated_event: {
        found: observerEvent?.status === 200,
        minimised: eventMinimised,
        stored_detail_keys: observerEvent?.body?.stored_detail_keys || [],
      },
      regression_test: core.buildRegressionTest("a02", counterexample),
      bounded_claim: contract.bounded_claim,
    };
  }

  async function resetSessions(variant) {
    return requestJson(
      `/observer/a07/${variant}/reset-case`,
      observerOptions({ method: "POST" }),
    );
  }

  async function loginSession(variant) {
    const form = new URLSearchParams({
      username: "admin",
      password: "demo-admin",
    });
    return requestJson(`/lab/a07/${variant}/login`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: form,
    });
  }

  async function runSessionSequence(variant, transition) {
    await resetSessions(variant);
    const login = await loginSession(variant);
    const token = login.body.lab_token;
    if (!token) throw new Error(`No synthetic ${variant} session token was issued.`);
    let transitionResponse;
    if (transition === "logout") {
      transitionResponse = await requestJson(`/lab/a07/${variant}/logout`, {
        method: "POST",
        headers: { "X-Lab-Session": token },
      });
    } else if (transition === "expire") {
      transitionResponse = await requestJson(
        `/observer/a07/${variant}/expire-session`,
        observerOptions({
          method: "POST",
          headers: { "X-Lab-Session": token },
        }),
      );
    } else {
      throw new Error(`Unsupported session transition: ${transition}`);
    }
    const state = await requestJson(
      `/observer/a07/${variant}/session-state`,
      observerOptions({ headers: { "X-Lab-Session": token } }),
    );
    const access = await requestJson(`/lab/a07/${variant}/admin`, {
      headers: { "X-Lab-Session": token },
    });
    return {
      variant,
      transition,
      sequence: ["login", transition, "Admin access"],
      login_http: login.status,
      transition_http: transitionResponse.status,
      state: {
        found: state.body.session_found,
        active: state.body.active,
        expired: state.body.expired,
        token_fingerprint: state.body.token_fingerprint,
      },
      access: {
        status: access.status,
        admin_data_returned: access.body.admin_data_returned === true,
        session_expired: access.body.session_expired,
        expiry_checked: access.body.expiry_checked,
      },
      response: access,
    };
  }

  async function baselineA07() {
    const sequence = await runSessionSequence("candidate", "logout");
    const fresh = await loginSession("candidate");
    const freshAccess = await requestJson("/lab/a07/candidate/admin", {
      headers: { "X-Lab-Session": fresh.body.lab_token },
    });
    const passed =
      sequence.state.active === false &&
      sequence.access.status === 401 &&
      sequence.access.admin_data_returned === false &&
      freshAccess.status === 200;
    return {
      module_id: "a07",
      passed,
      summary: passed
        ? "The repaired logout revokes the old token, so the original replay baseline passes."
        : "The candidate did not satisfy the original logout-replay baseline.",
      evidence: [
        evidence("Session active after logout", sequence.state.active),
        evidence("Old-token replay HTTP", sequence.access.status),
        evidence("Fresh Admin HTTP", freshAccess.status),
      ],
    };
  }

  async function auditA07(baseline) {
    const started = performance.now();
    const contract = manifest.contracts.a07;
    const id = runId("a07");
    const transitions = ["logout", "expire"];
    const cases = [];
    let firstCounterexampleAt = null;
    for (const transition of transitions) {
      const vulnerable = await runSessionSequence("vulnerable", transition);
      const candidate = await runSessionSequence("candidate", transition);
      const robust = await runSessionSequence("secure", transition);
      const candidateViolation =
        candidate.access.status === 200 &&
        candidate.access.admin_data_returned === true &&
        (candidate.state.active === false || candidate.state.expired === true);
      if (candidateViolation && firstCounterexampleAt === null) {
        firstCounterexampleAt = performance.now() - started;
      }
      cases.push({
        label: `login → ${transition} → Admin access`,
        input: transition,
        sequence: candidate.sequence,
        vulnerable: {
          status: vulnerable.access.status,
          violation:
            vulnerable.access.admin_data_returned === true &&
            (vulnerable.state.active === false || vulnerable.state.expired === true),
        },
        candidate: {
          status: candidate.access.status,
          violation: candidateViolation,
          result: candidate,
        },
        robust: {
          status: robust.access.status,
          violation:
            robust.access.admin_data_returned === true &&
            (robust.state.active === false || robust.state.expired === true),
        },
        oracle_violation: candidateViolation,
      });
    }
    const counterexample = core.chooseShortestCounterexample(
      cases,
      (item) => item.oracle_violation,
    );
    await resetSessions("secure");
    const legitimateLogin = await loginSession("secure");
    const legitimateAccess = await requestJson("/lab/a07/secure/admin", {
      headers: { "X-Lab-Session": legitimateLogin.body.lab_token },
    });
    const robustHolds = cases.every((item) => !item.robust.violation);
    return {
      module_id: "a07",
      run_id: id,
      contract_seed: contract.explorer.seed,
      baseline_passed: baseline.passed,
      baseline,
      counterexample_found: Boolean(counterexample),
      counterexample: counterexample
        ? {
            input: counterexample.input,
            sequence: counterexample.sequence,
            candidate_http: counterexample.candidate.status,
            authoritative_state: counterexample.candidate.result.state,
            expiry_checked:
              counterexample.candidate.result.access.expiry_checked,
            minimisation: "shortest violating sequence in the depth-three action model",
          }
        : null,
      robust_control_holds: robustHolds,
      legitimate_use_preserved: legitimateAccess.status === 200,
      actual_replay_confirmed: Boolean(counterexample),
      cases_executed: cases.length,
      time_to_counterexample_ms:
        firstCounterexampleAt === null ? null : Math.round(firstCounterexampleAt),
      elapsed_ms: Math.round(performance.now() - started),
      case_results: cases.map(({ candidate, ...item }) => ({
        ...item,
        candidate: {
          status: candidate.status,
          violation: candidate.violation,
          state: candidate.result.state,
        },
      })),
      provenance: counterexample
        ? traceOf(counterexample.candidate.result.response)
        : [],
      regression_test: core.buildRegressionTest("a07", counterexample),
      bounded_claim: contract.bounded_claim,
    };
  }

  const adapters = {
    a05: { baseline: baselineA05, audit: auditA05 },
    a07: { baseline: baselineA07, audit: auditA07 },
    a01: { baseline: baselineA01, audit: auditA01 },
    a02: { baseline: baselineA02, audit: auditA02 },
  };

  function setBadge(node, state, label) {
    node.className = `auditor-badge ${state}`;
    node.textContent = label;
  }

  function renderEvidenceList(node, items) {
    node.replaceChildren();
    for (const item of items || []) {
      const row = document.createElement("div");
      const term = document.createElement("dt");
      const value = document.createElement("dd");
      term.textContent = item.label;
      value.textContent = item.value;
      row.append(term, value);
      node.append(row);
    }
  }

  function attackStepNode(step, state = "queued") {
    const item = document.createElement("li");
    item.dataset.stepState = state;
    const marker = document.createElement("span");
    marker.className = "auditor-attack-marker";
    marker.textContent =
      state === "observed" ? "Observed" : state === "running" ? "Running" : "Queued";
    const actor = document.createElement("small");
    actor.textContent = step.actor;
    const title = document.createElement("strong");
    title.textContent = step.title;
    const action = document.createElement("p");
    action.textContent = step.action;
    const evidenceNode = document.createElement("code");
    evidenceNode.textContent = step.evidence || "Evidence will appear after execution.";
    item.append(marker, actor, title, action, evidenceNode);
    return item;
  }

  function renderAttackBrief(contract) {
    elements.attackObjective.textContent = contract.attack.objective;
    elements.attackCapability.textContent = contract.attack.capability;
    elements.attackManipulation.textContent = contract.attack.manipulation;
    elements.attackSuccess.textContent = contract.attack.success;
  }

  function renderAttackPlan(contract, baseline = null) {
    const knownObserved = Boolean(baseline);
    elements.attackStoryState.textContent = knownObserved
      ? "Known path observed · adversarial path not yet executed"
      : "Waiting for the known baseline";
    const plan = [
      {
        actor: "Attacker",
        title: "1. Establish the starting capability",
        action: contract.attack.capability,
        evidence: knownObserved
          ? "Synthetic starting state established by the baseline run."
          : "Not executed.",
      },
      {
        actor: "Known path",
        title: "2. Probe the Candidate with the known example",
        action: contract.attack.known_path,
        evidence: knownObserved
          ? `Actual baseline result: ${baseline.passed ? "PASS" : "FAIL"}`
          : "Not executed.",
      },
      {
        actor: "Attacker",
        title: "3. Change the attack strategy",
        action: contract.attack.manipulation,
        evidence: "A confirmed value or state sequence will appear after the audit.",
      },
      {
        actor: "Candidate target",
        title: "4. Observe the runtime security decision",
        action: "Send the selected case to the real Candidate route and retain its decision events.",
        evidence: "No Candidate replay yet.",
      },
      {
        actor: "Protected boundary",
        title: "5. Test the success condition",
        action: contract.attack.success,
        evidence: "No forbidden observation evaluated yet.",
      },
    ];
    elements.attackFlow.replaceChildren(
      ...plan.map((step, index) =>
        attackStepNode(step, knownObserved && index < 2 ? "observed" : "queued"),
      ),
    );
    elements.robustReplay.hidden = true;
    elements.replayFlow.replaceChildren();
  }

  function renderAttackRunning(contract, phase) {
    const baselinePhase = phase === "baseline";
    elements.attackStoryState.textContent = baselinePhase
      ? "Executing the known attack path against the Candidate"
      : "Generating, sending and evaluating bounded adversarial cases";
    const runningPlan = [
      {
        actor: "Attacker",
        title: "1. Establish the starting capability",
        action: contract.attack.capability,
        evidence: baselinePhase ? "Establishing state…" : "Known baseline already established.",
      },
      {
        actor: "Known path",
        title: "2. Probe the Candidate with the known example",
        action: contract.attack.known_path,
        evidence: baselinePhase ? "Request in progress…" : "Known baseline passed.",
      },
      {
        actor: "Attacker",
        title: "3. Change the attack strategy",
        action: contract.attack.manipulation,
        evidence: baselinePhase ? "Waiting for baseline." : "Explorer is evaluating bounded cases…",
      },
      {
        actor: "Candidate target",
        title: "4. Observe the runtime security decision",
        action: "Replay each selected case against the real target implementation.",
        evidence: baselinePhase ? "Waiting for baseline." : "Capturing response and decision trace…",
      },
      {
        actor: "Protected boundary",
        title: "5. Test the success condition",
        action: contract.attack.success,
        evidence: baselinePhase ? "Waiting for baseline." : "Evaluating the forbidden-observation oracle…",
      },
    ];
    elements.attackFlow.replaceChildren(
      ...runningPlan.map((step, index) => {
        const state = baselinePhase
          ? index < 2
            ? "running"
            : "queued"
          : index < 2
            ? "observed"
            : index === 2
              ? "running"
              : "queued";
        return attackStepNode(step, state);
      }),
    );
    elements.robustReplay.hidden = true;
  }

  function renderAttackResult(result) {
    const story =
      result.attack_story || core.buildAttackStory(result.module_id, result);
    elements.attackStoryState.textContent = result.counterexample_found
      ? "Confirmed attack path · every step below contains evidence from this run"
      : "Search completed without a confirmed attack path";
    elements.attackObjective.textContent = story.objective;
    elements.attackFlow.replaceChildren(
      ...story.steps.map((step) => attackStepNode(step, "observed")),
    );
    elements.replayFlow.replaceChildren();
    for (const [index, step] of story.replay.entries()) {
      const item = document.createElement("article");
      const marker = document.createElement("span");
      const title = document.createElement("strong");
      const evidenceNode = document.createElement("p");
      marker.textContent = String(index + 1);
      title.textContent = step.title;
      evidenceNode.textContent = step.evidence;
      item.append(marker, title, evidenceNode);
      elements.replayFlow.append(item);
    }
    elements.robustReplay.hidden = !story.replay.length;
  }

  function renderContract(moduleId) {
    selectedModule = moduleId;
    const contract = manifest.contracts[moduleId];
    for (const button of elements.moduleButtons) {
      const selected = button.dataset.auditorModule === moduleId;
      button.classList.toggle("selected", selected);
      button.setAttribute("aria-selected", String(selected));
    }
    elements.contractId.textContent = `${contract.owasp} · ${contract.explorer.kind} explorer`;
    elements.contractTitle.textContent = contract.title;
    elements.contractInvariant.textContent = contract.invariant;
    elements.candidateName.textContent = contract.candidate.name;
    elements.candidateSummary.textContent = contract.candidate.summary;
    elements.explorerName.textContent = contract.explorer.name;
    elements.explorerDimensions.textContent = contract.explorer.dimensions.join(
      " · ",
    );
    elements.oracleForbidden.textContent = contract.oracle.forbidden;
    elements.boundedClaim.textContent = contract.bounded_claim;
    renderAttackBrief(contract);
    renderModuleState();
  }

  function resetAuditPanels() {
    setBadge(elements.counterexampleBadge, "pending", "Not run");
    elements.counterexampleSummary.textContent = "No bounded search has run.";
    elements.counterexampleValue.hidden = true;
    elements.counterexampleValue.textContent = "";
    setBadge(elements.robustBadge, "pending", "Not run");
    elements.robustSummary.textContent =
      "The controlled implementation has not been challenged.";
    renderEvidenceList(elements.robustEvidence, []);
    elements.metricCases.textContent = "—";
    elements.metricTime.textContent = "—";
    elements.metricReplay.textContent = "—";
    elements.metricLegitimate.textContent = "—";
    elements.provenanceSection.hidden = true;
    elements.caseTableSection.hidden = true;
    elements.regressionSection.hidden = true;
    elements.rawEvidence.textContent = "No audit evidence yet.";
  }

  function renderModuleState() {
    const baseline = baselineByModule.get(selectedModule);
    const result = resultByModule.get(selectedModule);
    if (!baseline) {
      setBadge(elements.baselineBadge, "pending", "Not run");
      elements.baselineSummary.textContent = "The candidate has not been tested.";
      renderEvidenceList(elements.baselineEvidence, []);
      elements.auditButton.disabled = true;
      resetAuditPanels();
      renderAttackPlan(manifest.contracts[selectedModule]);
      return;
    }
    setBadge(
      elements.baselineBadge,
      baseline.passed ? "warning" : "fail",
      baseline.passed ? "Baseline PASS" : "Baseline FAIL",
    );
    elements.baselineSummary.textContent = baseline.summary;
    renderEvidenceList(elements.baselineEvidence, baseline.evidence);
    elements.auditButton.disabled = busy || !baseline.passed;
    if (result) renderAuditResult(result);
    else {
      resetAuditPanels();
      renderAttackPlan(manifest.contracts[selectedModule], baseline);
    }
  }

  function resultLabel(result) {
    if (result.violation) return "VIOLATION";
    if (result.blocked) return `BLOCKED · ${result.status}`;
    return `HELD · ${result.status}`;
  }

  function renderCaseTable(result) {
    elements.caseTableBody.replaceChildren();
    for (const item of result.case_results || []) {
      const row = document.createElement("tr");
      const caseCell = document.createElement("th");
      caseCell.scope = "row";
      caseCell.textContent = item.label;
      row.append(caseCell);
      for (const key of ["vulnerable", "candidate", "robust"]) {
        const cell = document.createElement("td");
        const value = item[key] || {};
        cell.textContent = resultLabel(value);
        cell.dataset.outcome = value.violation ? "fail" : "pass";
        row.append(cell);
      }
      const oracle = document.createElement("td");
      oracle.textContent = item.oracle_violation
        ? "Counterexample"
        : "No candidate violation";
      oracle.dataset.outcome = item.oracle_violation ? "fail" : "pass";
      row.append(oracle);
      elements.caseTableBody.append(row);
    }
    elements.caseTableCaption.textContent = `${result.cases_executed} bounded cases · ${result.elapsed_ms} ms total`;
    elements.caseTableSection.hidden = false;
  }

  function renderProvenance(events) {
    elements.provenanceFlow.replaceChildren();
    for (const event of events || []) {
      const node = document.createElement("article");
      const stage = document.createElement("span");
      const label = document.createElement("strong");
      const decision = document.createElement("p");
      stage.textContent = event.stage;
      label.textContent = event.label;
      decision.textContent = event.decision;
      node.append(stage, label, decision);
      elements.provenanceFlow.append(node);
    }
    elements.provenanceSection.hidden = !(events && events.length);
  }

  function counterexampleDisplay(result) {
    const counterexample = result.counterexample;
    if (!counterexample) return "";
    if (Array.isArray(counterexample.sequence)) {
      return counterexample.sequence.join(" → ");
    }
    if (Array.isArray(counterexample.channels)) {
      return counterexample.channels
        .map((hit) => `${hit.channel}: ${hit.canary}`)
        .join("\n");
    }
    return counterexample.input || "Confirmed bounded counterexample";
  }

  function renderAuditResult(result) {
    setBadge(
      elements.counterexampleBadge,
      result.counterexample_found ? "fail" : "pass",
      result.counterexample_found ? "CONTROL BROKEN" : "No counterexample",
    );
    elements.counterexampleSummary.textContent = result.counterexample_found
      ? "The candidate passed its known baseline, but a different bounded case produced a real invariant violation."
      : "No candidate violation was observed in this bounded search.";
    elements.counterexampleValue.hidden = !result.counterexample_found;
    elements.counterexampleValue.textContent = counterexampleDisplay(result);
    setBadge(
      elements.robustBadge,
      result.robust_control_holds ? "pass" : "fail",
      result.robust_control_holds ? "Invariant held" : "Control failed",
    );
    elements.robustSummary.textContent = result.robust_control_holds
      ? "The same explored cases did not produce the forbidden observation in the controlled implementation."
      : "At least one explored case violated the robust-control contract.";
    renderEvidenceList(elements.robustEvidence, [
      evidence("Bounded cases", result.cases_executed),
      evidence("Real replay confirmed", result.actual_replay_confirmed),
      evidence("Legitimate use preserved", result.legitimate_use_preserved),
    ]);
    elements.metricCases.textContent = String(result.cases_executed);
    elements.metricTime.textContent =
      result.time_to_counterexample_ms === null
        ? "Not found"
        : `${result.time_to_counterexample_ms} ms`;
    elements.metricReplay.textContent = result.actual_replay_confirmed
      ? "Confirmed"
      : "Not confirmed";
    elements.metricLegitimate.textContent = result.legitimate_use_preserved
      ? "Preserved"
      : "Regressed";
    renderProvenance(result.provenance);
    renderCaseTable(result);
    elements.regressionTest.textContent = result.regression_test;
    elements.regressionSection.hidden = !result.regression_test;
    elements.rawEvidence.textContent = JSON.stringify(
      core.redactEvidence(result),
      null,
      2,
    );
    elements.boundedClaim.textContent = result.bounded_claim;
    renderAttackResult(result);
  }

  function setBusy(nextBusy, message) {
    busy = nextBusy;
    elements.baselineButton.disabled = nextBusy;
    elements.runAllButton.disabled = nextBusy;
    elements.auditButton.disabled =
      nextBusy || !baselineByModule.get(selectedModule)?.passed;
    for (const button of elements.moduleButtons) button.disabled = nextBusy;
    if (message) elements.status.textContent = message;
  }

  async function runBaselineFor(moduleId, render = true) {
    const baseline = await adapters[moduleId].baseline();
    baselineByModule.set(moduleId, baseline);
    if (render && selectedModule === moduleId) renderModuleState();
    return baseline;
  }

  async function auditModule(moduleId, baseline, render = true) {
    const result = await adapters[moduleId].audit(baseline);
    result.attack_story = core.buildAttackStory(moduleId, result);
    resultByModule.set(moduleId, result);
    if (render && selectedModule === moduleId) renderAuditResult(result);
    elements.downloadButton.disabled = resultByModule.size === 0;
    return result;
  }

  async function runCurrentBaseline() {
    if (busy) return;
    setBusy(true, `Running the ${selectedModule.toUpperCase()} known example…`);
    renderAttackRunning(manifest.contracts[selectedModule], "baseline");
    try {
      const baseline = await runBaselineFor(selectedModule);
      elements.status.textContent = baseline.passed
        ? "Baseline passed. The candidate now looks secure; run the adversarial audit."
        : "Baseline failed. The candidate is not eligible for the deeper audit.";
    } catch (error) {
      elements.status.textContent = `Baseline error: ${error.message}`;
    } finally {
      setBusy(false);
      renderModuleState();
    }
  }

  async function runCurrentAudit() {
    if (busy) return;
    const baseline = baselineByModule.get(selectedModule);
    if (!baseline?.passed) return;
    setBusy(true, `Searching for a bounded ${selectedModule.toUpperCase()} counterexample…`);
    renderAttackRunning(manifest.contracts[selectedModule], "audit");
    try {
      const result = await auditModule(selectedModule, baseline);
      elements.status.textContent = result.counterexample_found
        ? "Confirmed counterexample found and replayed against the real target."
        : "Search complete. No counterexample was observed within this contract.";
    } catch (error) {
      elements.status.textContent = `Audit error: ${error.message}`;
    } finally {
      setBusy(false);
      renderModuleState();
    }
  }

  async function runAllAudits() {
    if (busy) return;
    setBusy(true, "Starting four bounded control audits…");
    const completed = [];
    try {
      for (let index = 0; index < moduleOrder.length; index += 1) {
        const moduleId = moduleOrder[index];
        elements.status.textContent = `${index + 1}/${moduleOrder.length} · ${moduleId.toUpperCase()} baseline and audit`;
        const baseline = await runBaselineFor(moduleId, false);
        if (!baseline.passed) {
          throw new Error(`${moduleId.toUpperCase()} candidate did not pass its baseline.`);
        }
        const result = await auditModule(moduleId, baseline, false);
        completed.push(result);
      }
      const summary = core.summariseAuditResults(completed);
      elements.summaryScore.textContent = `${summary.mutation_score_percent}% detected`;
      elements.summaryTotal.textContent = summary.total_seeded_defects;
      elements.summaryBaseline.textContent = `${summary.baseline_passed}/${summary.total_seeded_defects}`;
      elements.summaryDetected.textContent = `${summary.detected_seeded_defects}/${summary.total_seeded_defects}`;
      elements.summaryRobust.textContent = `${summary.robust_controls_held}/${summary.total_seeded_defects}`;
      elements.summarySection.hidden = false;
      elements.status.textContent =
        "All four candidate controls passed their known baselines; the bounded auditor results are now measured.";
      renderContract(moduleOrder[0]);
    } catch (error) {
      elements.status.textContent = `Four-control audit stopped: ${error.message}`;
    } finally {
      setBusy(false);
      renderModuleState();
    }
  }

  function downloadEvidence() {
    const results = moduleOrder
      .map((moduleId) => resultByModule.get(moduleId))
      .filter(Boolean);
    if (!results.length) return;
    const payload = {
      generated_at: new Date().toISOString(),
      scope: "localhost synthetic bounded security-control audit",
      summary: core.summariseAuditResults(results),
      results,
    };
    const blob = new Blob(
      [JSON.stringify(core.redactEvidence(payload), null, 2)],
      { type: "application/json" },
    );
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `twinlab-auditor-evidence-${Date.now()}.json`;
    document.body.append(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  }

  async function copyRegressionTest() {
    const text = elements.regressionTest.textContent;
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
      elements.status.textContent = "Generated regression test copied.";
    } catch (_error) {
      elements.status.textContent =
        "Clipboard access was unavailable; the generated test remains selectable.";
    }
  }

  for (const button of elements.moduleButtons) {
    button.addEventListener("click", () => {
      if (!busy) renderContract(button.dataset.auditorModule);
    });
  }
  elements.baselineButton.addEventListener("click", runCurrentBaseline);
  elements.auditButton.addEventListener("click", runCurrentAudit);
  elements.runAllButton.addEventListener("click", runAllAudits);
  elements.downloadButton.addEventListener("click", downloadEvidence);
  elements.copyTest.addEventListener("click", copyRegressionTest);

  renderContract(selectedModule);
})();
