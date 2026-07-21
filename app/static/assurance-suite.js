(function () {
  "use strict";

  const CHECK_IDS = [
    "vulnerability_reproduced",
    "control_effective",
    "authoritative_state_safe",
    "legitimate_use_preserved",
  ];
  const PHASES = ["vulnerable", "controlled", "legitimate"];

  function valueAtPath(value, path) {
    if (typeof path !== "string" || path === "") return undefined;
    return path.split(".").reduce((current, part) => {
      if (current === null || current === undefined) return undefined;
      return current[part];
    }, value);
  }

  function deepEqual(left, right) {
    if (Object.is(left, right)) return true;
    if (typeof left !== typeof right || left === null || right === null) return false;
    if (Array.isArray(left) || Array.isArray(right)) {
      return Array.isArray(left) && Array.isArray(right) &&
        left.length === right.length &&
        left.every((item, index) => deepEqual(item, right[index]));
    }
    if (typeof left === "object") {
      const leftKeys = Object.keys(left).sort();
      const rightKeys = Object.keys(right).sort();
      return leftKeys.length === rightKeys.length &&
        leftKeys.every((key, index) => key === rightKeys[index] && deepEqual(left[key], right[key]));
    }
    return false;
  }

  function evaluateAssertion(assertion, record) {
    const paths = Array.isArray(assertion.path) ? assertion.path : [assertion.path];
    const values = paths.map((path) => valueAtPath(record, path));
    const actual = values.length === 1 ? values[0] : values;
    let passed = false;

    if (values.some((value) => value === undefined)) {
      return {
        passed: false,
        actual: values.length === 1 ? "[missing]" : values.map((value) => value === undefined ? "[missing]" : value),
        error: `Evidence path not returned: ${paths.filter((_, index) => values[index] === undefined).join(", ")}`,
      };
    }

    switch (assertion.operator) {
      case "equals":
        passed = deepEqual(actual, assertion.expected);
        break;
      case "not_equals":
        passed = !deepEqual(actual, assertion.expected);
        break;
      case "truthy":
        passed = Boolean(actual);
        break;
      case "falsy":
        passed = !actual;
        break;
      case "in":
        passed = Array.isArray(assertion.expected) &&
          assertion.expected.some((candidate) => deepEqual(candidate, actual));
        break;
      case "unchanged":
        passed = values.length === 2 && deepEqual(values[0], values[1]);
        break;
      case "changed":
        passed = values.length === 2 && !deepEqual(values[0], values[1]);
        break;
      default:
        return {
          passed: false,
          actual,
          error: `Unsupported assertion operator: ${assertion.operator || "[missing]"}`,
        };
    }

    return { passed, actual, error: null };
  }

  if (typeof window !== "undefined") {
    window.TwinShopAssurance = Object.freeze({ evaluateAssertion, valueAtPath });
  }
  if (typeof document === "undefined") return;

  const manifestNode = document.getElementById("assurance-suite-manifest");
  const runButton = document.querySelector("[data-suite-run]");
  if (!manifestNode || !runButton) return;

  const manifest = JSON.parse(manifestNode.textContent);
  const downloadButton = document.querySelector("[data-suite-download]");
  const statusNode = document.querySelector("[data-suite-status]");
  const runIdNode = document.querySelector("[data-suite-run-id]");
  const progressNode = document.querySelector("[data-suite-progress]");
  const errorNode = document.querySelector("[data-suite-error]");
  let currentEvidence = null;

  function createRunId() {
    const stamp = new Date().toISOString().replace(/[-:.]/g, "").replace("Z", "Z");
    const random = typeof crypto !== "undefined" && typeof crypto.randomUUID === "function"
      ? crypto.randomUUID().split("-")[0]
      : Math.random().toString(16).slice(2, 10);
    return `suite-${stamp}-${random}`;
  }

  function withJsonFormat(rawUrl, comparisonRunId) {
    const url = new URL(rawUrl, window.location.href);
    if (url.origin !== window.location.origin) {
      throw new Error(`Refused non-local experiment URL: ${url.origin}`);
    }
    url.searchParams.set("format", "json");
    if (comparisonRunId) url.searchParams.set("comparison_run_id", comparisonRunId);
    return url.toString();
  }

  function resolveTemplates(value, runtimeValues) {
    if (typeof value === "string") {
      return value.replace(/\{\{([a-zA-Z0-9_]+)\}\}/g, (_match, name) => {
        if (!(name in runtimeValues)) throw new Error(`Missing captured value: ${name}`);
        return String(runtimeValues[name]);
      });
    }
    if (Array.isArray(value)) return value.map((item) => resolveTemplates(item, runtimeValues));
    if (value && typeof value === "object") {
      return Object.fromEntries(
        Object.entries(value).map(([key, item]) => [key, resolveTemplates(item, runtimeValues)])
      );
    }
    return value;
  }

  function sensitiveKey(key) {
    return /(?:token|signature|authorization|cookie|secret|password|set-cookie)/i.test(String(key));
  }

  function sanitized(value, key) {
    if (sensitiveKey(key)) return "[redacted]";
    if (Array.isArray(value)) return value.map((item) => sanitized(item, ""));
    if (value && typeof value === "object") {
      return Object.fromEntries(
        Object.entries(value).map(([childKey, childValue]) => [childKey, sanitized(childValue, childKey)])
      );
    }
    return value;
  }

  async function prepareSetup(setup) {
    if (!setup) return null;
    const method = (setup.method || "GET").toUpperCase();
    const options = {
      method,
      credentials: "same-origin",
      redirect: "follow",
      headers: { Accept: "application/json" },
    };
    if (method !== "GET" && method !== "HEAD") {
      options.headers["Content-Type"] = "application/x-www-form-urlencoded";
      options.body = new URLSearchParams(setup.fields || {});
    }
    const response = await fetch(new URL(setup.url, window.location.href), options);
    if (!response.ok) throw new Error(`Identity setup failed with HTTP ${response.status}`);
    return { status: response.status, redirected: response.redirected };
  }

  async function restoreInitialIdentity() {
    const actor = manifest.initial_actor;
    const url = new URL(
      actor ? `/identity/${encodeURIComponent(actor)}` : "/identity-clear",
      window.location.href
    );
    url.searchParams.set("format", "json");
    const response = await fetch(url, {
      method: "POST",
      credentials: "same-origin",
      headers: { Accept: "application/json" },
    });
    if (!response.ok) {
      throw new Error(`Could not restore the original run context (HTTP ${response.status})`);
    }
  }

  async function executeStep(unresolvedStep, runtimeValues) {
    const step = resolveTemplates(unresolvedStep, runtimeValues);
    const method = (step.method || "GET").toUpperCase();
    const headers = { Accept: "application/json", ...(step.headers || {}) };
    const options = { method, credentials: "same-origin", headers, redirect: "follow" };

    if (step.raw_body !== undefined) {
      options.body = step.raw_body;
      if (!Object.keys(headers).some((name) => name.toLowerCase() === "content-type")) {
        headers["Content-Type"] = "application/json";
      }
    } else if (method !== "GET" && method !== "HEAD") {
      headers["Content-Type"] = "application/x-www-form-urlencoded";
      options.body = new URLSearchParams(step.fields || {});
    }

    const response = await fetch(withJsonFormat(step.url, runtimeValues.comparison_run_id), options);
    const raw = await response.text();
    let payload = {};
    if (raw) {
      try {
        payload = JSON.parse(raw);
      } catch (_error) {
        throw new Error(`${step.label || step.id}: expected JSON, received HTTP ${response.status} non-JSON response`);
      }
    } else if (response.status !== 204) {
      payload = { outcome: "empty response" };
    }

    Object.entries(step.capture || {}).forEach(([runtimeName, payloadPath]) => {
      const captured = valueAtPath(payload, payloadPath);
      if (captured === undefined) {
        throw new Error(`${step.label || step.id}: response did not contain ${payloadPath}`);
      }
      runtimeValues[runtimeName] = captured;
    });

    const responseHeaders = {};
    response.headers.forEach((value, name) => { responseHeaders[name.toLowerCase()] = value; });
    return {
      id: step.id,
      label: step.label,
      status: response.status,
      headers: responseHeaders,
      payload,
    };
  }

  function buildSummary(run, results) {
    const stepMap = Object.fromEntries(results.map((result) => [result.id, {
      status: result.status,
      headers: result.headers,
      payload: result.payload,
    }]));
    const selected = results.find((result) => result.id === run.summary_step) || results[results.length - 1];
    if (!selected) throw new Error("Experiment phase contains no executable steps");
    return {
      ...selected.payload,
      http_status: selected.status,
      response_headers: selected.headers,
      steps: stepMap,
    };
  }

  function assertionsFor(config, run, moduleSpec, phase) {
    if (config.assertions && Array.isArray(config.assertions[phase])) return config.assertions[phase];
    if (Array.isArray(run.assertions)) return run.assertions;
    if (moduleSpec.assertions && Array.isArray(moduleSpec.assertions[phase])) {
      return moduleSpec.assertions[phase];
    }
    return [];
  }

  async function loadRunnerConfig(moduleSpec) {
    const url = new URL(moduleSpec.url, window.location.href);
    if (url.origin !== window.location.origin) throw new Error("Module URL is outside the local workbench");
    const response = await fetch(url, { credentials: "same-origin", headers: { Accept: "text/html" } });
    if (!response.ok) throw new Error(`Experiment page returned HTTP ${response.status}`);
    const page = new DOMParser().parseFromString(await response.text(), "text/html");
    const configNode = page.getElementById("lab-runner-config");
    if (!configNode) throw new Error("Experiment page did not provide #lab-runner-config");
    return JSON.parse(configNode.textContent);
  }

  function aggregateChecks(assertionResults) {
    return Object.fromEntries(CHECK_IDS.map((id) => {
      const relevant = assertionResults.filter((item) => item.id === id);
      if (!relevant.length) {
        return [id, {
          status: "error",
          passed: false,
          message: "No assertion was supplied for this acceptance claim.",
          assertions: [],
        }];
      }
      const passed = relevant.every((item) => item.passed);
      const failed = relevant.filter((item) => !item.passed);
      return [id, {
        status: passed ? "pass" : "fail",
        passed,
        message: passed
          ? relevant.map((item) => item.label).join(" · ")
          : failed.map((item) => `${item.label}: ${item.error || `observed ${JSON.stringify(item.actual)}`}`).join(" · "),
        assertions: relevant,
      }];
    }));
  }

  async function runModule(moduleSpec, suiteRunId) {
    const config = await loadRunnerConfig(moduleSpec);
    const runtimeValues = {
      suite_run_id: suiteRunId,
      comparison_run_id: `${suiteRunId}-${moduleSpec.id}`,
    };
    const phaseEvidence = {};
    const assertionResults = [];
    const setup = await prepareSetup(config.setup);

    for (const phase of PHASES) {
      const run = config.runs && config.runs[phase];
      if (!run || !Array.isArray(run.steps)) throw new Error(`Missing ${phase} run configuration`);
      const results = [];
      for (const step of run.steps) {
        results.push(await executeStep(step, runtimeValues));
      }
      const summary = buildSummary(run, results);
      const assertions = assertionsFor(config, run, moduleSpec, phase);
      assertions.forEach((assertion) => {
        const result = evaluateAssertion(assertion, summary);
        assertionResults.push({
          id: assertion.id,
          phase,
          label: assertion.label || assertion.id,
          operator: assertion.operator,
          path: assertion.path,
          expected: assertion.expected,
          ...result,
        });
      });
      phaseEvidence[phase] = {
        summary,
        steps: results,
      };
    }

    return {
      id: moduleSpec.id,
      owasp: moduleSpec.owasp,
      name: moduleSpec.name,
      status: "complete",
      setup,
      checks: aggregateChecks(assertionResults),
      phases: phaseEvidence,
    };
  }

  function cellFor(moduleId, checkId) {
    return document.querySelector(
      `[data-suite-row="${moduleId}"] [data-suite-cell="${checkId}"] .suite-cell`
    );
  }

  function setRowState(moduleId, state, message) {
    CHECK_IDS.forEach((checkId) => {
      const cell = cellFor(moduleId, checkId);
      cell.className = `suite-cell ${state}`;
      cell.textContent = state === "running" ? "Running" : state === "error" ? "Error" : "Not run";
      cell.title = message || "";
    });
  }

  function renderChecks(moduleResult) {
    CHECK_IDS.forEach((checkId) => {
      const check = moduleResult.checks[checkId];
      const cell = cellFor(moduleResult.id, checkId);
      cell.className = `suite-cell ${check.status}`;
      cell.textContent = check.status === "pass" ? "PASS" : check.status === "fail" ? "FAIL" : "ERROR";
      cell.title = check.message;
      cell.setAttribute("aria-label", `${checkId.replaceAll("_", " ")}: ${cell.textContent}. ${check.message}`);
    });
  }

  function resetMatrix() {
    manifest.modules.forEach((moduleSpec) => setRowState(moduleSpec.id, "pending", ""));
    progressNode.value = 0;
    progressNode.textContent = `0 of ${manifest.modules.length} modules`;
    errorNode.hidden = true;
    errorNode.textContent = "";
  }

  function countChecks(moduleResults) {
    const checks = moduleResults.flatMap((moduleResult) =>
      moduleResult.checks ? Object.values(moduleResult.checks) : []
    );
    return {
      total: manifest.modules.length * CHECK_IDS.length,
      passed: checks.filter((check) => check.status === "pass").length,
      failed: checks.filter((check) => check.status === "fail").length,
      errors: checks.filter((check) => check.status === "error").length +
        moduleResults.filter((moduleResult) => moduleResult.status === "error").length * CHECK_IDS.length,
    };
  }

  function visibleFailureSummary(moduleResults) {
    const messages = [];
    moduleResults.forEach((moduleResult) => {
      if (moduleResult.status === "error") {
        messages.push(`${moduleResult.owasp}: ${moduleResult.error}`);
        return;
      }
      Object.entries(moduleResult.checks).forEach(([checkId, check]) => {
        if (check.status !== "pass") {
          messages.push(`${moduleResult.owasp} ${checkId.replaceAll("_", " ")}: ${check.message}`);
        }
      });
    });
    const visible = messages.slice(0, 3).join(" · ");
    return messages.length > 3 ? `${visible} · ${messages.length - 3} more recorded in the evidence file.` : visible;
  }

  async function runSuite() {
    resetMatrix();
    runButton.disabled = true;
    downloadButton.disabled = true;
    runButton.textContent = "Running suite…";
    const runId = createRunId();
    const startedAt = new Date().toISOString();
    const moduleResults = [];
    runIdNode.textContent = `Run ID: ${runId}`;
    statusNode.textContent = "Running 0 of 10 modules";

    for (let index = 0; index < manifest.modules.length; index += 1) {
      const moduleSpec = manifest.modules[index];
      setRowState(moduleSpec.id, "running", "Executing real HTTP requests");
      statusNode.textContent = `Running ${index + 1} of ${manifest.modules.length}: ${moduleSpec.owasp}`;
      try {
        const result = await runModule(moduleSpec, runId);
        moduleResults.push(result);
        renderChecks(result);
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        moduleResults.push({
          id: moduleSpec.id,
          owasp: moduleSpec.owasp,
          name: moduleSpec.name,
          status: "error",
          error: message,
        });
        setRowState(moduleSpec.id, "error", message);
      }
      progressNode.value = index + 1;
      progressNode.textContent = `${index + 1} of ${manifest.modules.length} modules`;
    }

    let contextRestoreError = null;
    try {
      await restoreInitialIdentity();
    } catch (error) {
      contextRestoreError = error instanceof Error ? error.message : String(error);
    }

    const totals = countChecks(moduleResults);
    const completelyPassed =
      totals.passed === totals.total &&
      totals.failed === 0 &&
      totals.errors === 0 &&
      contextRestoreError === null;
    statusNode.textContent = completelyPassed
      ? `${totals.passed}/${totals.total} assertions passed`
      : `${totals.passed}/${totals.total} passed · ${totals.failed} failed · ${totals.errors} errors`;
    statusNode.className = completelyPassed ? "suite-status-pass" : "suite-status-fail";

    currentEvidence = sanitized({
      schema: "twinshop-assurance-evidence-v1",
      run_id: runId,
      started_at: startedAt,
      completed_at: new Date().toISOString(),
      outcome: completelyPassed ? "pass" : "fail",
      totals,
      modules: moduleResults,
    }, "");
    downloadButton.disabled = false;
    runButton.disabled = false;
    runButton.textContent = "Run again";

    if (!completelyPassed) {
      errorNode.hidden = false;
      const failureSummary = visibleFailureSummary(moduleResults);
      errorNode.textContent = `The suite did not pass. ${[failureSummary, contextRestoreError].filter(Boolean).join(" · ")}`;
    }
  }

  function downloadEvidence() {
    if (!currentEvidence) return;
    const blob = new Blob([JSON.stringify(currentEvidence, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `${currentEvidence.run_id}-evidence.json`;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
  }

  runButton.addEventListener("click", runSuite);
  downloadButton.addEventListener("click", downloadEvidence);
}());
