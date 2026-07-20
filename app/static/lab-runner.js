(function (root, factory) {
  "use strict";

  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  if (root && root.document) api.initialise(root.document, root);
}(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  const PHASES = ["vulnerable", "controlled", "legitimate"];
  const CONTRACT_IDS = [
    "vulnerability_reproduced",
    "control_effective",
    "authoritative_state_safe",
    "legitimate_use_preserved",
  ];

  function valueAtPath(value, path) {
    if (path === undefined || path === null || path === "") return value;
    return String(path).split(".").reduce((current, part) => {
      if (current === null || current === undefined) return undefined;
      return current[part];
    }, value);
  }

  function stableValue(value) {
    if (Array.isArray(value)) return value.map(stableValue);
    if (value && typeof value === "object") {
      return Object.fromEntries(
        Object.keys(value).sort().map((key) => [key, stableValue(value[key])])
      );
    }
    return value;
  }

  function valuesEqual(left, right) {
    return JSON.stringify(stableValue(left)) === JSON.stringify(stableValue(right));
  }

  function comparisonValues(assertion, record) {
    if (Array.isArray(assertion.path)) {
      if (assertion.path.length !== 2) {
        throw new Error("changed/unchanged assertions require exactly two evidence paths");
      }
      return {
        before: valueAtPath(record, assertion.path[0]),
        after: valueAtPath(record, assertion.path[1]),
      };
    }

    const actual = valueAtPath(record, assertion.path);
    if (assertion.expected && typeof assertion.expected === "object" && !Array.isArray(assertion.expected) && assertion.expected.path) {
      return { before: valueAtPath(record, assertion.expected.path), after: actual };
    }
    if (actual && typeof actual === "object" && "before" in actual && "after" in actual) {
      return { before: actual.before, after: actual.after };
    }
    return { before: assertion.expected, after: actual };
  }

  function evaluateAssertion(assertion, record, phase) {
    const operator = assertion.operator || "equals";
    const actual = valueAtPath(record, assertion.path);
    let passed = false;
    let evidence = actual;

    if (operator === "changed" || operator === "unchanged") {
      const values = comparisonValues(assertion, record);
      evidence = values;
      const complete = values.before !== undefined && values.after !== undefined;
      passed = complete && (operator === "changed"
        ? !valuesEqual(values.before, values.after)
        : valuesEqual(values.before, values.after));
    } else if (actual !== undefined) {
      switch (operator) {
        case "equals":
          passed = valuesEqual(actual, assertion.expected);
          break;
        case "not_equals":
          passed = !valuesEqual(actual, assertion.expected);
          break;
        case "truthy":
          passed = Boolean(actual);
          break;
        case "falsy":
          passed = !actual;
          break;
        case "in":
          passed = Array.isArray(assertion.expected) && assertion.expected.some((candidate) => valuesEqual(actual, candidate));
          break;
        default:
          throw new Error(`Unsupported assertion operator: ${operator}`);
      }
    }

    return {
      id: assertion.id,
      label: assertion.label || assertion.id,
      phase,
      path: assertion.path,
      operator,
      expected: assertion.expected,
      actual,
      evidence,
      passed,
      missing: actual === undefined && operator !== "changed" && operator !== "unchanged",
    };
  }

  function evaluateAssertions(assertions, record, phase) {
    return (assertions || []).map((assertion) => {
      try {
        return evaluateAssertion(assertion, record, phase);
      } catch (error) {
        return {
          id: assertion.id,
          label: assertion.label || assertion.id,
          phase,
          path: assertion.path,
          operator: assertion.operator,
          expected: assertion.expected,
          actual: undefined,
          evidence: undefined,
          passed: false,
          missing: true,
          error: error.message,
        };
      }
    });
  }

  function aggregateAssertionResults(allResults) {
    const grouped = {};
    allResults.forEach((result) => {
      if (!grouped[result.id]) grouped[result.id] = [];
      grouped[result.id].push(result);
    });
    return Object.fromEntries(Object.entries(grouped).map(([id, results]) => [id, {
      id,
      passed: results.length > 0 && results.every((result) => result.passed),
      label: results.length === 1
        ? results[0].label
        : `${results.length} executable checks`,
      evidence: results.map((result) => ({
        label: result.label,
        passed: result.passed,
        value: result.evidence,
        operator: result.operator,
        expected: result.expected,
      })),
    }]));
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

  function replaceLiteral(value, placeholder, replacement) {
    if (typeof value === "string") return value.split(placeholder).join(replacement);
    if (Array.isArray(value)) return value.map((item) => replaceLiteral(item, placeholder, replacement));
    if (value && typeof value === "object") {
      return Object.fromEntries(
        Object.entries(value).map(([key, item]) => [key, replaceLiteral(item, placeholder, replacement)])
      );
    }
    return value;
  }

  function applyInputControl(step, control, inputValue, phase) {
    if (!control || inputValue === undefined || inputValue === null) return step;
    const targets = control.target_steps || [];
    const qualifiedId = `${phase}.${step.id}`;
    if (targets.length && !targets.includes(step.id) && !targets.includes(qualifiedId) && !targets.includes(phase)) return step;

    const placeholder = control.placeholder || `{{${control.name || "input"}}}`;
    const encoded = (control.type === "path" || control.type === "query")
      ? encodeURIComponent(String(inputValue))
      : String(inputValue);
    return replaceLiteral(step, placeholder, encoded);
  }

  function makeRunId(browserRoot) {
    const cryptoApi = browserRoot && browserRoot.crypto;
    if (cryptoApi && typeof cryptoApi.randomUUID === "function") return cryptoApi.randomUUID();
    const random = Math.random().toString(36).slice(2, 10);
    return `run-${Date.now().toString(36)}-${random}`;
  }

  function invalidateSummaries(summaries, phases, fromIndex) {
    phases.slice(fromIndex).forEach((phase) => { delete summaries[phase]; });
    return summaries;
  }

  function summariesShareRun(summaries, phases, runId) {
    return Boolean(runId) && phases.every((phase) => summaries[phase] && summaries[phase].runId === runId);
  }

  function deriveAuthoritativeState(stepMap, selected) {
    const update = stepMap.update;
    const reset = stepMap.reset;
    if (!update || update.status !== 204 || !reset || !selected) return;

    const before = valueAtPath(reset, "payload.price_cents");
    const after = valueAtPath(selected, "payload.price_cents");
    if (before === undefined || after === undefined) return;

    update.payload = {
      ...update.payload,
      accepted: !valuesEqual(before, after),
      state_changed: !valuesEqual(before, after),
      before_price_cents: before,
      after_price_cents: after,
      evidence_source: "derived from the authoritative stored-price check after the HTTP 204 response",
    };
  }

  function buildSummary(run, results, runId, assertions, phase) {
    const stepMap = Object.fromEntries(results.map((result) => [result.id, {
      status: result.status,
      headers: result.headers,
      payload: { ...result.payload },
    }]));
    const selectedResult = results.find((result) => result.id === run.summary_step) || results[results.length - 1];
    const selected = selectedResult ? stepMap[selectedResult.id] : null;
    deriveAuthoritativeState(stepMap, selected);
    const record = selected ? {
      ...selected.payload,
      http_status: selected.status,
      response_headers: selected.headers,
      steps: stepMap,
    } : { steps: stepMap };

    return {
      runId,
      record,
      status: selected ? selected.status : 0,
      outcome: selected ? selected.payload.outcome || "response received" : "no response",
      observations: run.observations || [],
      assertions: evaluateAssertions(assertions, record, phase),
    };
  }

  function attackEvidenceForStep(result, path) {
    if (!result) {
      return {
        stepId: null,
        status: undefined,
        outcome: undefined,
        value: undefined,
        request: undefined,
      };
    }
    return {
      stepId: result.id,
      status: result.status,
      outcome: valueAtPath(result, "payload.outcome"),
      value: path ? valueAtPath(result, path) : undefined,
      request: result.request,
    };
  }

  function initialise(documentNode, browserRoot) {
    const configNode = documentNode.getElementById("lab-runner-config");
    if (!configNode) return null;

    const config = JSON.parse(configNode.textContent);
    const phaseSummaries = {};
    let comparisonRunId = null;
    let comparisonInputValue;
    let busy = false;
    let generation = 0;

    const getButton = (phase) => documentNode.querySelector(`[data-run-phase="${phase}"]`);
    const getOutput = (phase) => documentNode.querySelector(`[data-run-output="${phase}"]`);
    const getCard = (phase) => documentNode.querySelector(`[data-run-card="${phase}"]`);
    const getAdversaryRoot = () => documentNode.querySelector("[data-adversary-execution]");
    const getAdversaryButton = () => documentNode.querySelector("[data-run-adversary]");

    function fingerprint(value) {
      const text = String(value);
      if (text.length <= 12) return text;
      return `${text.slice(0, 8)}…${text.slice(-4)}`;
    }

    function safeDisplayValue(value, key, record) {
      if (key && (key === "lab_token" || key.endsWith(".lab_token"))) {
        return `synthetic token ${fingerprint(value)}`;
      }
      if (value === true) return "true";
      if (value === false) return "false";
      if (value === null) return "null";
      if (value === undefined) {
        return record && record.http_status === 204
          ? "No response body; use the stored-state evidence"
          : "Evidence field absent";
      }
      if (typeof value === "object") return JSON.stringify(value);
      return String(value);
    }

    function sanitizedPayload(value, key) {
      if (key === "lab_token" && typeof value === "string") {
        return `synthetic token ${fingerprint(value)}`;
      }
      if (Array.isArray(value)) return value.map((item) => sanitizedPayload(item, ""));
      if (value && typeof value === "object") {
        return Object.fromEntries(
          Object.entries(value).map(([childKey, childValue]) => [childKey, sanitizedPayload(childValue, childKey)])
        );
      }
      return value;
    }

    function safeHeaderValue(name, value) {
      const lower = name.toLowerCase();
      if (lower === "x-lab-session") return `synthetic token ${fingerprint(value)}`;
      if (lower === "x-twinlab-signature") return `signature ${fingerprint(value)}`;
      if (lower === "x-twinlab-observer") return "local observer capability";
      return value;
    }

    function sensitiveFieldName(name) {
      return /(?:password|token|signature|authorization|cookie|secret)/i.test(String(name));
    }

    function safeRequestBody(body) {
      if (!body) return "";
      try {
        const parsed = JSON.parse(body);
        return JSON.stringify(sanitizedPayload(parsed, ""), null, 2);
      } catch (_error) {
        const parameters = new URLSearchParams(body);
        if ([...parameters.keys()].length) {
          return [...parameters.entries()]
            .map(([key, value]) => `${key}=${sensitiveFieldName(key) ? "[redacted]" : value}`)
            .join("&");
        }
      }
      return body;
    }

    function escapeHtml(value) {
      return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
    }

    function adversaryStepNodes() {
      return [...documentNode.querySelectorAll("[data-adversary-step]")];
    }

    function adversaryNodesForEvidenceStep(stepId) {
      return adversaryStepNodes().filter(
        (node) => node.getAttribute("data-evidence-step") === stepId
      );
    }

    function setAdversaryStatus(state, label) {
      const rootNode = getAdversaryRoot();
      if (rootNode) rootNode.dataset.executionState = state;
      const labelNode = documentNode.querySelector("[data-adversary-status-label]");
      if (labelNode) labelNode.textContent = label;
    }

    function setAdversaryNodeState(node, state, label, evidence) {
      if (!node) return;
      node.dataset.stepState = state;
      const stateLabel = node.querySelector("[data-step-state-label]");
      if (stateLabel) stateLabel.textContent = label;
      const evidenceNode = node.querySelector("[data-step-evidence]");
      if (evidenceNode && evidence !== undefined) evidenceNode.textContent = evidence;
    }

    function resetAdversaryExecution() {
      setAdversaryStatus("idle", "Ready");
      adversaryStepNodes().forEach((node) => {
        setAdversaryNodeState(node, "idle", "Queued", "Evidence pending");
      });
      const liveNode = documentNode.querySelector("[data-adversary-live-evidence]");
      if (liveNode) {
        liveNode.textContent = "Run the path to attach response evidence.";
        delete liveNode.dataset.evidenceState;
      }
      const controlNode = documentNode.querySelector("[data-adversary-control-evidence]");
      if (controlNode) {
        controlNode.textContent = "Run the complete comparison to attach the controlled response.";
        delete controlNode.dataset.evidenceState;
      }
      const manipulationNode = documentNode.querySelector("[data-attack-manipulation] strong");
      if (manipulationNode && manipulationNode.dataset.defaultText) {
        manipulationNode.textContent = manipulationNode.dataset.defaultText;
      }
    }

    function beginAdversaryExecution(inputValue) {
      setAdversaryStatus("running", "Executing");
      adversaryStepNodes().forEach((node) => {
        if (node.hasAttribute("data-evidence-step")) {
          setAdversaryNodeState(node, "idle", "Queued", "Evidence pending");
        } else {
          setAdversaryNodeState(
            node,
            "completed",
            "Prepared",
            "Prepared from the fixed experiment conditions"
          );
        }
      });
      const manipulationNode = documentNode.querySelector("[data-attack-manipulation] strong");
      if (manipulationNode) {
        if (!manipulationNode.dataset.defaultText) {
          manipulationNode.dataset.defaultText = manipulationNode.textContent.trim();
        }
        manipulationNode.textContent = inputValue === undefined
          ? manipulationNode.dataset.defaultText
          : `${manipulationNode.dataset.defaultText} · Current input: ${inputValue}`;
      }
    }

    function beginAdversaryStep(stepId) {
      adversaryNodesForEvidenceStep(stepId).forEach((node) => {
        setAdversaryNodeState(node, "running", "Running", "Request in flight");
      });
    }

    function adversaryEvidenceText(result, node) {
      const path = node.getAttribute("data-evidence-path") || "";
      const evidence = attackEvidenceForStep(result, path);
      const valueText = evidence.value === undefined
        ? ""
        : ` · ${path}: ${safeDisplayValue(evidence.value, path, { http_status: evidence.status })}`;
      return `HTTP ${evidence.status} · ${evidence.outcome || "response received"}${valueText}`;
    }

    function attachAdversaryStepEvidence(result) {
      const nodes = adversaryNodesForEvidenceStep(result.id);
      nodes.forEach((node) => {
        setAdversaryNodeState(node, "completed", "Observed", adversaryEvidenceText(result, node));
      });
      if (!nodes.length || !result.request || !result.request.includes("/lab/")) return;
      const liveNode = documentNode.querySelector("[data-adversary-live-evidence]");
      if (liveNode) {
        const requestLine = result.request.split("\n")[0];
        liveNode.textContent = `${requestLine} → HTTP ${result.status} · ${result.payload.outcome || "response received"}`;
        liveNode.dataset.evidenceState = "attached";
      }
    }

    function refreshAdversaryEvidenceFromSummary(summary, results) {
      adversaryStepNodes().forEach((node) => {
        const stepId = node.getAttribute("data-evidence-step");
        if (!stepId) return;
        const summaryStep = valueAtPath(summary, `record.steps.${stepId}`);
        if (!summaryStep) return;
        const original = results.find((result) => result.id === stepId);
        attachAdversaryStepEvidence({
          id: stepId,
          status: summaryStep.status,
          headers: summaryStep.headers,
          payload: summaryStep.payload,
          request: original && original.request,
        });
      });
    }

    function finishAdversaryExecution(summary, results) {
      refreshAdversaryEvidenceFromSummary(summary, results);
      const vulnerabilityResult = summary.assertions.find(
        (result) => result.id === "vulnerability_reproduced"
      );
      setAdversaryStatus(
        vulnerabilityResult && vulnerabilityResult.passed ? "completed" : "failed",
        vulnerabilityResult && vulnerabilityResult.passed ? "Attack observed" : "Attack not proven"
      );
    }

    function attachControlledInterception(summary, results) {
      const node = documentNode.querySelector("[data-adversary-control-evidence]");
      if (!node) return;
      const mappedIds = new Set(
        adversaryStepNodes()
          .map((stepNode) => stepNode.getAttribute("data-evidence-step"))
          .filter(Boolean)
      );
      const decisive = [...results].reverse().find(
        (result) => mappedIds.has(result.id) && result.request && result.request.includes("/lab/")
      ) || results[results.length - 1];
      const assertion = summary.assertions.find((result) => result.id === "control_effective");
      const assertionText = assertion
        ? `${assertion.label}: ${assertion.passed ? "PASS" : "FAIL"} · observed ${safeDisplayValue(assertion.evidence)}`
        : "No control assertion was evaluated";
      const requestLine = decisive && decisive.request
        ? decisive.request.split("\n")[0]
        : "Controlled replay";
      node.textContent = `${requestLine} → HTTP ${decisive ? decisive.status : summary.status} · ${assertionText}`;
      node.dataset.evidenceState = assertion && assertion.passed ? "attached" : "error";
    }

    function failAdversaryExecution(error) {
      setAdversaryStatus("error", "Execution error");
      const liveNode = documentNode.querySelector("[data-adversary-live-evidence]");
      if (liveNode) {
        liveNode.textContent = error.message;
        liveNode.dataset.evidenceState = "error";
      }
    }

    async function prepareSetup() {
      if (!config.setup) return;
      const method = (config.setup.method || "GET").toUpperCase();
      const options = { method, credentials: "same-origin" };
      if (method === "POST") {
        options.headers = { "Content-Type": "application/x-www-form-urlencoded" };
        options.body = new URLSearchParams(config.setup.fields || {});
      }
      const response = await browserRoot.fetch(config.setup.url, options);
      if (!response.ok) throw new Error(`Identity setup failed with HTTP ${response.status}`);
      if (config.setup.actor) {
        documentNode.querySelectorAll("[data-current-actor], [data-current-actor-display]")
          .forEach((actorNode) => { actorNode.textContent = config.setup.actor; });
      }
    }

    function requestText(method, url, headers, body) {
      const parsed = new URL(url, browserRoot.location.href);
      const lines = [`${method} ${parsed.pathname}${parsed.search}`];
      Object.entries(headers).forEach(([name, value]) => {
        if (name.toLowerCase() !== "accept") lines.push(`${name}: ${safeHeaderValue(name, value)}`);
      });
      if (body) lines.push("", safeRequestBody(body));
      return lines.join("\n");
    }

    async function executeStep(step, runtimeValues) {
      const resolved = resolveTemplates(step, runtimeValues);
      const url = new URL(resolved.url, browserRoot.location.href);
      url.searchParams.set("format", "json");
      url.searchParams.set("comparison_run_id", comparisonRunId);
      const method = (resolved.method || "GET").toUpperCase();
      const headers = {
        Accept: "application/json",
        "X-TwinLab-Run-Id": comparisonRunId,
        ...(resolved.headers || {}),
      };
      const options = { method, credentials: "same-origin", headers };
      let bodyText = "";
      if (resolved.raw_body !== undefined) {
        bodyText = resolved.raw_body;
        options.body = resolved.raw_body;
        if (!headers["Content-Type"]) headers["Content-Type"] = "application/json";
      } else if (method === "POST") {
        headers["Content-Type"] = "application/x-www-form-urlencoded";
        const formBody = new URLSearchParams(resolved.fields || {});
        bodyText = formBody.toString();
        options.body = formBody;
      }

      const response = await browserRoot.fetch(url, options);
      const raw = await response.text();
      const responseHeaders = {};
      response.headers.forEach((value, name) => { responseHeaders[name.toLowerCase()] = value; });
      let payload;
      if (!raw) {
        payload = { outcome: response.status === 204 ? "request completed with no response body" : "empty response" };
      } else {
        try {
          payload = JSON.parse(raw);
        } catch (_error) {
          throw new Error(`${resolved.label}: expected JSON but received a non-JSON response.`);
        }
      }
      if (url.pathname.startsWith("/identity/") && payload.actor) {
        documentNode.querySelectorAll("[data-current-actor], [data-current-actor-display]")
          .forEach((actorNode) => { actorNode.textContent = payload.actor; });
      }

      Object.entries(resolved.capture || {}).forEach(([runtimeName, payloadPath]) => {
        const captured = valueAtPath(payload, payloadPath);
        if (captured === undefined) throw new Error(`${resolved.label}: response did not contain ${payloadPath}`);
        runtimeValues[runtimeName] = captured;
      });

      return {
        id: resolved.id,
        label: resolved.label,
        status: response.status,
        payload,
        headers: responseHeaders,
        request: requestText(method, url.toString(), headers, bodyText),
        observations: resolved.observations || [],
      };
    }

    function observationGrid(observations, record) {
      return observations.map((item) => {
        const value = valueAtPath(record, item.key);
        const valueClass = value === true ? "value-true" : value === false ? "value-false" : "";
        return `<div><dt>${escapeHtml(item.label)}</dt><dd class="${valueClass}">${escapeHtml(safeDisplayValue(value, item.key, record))}</dd></div>`;
      }).join("");
    }

    function stepRecord(result) {
      return {
        ...result.payload,
        http_status: result.status,
        response_headers: result.headers,
      };
    }

    function renderTrace(results, pendingLabel) {
      const completed = results.map((result, index) => `
        <article class="trace-step">
          <header><span>${index + 1}</span><strong>${escapeHtml(result.label)}</strong></header>
          <pre class="trace-request">${escapeHtml(result.request)}</pre>
          <div class="trace-response">
            <span>HTTP ${result.status}</span>
            <strong>${escapeHtml(result.payload.outcome || "response received")}</strong>
          </div>
          ${result.observations.length ? `<dl class="inline-observations">${observationGrid(result.observations, stepRecord(result))}</dl>` : ""}
          <details class="inline-raw">
            <summary>Response evidence</summary>
            <pre>${escapeHtml(JSON.stringify({ status: result.status, headers: result.headers, body: sanitizedPayload(result.payload, "") }, null, 2))}</pre>
          </details>
        </article>`).join("");
      const pending = pendingLabel ? `<p class="trace-progress">Running: ${escapeHtml(pendingLabel)}</p>` : "";
      return `<div class="request-trace">${completed}${pending}</div>`;
    }

    function assertionEvidence(result) {
      const value = result.evidence;
      if (Array.isArray(value)) {
        const rendered = value.map((item) => {
          const itemValue = item.value && typeof item.value === "object" && "before" in item.value && "after" in item.value
            ? `${safeDisplayValue(item.value.before)} → ${safeDisplayValue(item.value.after)}`
            : safeDisplayValue(item.value);
          const expectation = ["equals", "not_equals", "in"].includes(item.operator)
            ? `; expected ${item.operator === "not_equals" ? "not " : ""}${safeDisplayValue(item.expected)}`
            : "";
          return { label: item.label, text: `observed ${itemValue}${expectation}` };
        });
        if (rendered.length === 1) {
          return `${rendered[0].text.charAt(0).toUpperCase()}${rendered[0].text.slice(1)}`;
        }
        return rendered.map((item) => `${item.label}: ${item.text}`).join(" · ");
      }
      if (value && typeof value === "object" && "before" in value && "after" in value) {
        return `${safeDisplayValue(value.before)} → ${safeDisplayValue(value.after)}`;
      }
      return safeDisplayValue(value);
    }

    function renderContractResults(allResults) {
      const byId = aggregateAssertionResults(allResults);
      documentNode.querySelectorAll("[data-verdict-assertion]").forEach((node) => {
        const id = node.getAttribute("data-verdict-assertion");
        const result = byId[id];
        node.dataset.outcome = result ? (result.passed ? "pass" : "fail") : "not-evaluated";
        node.innerHTML = result
          ? `<span>${escapeHtml(result.label)}</span><strong>${result.passed ? "PASS" : "FAIL"}</strong><p>${escapeHtml(assertionEvidence(result))}</p>`
          : `<span>${escapeHtml(id.replaceAll("_", " "))}</span><strong>NOT EVALUATED</strong><p>No executable assertion was configured.</p>`;
      });

      const overallNode = documentNode.querySelector("[data-overall-verdict]");
      if (!overallNode) return;
      const required = CONTRACT_IDS.map((id) => byId[id]);
      if (required.some((result) => !result)) {
        overallNode.dataset.outcome = "not-evaluated";
        overallNode.textContent = "Contract incomplete";
      } else if (required.every((result) => result.passed)) {
        overallNode.dataset.outcome = "pass";
        overallNode.textContent = "All four security claims verified";
      } else {
        overallNode.dataset.outcome = "fail";
        overallNode.textContent = "One or more security claims failed";
      }
    }

    function businessEvidenceHtml(phase, summary) {
      const record = summary.record || {};
      const status = summary.status;
      const statusLine = `<span class="business-http">HTTP ${status}</span>`;
      if (config.lab_id === "a01") {
        if (record.order) {
          return `${statusLine}<strong>Order #${escapeHtml(record.order.id)} · ${escapeHtml(record.order.owner)}</strong>
            <p>${escapeHtml(record.order.item)} · ${escapeHtml(record.order.shipping_address)} · $${escapeHtml((record.order.total_cents / 100).toFixed(2))}</p>
            <small>${record.authorized ? "Owner access allowed" : "Cross-owner customer data returned"}</small>`;
        }
        return `${statusLine}<strong>Order data withheld</strong><p>The ownership-constrained lookup returned no cross-customer record.</p>`;
      }
      if (config.lab_id === "a02") {
        if (record.internal_details_returned) {
          return `${statusLine}<strong>Customer received internal diagnostics</strong><p>${escapeHtml(record.synthetic_path || "internal path")} · ${escapeHtml(record.synthetic_config || "configuration marker")}</p>`;
        }
        const eventFound = valueAtPath(record, "steps.audit.payload.event_found");
        return `${statusLine}<strong>${escapeHtml(record.error_code || summary.outcome)}</strong><p>${escapeHtml(record.message || "Normal order lookup completed")}</p>
          ${eventFound === true ? "<small>Observer: correlated minimised event found</small>" : ""}`;
      }
      if (config.lab_id === "a05") {
        const products = Array.isArray(record.products) ? record.products : [];
        const productRows = products.length
          ? products.map((product) => `<li class="${product.is_public ? "" : "internal-product"}"><strong>${escapeHtml(product.name)}</strong><span>${product.is_public ? "Public" : "Internal-only"}</span></li>`).join("")
          : "<li><span>No matching public products</span></li>";
        return `${statusLine}<strong>${record.hidden_exposed ? "Internal catalogue row exposed" : "Public catalogue boundary preserved"}</strong><ul class="business-product-list">${productRows}</ul>`;
      }
      if (config.lab_id === "a07") {
        if (phase === "legitimate") {
          return `${statusLine}<strong>Fresh Admin session accepted</strong>
            <p>${escapeHtml(record.username || "admin")} reached the protected dashboard with newly issued server-side state.</p>`;
        }
        const replay = valueAtPath(record, "steps.replay.status");
        const fresh = valueAtPath(record, "steps.fresh_admin.status") || status;
        const expired = valueAtPath(record, "steps.expired_admin.status");
        const random = valueAtPath(record, "steps.random_admin.status");
        const decisions = [
          ["Old token after logout", replay],
          ["Fresh token", fresh],
          ...(expired === undefined ? [] : [["Expired token", expired]]),
          ...(random === undefined ? [] : [["Unknown token", random]]),
        ];
        return `${statusLine}<strong>Session decision matrix</strong><dl class="session-decision-list">${decisions.map(([label, value]) => `<div><dt>${escapeHtml(label)}</dt><dd>HTTP ${escapeHtml(value)}</dd></div>`).join("")}</dl>`;
      }
      if (config.lab_id === "a08") {
        const updateStatus = valueAtPath(record, "steps.update.status");
        const storedPrice = record.price_cents;
        const heading = phase === "vulnerable"
          ? "Tampered price became authoritative"
          : phase === "controlled"
            ? "Tampered message rejected before mutation"
            : "Exact signed message accepted";
        return `<span class="business-http">UPDATE HTTP ${escapeHtml(updateStatus)}</span>
          <strong>${heading}</strong>
          <dl class="business-observations">
            <div><dt>Stored price</dt><dd>${escapeHtml(storedPrice)} cents</dd></div>
            <div><dt>Observer plane</dt><dd>HTTP ${escapeHtml(status)}</dd></div>
          </dl>`;
      }
      const observations = summary.observations || [];
      return `${statusLine}<strong>${escapeHtml(summary.outcome)}</strong>${observations.length ? `<dl class="business-observations">${observationGrid(observations.slice(0, 4), record)}</dl>` : ""}`;
    }

    function renderBusinessEvidence(phase, summary) {
      const node = documentNode.querySelector(`[data-business-result="${phase}"]`);
      if (!node) return;
      node.dataset.outcome = summary.assertions.length && summary.assertions.every((result) => result.passed)
        ? "pass"
        : (phase === "vulnerable" ? "vulnerable" : "review");
      node.innerHTML = `<span class="business-result-label">Live target outcome</span>${businessEvidenceHtml(phase, summary)}`;
    }

    function renderVerdict() {
      if (!summariesShareRun(phaseSummaries, PHASES, comparisonRunId)) return;
      const container = documentNode.querySelector("[data-comparison-verdict]");
      if (!container) return;
      const labels = {
        vulnerable: "Vulnerable attack",
        controlled: "Equivalent attack + control",
        legitimate: "Legitimate use",
      };
      const allAssertionResults = [];
      PHASES.forEach((phase) => {
        const summary = phaseSummaries[phase];
        allAssertionResults.push(...summary.assertions);
        const card = documentNode.querySelector(`[data-verdict-phase="${phase}"]`);
        if (!card) return;
        const assertionSummary = summary.assertions.length
          ? summary.assertions.map((result) => `${result.passed ? "PASS" : "FAIL"} · ${escapeHtml(result.label)}`).join("<br>")
          : `HTTP ${summary.status} · ${escapeHtml(summary.outcome)}`;
        card.dataset.outcome = summary.assertions.length
          ? (summary.assertions.every((result) => result.passed) ? "pass" : "fail")
          : "not-evaluated";
        card.dataset.runId = summary.runId;
        card.innerHTML = `
          <span>${escapeHtml(labels[phase])}</span>
          <strong>${assertionSummary}</strong>
          <dl>${observationGrid(summary.observations, summary.record)}</dl>`;
      });
      renderContractResults(allAssertionResults);
      const runIdNode = documentNode.querySelector("[data-comparison-run-id]");
      if (runIdNode) runIdNode.textContent = comparisonRunId;
      container.dataset.runId = comparisonRunId;
      container.hidden = false;
    }

    function clearPhaseDisplay(phase) {
      const card = getCard(phase);
      const output = getOutput(phase);
      if (card) card.classList.remove("completed", "running");
      if (output) {
        output.classList.remove("has-result");
        output.innerHTML = '<p class="output-placeholder">The actual requests, responses and state checks will appear here.</p>';
      }
      const businessResult = documentNode.querySelector(`[data-business-result="${phase}"]`);
      if (businessResult) {
        delete businessResult.dataset.outcome;
        businessResult.innerHTML = '<span class="business-result-label">Target view</span><p>Run this phase to populate the live TwinShop outcome.</p>';
      }
    }

    function hideVerdict() {
      const verdict = documentNode.querySelector("[data-comparison-verdict]");
      if (verdict) {
        verdict.hidden = true;
        delete verdict.dataset.runId;
      }
    }

    function refreshButtons() {
      PHASES.forEach((phase, index) => {
        const button = getButton(phase);
        if (!button) return;
        const prerequisiteMet = index === 0 || Boolean(phaseSummaries[PHASES[index - 1]]);
        button.disabled = busy || !prerequisiteMet;
      });
      const adversaryButton = getAdversaryButton();
      if (adversaryButton) adversaryButton.disabled = busy;
    }

    function invalidateFrom(index) {
      generation += 1;
      invalidateSummaries(phaseSummaries, PHASES, index);
      PHASES.slice(index).forEach(clearPhaseDisplay);
      hideVerdict();
    }

    function renderError(phase, error, completedResults) {
      const output = getOutput(phase);
      if (!output) return;
      output.innerHTML = renderTrace(completedResults, "") +
        `<p class="runner-error"><strong>Runner error</strong><br>${escapeHtml(error.message)}</p>`;
      output.classList.add("has-result");
    }

    function configuredAssertions(phase, run) {
      return run.assertions || (config.assertions && config.assertions[phase]) || [];
    }

    function readAttackInput(phase) {
      if (!config.input_control) return undefined;
      if (phase !== "vulnerable" && comparisonInputValue !== undefined) return comparisonInputValue;
      const node = documentNode.querySelector("[data-attack-input]");
      return node ? node.value : undefined;
    }

    async function runPhase(phase) {
      if (busy) return;
      const index = PHASES.indexOf(phase);
      if (index < 0 || (index > 0 && !phaseSummaries[PHASES[index - 1]])) return;

      const button = getButton(phase);
      const output = getOutput(phase);
      const card = getCard(phase);
      if (!button || !output || !card) return;
      const originalLabel = button.textContent;
      const results = [];
      const runtimeValues = {};
      const inputValue = readAttackInput(phase);

      invalidateFrom(index);
      if (phase === "vulnerable") {
        comparisonRunId = makeRunId(browserRoot);
        comparisonInputValue = inputValue;
        beginAdversaryExecution(inputValue);
      }
      const runIdNode = documentNode.querySelector("[data-comparison-run-id]");
      if (runIdNode) runIdNode.textContent = comparisonRunId;
      const runGeneration = generation;
      busy = true;
      refreshButtons();
      button.textContent = "Running…";
      card.classList.add("running");
      output.classList.add("has-result");
      try {
        // Re-establish the configured actor before every phase.  A comparison
        // must not inherit an identity changed in another tab between runs.
        await prepareSetup();
        const run = config.runs[phase];
        for (const originalStep of run.steps) {
          if (runGeneration !== generation) throw new Error("This result was superseded by a newer comparison run.");
          const step = applyInputControl(originalStep, config.input_control, comparisonInputValue, phase);
          if (phase === "vulnerable") beginAdversaryStep(step.id);
          output.innerHTML = renderTrace(results, step.label);
          const result = await executeStep(step, runtimeValues);
          if (runGeneration !== generation) return;
          results.push(result);
          if (phase === "vulnerable") attachAdversaryStepEvidence(result);
          output.innerHTML = renderTrace(results, "");
        }
        if (runGeneration !== generation) return;
        phaseSummaries[phase] = buildSummary(
          run,
          results,
          comparisonRunId,
          configuredAssertions(phase, run),
          phase
        );
        renderBusinessEvidence(phase, phaseSummaries[phase]);
        if (phase === "vulnerable") {
          finishAdversaryExecution(phaseSummaries[phase], results);
        } else if (phase === "controlled") {
          attachControlledInterception(phaseSummaries[phase], results);
        }
        card.classList.add("completed");
        renderVerdict();
      } catch (error) {
        delete phaseSummaries[phase];
        renderError(phase, error, results);
        if (phase === "vulnerable") failAdversaryExecution(error);
      } finally {
        card.classList.remove("running");
        busy = false;
        button.textContent = originalLabel;
        refreshButtons();
      }
    }

    PHASES.forEach((phase) => {
      const button = getButton(phase);
      if (button) button.addEventListener("click", () => runPhase(phase));
    });

    const adversaryButton = getAdversaryButton();
    if (adversaryButton) adversaryButton.addEventListener("click", async () => {
      if (busy) return;
      const originalLabel = adversaryButton.textContent;
      adversaryButton.textContent = "Executing attack…";
      try {
        await runPhase("vulnerable");
      } finally {
        adversaryButton.textContent = originalLabel;
      }
    });

    const resetButton = documentNode.querySelector("[data-reset-comparison]");
    if (resetButton) resetButton.addEventListener("click", () => {
      generation += 1;
      invalidateSummaries(phaseSummaries, PHASES, 0);
      PHASES.forEach(clearPhaseDisplay);
      comparisonRunId = null;
      comparisonInputValue = undefined;
      hideVerdict();
      resetAdversaryExecution();
      refreshButtons();
    });

    const runAllButton = documentNode.querySelector("[data-run-all-phases]");
    if (runAllButton) runAllButton.addEventListener("click", async () => {
      if (busy) return;
      runAllButton.disabled = true;
      const originalLabel = runAllButton.textContent;
      runAllButton.textContent = "Running comparison…";
      generation += 1;
      invalidateSummaries(phaseSummaries, PHASES, 0);
      PHASES.forEach(clearPhaseDisplay);
      comparisonRunId = null;
      comparisonInputValue = undefined;
      hideVerdict();
      try {
        for (const phase of PHASES) await runPhase(phase);
      } finally {
        runAllButton.disabled = false;
        runAllButton.textContent = originalLabel;
      }
    });

    refreshButtons();
    return { runPhase, phaseSummaries };
  }

  return {
    PHASES,
    CONTRACT_IDS,
    valueAtPath,
    evaluateAssertion,
    evaluateAssertions,
    aggregateAssertionResults,
    applyInputControl,
    makeRunId,
    invalidateSummaries,
    summariesShareRun,
    buildSummary,
    attackEvidenceForStep,
    initialise,
  };
}));
