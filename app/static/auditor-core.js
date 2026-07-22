(function auditorCoreFactory(root, factory) {
  const api = factory();
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  root.TwinLabAuditorCore = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function buildAuditorCore() {
  "use strict";

  function buildSqlMutationCorpus(limit = 28) {
    const corpus = ["%' OR 1=1 --"];
    const prefixes = ["%'", "_'"];
    const operators = ["oR", "Or", "or"];
    const spacing = [" ", "/**/"];
    const conditions = ["1=1", "2>1"];
    const suffixes = ["/*", "--"];
    for (const prefix of prefixes) {
      for (const leftSpace of spacing) {
        for (const operator of operators) {
          for (const rightSpace of spacing) {
            for (const condition of conditions) {
              for (const suffix of suffixes) {
                corpus.push(
                  `${prefix}${leftSpace}${operator}${rightSpace}${condition}${leftSpace}${suffix}`,
                );
              }
            }
          }
        }
      }
    }
    return [...new Set(corpus)].slice(0, Math.max(1, limit));
  }

  function chooseShortestCounterexample(items, predicate) {
    return items
      .filter(predicate)
      .map((item, index) => ({ item, index }))
      .sort((left, right) => {
        const leftInput = String(left.item.input ?? left.item.sequence?.join(" → ") ?? "");
        const rightInput = String(right.item.input ?? right.item.sequence?.join(" → ") ?? "");
        return leftInput.length - rightInput.length || left.index - right.index;
      })[0]?.item ?? null;
  }

  function scanCanaries(response, canaries) {
    const hits = [];
    const bodyText = String(response.bodyText || "");
    const headers = response.headers || {};
    for (const canary of canaries) {
      if (bodyText.includes(canary)) hits.push({ channel: "body", canary });
      for (const [name, value] of Object.entries(headers)) {
        if (String(value).includes(canary)) {
          hits.push({ channel: `header:${name.toLowerCase()}`, canary });
        }
      }
    }
    return hits;
  }

  function summariseAuditResults(results) {
    const total = results.length;
    const detected = results.filter((result) => result.counterexample_found).length;
    const baselinePassed = results.filter((result) => result.baseline_passed).length;
    const robustHeld = results.filter((result) => result.robust_control_holds).length;
    const legitimatePreserved = results.filter(
      (result) => result.legitimate_use_preserved,
    ).length;
    return {
      total_seeded_defects: total,
      detected_seeded_defects: detected,
      baseline_passed: baselinePassed,
      robust_controls_held: robustHeld,
      legitimate_uses_preserved: legitimatePreserved,
      mutation_score_percent: total ? Math.round((detected / total) * 100) : 0,
    };
  }

  function buildAttackStory(moduleId, result) {
    const counterexample = result?.counterexample || {};
    const baseline = result?.baseline_passed ? "PASS" : "FAIL";
    const actual = result?.actual_replay_confirmed ? "confirmed" : "not confirmed";
    const robust = result?.robust_control_holds ? "invariant held" : "control failed";
    const legitimate = result?.legitimate_use_preserved ? "preserved" : "regressed";
    const commonReplay = [
      {
        title: "Replay the same confirmed case",
        evidence: `Real target replay ${actual}`,
      },
      {
        title: "Execute the Robust decision",
        evidence: `Robust result: ${robust}`,
      },
      {
        title: "Run a legitimate counterexample",
        evidence: `Normal business use: ${legitimate}`,
      },
    ];

    if (moduleId === "a05") {
      return {
        objective: "Return an internal-only product through the public search boundary.",
        steps: [
          {
            actor: "Attacker",
            title: "1. Probe the known guard",
            action: "Submit the original known input to the Candidate search.",
            evidence: `Known baseline ${baseline}; the Candidate returns a blocked response.`,
          },
          {
            actor: "Attacker",
            title: "2. Preserve meaning, change syntax",
            action: "Mutate keyword case, spacing, comment form and an equivalent boolean condition.",
            evidence: `Shortest confirmed mutation: ${counterexample.input || "none"}`,
          },
          {
            actor: "HTTP request",
            title: "3. Send the mutated search",
            action: "Deliver the selected mutation to the real Candidate target.",
            evidence: `Candidate HTTP ${counterexample.candidate_http ?? "—"}`,
          },
          {
            actor: "Candidate control",
            title: "4. Make the incomplete decision",
            action: "The case-sensitive guard sees none of its exact blocked tokens and allows the value into SQL construction.",
            evidence: result?.provenance?.[1]?.decision || "No decision event recorded.",
          },
          {
            actor: "Business boundary",
            title: "5. Observe the protected effect",
            action: "Inspect the returned product set instead of treating HTTP 200 alone as success.",
            evidence: counterexample.hidden_product_returned
              ? "Internal-only product returned: invariant violated."
              : "Protected product was not observed.",
          },
        ],
        replay: commonReplay,
      };
    }

    if (moduleId === "a07") {
      const state = counterexample.authoritative_state || {};
      return {
        objective: "Retrieve Admin data with a session that is no longer valid.",
        steps: [
          {
            actor: "Attacker",
            title: "1. Obtain a valid session capability",
            action: "Login through the synthetic Admin flow and retain the issued session capability.",
            evidence: state.token_fingerprint
              ? `Only fingerprint ${state.token_fingerprint} is displayed.`
              : "Synthetic session issued; token material remains redacted.",
          },
          {
            actor: "Lifecycle transition",
            title: "2. Move authoritative state",
            action: "Expire the session in the Observer plane while keeping the issued token string.",
            evidence: `Authoritative state: active=${state.active}, expired=${state.expired}`,
          },
          {
            actor: "Attacker",
            title: "3. Replay after expiry",
            action: "Present the retained capability to the Candidate Admin endpoint.",
            evidence: `Sequence: ${(counterexample.sequence || []).join(" → ") || "not recorded"}`,
          },
          {
            actor: "Candidate control",
            title: "4. Omit a required mediation check",
            action: "Check existence and active state, but do not compare the session expiry.",
            evidence: `expiry_checked=${counterexample.expiry_checked}`,
          },
          {
            actor: "Protected endpoint",
            title: "5. Observe privileged release",
            action: "Evaluate whether the response crosses the Admin-data boundary.",
            evidence: `Candidate HTTP ${counterexample.candidate_http ?? "—"}; Admin release confirmed.`,
          },
        ],
        replay: commonReplay,
      };
    }

    if (moduleId === "a01") {
      return {
        objective: "Read Bob's order while the signed application identity remains Alice.",
        steps: [
          {
            actor: "Attacker",
            title: "1. Start as authenticated Alice",
            action: "Keep the server-recognised signed session principal unchanged.",
            evidence: `Signed session principal: ${counterexample.signed_session || "—"}`,
          },
          {
            actor: "Attacker",
            title: "2. Manipulate the principal source",
            action: "Add a caller-controlled Bob identity while requesting Bob's order.",
            evidence: `Selected manipulation: ${counterexample.input || "—"}`,
          },
          {
            actor: "HTTP request",
            title: "3. Request protected object 202",
            action: "Send the manipulated request to the Candidate object endpoint.",
            evidence: `Candidate HTTP ${counterexample.candidate_http ?? "—"}`,
          },
          {
            actor: "Candidate control",
            title: "4. Evaluate a real owner predicate with the wrong principal",
            action: "Use the caller-supplied actor instead of the signed-session actor in the owner comparison.",
            evidence: `Decision actor: ${counterexample.request_actor || "—"}; session actor: ${counterexample.signed_session || "—"}`,
          },
          {
            actor: "Object boundary",
            title: "5. Observe cross-customer disclosure",
            action: "Inspect the returned owner rather than relying only on the status code.",
            evidence: `Returned owner: ${counterexample.returned_owner || "—"}; invariant violated.`,
          },
        ],
        replay: commonReplay,
      };
    }

    if (moduleId === "a02") {
      const channels = (counterexample.channels || [])
        .map((hit) => hit.channel)
        .join(", ");
      return {
        objective: "Recover internal diagnostics from a client-visible error response.",
        steps: [
          {
            actor: "Attacker",
            title: "1. Trigger a controlled failure",
            action: "Submit the selected invalid order reference without authentication.",
            evidence: `Failure input: ${counterexample.input || "—"}`,
          },
          {
            actor: "Candidate response",
            title: "2. Confirm the known body-only check",
            action: "Inspect the JSON body and observe a generic error with no body canary.",
            evidence: `Known baseline ${baseline}; generic body check passes.`,
          },
          {
            actor: "Attacker",
            title: "3. Expand inspection to the full response",
            action: "Read headers and other client-visible channels, not only the JSON body.",
            evidence: `Channels inspected; Candidate HTTP ${counterexample.candidate_http ?? "—"}`,
          },
          {
            actor: "Candidate middleware",
            title: "4. Cross the response boundary",
            action: "Attach operator diagnostics to response metadata after the body renderer has redacted the message.",
            evidence: result?.provenance?.[1]?.decision || "No middleware event recorded.",
          },
          {
            actor: "Client boundary",
            title: "5. Observe diagnostic disclosure",
            action: "Scan the complete response for fixed synthetic canaries.",
            evidence: channels
              ? `Confirmed client-visible channel(s): ${channels}`
              : "No client-visible canary observed.",
          },
        ],
        replay: commonReplay,
      };
    }

    return {
      objective: "Test the selected security invariant.",
      steps: [],
      replay: commonReplay,
    };
  }

  function pythonString(value) {
    return JSON.stringify(String(value)).replace(/\u2028|\u2029/g, "");
  }

  function buildRegressionTest(moduleId, counterexample) {
    if (!counterexample) return "# No confirmed counterexample was available.";
    if (moduleId === "a05") {
      return [
        "from urllib.parse import quote",
        "",
        "def test_generated_a05_counterexample(json_get):",
        `    payload = ${pythonString(counterexample.input)}`,
        '    response = json_get("/lab/a05/secure/search?q=" + quote(payload, safe=""))',
        '    assert response.status_code == 200',
        '    assert response.json["hidden_exposed"] is False',
      ].join("\n");
    }
    if (moduleId === "a01") {
      const actor = counterexample.request_actor || "bob";
      return [
        "def test_generated_a01_principal_override_is_ignored(client, json_get):",
        '    client.post("/identity/alice")',
        `    headers = {"X-TwinLab-Actor": ${pythonString(actor)}}`,
        '    response = json_get("/lab/a01/secure/orders/202", headers=headers)',
        '    assert response.status_code == 404',
        '    assert response.json["sensitive_data_returned"] is False',
      ].join("\n");
    }
    if (moduleId === "a02") {
      return [
        "def test_generated_a02_response_boundary_has_no_canary(json_get):",
        `    response = json_get("/lab/a02/secure/order-lookup?id=${encodeURIComponent(
          counterexample.input || "explode",
        )}")`,
        '    assert "X-TwinLab-Debug-Path" not in response.headers',
        '    assert "X-TwinLab-Debug-Config" not in response.headers',
      ].join("\n");
    }
    if (moduleId === "a07") {
      return [
        "def test_generated_a07_expired_session_is_rejected(json_get, json_post):",
        '    login = json_post("/lab/a07/secure/login",',
        '        data={"username": "admin", "password": "demo-admin"})',
        '    token = login.json["lab_token"]',
        '    json_post("/observer/a07/secure/expire-session",',
        '        headers={"X-TwinLab-Observer": "evidence-console", "X-Lab-Session": token})',
        '    response = json_get("/lab/a07/secure/admin",',
        '        headers={"X-Lab-Session": token})',
        '    assert response.status_code == 401',
        '    assert response.json["admin_data_returned"] is False',
      ].join("\n");
    }
    return "# Unsupported auditor module.";
  }

  function redactEvidence(value) {
    if (Array.isArray(value)) return value.map(redactEvidence);
    if (!value || typeof value !== "object") return value;
    const redacted = {};
    for (const [key, item] of Object.entries(value)) {
      const lower = key.toLowerCase();
      if (
        !lower.includes("fingerprint") &&
        (lower === "lab_token" ||
          lower === "token" ||
          lower.includes("password") ||
          lower.includes("observer_capability"))
      ) {
        redacted[key] = "[REDACTED]";
      } else {
        redacted[key] = redactEvidence(item);
      }
    }
    return redacted;
  }

  return {
    buildRegressionTest,
    buildAttackStory,
    buildSqlMutationCorpus,
    chooseShortestCounterexample,
    redactEvidence,
    scanCanaries,
    summariseAuditResults,
  };
});
