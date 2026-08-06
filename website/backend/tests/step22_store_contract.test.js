const test = require("node:test");
const assert = require("node:assert/strict");

const { insertEvent } = require("../event_store");
const { insertIDSResult } = require("../ids_result_store");

function insertOnlyDatabase(calls) {
  return {
    run(sql, params, callback) {
      calls.push({ sql, params });
      callback.call({ changes: 1, lastID: 1 }, null);
    },
  };
}

test("Step 22 event insert records an IST receive time", async () => {
  const calls = [];
  const record = {
    schema_version: "1.0",
    event_id: "9f7648bc-6797-4db1-b50a-71bb288c2001",
    timestamp: "2026-08-03T17:30:00.000+05:30",
    source_ip: "127.0.0.1",
    source_port: 49152,
    destination_port: 8080,
    service: "http",
    protocol: "http",
    event_type: "attack",
    event: "http_login_sql_injection",
    attack_type: "sql_injection",
    severity: "critical",
    status: "detected",
    username: null,
    session_id: null,
    request_method: "POST",
    request_path: "/login",
    payload: null,
    metadata: {},
  };

  await insertEvent(insertOnlyDatabase(calls), record);
  assert.equal(calls.length, 1);
  assert.equal(
    (calls[0].sql.match(/\?/g) || []).length,
    calls[0].params.length
  );
  assert.match(calls[0].params.at(-1), /\+05:30$/);
});

test("Step 22 IDS insert stores agent output and an IST receive time", async () => {
  const calls = [];
  const record = {
    ids_result_schema_version: "1.0",
    hybrid_ids_version: "1.2",
    event_id: "9f7648bc-6797-4db1-b50a-71bb288c2002",
    processed_at: "2026-08-03T17:30:01.000+05:30",
    timestamp: "2026-08-03T17:30:00.000+05:30",
    source_ip: "127.0.0.1",
    destination_port: 8080,
    service: "http",
    event_type: "attack",
    event: "http_login_sql_injection",
    status: "detected",
    request_method: "POST",
    request_path: "/login",
    attack_type: "sql_injection",
    prediction: "attack",
    confidence: 0.96,
    anomaly_score: 0.02,
    model_used: "rules",
    threat_reporting_version: "1.0",
    threat_level: "Critical",
    threat_score: 94,
    threat_factors: [],
    components: {},
    fusion_reason: "deterministic rule matched",
    xai: {
      shap: {},
      human_reason: { summary: "Sanitized SQL pattern matched." },
      privacy: {
        raw_payload_included: false,
        source_ip_included: false,
        credentials_included: false,
      },
    },
    safety: {
      model_fit_called: false,
      protected_artifacts_modified: false,
      xai_changed_prediction: false,
    },
    integration: {
      raw_payload_included: false,
      credentials_included: false,
      producer_attack_type_used_as_prediction: false,
    },
    agents: {
      agent_pipeline_version: "1.0",
      safety: {
        original_prediction_changed: false,
        original_threat_level_changed: false,
        original_xai_changed: false,
        host_firewall_changed: false,
        raw_payload_included: false,
        credentials_included: false,
      },
    },
  };

  await insertIDSResult(insertOnlyDatabase(calls), record);
  assert.equal(calls.length, 1);
  assert.equal(
    (calls[0].sql.match(/\?/g) || []).length,
    calls[0].params.length
  );
  assert.equal(JSON.parse(calls[0].params.at(-2)).agent_pipeline_version, "1.0");
  assert.match(calls[0].params.at(-1), /\+05:30$/);
});
