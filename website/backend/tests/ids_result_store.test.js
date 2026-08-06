const test = require("node:test");
const assert = require("node:assert/strict");
const sqlite3 = require("sqlite3").verbose();

const {
  getIDSResultStats,
  initializeIDSResultStore,
  insertIDSResult,
  listIDSResults,
  validateIDSResult,
} = require("../ids_result_store");

function sampleIDSResult(overrides = {}) {
  return {
    ids_result_schema_version: "1.0",
    hybrid_ids_version: "1.2",
    event_id: "9f7648bc-6797-4db1-b50a-71bb288c1001",
    processed_at: "2026-07-28T08:15:01+00:00",
    timestamp: "2026-07-28T08:15:00+00:00",
    source_ip: "127.0.0.1",
    destination_port: 8080,
    service: "http",
    event_type: "attack",
    event: "http_search_sql_injection",
    status: "detected",
    request_method: "GET",
    request_path: "/search",
    attack_type: "sql_injection",
    prediction: "attack",
    confidence: 0.93,
    anomaly_score: 0.04,
    model_used: "rules",
    threat_reporting_version: "1.0",
    threat_level: "Critical",
    threat_score: 91,
    threat_factors: [{ factor: "attack_type", points: 45 }],
    components: {
      rules: { finding_count: 1, findings: [] },
      tabular: {
        model: "decision_tree",
        attack_type: "normal",
        confidence: 0.8,
      },
      sequence: {
        model: "lstm_classifier",
        attack_type: "normal",
        confidence: 0.8,
        context_events: 1,
        sequence_length: 10,
      },
      anomaly: {
        model: "isolation_forest",
        is_anomaly: false,
        anomaly_score: 0.04,
      },
    },
    fusion_reason: "deterministic rule matched",
    xai: {
      xai_version: "1.0",
      lime_used: false,
      shap: { status: "ready", top_features: [] },
      human_reason: { summary: "A sanitized SQL pattern matched." },
      privacy: {
        raw_payload_included: false,
        source_ip_included: false,
        credentials_included: false,
      },
      safety: {
        prediction_changed: false,
        model_fit_called: false,
        artifact_written: false,
      },
    },
    safety: {
      model_fit_called: false,
      protected_artifacts_modified: false,
      producer_attack_type_used_as_model_feature: false,
      raw_payload_in_result: false,
      future_events_used: false,
      xai_changed_prediction: false,
    },
    integration: {
      source: "live_common_event",
      raw_payload_included: false,
      credentials_included: false,
      producer_attack_type_used_as_prediction: false,
    },
    agents: {
      agent_pipeline_version: "1.0",
      run_order: [
        "detection",
        "correlation",
        "severity",
        "explanation",
        "response",
        "daily_report",
      ],
      safety: {
        original_prediction_changed: false,
        original_threat_level_changed: false,
        original_xai_changed: false,
        model_fit_called: false,
        host_firewall_changed: false,
        raw_payload_included: false,
        credentials_included: false,
      },
    },
    ...overrides,
  };
}

function closeDatabase(database) {
  return new Promise((resolve, reject) => {
    database.close((error) => (error ? reject(error) : resolve()));
  });
}

test("IDS store validates, deduplicates, filters and summarizes results", async () => {
  const database = new sqlite3.Database(":memory:");
  initializeIDSResultStore(database);

  try {
    const result = sampleIDSResult();
    assert.deepEqual(validateIDSResult(result), []);

    const inserted = await insertIDSResult(database, result);
    assert.equal(inserted.inserted, true);
    assert.ok(inserted.id > 0);

    const duplicate = await insertIDSResult(database, result);
    assert.equal(duplicate.inserted, false);
    assert.equal(duplicate.id, inserted.id);

    const second = sampleIDSResult({
      event_id: "9f7648bc-6797-4db1-b50a-71bb288c1002",
      processed_at: "2026-07-28T08:16:01+00:00",
      timestamp: "2026-07-28T08:16:00+00:00",
      destination_port: 2222,
      service: "ssh",
      event_type: "authentication",
      event: "ssh_login_attempt",
      request_method: null,
      request_path: null,
      attack_type: "normal",
      prediction: "normal",
      confidence: 0.88,
      threat_level: "Low",
      threat_score: 0,
      model_used: "decision_tree+lstm_classifier",
    });
    await insertIDSResult(database, second);

    const httpResults = await listIDSResults(database, {
      service: "http",
      prediction: "attack",
      threatLevel: "Critical",
      limit: 10,
    });
    assert.equal(httpResults.length, 1);
    assert.equal(httpResults[0].event_id, result.event_id);
    assert.equal(httpResults[0].xai.shap.status, "ready");
    assert.equal(httpResults[0].agents.agent_pipeline_version, "1.0");
    assert.match(httpResults[0].received_at, /\+05:30$/);
    assert.deepEqual(httpResults[0].threat_factors, result.threat_factors);

    const stats = await getIDSResultStats(database);
    assert.equal(stats.total_results, 2);
    assert.equal(stats.attacks_detected, 1);
    assert.equal(stats.unique_ips, 1);
    assert.deepEqual(stats.by_service, { http: 1, ssh: 1 });
    assert.equal(stats.by_attack_type.sql_injection, 1);
    assert.equal(stats.by_threat_level.Critical, 1);
  } finally {
    await closeDatabase(database);
  }
});

test("IDS store rejects unsafe or malformed integration results", async () => {
  const database = new sqlite3.Database(":memory:");
  initializeIDSResultStore(database);

  try {
    const unsafe = sampleIDSResult({
      integration: {
        source: "live_common_event",
        raw_payload_included: true,
        credentials_included: false,
        producer_attack_type_used_as_prediction: false,
      },
    });
    assert.match(
      validateIDSResult(unsafe).join(" "),
      /integration safety flags must remain false/
    );
    await assert.rejects(
      insertIDSResult(database, unsafe),
      /integration safety flags must remain false/
    );

    const invalidScore = sampleIDSResult({ threat_score: 101 });
    assert.match(
      validateIDSResult(invalidScore).join(" "),
      /threat_score must be an integer from 0 to 100/
    );
  } finally {
    await closeDatabase(database);
  }
});
