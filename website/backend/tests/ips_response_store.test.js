const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
const sqlite3 = require("sqlite3").verbose();

const {
  AUTOMATIC_HOST_BLOCKING,
  HOST_FIREWALL_CHANGED,
  IPS_MODE,
  applyAnalystFeedbackToIPS,
  backfillIPSRecommendations,
  getIPSStatus,
  initializeIPSResponseStore,
  listIPSActions,
  listIPSRecommendations,
  performIPSAction,
  policyDecision,
  syncRuntimeState,
  upsertIPSRecommendation,
  validateIPSActionInput,
} = require("../ips_response_store");

function run(database, sql, params = []) {
  return new Promise((resolve, reject) => {
    database.run(sql, params, function onRun(error) {
      if (error) {
        reject(error);
        return;
      }
      resolve(this);
    });
  });
}

function close(database) {
  return new Promise((resolve, reject) => {
    database.close((error) => (error ? reject(error) : resolve()));
  });
}

async function makeDatabase() {
  const database = new sqlite3.Database(":memory:");
  await run(
    database,
    `
      CREATE TABLE ids_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id TEXT UNIQUE NOT NULL,
        source_ip TEXT NOT NULL,
        service TEXT NOT NULL,
        attack_type TEXT NOT NULL,
        prediction TEXT NOT NULL,
        threat_level TEXT NOT NULL,
        confidence REAL
      )
    `
  );
  await run(
    database,
    `
      CREATE TABLE honeypot_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id TEXT UNIQUE NOT NULL,
        source_ip TEXT NOT NULL,
        service TEXT NOT NULL,
        session_id TEXT,
        attack_type TEXT NOT NULL,
        received_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `
  );
  await run(
    database,
    `
      CREATE TABLE analyst_feedback (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id TEXT NOT NULL,
        verdict TEXT NOT NULL,
        severity_override TEXT
      )
    `
  );
  initializeIPSResponseStore(database);

  for (let index = 1; index <= 6; index += 1) {
    await run(
      database,
      `
        INSERT INTO honeypot_events (
          event_id, source_ip, service, session_id, attack_type
        ) VALUES (?, '10.0.0.8', 'ssh', 'session-ssh-1', 'ssh_bruteforce')
      `,
      [`related-${index}`]
    );
  }
  await run(
    database,
    `
      INSERT INTO ids_results (
        event_id, source_ip, service, attack_type, prediction,
        threat_level, confidence
      ) VALUES
        ('related-1', '10.0.0.8', 'ssh', 'ssh_bruteforce', 'attack', 'High', 0.94),
        ('event-http', '10.0.0.9', 'http', 'sql_injection', 'attack', 'Critical', 0.98),
        ('event-normal', '10.0.0.10', 'ftp', 'normal', 'normal', 'Low', 0.77)
    `
  );
  await run(
    database,
    `
      INSERT INTO honeypot_events (
        event_id, source_ip, service, session_id, attack_type
      ) VALUES
        ('event-http', '10.0.0.9', 'http', 'session-http-1', 'sql_injection'),
        ('event-normal', '10.0.0.10', 'ftp', 'session-ftp-1', 'normal')
    `
  );
  return database;
}

function makeStateTarget() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "step21-ips-"));
  return {
    directory,
    stateFile: path.join(directory, "simulated_ips_state.json"),
  };
}

const analyst = { id: 7, username: "analyst_one" };

test("IPS safety constants make host blocking unavailable", () => {
  assert.equal(IPS_MODE, "simulation");
  assert.equal(AUTOMATIC_HOST_BLOCKING, false);
  assert.equal(HOST_FIREWALL_CHANGED, false);
  assert.deepEqual(
    validateIPSActionInput({
      action_type: "simulate_block",
      event_id: "event-http",
      duration_seconds: 300,
    }),
    []
  );
  assert.match(
    validateIPSActionInput({ action_type: "real_firewall_block" }).join(" "),
    /action_type/
  );
});

test("policy selects monitoring, rate limiting and safe block recommendations", () => {
  assert.equal(
    policyDecision({ prediction: "normal", original_severity: "Critical" }).action,
    "continue_monitoring"
  );
  assert.equal(
    policyDecision({ prediction: "attack", original_severity: "Medium", repeat_count: 2 }).action,
    "rate_limit"
  );
  assert.equal(
    policyDecision({ prediction: "attack", original_severity: "High", repeat_count: 2 }).action,
    "recommend_block"
  );
  assert.equal(
    policyDecision({ prediction: "attack", original_severity: "Critical", repeat_count: 2 }).action,
    "simulate_block"
  );
  assert.equal(
    policyDecision({
      prediction: "attack",
      original_severity: "Critical",
      feedback_verdict: "false_positive",
    }).action,
    "no_response"
  );
});

test("recommendation uses repeat context and honeypot session ID", async () => {
  const database = await makeDatabase();
  try {
    await upsertIPSRecommendation(database, "related-1");
    const recommendations = await listIPSRecommendations(database, {
      eventId: "related-1",
    });
    assert.equal(recommendations.length, 1);
    assert.equal(recommendations[0].recommended_action, "recommend_block");
    assert.equal(recommendations[0].repeat_count, 6);
    assert.equal(recommendations[0].session_id, "session-ssh-1");
    assert.match(recommendations[0].reason, /6 related attempts/);
  } finally {
    await close(database);
  }
});

test("simulated block persists an audit record and safe runtime state", async () => {
  const database = await makeDatabase();
  const target = makeStateTarget();
  try {
    const recommendation = await upsertIPSRecommendation(database, "event-http");
    const action = await performIPSAction(
      database,
      {
        action_type: "simulate_block",
        recommendation_id: recommendation.id,
        duration_seconds: 600,
        reason: "Confirmed critical test event.",
      },
      analyst,
      { stateFile: target.stateFile }
    );
    assert.equal(action.action_type, "simulate_block");
    assert.equal(action.status, "active");
    assert.equal(action.safety.host_firewall_changed, false);

    const state = JSON.parse(fs.readFileSync(target.stateFile, "utf8"));
    assert.equal(state.mode, "simulation");
    assert.equal(state.automatic_host_blocking, false);
    assert.equal(state.host_firewall_changed, false);
    assert.equal(state.simulated_blocks.length, 1);
    assert.equal(state.simulated_blocks[0].source_ip, "10.0.0.9");

    const status = await getIPSStatus(database);
    assert.equal(status.simulated_blocks, 1);
    assert.equal(status.host_firewall_changed, false);
  } finally {
    await close(database);
    fs.rmSync(target.directory, { recursive: true, force: true });
  }
});

test("rate limit can be activated and safely released", async () => {
  const database = await makeDatabase();
  const target = makeStateTarget();
  try {
    const recommendation = await upsertIPSRecommendation(database, "related-1");
    const limit = await performIPSAction(
      database,
      {
        action_type: "rate_limit",
        recommendation_id: recommendation.id,
        duration_seconds: 300,
      },
      analyst,
      { stateFile: target.stateFile }
    );
    assert.equal(limit.rate_limit_delay_ms, 750);
    assert.equal(limit.status, "active");

    const released = await performIPSAction(
      database,
      {
        action_type: "release",
        related_action_id: limit.action_id,
        reason: "Live validation complete.",
      },
      analyst,
      { stateFile: target.stateFile }
    );
    assert.equal(released.action_type, "release");
    const actions = await listIPSActions(database);
    const original = actions.find((item) => item.action_id === limit.action_id);
    assert.equal(original.status, "reversed");
    const state = JSON.parse(fs.readFileSync(target.stateFile, "utf8"));
    assert.deepEqual(state.rate_limits, []);
  } finally {
    await close(database);
    fs.rmSync(target.directory, { recursive: true, force: true });
  }
});

test("false-positive feedback suppresses and reverses active responses", async () => {
  const database = await makeDatabase();
  const target = makeStateTarget();
  try {
    const recommendation = await upsertIPSRecommendation(database, "event-http");
    await performIPSAction(
      database,
      {
        action_type: "simulate_block",
        recommendation_id: recommendation.id,
      },
      analyst,
      { stateFile: target.stateFile }
    );
    await run(
      database,
      `
        INSERT INTO analyst_feedback (event_id, verdict, severity_override)
        VALUES ('event-http', 'false_positive', NULL)
      `
    );
    const updated = await applyAnalystFeedbackToIPS(
      database,
      "event-http",
      { verdict: "false_positive" },
      { stateFile: target.stateFile }
    );
    assert.equal(updated.recommended_action, "no_response");
    assert.equal(updated.status, "suppressed");
    const actions = await listIPSActions(database);
    assert.equal(actions[0].status, "reversed");
    const state = JSON.parse(fs.readFileSync(target.stateFile, "utf8"));
    assert.deepEqual(state.simulated_blocks, []);
  } finally {
    await close(database);
    fs.rmSync(target.directory, { recursive: true, force: true });
  }
});

test("action IDs and durations reject coercion, fractions, and unsafe integers", () => {
  for (const id of [true, false, null, [], {}, 0, -1, 1.5, "1.5", "01", "1 OR 1=1", Number.MAX_SAFE_INTEGER + 1]) {
    assert.ok(validateIPSActionInput({ action_type: "simulate_block", recommendation_id: id }).length, String(id));
    assert.ok(validateIPSActionInput({ action_type: "release", related_action_id: id }).length, String(id));
  }
  for (const duration of [true, [], {}, -1, 0, 1.5, "1.5", 86401]) {
    assert.ok(validateIPSActionInput({ action_type: "rate_limit", event_id: "event-http", duration_seconds: duration }).length);
  }
  assert.deepEqual(validateIPSActionInput({ action_type: "release", related_action_id: "7" }), []);
});

test("expired and released responses return recommendations to pending", async () => {
  const database = await makeDatabase();
  const target = makeStateTarget();
  try {
    const recommendation = await upsertIPSRecommendation(database, "event-http");
    const action = await performIPSAction(database, { action_type: "rate_limit", recommendation_id: recommendation.id }, analyst, target);
    await run(database, "UPDATE ips_actions SET expires_at = '2000-01-01T00:00:00Z' WHERE id = ?", [action.action_id]);
    assert.equal((await listIPSRecommendations(database, { eventId: "event-http" }))[0].status, "pending");
    assert.equal((await listIPSActions(database))[0].status, "expired");
    const replacement = await performIPSAction(database, { action_type: "rate_limit", recommendation_id: recommendation.id }, analyst, target);
    await performIPSAction(database, { action_type: "release", related_action_id: replacement.action_id }, analyst, target);
    assert.equal((await listIPSRecommendations(database, { eventId: "event-http" }))[0].status, "pending");
    assert.deepEqual(JSON.parse(fs.readFileSync(target.stateFile, "utf8")).rate_limits, []);
  } finally {
    await close(database);
    fs.rmSync(target.directory, { recursive: true, force: true });
  }
});

test("current IDS and analyst feedback suppress stale, normal, and dismissed targets", async () => {
  const database = await makeDatabase();
  const target = makeStateTarget();
  try {
    const normal = await upsertIPSRecommendation(database, "event-normal");
    await assert.rejects(performIPSAction(database, { action_type: "simulate_block", recommendation_id: normal.id }, analyst, target), { code: "IPS_RESPONSE_SUPPRESSED" });
    const rec = await upsertIPSRecommendation(database, "event-http");
    await assert.rejects(performIPSAction(database, { action_type: "rate_limit", recommendation_id: rec.id, event_id: "related-1" }, analyst, target), { code: "INVALID_IPS_ACTION" });
    await performIPSAction(database, { action_type: "simulate_block", recommendation_id: rec.id }, analyst, target);
    await assert.rejects(performIPSAction(database, { action_type: "dismiss", recommendation_id: rec.id }, analyst, target), { code: "IPS_RESPONSE_SUPPRESSED" });
    await run(database, "INSERT INTO analyst_feedback(event_id, verdict) VALUES ('event-http', 'false_positive')");
    // Recovery must use the persisted latest verdict even if the feedback hook was interrupted.
    await syncRuntimeState(database, target.stateFile);
    const updated = (await listIPSRecommendations(database, { eventId: "event-http" }))[0];
    assert.equal(updated.status, "suppressed");
    assert.equal(updated.feedback_verdict, "false_positive");
    assert.deepEqual(JSON.parse(fs.readFileSync(target.stateFile, "utf8")).simulated_blocks, []);
    await assert.rejects(performIPSAction(database, { action_type: "rate_limit", recommendation_id: rec.id }, analyst, target), { code: "IPS_RESPONSE_SUPPRESSED" });
    const other = await upsertIPSRecommendation(database, "related-1");
    await performIPSAction(database, { action_type: "dismiss", recommendation_id: other.id }, analyst, target);
    await assert.rejects(performIPSAction(database, { action_type: "simulate_block", recommendation_id: other.id }, analyst, target), { code: "IPS_RESPONSE_SUPPRESSED" });
  } finally {
    await close(database);
    fs.rmSync(target.directory, { recursive: true, force: true });
  }
});

test("session termination is available only for a targeted persistent FTP session", async () => {
  const database = await makeDatabase();
  const target = makeStateTarget();
  try {
    for (const eventId of ["event-http", "related-1"]) {
      const rec = await upsertIPSRecommendation(database, eventId);
      await assert.rejects(performIPSAction(database, { action_type: "terminate_session", recommendation_id: rec.id }, analyst, target), { code: "INVALID_IPS_ACTION" });
    }
    await run(database, "UPDATE ids_results SET prediction = 'attack', threat_level = 'High' WHERE event_id = 'event-normal'");
    const rec = await upsertIPSRecommendation(database, "event-normal");
    const action = await performIPSAction(database, { action_type: "terminate_session", recommendation_id: rec.id }, analyst, target);
    assert.equal(action.session_id, "session-ftp-1");
    assert.equal(JSON.parse(fs.readFileSync(target.stateFile, "utf8")).terminated_sessions[0].service, "ftp");
  } finally {
    await close(database);
    fs.rmSync(target.directory, { recursive: true, force: true });
  }
});

test("concurrent actions replace earlier controls and cannot release a target twice", async () => {
  const database = await makeDatabase();
  const target = makeStateTarget();
  try {
    const rec = await upsertIPSRecommendation(database, "event-http");
    const actions = await Promise.all([1, 2, 3].map(() => performIPSAction(database, { action_type: "rate_limit", recommendation_id: rec.id }, analyst, target)));
    const active = await listIPSActions(database, { status: "active" });
    assert.equal(active.length, 1);
    assert.equal(active[0].action_id, actions.at(-1).action_id);
    assert.equal(JSON.parse(fs.readFileSync(target.stateFile, "utf8")).rate_limits.length, 1);
    const results = await Promise.allSettled([1, 2].map(() => performIPSAction(database, { action_type: "release", related_action_id: active[0].action_id }, analyst, target)));
    assert.equal(results.filter(result => result.status === "fulfilled").length, 1);
    assert.equal(results.find(result => result.status === "rejected").reason.code, "IPS_TARGET_NOT_FOUND");
  } finally {
    await close(database);
    fs.rmSync(target.directory, { recursive: true, force: true });
  }
});

test("failed publication preserves the previous complete snapshot and can recover", async t => {
  const database = await makeDatabase();
  const target = makeStateTarget();
  try {
    await syncRuntimeState(database, target.stateFile);
    const previous = fs.readFileSync(target.stateFile, "utf8");
    const rec = await upsertIPSRecommendation(database, "event-http");
    const rename = t.mock.method(fs, "renameSync", () => { throw new Error("simulated unavailable destination"); });
    await assert.rejects(performIPSAction(database, { action_type: "simulate_block", recommendation_id: rec.id }, analyst, target), error => {
      assert.equal(error.code, "IPS_STATE_SYNC_FAILED");
      assert.equal(error.action.status, "active");
      return true;
    });
    assert.equal(fs.readFileSync(target.stateFile, "utf8"), previous);
    assert.deepEqual(fs.readdirSync(target.directory), ["simulated_ips_state.json"]);
    rename.mock.restore();
    await syncRuntimeState(database, target.stateFile);
    assert.equal(JSON.parse(fs.readFileSync(target.stateFile, "utf8")).simulated_blocks.length, 1);
    assert.equal((await listIPSActions(database)).length, 1);
  } finally {
    await close(database);
    fs.rmSync(target.directory, { recursive: true, force: true });
  }
});

test("repeat context excludes future timestamps and backfill prioritizes newest IDS results", async () => {
  const database = await makeDatabase();
  try {
    await run(database, "INSERT INTO honeypot_events(event_id, source_ip, service, attack_type, received_at) VALUES ('future', '10.0.0.8', 'ssh', 'ssh_bruteforce', '2099-01-01')");
    assert.equal((await upsertIPSRecommendation(database, "related-1")).repeat_count, 6);
    await run(database, "DELETE FROM ips_recommendations");
    assert.equal(await backfillIPSRecommendations(database, 1), 1);
    assert.equal((await listIPSRecommendations(database))[0].event_id, "event-normal");
  } finally {
    await close(database);
  }
});

test("a failed audit insert does not release, dismiss, or replace the existing response", async () => {
  const database = await makeDatabase();
  const target = makeStateTarget();
  try {
    const rec = await upsertIPSRecommendation(database, "event-http");
    const original = await performIPSAction(database, { action_type: "rate_limit", recommendation_id: rec.id }, analyst, target);
    const previous = fs.readFileSync(target.stateFile, "utf8");
    await run(database, "CREATE TRIGGER reject_test_actions BEFORE INSERT ON ips_actions BEGIN SELECT RAISE(ABORT, 'test audit insert failure'); END");
    for (const input of [{ action_type: "rate_limit", recommendation_id: rec.id }, { action_type: "release", related_action_id: original.action_id }]) {
      await assert.rejects(performIPSAction(database, input, analyst, target), /test audit insert failure/);
      assert.equal((await listIPSActions(database, { status: "active" }))[0]?.action_id, original.action_id);
      assert.equal(fs.readFileSync(target.stateFile, "utf8"), previous);
    }
    const other = await upsertIPSRecommendation(database, "related-1");
    await assert.rejects(performIPSAction(database, { action_type: "dismiss", recommendation_id: other.id }, analyst, target), /test audit insert failure/);
    assert.equal((await listIPSRecommendations(database, { eventId: "related-1" }))[0].status, "pending");
    assert.equal((await listIPSActions(database)).length, 1);
    await run(database, "DROP TRIGGER reject_test_actions");
    await run(database, "CREATE TRIGGER reject_test_activation BEFORE UPDATE OF status ON ips_recommendations WHEN NEW.status = 'executed' BEGIN SELECT RAISE(ABORT, 'test activation failure'); END");
    await assert.rejects(performIPSAction(database, { action_type: "rate_limit", recommendation_id: rec.id }, analyst, target), /test activation failure/);
    assert.equal((await listIPSActions(database, { status: "active" }))[0].action_id, original.action_id);
    assert.equal((await listIPSActions(database)).length, 1);
    assert.equal(fs.readFileSync(target.stateFile, "utf8"), previous);
  } finally {
    await close(database);
    fs.rmSync(target.directory, { recursive: true, force: true });
  }
});
