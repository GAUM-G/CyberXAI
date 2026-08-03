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
  getIPSStatus,
  initializeIPSResponseStore,
  listIPSActions,
  listIPSRecommendations,
  performIPSAction,
  policyDecision,
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
