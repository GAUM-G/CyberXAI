const test = require("node:test");
const assert = require("node:assert/strict");
const sqlite3 = require("sqlite3").verbose();

const {
  getFeedbackStats,
  getLatestFeedbackByEvent,
  initializeAnalystFeedbackStore,
  insertAnalystFeedback,
  listAnalystFeedback,
  validateFeedbackInput,
} = require("../analyst_feedback_store");

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

function closeDatabase(database) {
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
        event_id TEXT PRIMARY KEY,
        prediction TEXT NOT NULL,
        threat_level TEXT NOT NULL,
        attack_type TEXT NOT NULL
      )
    `
  );
  initializeAnalystFeedbackStore(database);
  await run(
    database,
    `
      INSERT INTO ids_results (
        event_id, prediction, threat_level, attack_type
      ) VALUES
        ('event-1', 'attack', 'Critical', 'sql_injection'),
        ('event-2', 'attack', 'High', 'ssh_bruteforce'),
        ('event-3', 'normal', 'Low', 'normal')
    `
  );
  return database;
}

const analyst = { id: 7, username: "analyst_one" };

test("feedback validation accepts only supported analyst decisions", () => {
  assert.deepEqual(
    validateFeedbackInput({
      verdict: "confirmed_attack",
      severity_override: "High",
      notes: "Reviewed the XAI evidence.",
    }),
    []
  );
  assert.match(
    validateFeedbackInput({ verdict: "unknown" }).join(" "),
    /verdict must be/
  );
  assert.match(
    validateFeedbackInput({
      verdict: "false_positive",
      severity_override: "Urgent",
    }).join(" "),
    /severity_override/
  );
});

test("feedback is append-only and preserves the original IDS decision", async () => {
  const database = await makeDatabase();
  try {
    const first = await insertAnalystFeedback(
      database,
      "event-1",
      {
        verdict: "confirmed_attack",
        severity_override: "High",
        notes: "Pattern and service context agree.",
      },
      analyst
    );
    const second = await insertAnalystFeedback(
      database,
      "event-1",
      {
        verdict: "false_positive",
        severity_override: null,
        notes: "Re-reviewed after investigation.",
      },
      { id: 8, username: "senior_analyst" }
    );

    assert.notEqual(first.feedback_id, second.feedback_id);
    assert.equal(first.original_prediction, "attack");
    assert.equal(first.original_severity, "Critical");
    assert.equal(first.original_attack_type, "sql_injection");
    assert.equal(first.analyst.username, "analyst_one");

    const history = await listAnalystFeedback(database, {
      eventId: "event-1",
    });
    assert.equal(history.length, 2);
    assert.equal(history[0].verdict, "false_positive");
    assert.equal(history[1].verdict, "confirmed_attack");
  } finally {
    await closeDatabase(database);
  }
});

test("feedback rejects unknown IDS events and missing analyst identity", async () => {
  const database = await makeDatabase();
  try {
    await assert.rejects(
      insertAnalystFeedback(
        database,
        "missing-event",
        { verdict: "confirmed_attack" },
        analyst
      ),
      /IDS result was not found/
    );
    await assert.rejects(
      insertAnalystFeedback(
        database,
        "event-1",
        { verdict: "confirmed_attack" },
        { id: 0, username: "" }
      ),
      /authenticated analyst identity is required/
    );
  } finally {
    await closeDatabase(database);
  }
});

test("latest feedback is selected independently for every event", async () => {
  const database = await makeDatabase();
  try {
    await insertAnalystFeedback(
      database,
      "event-1",
      { verdict: "confirmed_attack" },
      analyst
    );
    await insertAnalystFeedback(
      database,
      "event-1",
      { verdict: "false_positive" },
      analyst
    );
    await insertAnalystFeedback(
      database,
      "event-2",
      { verdict: "confirmed_attack", severity_override: "Critical" },
      analyst
    );

    const latest = await getLatestFeedbackByEvent(database, [
      "event-1",
      "event-2",
      "event-3",
    ]);
    assert.equal(latest["event-1"].verdict, "false_positive");
    assert.equal(latest["event-2"].severity_override, "Critical");
    assert.equal(latest["event-3"], undefined);
  } finally {
    await closeDatabase(database);
  }
});

test("feedback statistics use the latest review and count awaiting events", async () => {
  const database = await makeDatabase();
  try {
    await insertAnalystFeedback(
      database,
      "event-1",
      { verdict: "confirmed_attack", severity_override: "High" },
      analyst
    );
    await insertAnalystFeedback(
      database,
      "event-1",
      { verdict: "false_positive" },
      analyst
    );
    await insertAnalystFeedback(
      database,
      "event-2",
      { verdict: "confirmed_attack", severity_override: "Critical" },
      analyst
    );

    assert.deepEqual(await getFeedbackStats(database), {
      total_results: 3,
      reviewed: 2,
      awaiting_review: 1,
      confirmed_attacks: 1,
      false_positives: 1,
      severity_overrides: 1,
    });
  } finally {
    await closeDatabase(database);
  }
});
