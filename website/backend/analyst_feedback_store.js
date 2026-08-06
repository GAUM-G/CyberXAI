const ALLOWED_VERDICTS = new Set(["confirmed_attack", "false_positive"]);
const ALLOWED_SEVERITIES = new Set(["Low", "Medium", "High", "Critical"]);
const MAX_NOTES_LENGTH = 2000;
const { toISTISOString } = require("./time");

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function validateFeedbackInput(input) {
  if (!isObject(input)) {
    return ["feedback must be a JSON object"];
  }

  const errors = [];
  if (!ALLOWED_VERDICTS.has(input.verdict)) {
    errors.push("verdict must be confirmed_attack or false_positive");
  }

  const severity = input.severity_override;
  if (
    severity !== undefined &&
    severity !== null &&
    severity !== "" &&
    !ALLOWED_SEVERITIES.has(severity)
  ) {
    errors.push("severity_override must be Low, Medium, High, Critical or null");
  }

  if (
    input.notes !== undefined &&
    input.notes !== null &&
    typeof input.notes !== "string"
  ) {
    errors.push("notes must be a string");
  } else if (String(input.notes || "").trim().length > MAX_NOTES_LENGTH) {
    errors.push(`notes must not exceed ${MAX_NOTES_LENGTH} characters`);
  }

  return errors;
}

function initializeAnalystFeedbackStore(database) {
  database.serialize(() => {
    database.run(`
      CREATE TABLE IF NOT EXISTS analyst_feedback (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id TEXT NOT NULL,
        analyst_id INTEGER NOT NULL,
        analyst_username TEXT NOT NULL,
        verdict TEXT NOT NULL
          CHECK (verdict IN ('confirmed_attack', 'false_positive')),
        severity_override TEXT
          CHECK (
            severity_override IS NULL OR
            severity_override IN ('Low', 'Medium', 'High', 'Critical')
          ),
        notes TEXT NOT NULL DEFAULT '',
        original_prediction TEXT NOT NULL,
        original_severity TEXT NOT NULL,
        original_attack_type TEXT NOT NULL,
        created_at TEXT NOT NULL
      )
    `);

    database.run(`
      CREATE INDEX IF NOT EXISTS idx_analyst_feedback_event
      ON analyst_feedback(event_id, id DESC)
    `);
    database.run(`
      CREATE INDEX IF NOT EXISTS idx_analyst_feedback_verdict
      ON analyst_feedback(verdict)
    `);
    database.run(`
      CREATE INDEX IF NOT EXISTS idx_analyst_feedback_created
      ON analyst_feedback(created_at DESC)
    `);
  });
}

function rowToFeedback(row) {
  if (!row) {
    return null;
  }
  return {
    feedback_id: row.id,
    event_id: row.event_id,
    verdict: row.verdict,
    review_status:
      row.verdict === "confirmed_attack" ? "confirmed" : "false_positive",
    severity_override: row.severity_override,
    notes: row.notes,
    analyst: {
      id: row.analyst_id,
      username: row.analyst_username,
    },
    original_prediction: row.original_prediction,
    original_severity: row.original_severity,
    original_attack_type: row.original_attack_type,
    created_at: row.created_at,
  };
}

function getIDSResult(database, eventId) {
  return new Promise((resolve, reject) => {
    database.get(
      `
        SELECT event_id, prediction, threat_level, attack_type
        FROM ids_results
        WHERE event_id = ?
      `,
      [eventId],
      (error, row) => {
        if (error) {
          reject(error);
          return;
        }
        resolve(row || null);
      }
    );
  });
}

async function insertAnalystFeedback(database, eventId, input, analyst) {
  const errors = validateFeedbackInput(input);
  if (typeof eventId !== "string" || !eventId.trim()) {
    errors.push("event_id must be a non-empty string");
  }
  if (
    !analyst ||
    !Number.isInteger(analyst.id) ||
    analyst.id < 1 ||
    typeof analyst.username !== "string" ||
    !analyst.username.trim()
  ) {
    errors.push("authenticated analyst identity is required");
  }
  if (errors.length > 0) {
    const error = new Error(errors.join("; "));
    error.code = "INVALID_ANALYST_FEEDBACK";
    throw error;
  }

  const idsResult = await getIDSResult(database, eventId.trim());
  if (!idsResult) {
    const error = new Error("IDS result was not found");
    error.code = "IDS_RESULT_NOT_FOUND";
    throw error;
  }

  const params = [
    idsResult.event_id,
    analyst.id,
    analyst.username.trim(),
    input.verdict,
    input.severity_override || null,
    String(input.notes || "").trim(),
    idsResult.prediction,
    idsResult.threat_level,
    idsResult.attack_type,
    toISTISOString(),
  ];

  const feedbackId = await new Promise((resolve, reject) => {
    database.run(
      `
        INSERT INTO analyst_feedback (
          event_id, analyst_id, analyst_username, verdict,
          severity_override, notes, original_prediction,
          original_severity, original_attack_type, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `,
      params,
      function onInsert(error) {
        if (error) {
          reject(error);
          return;
        }
        resolve(this.lastID);
      }
    );
  });

  return new Promise((resolve, reject) => {
    database.get(
      "SELECT * FROM analyst_feedback WHERE id = ?",
      [feedbackId],
      (error, row) => {
        if (error) {
          reject(error);
          return;
        }
        resolve(rowToFeedback(row));
      }
    );
  });
}

function listAnalystFeedback(database, filters = {}) {
  const where = [];
  const params = [];
  if (filters.eventId) {
    where.push("event_id = ?");
    params.push(filters.eventId);
  }
  if (filters.verdict) {
    where.push("verdict = ?");
    params.push(filters.verdict);
  }

  const requestedLimit = Number(filters.limit || 100);
  const limit = Math.max(
    1,
    Math.min(Number.isFinite(requestedLimit) ? Math.floor(requestedLimit) : 100, 2000)
  );
  const requestedOffset = Number(filters.offset || 0);
  const offset = Math.max(
    0,
    Math.floor(Number.isFinite(requestedOffset) ? requestedOffset : 0)
  );
  params.push(limit, offset);

  return new Promise((resolve, reject) => {
    database.all(
      `
        SELECT *
        FROM analyst_feedback
        ${where.length ? `WHERE ${where.join(" AND ")}` : ""}
        ORDER BY id DESC
        LIMIT ? OFFSET ?
      `,
      params,
      (error, rows) => {
        if (error) {
          reject(error);
          return;
        }
        resolve(rows.map(rowToFeedback));
      }
    );
  });
}

function getLatestFeedbackByEvent(database, eventIds = []) {
  const uniqueIds = [...new Set(eventIds.filter(Boolean))].slice(0, 2000);
  if (uniqueIds.length === 0) {
    return Promise.resolve({});
  }

  const placeholders = uniqueIds.map(() => "?").join(", ");
  return new Promise((resolve, reject) => {
    database.all(
      `
        SELECT feedback.*
        FROM analyst_feedback AS feedback
        INNER JOIN (
          SELECT event_id, MAX(id) AS latest_id
          FROM analyst_feedback
          WHERE event_id IN (${placeholders})
          GROUP BY event_id
        ) AS latest ON latest.latest_id = feedback.id
      `,
      uniqueIds,
      (error, rows) => {
        if (error) {
          reject(error);
          return;
        }
        resolve(
          Object.fromEntries(
            rows.map((row) => [row.event_id, rowToFeedback(row)])
          )
        );
      }
    );
  });
}

function getFeedbackStats(database) {
  return new Promise((resolve, reject) => {
    database.get(
      `
        WITH latest AS (
          SELECT feedback.*
          FROM analyst_feedback AS feedback
          INNER JOIN (
            SELECT event_id, MAX(id) AS latest_id
            FROM analyst_feedback
            GROUP BY event_id
          ) AS selected ON selected.latest_id = feedback.id
        )
        SELECT
          (SELECT COUNT(*) FROM ids_results) AS total_results,
          COUNT(*) AS reviewed,
          SUM(CASE WHEN verdict = 'confirmed_attack' THEN 1 ELSE 0 END)
            AS confirmed_attacks,
          SUM(CASE WHEN verdict = 'false_positive' THEN 1 ELSE 0 END)
            AS false_positives,
          SUM(CASE WHEN severity_override IS NOT NULL THEN 1 ELSE 0 END)
            AS severity_overrides
        FROM latest
      `,
      [],
      (error, row) => {
        if (error) {
          reject(error);
          return;
        }
        const totalResults = row?.total_results || 0;
        const reviewed = row?.reviewed || 0;
        resolve({
          total_results: totalResults,
          reviewed,
          awaiting_review: Math.max(0, totalResults - reviewed),
          confirmed_attacks: row?.confirmed_attacks || 0,
          false_positives: row?.false_positives || 0,
          severity_overrides: row?.severity_overrides || 0,
        });
      }
    );
  });
}

module.exports = {
  ALLOWED_SEVERITIES,
  ALLOWED_VERDICTS,
  MAX_NOTES_LENGTH,
  getFeedbackStats,
  getLatestFeedbackByEvent,
  initializeAnalystFeedbackStore,
  insertAnalystFeedback,
  listAnalystFeedback,
  validateFeedbackInput,
};
