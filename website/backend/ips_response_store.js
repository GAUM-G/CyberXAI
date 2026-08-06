const fs = require("fs");
const path = require("path");
const { toISTISOString } = require("./time");

const IPS_MODE = "simulation";
const AUTOMATIC_HOST_BLOCKING = false;
const HOST_FIREWALL_CHANGED = false;
const POLICY_VERSION = "step21-v1";
const MAX_DURATION_SECONDS = 24 * 60 * 60;
const MAX_REASON_LENGTH = 1000;
const configuredStateFile = String(process.env.IPS_STATE_FILE || "").trim();
const DEFAULT_STATE_FILE = configuredStateFile
  ? path.resolve(configuredStateFile)
  : path.join(
      __dirname,
      "..",
      "..",
      "data",
      "ips",
      "simulated_ips_state.json"
    );

const ACTION_TYPES = new Set([
  "recommend_block",
  "simulate_block",
  "rate_limit",
  "terminate_session",
  "release",
  "dismiss",
]);

const ACTIVE_ACTION_TYPES = new Set([
  "simulate_block",
  "rate_limit",
  "terminate_session",
]);

const DEFAULT_DURATIONS = Object.freeze({
  simulate_block: 15 * 60,
  rate_limit: 5 * 60,
  terminate_session: 60 * 60,
});

const POLICY = Object.freeze({
  repeat_window_minutes: 5,
  repeated_attempt_threshold: 5,
  rate_limit_delay_ms: 750,
  actions_by_severity: {
    Low: "continue_monitoring",
    Medium: "rate_limit",
    High: "recommend_block",
    Critical: "simulate_block",
  },
});

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

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

function get(database, sql, params = []) {
  return new Promise((resolve, reject) => {
    database.get(sql, params, (error, row) => {
      if (error) {
        reject(error);
        return;
      }
      resolve(row || null);
    });
  });
}

function all(database, sql, params = []) {
  return new Promise((resolve, reject) => {
    database.all(sql, params, (error, rows) => {
      if (error) {
        reject(error);
        return;
      }
      resolve(rows || []);
    });
  });
}

function initializeIPSResponseStore(database) {
  database.serialize(() => {
    database.run(`
      CREATE TABLE IF NOT EXISTS ips_recommendations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id TEXT UNIQUE NOT NULL,
        source_ip TEXT NOT NULL,
        service TEXT NOT NULL,
        session_id TEXT,
        attack_type TEXT NOT NULL,
        prediction TEXT NOT NULL,
        original_severity TEXT NOT NULL,
        effective_severity TEXT NOT NULL,
        confidence REAL,
        repeat_count INTEGER NOT NULL DEFAULT 1,
        recommended_action TEXT NOT NULL,
        recommended_duration_seconds INTEGER,
        reason TEXT NOT NULL,
        feedback_verdict TEXT,
        policy_version TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      )
    `);

    database.run(`
      CREATE TABLE IF NOT EXISTS ips_actions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        recommendation_id INTEGER,
        event_id TEXT,
        source_ip TEXT NOT NULL,
        service TEXT NOT NULL,
        session_id TEXT,
        action_type TEXT NOT NULL,
        status TEXT NOT NULL,
        mode TEXT NOT NULL DEFAULT 'simulation',
        duration_seconds INTEGER,
        rate_limit_delay_ms INTEGER,
        reason TEXT NOT NULL,
        analyst_id INTEGER NOT NULL,
        analyst_username TEXT NOT NULL,
        related_action_id INTEGER,
        expires_at TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      )
    `);

    database.run(
      "CREATE INDEX IF NOT EXISTS idx_ips_recommendations_status ON ips_recommendations(status, id DESC)"
    );
    database.run(
      "CREATE INDEX IF NOT EXISTS idx_ips_recommendations_ip ON ips_recommendations(source_ip, id DESC)"
    );
    database.run(
      "CREATE INDEX IF NOT EXISTS idx_ips_actions_status ON ips_actions(status, action_type, id DESC)"
    );
    database.run(
      "CREATE INDEX IF NOT EXISTS idx_ips_actions_ip ON ips_actions(source_ip, service, id DESC)"
    );
    database.run(
      "CREATE INDEX IF NOT EXISTS idx_ips_actions_session ON ips_actions(session_id, id DESC)"
    );
  });
}

function normalizeDuration(value, fallback = null) {
  if (value === undefined || value === null || value === "") {
    return fallback;
  }
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < 1 || parsed > MAX_DURATION_SECONDS) {
    return null;
  }
  return Math.floor(parsed);
}

function validateIPSActionInput(input) {
  if (!isObject(input)) {
    return ["IPS action must be a JSON object"];
  }

  const errors = [];
  if (!ACTION_TYPES.has(input.action_type)) {
    errors.push(`action_type must be one of: ${[...ACTION_TYPES].join(", ")}`);
  }
  if (
    input.reason !== undefined &&
    input.reason !== null &&
    typeof input.reason !== "string"
  ) {
    errors.push("reason must be a string");
  } else if (String(input.reason || "").trim().length > MAX_REASON_LENGTH) {
    errors.push(`reason must not exceed ${MAX_REASON_LENGTH} characters`);
  }

  if (
    input.duration_seconds !== undefined &&
    input.duration_seconds !== null &&
    input.duration_seconds !== "" &&
    normalizeDuration(input.duration_seconds) === null
  ) {
    errors.push(`duration_seconds must be from 1 to ${MAX_DURATION_SECONDS}`);
  }

  if (input.action_type === "release") {
    if (!Number.isInteger(Number(input.related_action_id)) || Number(input.related_action_id) < 1) {
      errors.push("related_action_id is required for release");
    }
  } else if (input.action_type === "dismiss") {
    if (!Number.isInteger(Number(input.recommendation_id)) || Number(input.recommendation_id) < 1) {
      errors.push("recommendation_id is required for dismiss");
    }
  } else if (
    !Number.isInteger(Number(input.recommendation_id)) &&
    (typeof input.event_id !== "string" || !input.event_id.trim())
  ) {
    errors.push("recommendation_id or event_id is required");
  }

  return errors;
}

function policyDecision(context) {
  const verdict = context.feedback_verdict || null;
  const prediction = String(context.prediction || "normal").toLowerCase();
  const severity = context.effective_severity || context.original_severity || "Low";
  const repeatCount = Math.max(1, Number(context.repeat_count || 1));

  if (verdict === "false_positive") {
    return {
      action: "no_response",
      duration_seconds: null,
      status: "suppressed",
      reason: "The latest analyst verdict is false positive, so IPS response is suppressed.",
    };
  }
  if (prediction !== "attack") {
    return {
      action: "continue_monitoring",
      duration_seconds: null,
      status: "suppressed",
      reason: "The final IDS prediction is normal; continue monitoring without intervention.",
    };
  }

  let action = POLICY.actions_by_severity[severity] || "continue_monitoring";
  if (
    repeatCount >= POLICY.repeated_attempt_threshold &&
    ["continue_monitoring", "rate_limit"].includes(action)
  ) {
    action = "rate_limit";
  }

  const duration = DEFAULT_DURATIONS[action] || null;
  const analystText = verdict === "confirmed_attack"
    ? " The analyst confirmed the attack."
    : " Analyst confirmation is still pending.";
  const repeatText = repeatCount > 1
    ? ` ${repeatCount} related attempts were observed in the policy window.`
    : "";
  const reasonByAction = {
    continue_monitoring: "Low-risk activity should remain under observation.",
    rate_limit: "Repeated or medium-risk activity should be rate-limited inside the honeypot.",
    recommend_block: "High-risk activity warrants an analyst-reviewed simulated block recommendation.",
    simulate_block: "Critical activity warrants a simulation-only block and session review.",
  };

  return {
    action,
    duration_seconds: duration,
    status: action === "continue_monitoring" ? "monitoring" : "pending",
    reason: `${reasonByAction[action]}${repeatText}${analystText}`,
  };
}

async function loadRecommendationContext(database, eventId) {
  const row = await get(
    database,
    `
      SELECT
        ids.event_id,
        ids.source_ip,
        ids.service,
        events.session_id,
        ids.attack_type,
        ids.prediction,
        ids.threat_level AS original_severity,
        COALESCE(feedback.severity_override, ids.threat_level) AS effective_severity,
        ids.confidence,
        feedback.verdict AS feedback_verdict,
        (
          SELECT COUNT(*)
          FROM honeypot_events AS repeated
          WHERE repeated.source_ip = ids.source_ip
            AND repeated.service = ids.service
            AND repeated.attack_type = events.attack_type
            AND datetime(repeated.received_at) >= datetime('now', '-5 minutes')
        ) AS repeat_count
      FROM ids_results AS ids
      LEFT JOIN honeypot_events AS events ON events.event_id = ids.event_id
      LEFT JOIN analyst_feedback AS feedback ON feedback.id = (
        SELECT MAX(latest_feedback.id)
        FROM analyst_feedback AS latest_feedback
        WHERE latest_feedback.event_id = ids.event_id
      )
      WHERE ids.event_id = ?
    `,
    [eventId]
  );

  if (!row) {
    const error = new Error("IDS result was not found");
    error.code = "IDS_RESULT_NOT_FOUND";
    throw error;
  }
  row.repeat_count = Math.max(1, Number(row.repeat_count || 1));
  return row;
}

async function upsertIPSRecommendation(database, eventId) {
  const context = await loadRecommendationContext(database, eventId);
  const decision = policyDecision(context);
  const istTimestamp = toISTISOString();
  const params = [
    context.event_id,
    context.source_ip,
    context.service,
    context.session_id || null,
    context.attack_type,
    context.prediction,
    context.original_severity,
    context.effective_severity,
    context.confidence,
    context.repeat_count,
    decision.action,
    decision.duration_seconds,
    decision.reason,
    context.feedback_verdict || null,
    POLICY_VERSION,
    decision.status,
    istTimestamp,
    istTimestamp,
  ];

  await run(
    database,
    `
      INSERT INTO ips_recommendations (
        event_id, source_ip, service, session_id, attack_type, prediction,
        original_severity, effective_severity, confidence, repeat_count,
        recommended_action, recommended_duration_seconds, reason,
        feedback_verdict, policy_version, status, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(event_id) DO UPDATE SET
        source_ip = excluded.source_ip,
        service = excluded.service,
        session_id = excluded.session_id,
        attack_type = excluded.attack_type,
        prediction = excluded.prediction,
        original_severity = excluded.original_severity,
        effective_severity = excluded.effective_severity,
        confidence = excluded.confidence,
        repeat_count = excluded.repeat_count,
        recommended_action = excluded.recommended_action,
        recommended_duration_seconds = excluded.recommended_duration_seconds,
        reason = excluded.reason,
        feedback_verdict = excluded.feedback_verdict,
        policy_version = excluded.policy_version,
        status = CASE
          WHEN ips_recommendations.status IN ('executed', 'dismissed')
            AND excluded.status NOT IN ('suppressed')
          THEN ips_recommendations.status
          ELSE excluded.status
        END,
        updated_at = excluded.updated_at
    `,
    params
  );

  return get(
    database,
    "SELECT * FROM ips_recommendations WHERE event_id = ?",
    [eventId]
  );
}

async function backfillIPSRecommendations(database, limit = 1000) {
  const safeLimit = Math.max(1, Math.min(Number(limit) || 1000, 5000));
  const rows = await all(
    database,
    "SELECT event_id FROM ids_results ORDER BY id ASC LIMIT ?",
    [safeLimit]
  );
  let updated = 0;
  for (const row of rows) {
    await upsertIPSRecommendation(database, row.event_id);
    updated += 1;
  }
  return updated;
}

async function expireIPSActions(database) {
  await run(
    database,
    `
      UPDATE ips_actions
      SET status = 'expired', updated_at = ?
      WHERE status = 'active'
        AND expires_at IS NOT NULL
        AND datetime(expires_at) <= datetime('now')
    `,
    [toISTISOString()]
  );
}

function recommendationToJSON(row) {
  if (!row) return null;
  return {
    recommendation_id: row.id,
    event_id: row.event_id,
    source_ip: row.source_ip,
    service: row.service,
    session_id: row.session_id,
    attack_type: row.attack_type,
    prediction: row.prediction,
    original_severity: row.original_severity,
    effective_severity: row.effective_severity,
    confidence: row.confidence,
    repeat_count: row.repeat_count,
    recommended_action: row.recommended_action,
    recommended_duration_seconds: row.recommended_duration_seconds,
    reason: row.reason,
    feedback_verdict: row.feedback_verdict,
    policy_version: row.policy_version,
    status: row.status,
    created_at: row.created_at,
    updated_at: row.updated_at,
  };
}

function actionToJSON(row) {
  if (!row) return null;
  return {
    action_id: row.id,
    recommendation_id: row.recommendation_id,
    event_id: row.event_id,
    source_ip: row.source_ip,
    service: row.service,
    session_id: row.session_id,
    action_type: row.action_type,
    status: row.status,
    mode: row.mode,
    duration_seconds: row.duration_seconds,
    rate_limit_delay_ms: row.rate_limit_delay_ms,
    reason: row.reason,
    analyst: {
      id: row.analyst_id,
      username: row.analyst_username,
    },
    related_action_id: row.related_action_id,
    expires_at: row.expires_at,
    created_at: row.created_at,
    updated_at: row.updated_at,
    safety: {
      automatic_host_blocking: AUTOMATIC_HOST_BLOCKING,
      host_firewall_changed: HOST_FIREWALL_CHANGED,
    },
  };
}

async function listIPSRecommendations(database, filters = {}) {
  const where = [];
  const params = [];
  for (const [column, value] of [
    ["status", filters.status],
    ["source_ip", filters.sourceIp],
    ["service", filters.service],
    ["event_id", filters.eventId],
  ]) {
    if (value) {
      where.push(`${column} = ?`);
      params.push(value);
    }
  }
  const requested = Number(filters.limit || 100);
  const limit = Math.max(1, Math.min(Number.isFinite(requested) ? Math.floor(requested) : 100, 1000));
  params.push(limit);
  const rows = await all(
    database,
    `
      SELECT * FROM ips_recommendations
      ${where.length ? `WHERE ${where.join(" AND ")}` : ""}
      ORDER BY id DESC
      LIMIT ?
    `,
    params
  );
  return rows.map(recommendationToJSON);
}

async function listIPSActions(database, filters = {}) {
  await expireIPSActions(database);
  const where = [];
  const params = [];
  for (const [column, value] of [
    ["status", filters.status],
    ["action_type", filters.actionType],
    ["source_ip", filters.sourceIp],
    ["event_id", filters.eventId],
  ]) {
    if (value) {
      where.push(`${column} = ?`);
      params.push(value);
    }
  }
  const requested = Number(filters.limit || 200);
  const limit = Math.max(1, Math.min(Number.isFinite(requested) ? Math.floor(requested) : 200, 2000));
  params.push(limit);
  const rows = await all(
    database,
    `
      SELECT * FROM ips_actions
      ${where.length ? `WHERE ${where.join(" AND ")}` : ""}
      ORDER BY id DESC
      LIMIT ?
    `,
    params
  );
  return rows.map(actionToJSON);
}

async function getIPSStatus(database) {
  await expireIPSActions(database);
  const row = await get(
    database,
    `
      SELECT
        (SELECT COUNT(*) FROM ips_recommendations WHERE status = 'pending') AS pending_recommendations,
        (SELECT COUNT(*) FROM ips_recommendations WHERE status = 'suppressed') AS suppressed_recommendations,
        (SELECT COUNT(*) FROM ips_actions WHERE status = 'active' AND action_type = 'simulate_block') AS simulated_blocks,
        (SELECT COUNT(*) FROM ips_actions WHERE status = 'active' AND action_type = 'rate_limit') AS rate_limits,
        (SELECT COUNT(*) FROM ips_actions WHERE status = 'active' AND action_type = 'terminate_session') AS terminated_sessions,
        (SELECT COUNT(*) FROM ips_actions) AS total_audit_actions
    `
  );
  return {
    mode: IPS_MODE,
    automatic_host_blocking: AUTOMATIC_HOST_BLOCKING,
    host_firewall_changed: HOST_FIREWALL_CHANGED,
    policy_version: POLICY_VERSION,
    policy: POLICY,
    pending_recommendations: row?.pending_recommendations || 0,
    suppressed_recommendations: row?.suppressed_recommendations || 0,
    simulated_blocks: row?.simulated_blocks || 0,
    rate_limits: row?.rate_limits || 0,
    terminated_sessions: row?.terminated_sessions || 0,
    total_audit_actions: row?.total_audit_actions || 0,
  };
}

async function resolveActionTarget(database, input) {
  if (input.action_type === "release") {
    const target = await get(
      database,
      "SELECT * FROM ips_actions WHERE id = ?",
      [Number(input.related_action_id)]
    );
    if (!target || target.status !== "active" || !ACTIVE_ACTION_TYPES.has(target.action_type)) {
      const error = new Error("Active simulated action was not found");
      error.code = "IPS_TARGET_NOT_FOUND";
      throw error;
    }
    return { action: target, recommendation: null };
  }

  let recommendation = null;
  if (Number.isInteger(Number(input.recommendation_id))) {
    recommendation = await get(
      database,
      "SELECT * FROM ips_recommendations WHERE id = ?",
      [Number(input.recommendation_id)]
    );
  } else if (input.event_id) {
    recommendation = await get(
      database,
      "SELECT * FROM ips_recommendations WHERE event_id = ?",
      [String(input.event_id).trim()]
    );
  }

  if (!recommendation) {
    const error = new Error("IPS recommendation was not found");
    error.code = "IPS_TARGET_NOT_FOUND";
    throw error;
  }
  return { action: null, recommendation };
}

async function syncRuntimeState(database, stateFile = DEFAULT_STATE_FILE) {
  await expireIPSActions(database);
  const active = await all(
    database,
    `
      SELECT * FROM ips_actions
      WHERE status = 'active'
        AND action_type IN ('simulate_block', 'rate_limit', 'terminate_session')
      ORDER BY id ASC
    `
  );

  const base = {
    schema_version: "1.0",
    mode: IPS_MODE,
    automatic_host_blocking: AUTOMATIC_HOST_BLOCKING,
    host_firewall_changed: HOST_FIREWALL_CHANGED,
    generated_at: toISTISOString(),
    simulated_blocks: [],
    rate_limits: [],
    terminated_sessions: [],
  };

  for (const row of active) {
    const value = {
      action_id: row.id,
      event_id: row.event_id,
      source_ip: row.source_ip,
      service: row.service,
      session_id: row.session_id,
      expires_at: row.expires_at,
      rate_limit_delay_ms: row.rate_limit_delay_ms,
      reason: row.reason,
    };
    if (row.action_type === "simulate_block") base.simulated_blocks.push(value);
    if (row.action_type === "rate_limit") base.rate_limits.push(value);
    if (row.action_type === "terminate_session") base.terminated_sessions.push(value);
  }

  fs.mkdirSync(path.dirname(stateFile), { recursive: true });
  fs.writeFileSync(stateFile, `${JSON.stringify(base, null, 2)}\n`, {
    encoding: "utf8",
  });
  return base;
}

async function performIPSAction(
  database,
  input,
  analyst,
  { stateFile = DEFAULT_STATE_FILE } = {}
) {
  const errors = validateIPSActionInput(input);
  if (
    !analyst ||
    !Number.isInteger(analyst.id) ||
    analyst.id < 1 ||
    typeof analyst.username !== "string" ||
    !analyst.username.trim()
  ) {
    errors.push("authenticated analyst identity is required");
  }
  if (errors.length) {
    const error = new Error(errors.join("; "));
    error.code = "INVALID_IPS_ACTION";
    throw error;
  }

  await expireIPSActions(database);
  const { action: targetAction, recommendation } = await resolveActionTarget(database, input);
  const actionType = input.action_type;
  const reason = String(input.reason || "Analyst-approved Step 21 simulated response.").trim();

  if (actionType === "dismiss") {
    await run(
      database,
      "UPDATE ips_recommendations SET status = 'dismissed', updated_at = ? WHERE id = ?",
      [toISTISOString(), recommendation.id]
    );
  }

  if (actionType === "release") {
    await run(
      database,
      "UPDATE ips_actions SET status = 'reversed', updated_at = ? WHERE id = ?",
      [toISTISOString(), targetAction.id]
    );
  }

  const target = targetAction || recommendation;
  if (actionType === "terminate_session" && !target.session_id) {
    const error = new Error("The selected event does not have a honeypot session ID");
    error.code = "INVALID_IPS_ACTION";
    throw error;
  }
  if (recommendation?.feedback_verdict === "false_positive" && ACTIVE_ACTION_TYPES.has(actionType)) {
    const error = new Error("Active response is blocked because the latest analyst verdict is false positive");
    error.code = "IPS_RESPONSE_SUPPRESSED";
    throw error;
  }

  const duration = ACTIVE_ACTION_TYPES.has(actionType)
    ? normalizeDuration(input.duration_seconds, DEFAULT_DURATIONS[actionType])
    : null;
  const expiresAt = duration
    ? toISTISOString(new Date(Date.now() + duration * 1000))
    : null;
  const status = ACTIVE_ACTION_TYPES.has(actionType)
    ? "active"
    : actionType === "dismiss"
      ? "dismissed"
      : "completed";

  if (ACTIVE_ACTION_TYPES.has(actionType)) {
    await run(
      database,
      `
        UPDATE ips_actions
        SET status = 'reversed', updated_at = ?
        WHERE status = 'active'
          AND action_type = ?
          AND source_ip = ?
          AND service = ?
          AND (
            ? != 'terminate_session' OR session_id = ?
          )
      `,
      [toISTISOString(), actionType, target.source_ip, target.service, actionType, target.session_id]
    );
  }

  const inserted = await run(
    database,
    `
      INSERT INTO ips_actions (
        recommendation_id, event_id, source_ip, service, session_id,
        action_type, status, mode, duration_seconds, rate_limit_delay_ms,
        reason, analyst_id, analyst_username, related_action_id, expires_at,
        created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `,
    [
      recommendation?.id || targetAction?.recommendation_id || null,
      target.event_id || null,
      target.source_ip,
      target.service,
      target.session_id || null,
      actionType,
      status,
      IPS_MODE,
      duration,
      actionType === "rate_limit" ? POLICY.rate_limit_delay_ms : null,
      reason,
      analyst.id,
      analyst.username.trim(),
      targetAction?.id || null,
      expiresAt,
      toISTISOString(),
      toISTISOString(),
    ]
  );

  if (recommendation && ACTIVE_ACTION_TYPES.has(actionType)) {
    await run(
      database,
      "UPDATE ips_recommendations SET status = 'executed', updated_at = ? WHERE id = ?",
      [toISTISOString(), recommendation.id]
    );
  }

  const row = await get(database, "SELECT * FROM ips_actions WHERE id = ?", [inserted.lastID]);
  await syncRuntimeState(database, stateFile);
  return actionToJSON(row);
}

async function applyAnalystFeedbackToIPS(
  database,
  eventId,
  feedback,
  { stateFile = DEFAULT_STATE_FILE } = {}
) {
  const recommendation = await upsertIPSRecommendation(database, eventId);
  if (feedback?.verdict === "false_positive") {
    await run(
      database,
      `
        UPDATE ips_actions
        SET status = 'reversed', updated_at = ?
        WHERE event_id = ? AND status = 'active'
      `,
      [toISTISOString(), eventId]
    );
  }
  await syncRuntimeState(database, stateFile);
  return recommendationToJSON(recommendation);
}

module.exports = {
  ACTION_TYPES,
  ACTIVE_ACTION_TYPES,
  AUTOMATIC_HOST_BLOCKING,
  DEFAULT_DURATIONS,
  DEFAULT_STATE_FILE,
  HOST_FIREWALL_CHANGED,
  IPS_MODE,
  MAX_DURATION_SECONDS,
  POLICY,
  POLICY_VERSION,
  applyAnalystFeedbackToIPS,
  backfillIPSRecommendations,
  expireIPSActions,
  getIPSStatus,
  initializeIPSResponseStore,
  listIPSActions,
  listIPSRecommendations,
  performIPSAction,
  policyDecision,
  syncRuntimeState,
  upsertIPSRecommendation,
  validateIPSActionInput,
};
