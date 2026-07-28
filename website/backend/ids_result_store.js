const REQUIRED_IDS_RESULT_FIELDS = [
  "ids_result_schema_version",
  "hybrid_ids_version",
  "event_id",
  "processed_at",
  "timestamp",
  "source_ip",
  "destination_port",
  "service",
  "event_type",
  "event",
  "status",
  "attack_type",
  "prediction",
  "confidence",
  "anomaly_score",
  "model_used",
  "threat_reporting_version",
  "threat_level",
  "threat_score",
  "threat_factors",
  "components",
  "fusion_reason",
  "xai",
  "safety",
  "integration",
];

const ALLOWED_SERVICES = new Set(["ssh", "ftp", "http"]);
const ALLOWED_PREDICTIONS = new Set(["normal", "attack"]);
const ALLOWED_THREAT_LEVELS = new Set(["Low", "Medium", "High", "Critical"]);

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isFiniteNumber(value) {
  return typeof value === "number" && Number.isFinite(value);
}

function validateIDSResult(record) {
  if (!isObject(record)) {
    return ["IDS result must be a JSON object"];
  }

  const errors = [];
  const missing = REQUIRED_IDS_RESULT_FIELDS.filter(
    (field) => !Object.prototype.hasOwnProperty.call(record, field)
  );
  if (missing.length > 0) {
    errors.push(`missing fields: ${missing.join(", ")}`);
  }

  if (record.ids_result_schema_version !== "1.0") {
    errors.push("unsupported ids_result_schema_version");
  }
  if (!ALLOWED_SERVICES.has(record.service)) {
    errors.push("service must be ssh, ftp or http");
  }
  if (!ALLOWED_PREDICTIONS.has(record.prediction)) {
    errors.push("prediction must be normal or attack");
  }
  if (!ALLOWED_THREAT_LEVELS.has(record.threat_level)) {
    errors.push("threat_level must be Low, Medium, High or Critical");
  }

  for (const field of [
    "hybrid_ids_version",
    "event_id",
    "processed_at",
    "timestamp",
    "source_ip",
    "event_type",
    "event",
    "status",
    "attack_type",
    "model_used",
    "threat_reporting_version",
    "fusion_reason",
  ]) {
    if (typeof record[field] !== "string" || !record[field].trim()) {
      errors.push(`${field} must be a non-empty string`);
    }
  }

  if (
    typeof record.event_id === "string" &&
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
      record.event_id
    )
  ) {
    errors.push("event_id must be a UUID");
  }
  for (const field of ["processed_at", "timestamp"]) {
    if (typeof record[field] === "string" && Number.isNaN(Date.parse(record[field]))) {
      errors.push(`${field} must be ISO-8601`);
    }
  }

  if (
    record.destination_port !== null &&
    (!Number.isInteger(record.destination_port) ||
      record.destination_port < 0 ||
      record.destination_port > 65535)
  ) {
    errors.push("destination_port must be a valid port or null");
  }
  for (const field of ["request_method", "request_path"]) {
    if (
      Object.prototype.hasOwnProperty.call(record, field) &&
      record[field] !== null &&
      typeof record[field] !== "string"
    ) {
      errors.push(`${field} must be a string or null`);
    }
  }

  if (
    record.confidence !== null &&
    (!isFiniteNumber(record.confidence) ||
      record.confidence < 0 ||
      record.confidence > 1)
  ) {
    errors.push("confidence must be between 0 and 1 or null");
  }
  if (!isFiniteNumber(record.anomaly_score)) {
    errors.push("anomaly_score must be a finite number");
  }
  if (
    !Number.isInteger(record.threat_score) ||
    record.threat_score < 0 ||
    record.threat_score > 100
  ) {
    errors.push("threat_score must be an integer from 0 to 100");
  }

  if (!Array.isArray(record.threat_factors)) {
    errors.push("threat_factors must be an array");
  }
  for (const field of ["components", "xai", "safety", "integration"]) {
    if (!isObject(record[field])) {
      errors.push(`${field} must be a JSON object`);
    }
  }

  if (isObject(record.xai)) {
    if (!isObject(record.xai.shap)) {
      errors.push("xai.shap must be a JSON object");
    }
    if (
      !isObject(record.xai.human_reason) ||
      typeof record.xai.human_reason.summary !== "string" ||
      !record.xai.human_reason.summary.trim()
    ) {
      errors.push("xai.human_reason.summary must be non-empty");
    }
    if (
      !isObject(record.xai.privacy) ||
      record.xai.privacy.raw_payload_included !== false ||
      record.xai.privacy.source_ip_included !== false ||
      record.xai.privacy.credentials_included !== false
    ) {
      errors.push("XAI privacy flags must remain false");
    }
  }

  if (
    isObject(record.safety) &&
    (record.safety.model_fit_called !== false ||
      record.safety.protected_artifacts_modified !== false ||
      record.safety.xai_changed_prediction !== false)
  ) {
    errors.push("IDS safety flags must remain false");
  }
  if (
    isObject(record.integration) &&
    (record.integration.raw_payload_included !== false ||
      record.integration.credentials_included !== false ||
      record.integration.producer_attack_type_used_as_prediction !== false)
  ) {
    errors.push("integration safety flags must remain false");
  }

  return errors;
}

function initializeIDSResultStore(database) {
  database.serialize(() => {
    database.run(`
      CREATE TABLE IF NOT EXISTS ids_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id TEXT UNIQUE NOT NULL,
        ids_result_schema_version TEXT NOT NULL,
        hybrid_ids_version TEXT NOT NULL,
        processed_at TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        source_ip TEXT NOT NULL,
        destination_port INTEGER,
        service TEXT NOT NULL,
        event_type TEXT NOT NULL,
        event TEXT NOT NULL,
        status TEXT NOT NULL,
        request_method TEXT,
        request_path TEXT,
        attack_type TEXT NOT NULL,
        prediction TEXT NOT NULL,
        confidence REAL,
        anomaly_score REAL NOT NULL,
        model_used TEXT NOT NULL,
        threat_reporting_version TEXT NOT NULL,
        threat_level TEXT NOT NULL,
        threat_score INTEGER NOT NULL,
        threat_factors_json TEXT NOT NULL,
        components_json TEXT NOT NULL,
        fusion_reason TEXT NOT NULL,
        xai_json TEXT NOT NULL,
        safety_json TEXT NOT NULL,
        integration_json TEXT NOT NULL,
        received_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    database.run(
      "CREATE INDEX IF NOT EXISTS idx_ids_results_timestamp ON ids_results(timestamp DESC)"
    );
    database.run(
      "CREATE INDEX IF NOT EXISTS idx_ids_results_service ON ids_results(service)"
    );
    database.run(
      "CREATE INDEX IF NOT EXISTS idx_ids_results_attack_type ON ids_results(attack_type)"
    );
    database.run(
      "CREATE INDEX IF NOT EXISTS idx_ids_results_threat_level ON ids_results(threat_level)"
    );
    database.run(
      "CREATE INDEX IF NOT EXISTS idx_ids_results_prediction ON ids_results(prediction)"
    );
  });
}

function insertIDSResult(database, record) {
  const errors = validateIDSResult(record);
  if (errors.length > 0) {
    const error = new Error(errors.join("; "));
    error.code = "INVALID_IDS_RESULT";
    return Promise.reject(error);
  }

  const sql = `
    INSERT OR IGNORE INTO ids_results (
      event_id, ids_result_schema_version, hybrid_ids_version, processed_at,
      timestamp, source_ip, destination_port, service, event_type, event,
      status, request_method, request_path, attack_type, prediction,
      confidence, anomaly_score, model_used, threat_reporting_version,
      threat_level, threat_score, threat_factors_json, components_json,
      fusion_reason, xai_json, safety_json, integration_json
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
              ?, ?, ?, ?, ?, ?)
  `;

  const params = [
    record.event_id,
    record.ids_result_schema_version,
    record.hybrid_ids_version,
    record.processed_at,
    record.timestamp,
    record.source_ip,
    record.destination_port,
    record.service,
    record.event_type,
    record.event,
    record.status,
    record.request_method ?? null,
    record.request_path ?? null,
    record.attack_type,
    record.prediction,
    record.confidence,
    record.anomaly_score,
    record.model_used,
    record.threat_reporting_version,
    record.threat_level,
    record.threat_score,
    JSON.stringify(record.threat_factors),
    JSON.stringify(record.components),
    record.fusion_reason,
    JSON.stringify(record.xai),
    JSON.stringify(record.safety),
    JSON.stringify(record.integration),
  ];

  return new Promise((resolve, reject) => {
    database.run(sql, params, function onInsert(error) {
      if (error) {
        reject(error);
        return;
      }
      if (this.changes === 1) {
        resolve({ inserted: true, id: this.lastID, event_id: record.event_id });
        return;
      }

      database.get(
        "SELECT id FROM ids_results WHERE event_id = ?",
        [record.event_id],
        (selectError, row) => {
          if (selectError) {
            reject(selectError);
            return;
          }
          resolve({
            inserted: false,
            id: row?.id ?? null,
            event_id: record.event_id,
          });
        }
      );
    });
  });
}

function parseJson(value, fallback) {
  try {
    return JSON.parse(value);
  } catch (_error) {
    return fallback;
  }
}

function rowToIDSResult(row) {
  return {
    database_id: row.id,
    ids_result_schema_version: row.ids_result_schema_version,
    hybrid_ids_version: row.hybrid_ids_version,
    event_id: row.event_id,
    processed_at: row.processed_at,
    timestamp: row.timestamp,
    source_ip: row.source_ip,
    destination_port: row.destination_port,
    service: row.service,
    event_type: row.event_type,
    event: row.event,
    status: row.status,
    request_method: row.request_method,
    request_path: row.request_path,
    attack_type: row.attack_type,
    prediction: row.prediction,
    confidence: row.confidence,
    anomaly_score: row.anomaly_score,
    model_used: row.model_used,
    threat_reporting_version: row.threat_reporting_version,
    threat_level: row.threat_level,
    threat_score: row.threat_score,
    threat_factors: parseJson(row.threat_factors_json, []),
    components: parseJson(row.components_json, {}),
    fusion_reason: row.fusion_reason,
    xai: parseJson(row.xai_json, {}),
    safety: parseJson(row.safety_json, {}),
    integration: parseJson(row.integration_json, {}),
    received_at: row.received_at,
  };
}

function listIDSResults(database, filters = {}) {
  const where = [];
  const params = [];
  for (const [column, value] of [
    ["service", filters.service],
    ["prediction", filters.prediction],
    ["threat_level", filters.threatLevel],
    ["attack_type", filters.attackType],
    ["model_used", filters.modelUsed],
  ]) {
    if (value) {
      where.push(`${column} = ?`);
      params.push(value);
    }
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

  const sql = `
    SELECT * FROM ids_results
    ${where.length > 0 ? `WHERE ${where.join(" AND ")}` : ""}
    ORDER BY timestamp DESC, id DESC
    LIMIT ? OFFSET ?
  `;
  return new Promise((resolve, reject) => {
    database.all(sql, params, (error, rows) => {
      if (error) {
        reject(error);
        return;
      }
      resolve(rows.map(rowToIDSResult));
    });
  });
}

function allRows(database, sql) {
  return new Promise((resolve, reject) => {
    database.all(sql, [], (error, rows) => {
      if (error) {
        reject(error);
        return;
      }
      resolve(rows);
    });
  });
}

async function getIDSResultStats(database) {
  const [
    totalRows,
    attackRows,
    uniqueIpRows,
    serviceRows,
    attackTypeRows,
    threatRows,
    modelRows,
  ] = await Promise.all([
    allRows(database, "SELECT COUNT(*) AS count FROM ids_results"),
    allRows(
      database,
      "SELECT COUNT(*) AS count FROM ids_results WHERE prediction = 'attack'"
    ),
    allRows(database, "SELECT COUNT(DISTINCT source_ip) AS count FROM ids_results"),
    allRows(
      database,
      "SELECT service AS name, COUNT(*) AS count FROM ids_results GROUP BY service"
    ),
    allRows(
      database,
      "SELECT attack_type AS name, COUNT(*) AS count FROM ids_results GROUP BY attack_type"
    ),
    allRows(
      database,
      "SELECT threat_level AS name, COUNT(*) AS count FROM ids_results GROUP BY threat_level"
    ),
    allRows(
      database,
      "SELECT model_used AS name, COUNT(*) AS count FROM ids_results GROUP BY model_used"
    ),
  ]);

  const toObject = (rows) =>
    Object.fromEntries(rows.map((row) => [row.name, row.count]));

  return {
    total_results: totalRows[0]?.count || 0,
    attacks_detected: attackRows[0]?.count || 0,
    unique_ips: uniqueIpRows[0]?.count || 0,
    by_service: toObject(serviceRows),
    by_attack_type: toObject(attackTypeRows),
    by_threat_level: toObject(threatRows),
    by_model: toObject(modelRows),
  };
}

module.exports = {
  REQUIRED_IDS_RESULT_FIELDS,
  getIDSResultStats,
  initializeIDSResultStore,
  insertIDSResult,
  listIDSResults,
  validateIDSResult,
};
