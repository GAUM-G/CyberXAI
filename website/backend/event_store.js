const REQUIRED_EVENT_FIELDS = [
  "schema_version",
  "event_id",
  "timestamp",
  "source_ip",
  "source_port",
  "destination_port",
  "service",
  "protocol",
  "event_type",
  "event",
  "attack_type",
  "severity",
  "status",
  "username",
  "session_id",
  "request_method",
  "request_path",
  "payload",
  "metadata",
];

const ALLOWED_SERVICES = new Set(["ssh", "ftp", "http"]);
const ALLOWED_SEVERITIES = new Set(["info", "warning", "critical"]);
const { toISTISOString } = require("./time");

function validateEventRecord(record) {
  const errors = [];

  if (!record || typeof record !== "object" || Array.isArray(record)) {
    return ["event must be a JSON object"];
  }

  const missing = REQUIRED_EVENT_FIELDS.filter(
    (field) => !Object.prototype.hasOwnProperty.call(record, field)
  );
  if (missing.length > 0) {
    errors.push(`missing fields: ${missing.join(", ")}`);
  }

  if (record.schema_version !== "1.0") {
    errors.push("unsupported schema_version");
  }
  if (!ALLOWED_SERVICES.has(record.service)) {
    errors.push("service must be ssh, ftp or http");
  }
  if (!ALLOWED_SEVERITIES.has(record.severity)) {
    errors.push("severity must be info, warning or critical");
  }

  for (const field of [
    "event_id",
    "timestamp",
    "source_ip",
    "protocol",
    "event_type",
    "event",
    "attack_type",
    "status",
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
  if (typeof record.timestamp === "string" && Number.isNaN(Date.parse(record.timestamp))) {
    errors.push("timestamp must be ISO-8601");
  }
  if (record.protocol !== record.service) {
    errors.push("protocol must match service");
  }

  for (const field of ["source_port", "destination_port"]) {
    const value = record[field];
    if (value !== null && (!Number.isInteger(value) || value < 0 || value > 65535)) {
      errors.push(`${field} must be a valid port or null`);
    }
  }

  if (
    record.metadata === null ||
    typeof record.metadata !== "object" ||
    Array.isArray(record.metadata)
  ) {
    errors.push("metadata must be a JSON object");
  }

  for (const field of [
    "username",
    "session_id",
    "request_method",
    "request_path",
  ]) {
    if (record[field] !== null && typeof record[field] !== "string") {
      errors.push(`${field} must be a string or null`);
    }
  }

  return errors;
}

function initializeEventStore(database) {
  database.serialize(() => {
    database.run(`
      CREATE TABLE IF NOT EXISTS honeypot_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id TEXT UNIQUE NOT NULL,
        schema_version TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        source_ip TEXT NOT NULL,
        source_port INTEGER,
        destination_port INTEGER,
        service TEXT NOT NULL,
        protocol TEXT NOT NULL,
        event_type TEXT NOT NULL,
        event TEXT NOT NULL,
        attack_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        status TEXT NOT NULL,
        username TEXT,
        session_id TEXT,
        request_method TEXT,
        request_path TEXT,
        payload_json TEXT NOT NULL,
        metadata_json TEXT NOT NULL,
        received_at TEXT NOT NULL
      )
    `);

    database.run(
      "CREATE INDEX IF NOT EXISTS idx_honeypot_events_timestamp ON honeypot_events(timestamp DESC)"
    );
    database.run(
      "CREATE INDEX IF NOT EXISTS idx_honeypot_events_service ON honeypot_events(service)"
    );
    database.run(
      "CREATE INDEX IF NOT EXISTS idx_honeypot_events_severity ON honeypot_events(severity)"
    );
    database.run(
      "CREATE INDEX IF NOT EXISTS idx_honeypot_events_attack_type ON honeypot_events(attack_type)"
    );
  });
}

function insertEvent(database, record) {
  const errors = validateEventRecord(record);
  if (errors.length > 0) {
    const error = new Error(errors.join("; "));
    error.code = "INVALID_EVENT";
    return Promise.reject(error);
  }

  const sql = `
    INSERT OR IGNORE INTO honeypot_events (
      event_id, schema_version, timestamp, source_ip, source_port,
      destination_port, service, protocol, event_type, event,
      attack_type, severity, status, username, session_id,
      request_method, request_path, payload_json, metadata_json, received_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `;

  const params = [
    record.event_id,
    record.schema_version,
    record.timestamp,
    record.source_ip,
    record.source_port,
    record.destination_port,
    record.service,
    record.protocol,
    record.event_type,
    record.event,
    record.attack_type,
    record.severity,
    record.status,
    record.username,
    record.session_id,
    record.request_method,
    record.request_path,
    JSON.stringify(record.payload ?? null),
    JSON.stringify(record.metadata),
    toISTISOString(),
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
        "SELECT id FROM honeypot_events WHERE event_id = ?",
        [record.event_id],
        (selectError, row) => {
          if (selectError) {
            reject(selectError);
            return;
          }
          resolve({ inserted: false, id: row?.id ?? null, event_id: record.event_id });
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

function rowToEvent(row) {
  return {
    database_id: row.id,
    schema_version: row.schema_version,
    event_id: row.event_id,
    timestamp: row.timestamp,
    source_ip: row.source_ip,
    source_port: row.source_port,
    destination_port: row.destination_port,
    service: row.service,
    protocol: row.protocol,
    event_type: row.event_type,
    event: row.event,
    attack_type: row.attack_type,
    severity: row.severity,
    status: row.status,
    username: row.username,
    session_id: row.session_id,
    request_method: row.request_method,
    request_path: row.request_path,
    payload: parseJson(row.payload_json, null),
    metadata: parseJson(row.metadata_json, {}),
    received_at: row.received_at,
  };
}

function listEvents(database, filters = {}) {
  const where = [];
  const params = [];

  for (const [column, value] of [
    ["service", filters.service],
    ["severity", filters.severity],
    ["event_type", filters.eventType],
    ["attack_type", filters.attackType],
  ]) {
    if (value) {
      where.push(`${column} = ?`);
      params.push(value);
    }
  }

  const requestedLimit = Number(filters.limit || 100);
  const limit = Math.max(1, Math.min(Number.isFinite(requestedLimit) ? requestedLimit : 100, 1000));
  const requestedOffset = Number(filters.offset || 0);
  const offset = Math.max(
    0, Math.floor(Number.isFinite(requestedOffset) ? requestedOffset : 0)
  );
  params.push(limit, offset);

  const sql = `
    SELECT * FROM honeypot_events
    ${where.length > 0 ? `WHERE ${where.join(" AND ")}` : ""}
    ORDER BY datetime(timestamp) DESC, id DESC
    LIMIT ? OFFSET ?
  `;

  return new Promise((resolve, reject) => {
    database.all(sql, params, (error, rows) => {
      if (error) {
        reject(error);
        return;
      }
      resolve(rows.map(rowToEvent));
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

async function getEventStats(database) {
  const [totalRows, serviceRows, severityRows, attackRows] = await Promise.all([
    allRows(database, "SELECT COUNT(*) AS count FROM honeypot_events"),
    allRows(database, "SELECT service AS name, COUNT(*) AS count FROM honeypot_events GROUP BY service"),
    allRows(database, "SELECT severity AS name, COUNT(*) AS count FROM honeypot_events GROUP BY severity"),
    allRows(database, "SELECT attack_type AS name, COUNT(*) AS count FROM honeypot_events GROUP BY attack_type"),
  ]);

  const toObject = (rows) =>
    Object.fromEntries(rows.map((row) => [row.name, row.count]));

  return {
    total_events: totalRows[0]?.count || 0,
    by_service: toObject(serviceRows),
    by_severity: toObject(severityRows),
    by_attack_type: toObject(attackRows),
  };
}

module.exports = {
  REQUIRED_EVENT_FIELDS,
  getEventStats,
  initializeEventStore,
  insertEvent,
  listEvents,
  validateEventRecord,
};
