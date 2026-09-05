const { randomUUID } = require("node:crypto");

const { toISTISOString } = require("./time");

const ATTACK_TYPES = new Set([
  "sql_injection",
  "xss",
  "directory_scanning",
  "http_bruteforce",
]);

function toPort(value) {
  if (value === null || value === undefined || value === "") {
    return null;
  }
  const port = Number(value);
  return Number.isInteger(port) && port >= 0 && port <= 65535 ? port : null;
}

function normalizeSourceIp(value) {
  const ip = String(value || "127.0.0.1").trim();
  if (ip === "::1") {
    return "127.0.0.1";
  }
  return ip.startsWith("::ffff:") ? ip.slice(7) : ip;
}

function deriveEventType(event, attackType) {
  if (ATTACK_TYPES.has(attackType)) {
    return "attack";
  }
  if (String(event).includes("login")) {
    return "authentication";
  }
  if (String(event).includes("file")) {
    return "file_access";
  }
  return "request";
}

function deriveStatus(metadata, attackType) {
  if (metadata.status !== null && metadata.status !== undefined && metadata.status !== "") {
    return String(metadata.status).toLowerCase();
  }
  return ATTACK_TYPES.has(attackType) ? "detected" : "observed";
}

function buildCommonEvent({
  sourceIp,
  event,
  attackType = "web_activity",
  payload = null,
  metadata = {},
  severity = "info",
  destinationPort = 5173,
}) {
  const context = metadata && typeof metadata === "object" && !Array.isArray(metadata)
    ? { ...metadata }
    : {};
  const requestMethod = context.method ? String(context.method).toUpperCase() : null;
  const requestPath = context.path || context.route || context.target || null;
  const username = context.username || context.user || null;

  return {
    schema_version: "1.0",
    event_id: randomUUID(),
    timestamp: toISTISOString(),
    source_ip: normalizeSourceIp(sourceIp),
    source_port: toPort(
      context.source_port ?? context.sourcePort ?? context.remote_port ?? context.remotePort
    ),
    destination_port: toPort(
      context.destination_port ?? context.destinationPort ?? destinationPort
    ),
    service: "http",
    protocol: "http",
    event_type: deriveEventType(event, attackType),
    event: String(event || "website_request"),
    attack_type: String(attackType || "web_activity"),
    severity,
    status: deriveStatus(context, attackType),
    username: username === null ? null : String(username),
    session_id: String(context.session_id || context.sessionId || randomUUID()),
    request_method: requestMethod,
    request_path: requestPath === null ? null : String(requestPath),
    payload,
    metadata: context,
  };
}

module.exports = {
  ATTACK_TYPES,
  buildCommonEvent,
  normalizeSourceIp,
};
