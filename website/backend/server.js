require("dotenv").config();

const express = require("express");
const cors = require("cors");
const path = require("path");
const fs = require("fs");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const db = require("./db");
const { toISTISOString } = require("./time");
const {
  getEventStats,
  insertEvent,
  listEvents,
  validateEventRecord,
} = require("./event_store");
const {
  getIDSResultStats,
  insertIDSResult,
  listIDSResults,
  validateIDSResult,
} = require("./ids_result_store");
const {
  getFeedbackStats,
  getLatestFeedbackByEvent,
  insertAnalystFeedback,
  listAnalystFeedback,
  validateFeedbackInput,
} = require("./analyst_feedback_store");
const {
  AUTOMATIC_HOST_BLOCKING,
  HOST_FIREWALL_CHANGED,
  IPS_MODE,
  POLICY_VERSION,
  applyAnalystFeedbackToIPS,
  backfillIPSRecommendations,
  getIPSStatus,
  listIPSActions,
  listIPSRecommendations,
  performIPSAction,
  syncRuntimeState,
  upsertIPSRecommendation,
  validateIPSActionInput,
} = require("./ips_response_store");
const { requireAuth } = require("./middleware/auth");
const { requireDashboardAccess } = require("./middleware/dashboard_access");
const { buildCommonEvent } = require("./common_event");
const {
  buildDecoyExposure,
  buildExposureAudit,
  detectAttack,
  searchDecoyRecords,
} = require("./decoy_simulation");

const app = express();
const PORT = Number(process.env.PORT || 5000);

const allowedFrontendOrigins = new Set([
  "http://localhost:5173",
  "http://127.0.0.1:5173",
  ...String(process.env.FRONTEND_URL || "")
    .split(",")
    .map((origin) => origin.trim())
    .filter(Boolean),
]);

app.use(cors({
  origin(origin, callback) {
    if (!origin || allowedFrontendOrigins.has(origin)) {
      return callback(null, true);
    }
    return callback(new Error("Frontend origin is not allowed by CORS"));
  },
}));
app.use(express.json());

const decoyDir = path.join(__dirname, "..", "decoy_files");
const logDir = path.join(__dirname, "logs");
const backendLogFile = path.join(logDir, "events.log");
const frontendLogFile = path.join(logDir, "frontend-events.log");
const honeypotLogDir = path.join(__dirname, "..", "..", "data", "raw_logs");
const honeypotLogFile = path.join(honeypotLogDir, "honeypot_events.jsonl");

if (!fs.existsSync(logDir)) {
  fs.mkdirSync(logDir, { recursive: true });
}

if (!fs.existsSync(honeypotLogDir)) {
  fs.mkdirSync(honeypotLogDir, { recursive: true });
}

function appendJsonLog(filePath, event, details) {
  const line = JSON.stringify({ timestamp: toISTISOString(), event, details });
  fs.appendFile(filePath, `${line}\n`, () => {});
}

function pickRequestHeaders(req) {
  const wanted = [
    "user-agent",
    "referer",
    "origin",
    "host",
    "x-forwarded-for",
    "x-real-ip",
    "accept",
    "accept-language",
    "content-type",
    "content-length",
    "cookie",
    "authorization",
  ];

  const headers = {};
  for (const key of wanted) {
    if (req.headers[key]) {
      headers[key] = req.headers[key];
    }
  }
  return headers;
}

function writeHoneypotEvent({ sourceIp, event, attackType, payload, metadata, severity = "info" }) {
  const record = buildCommonEvent({
    sourceIp,
    event,
    attackType,
    payload,
    metadata,
    severity,
  });
  fs.appendFile(honeypotLogFile, `${JSON.stringify(record)}\n`, () => {});
  insertEvent(db, record).catch((error) => {
    console.error("[Event Store] Portal telemetry insert failed:", error.message);
  });
}

function logEvent(event, details) {
  appendJsonLog(backendLogFile, event, details);

  const attackType = details?.attackType || "web_activity";
  const severity = attackType === "web_activity" ? "info" : "warning";
  writeHoneypotEvent({
    sourceIp: details?.ip,
    event,
    attackType,
    payload: details?.payload ?? details?.query ?? null,
    metadata: details,
    severity,
  });
}

function logFrontendEvent(event, details) {
  appendJsonLog(frontendLogFile, event, details);

  const attackType = details?.findings?.[0] || "web_activity";
  const severity = attackType === "web_activity" ? "info" : "warning";
  writeHoneypotEvent({
    sourceIp: details?.ip,
    event,
    attackType,
    payload: details?.path || null,
    metadata: details,
    severity,
  });
}

function sanitizeBody(body) {
  if (!body || typeof body !== "object") {
    return body;
  }

  return body;
}

function readRecentLogEntries(filePath, limit) {
  if (!fs.existsSync(filePath)) {
    return [];
  }

  const content = fs.readFileSync(filePath, "utf8");
  const lines = content
    .split(/\r?\n/)
    .filter(Boolean)
    .slice(-limit);

  return lines
    .map((line) => {
      try {
        return JSON.parse(line);
      } catch (_err) {
        return { raw: line };
      }
    })
    .reverse();
}

app.use((req, res, next) => {
  const startedAt = Date.now();

  res.on("finish", () => {
    if (
      req.path.startsWith("/logs") ||
      req.path.startsWith("/api/events") ||
      req.path.startsWith("/api/ids-results") ||
      req.path.startsWith("/api/analyst-feedback") ||
      req.path.startsWith("/api/ips") ||
      req.path.startsWith("/api/auth") ||
      req.path.startsWith("/api/decoy") ||
      req.path === "/frontend/log" ||
      req.path === "/search" ||
      req.path === "/login" ||
      req.path === "/signup" ||
      req.path.startsWith("/files/")
    ) {
      return;
    }

    logEvent("backend_request", {
      method: req.method,
      path: req.path,
      status: res.statusCode,
      durationMs: Date.now() - startedAt,
      ip: req.ip,
      remotePort: req.socket?.remotePort,
      remoteAddress: req.socket?.remoteAddress,
      protocol: req.protocol,
      httpVersion: req.httpVersion,
      userAgent: req.get("user-agent") || "unknown",
      referer: req.get("referer") || "",
      origin: req.get("origin") || "",
      host: req.get("host") || "",
      headers: pickRequestHeaders(req),
      query: req.query,
      body: sanitizeBody(req.body),
    });
  });

  next();
});

app.post("/api/events", async (req, res) => {
  const errors = validateEventRecord(req.body);
  if (errors.length > 0) {
    return res.status(400).json({
      stored: false,
      error: "Invalid common event",
      details: errors,
    });
  }

  try {
    const result = await insertEvent(db, req.body);
    return res.status(result.inserted ? 201 : 200).json({
      stored: true,
      duplicate: !result.inserted,
      database_id: result.id,
      event_id: result.event_id,
    });
  } catch (error) {
    console.error("[Event Store] Insert failed:", error.message);
    return res.status(500).json({ stored: false, error: "Could not store event" });
  }
});

app.get("/api/events", requireDashboardAccess, async (req, res) => {
  try {
    const events = await listEvents(db, {
      limit: req.query.limit,
      offset: req.query.offset,
      service: req.query.service,
      severity: req.query.severity,
      eventType: req.query.event_type,
      attackType: req.query.attack_type,
    });
    return res.json({ source: "sqlite", count: events.length, events });
  } catch (error) {
    console.error("[Event Store] Query failed:", error.message);
    return res.status(500).json({ error: "Could not read centralized events" });
  }
});

app.get("/api/events/stats", requireDashboardAccess, async (_req, res) => {
  try {
    const stats = await getEventStats(db);
    return res.json({ source: "sqlite", ...stats });
  } catch (error) {
    console.error("[Event Store] Stats failed:", error.message);
    return res.status(500).json({ error: "Could not calculate event statistics" });
  }
});

app.post("/api/ids-results", async (req, res) => {
  const errors = validateIDSResult(req.body);
  if (errors.length > 0) {
    return res.status(400).json({
      stored: false,
      error: "Invalid IDS result",
      details: errors,
    });
  }

  try {
    const result = await insertIDSResult(db, req.body);
    let ipsRecommendation = null;
    try {
      ipsRecommendation = await upsertIPSRecommendation(db, result.event_id);
    } catch (ipsError) {
      console.error("[Simulated IPS] Recommendation failed:", ipsError.message);
    }
    return res.status(result.inserted ? 201 : 200).json({
      stored: true,
      duplicate: !result.inserted,
      database_id: result.id,
      event_id: result.event_id,
      ips_recommendation: ipsRecommendation,
    });
  } catch (error) {
    console.error("[IDS Result Store] Insert failed:", error.message);
    return res.status(500).json({
      stored: false,
      error: "Could not store IDS result",
    });
  }
});

app.get("/api/ids-results", requireDashboardAccess, async (req, res) => {
  try {
    const results = await listIDSResults(db, {
      limit: req.query.limit,
      offset: req.query.offset,
      service: req.query.service,
      prediction: req.query.prediction,
      threatLevel: req.query.threat_level,
      attackType: req.query.attack_type,
      modelUsed: req.query.model_used,
    });
    return res.json({ source: "sqlite", count: results.length, results });
  } catch (error) {
    console.error("[IDS Result Store] Query failed:", error.message);
    return res.status(500).json({ error: "Could not read IDS results" });
  }
});

app.get("/api/ids-results/stats", requireDashboardAccess, async (_req, res) => {
  try {
    const stats = await getIDSResultStats(db);
    return res.json({ source: "sqlite", ...stats });
  } catch (error) {
    console.error("[IDS Result Store] Stats failed:", error.message);
    return res.status(500).json({
      error: "Could not calculate IDS result statistics",
    });
  }
});

app.get("/api/analyst-feedback", requireDashboardAccess, async (req, res) => {
  try {
    const feedback = await listAnalystFeedback(db, {
      eventId: req.query.event_id,
      verdict: req.query.verdict,
      limit: req.query.limit,
      offset: req.query.offset,
    });
    return res.json({ source: "sqlite", count: feedback.length, feedback });
  } catch (error) {
    console.error("[Analyst Feedback] Query failed:", error.message);
    return res.status(500).json({ error: "Could not read analyst feedback" });
  }
});

app.get("/api/analyst-feedback/latest", requireDashboardAccess, async (req, res) => {
  const eventIds = String(req.query.event_ids || "")
    .split(",")
    .map((eventId) => eventId.trim())
    .filter(Boolean);
  if (eventIds.length > 100) {
    return res.status(400).json({ error: "At most 100 event IDs are allowed" });
  }

  try {
    const latest_by_event = await getLatestFeedbackByEvent(db, eventIds);
    return res.json({ source: "sqlite", latest_by_event });
  } catch (error) {
    console.error("[Analyst Feedback] Latest query failed:", error.message);
    return res.status(500).json({ error: "Could not read latest analyst feedback" });
  }
});

app.get("/api/analyst-feedback/stats", requireDashboardAccess, async (_req, res) => {
  try {
    const stats = await getFeedbackStats(db);
    return res.json({ source: "sqlite", ...stats });
  } catch (error) {
    console.error("[Analyst Feedback] Stats failed:", error.message);
    return res.status(500).json({ error: "Could not calculate feedback statistics" });
  }
});

app.post("/api/analyst-feedback/:eventId", requireDashboardAccess, async (req, res) => {
  const errors = validateFeedbackInput(req.body);
  if (errors.length > 0) {
    return res.status(400).json({
      stored: false,
      error: "Invalid analyst feedback",
      details: errors,
    });
  }

  try {
    const feedback = await insertAnalystFeedback(
      db,
      req.params.eventId,
      req.body,
      {
        id: req.user.userId,
        username: req.user.username,
      }
    );
    let ipsRecommendation = null;
    try {
      ipsRecommendation = await applyAnalystFeedbackToIPS(
        db,
        req.params.eventId,
        feedback
      );
    } catch (ipsError) {
      console.error("[Simulated IPS] Feedback recalculation failed:", ipsError.message);
    }
    const stats = await getFeedbackStats(db);
    return res.status(201).json({
      stored: true,
      feedback,
      stats,
      ips_recommendation: ipsRecommendation,
    });
  } catch (error) {
    if (error.code === "IDS_RESULT_NOT_FOUND") {
      return res.status(404).json({ stored: false, error: error.message });
    }
    if (error.code === "INVALID_ANALYST_FEEDBACK") {
      return res.status(400).json({
        stored: false,
        error: "Invalid analyst feedback",
        details: String(error.message).split("; "),
      });
    }
    console.error("[Analyst Feedback] Insert failed:", error.message);
    return res.status(500).json({ stored: false, error: "Could not store feedback" });
  }
});

app.get("/api/ips/safety", requireDashboardAccess, (_req, res) => {
  return res.json({
    mode: IPS_MODE,
    automatic_host_blocking: AUTOMATIC_HOST_BLOCKING,
    host_firewall_changed: HOST_FIREWALL_CHANGED,
    policy_version: POLICY_VERSION,
  });
});

app.get("/api/ips/status", requireDashboardAccess, async (_req, res) => {
  try {
    const status = await getIPSStatus(db);
    return res.json({ source: "sqlite", ...status });
  } catch (error) {
    console.error("[Simulated IPS] Status failed:", error.message);
    return res.status(500).json({ error: "Could not calculate IPS status" });
  }
});

app.get("/api/ips/recommendations", requireDashboardAccess, async (req, res) => {
  try {
    const recommendations = await listIPSRecommendations(db, {
      status: req.query.status,
      sourceIp: req.query.source_ip,
      service: req.query.service,
      eventId: req.query.event_id,
      limit: req.query.limit,
    });
    return res.json({
      source: "sqlite",
      count: recommendations.length,
      recommendations,
    });
  } catch (error) {
    console.error("[Simulated IPS] Recommendation query failed:", error.message);
    return res.status(500).json({ error: "Could not read IPS recommendations" });
  }
});

app.get("/api/ips/actions", requireDashboardAccess, async (req, res) => {
  try {
    const actions = await listIPSActions(db, {
      status: req.query.status,
      actionType: req.query.action_type,
      sourceIp: req.query.source_ip,
      eventId: req.query.event_id,
      limit: req.query.limit,
    });
    return res.json({ source: "sqlite", count: actions.length, actions });
  } catch (error) {
    console.error("[Simulated IPS] Action query failed:", error.message);
    return res.status(500).json({ error: "Could not read IPS audit actions" });
  }
});

app.post("/api/ips/actions", requireDashboardAccess, async (req, res) => {
  const errors = validateIPSActionInput(req.body);
  if (errors.length > 0) {
    return res.status(400).json({
      executed: false,
      error: "Invalid simulated IPS action",
      details: errors,
    });
  }

  try {
    const action = await performIPSAction(db, req.body, {
      id: req.user.userId,
      username: req.user.username,
    });
    const status = await getIPSStatus(db);
    return res.status(201).json({
      executed: true,
      action,
      status,
      safety: {
        mode: IPS_MODE,
        automatic_host_blocking: AUTOMATIC_HOST_BLOCKING,
        host_firewall_changed: HOST_FIREWALL_CHANGED,
      },
    });
  } catch (error) {
    if (error.code === "INVALID_IPS_ACTION") {
      return res.status(400).json({ executed: false, error: error.message });
    }
    if (error.code === "IPS_TARGET_NOT_FOUND") {
      return res.status(404).json({ executed: false, error: error.message });
    }
    if (error.code === "IPS_RESPONSE_SUPPRESSED") {
      return res.status(409).json({ executed: false, error: error.message });
    }
    console.error("[Simulated IPS] Action failed:", error.message);
    return res.status(500).json({ executed: false, error: "Could not execute simulated IPS action" });
  }
});

app.get("/", (_req, res) => {
  logEvent("website_index", { type: "web_activity" });
  res.json({
    name: "Employee Service Portal",
    message: "Backend is live",
    routes: [
      "/signup",
      "/login",
      "/api/auth/session",
      "/dashboard",
      "/api/decoy/login",
      "/api/decoy/search",
      "/search",
      "/files",
      "/files/:filename",
      "/frontend/log",
      "/logs/backend",
      "/logs/frontend",
      "/api/events",
      "/api/events/stats",
      "/api/ids-results",
      "/api/ids-results/stats",
      "/api/analyst-feedback",
      "/api/analyst-feedback/latest",
      "/api/analyst-feedback/stats",
      "/api/ips/safety",
      "/api/ips/status",
      "/api/ips/recommendations",
      "/api/ips/actions",
    ],
  });
});

app.post("/frontend/log", (req, res) => {
  const { event = "frontend_event", details = {}, path: routePath = "", level = "info" } = req.body || {};
  const findings = detectAttack(`${event} ${routePath} ${JSON.stringify(details)}`);

  logFrontendEvent(event, {
    level,
    path: routePath,
    details,
    findings,
    ip: req.ip,
    method: req.method,
    headers: pickRequestHeaders(req),
    userAgent: req.get("user-agent") || "unknown",
  });

  res.status(202).json({ recorded: true });
});

app.post("/signup", async (req, res) => {
  const { username = "", email = "", password = "" } = req.body || {};

  if (!username || !email || !password) {
    return res.status(400).json({ error: "username, email and password are required" });
  }

  try {
    const passwordHash = await bcrypt.hash(password, 10);

    db.run(
      "INSERT INTO users (username, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
      [username.trim(), email.trim().toLowerCase(), passwordHash, toISTISOString()],
      function onInsert(err) {
        if (err) {
          if (String(err.message || "").includes("UNIQUE")) {
            return res.status(409).json({ error: "User already exists" });
          }
          return res.status(500).json({ error: "Could not create user" });
        }

        logEvent("website_signup", { username, email, userId: this.lastID });
        return res.status(201).json({ message: "Signup successful" });
      }
    );
  } catch (_err) {
    return res.status(500).json({ error: "Unexpected server error" });
  }
});

app.post("/login", (req, res) => {
  const { username = "", password = "" } = req.body || {};
  const payload = `username=${username}&password=${password}`;
  const findings = detectAttack(payload);

  db.get(
    "SELECT id, username, email, password_hash FROM users WHERE username = ?",
    [username.trim()],
    async (err, user) => {
      if (err) {
        return res.status(500).json({ error: "Login check failed" });
      }

      const isValid = Boolean(user) && (await bcrypt.compare(password, user.password_hash));
      if (!isValid) {
        logEvent("website_login_attempt", {
          attackType: findings[0] || "authentication_probe",
          payload,
          findings,
          username,
          status: "failed",
        });
        return res.status(401).json({ error: "Login failed" });
      }

      const token = jwt.sign(
        { userId: user.id, username: user.username, email: user.email },
        process.env.JWT_SECRET || "dev_secret",
        { expiresIn: "8h" }
      );

      logEvent("website_login_attempt", {
        attackType: findings[0] || "web_activity",
        payload,
        findings,
        username,
        userId: user.id,
        email: user.email,
        status: "success",
      });

      return res.json({
        message: "Login successful",
        token,
        user: { id: user.id, username: user.username, email: user.email },
      });
    }
  );
});

app.get("/api/auth/session", requireAuth, (req, res) => {
  return res.json({
    authenticated: true,
    user: req.user,
  });
});

app.get("/dashboard", requireAuth, (req, res) => {
  logEvent("website_dashboard_access", { username: req.user.username });
  res.json({
    title: "Dashboard",
    panel: {
      alertsToday: Math.floor(Math.random() * 8) + 3,
      suspiciousLogins: Math.floor(Math.random() * 5) + 1,
      activeDecoys: 3,
    },
    user: req.user,
  });
});

app.post("/api/decoy/login", (req, res) => {
  const { username = "", password = "" } = req.body || {};
  const payload = `username=${username}&password=${password}`;
  const findings = detectAttack(payload);
  const exposureAttack = findings.find((finding) =>
    ["sql_injection", "xss"].includes(finding)
  );
  const attackType = findings[0] || "authentication_probe";
  const exposure = buildDecoyExposure(exposureAttack, "employee_login");
  const exposureAudit = buildExposureAudit(exposure);

  const eventName = exposureAttack
    ? `website_decoy_login_${exposureAttack}`
    : "website_decoy_login_attempt";
  logEvent(eventName, {
    attackType,
    payload,
    findings,
    username,
    status: exposure ? "simulated_exposure" : "failed",
    simulation: Boolean(exposure),
    exposedRecordCount: exposure?.rows.length || 0,
    exposureAudit,
    ip: req.ip,
    sourcePort: req.socket?.remotePort,
    destinationPort: 5173,
    method: req.method,
    path: req.path,
  });

  if (exposure) {
    return res.json({
      authenticated: false,
      message: exposure.title,
      exposure,
    });
  }

  return res.status(401).json({
    authenticated: false,
    error: "Employee ID or password was not recognized",
  });
});

app.get("/api/decoy/search", (req, res) => {
  const query = String(req.query.q || "");
  const findings = detectAttack(query);
  const exposureAttack = findings.find((finding) =>
    ["sql_injection", "xss"].includes(finding)
  );
  const attackType = findings[0] || "web_activity";
  const exposure = buildDecoyExposure(exposureAttack, "resource_search");
  const exposureAudit = buildExposureAudit(exposure);
  const results = exposure ? [] : searchDecoyRecords(query);

  const eventName = attackType === "web_activity"
    ? "website_decoy_search"
    : `website_decoy_search_${attackType}`;
  logEvent(eventName, {
    attackType,
    query,
    findings,
    queryLength: query.length,
    status: exposure ? "simulated_exposure" : "search_complete",
    simulation: Boolean(exposure),
    exposedRecordCount: exposure?.rows.length || 0,
    exposureAudit,
    resultCount: results.length,
    ip: req.ip,
    sourcePort: req.socket?.remotePort,
    destinationPort: 5173,
    method: req.method,
    path: req.path,
  });

  return res.json({ query, results, exposure });
});

app.get("/search", (req, res) => {
  const query = String(req.query.q || "");
  const findings = detectAttack(query);

  logEvent("website_search", {
    attackType: findings[0] || "web_activity",
    query,
    findings,
    queryLength: query.length,
  });

  res.json({ query, results: [] });
});

app.get("/files", (_req, res) => {
  fs.readdir(decoyDir, (err, files) => {
    if (err) {
      return res.status(500).json({ error: "Could not read files" });
    }

    const safeFiles = files.filter((f) => fs.statSync(path.join(decoyDir, f)).isFile());
    return res.json({ files: safeFiles });
  });
});

app.get("/files/:filename", (req, res) => {
  const { filename } = req.params;
  const safePath = path.join(decoyDir, filename);

  if (!fs.existsSync(safePath) || !fs.statSync(safePath).isFile()) {
    logEvent("website_file_not_found", { attackType: "directory_scanning", filename });
    return res.status(404).json({ error: "File not found" });
  }

  const findings = detectAttack(filename);
  logEvent("website_file_access", {
    attackType: findings[0] || "file_access",
    filename,
    findings,
    path: `/files/${filename}`,
  });

  return res.sendFile(safePath);
});

app.get("/logs/backend", requireAuth, (req, res) => {
  const limit = Math.max(1, Math.min(Number(req.query.limit || 100), 500));
  return res.json({
    source: "backend",
    count: limit,
    entries: readRecentLogEntries(backendLogFile, limit),
  });
});

app.get("/logs/frontend", requireAuth, (req, res) => {
  const limit = Math.max(1, Math.min(Number(req.query.limit || 100), 500));
  return res.json({
    source: "frontend",
    count: limit,
    entries: readRecentLogEntries(frontendLogFile, limit),
  });
});

app.use((req, res) => {
  const findings = detectAttack(req.path);
  logEvent("website_unknown_path", {
    attackType: findings[0] || "web_activity",
    payload: req.path,
    method: req.method,
    query: req.query,
  });
  res.status(404).json({ error: "Route not found" });
});

app.listen(PORT, () => {
  console.log(`[Backend] Running on http://localhost:${PORT}`);
  backfillIPSRecommendations(db)
    .then((count) => syncRuntimeState(db).then(() => count))
    .then((count) => {
      console.log(`[Simulated IPS] Simulation-only policy ready (${count} IDS results evaluated)`);
    })
    .catch((error) => {
      console.error("[Simulated IPS] Runtime-state initialization failed:", error.message);
    });
});
