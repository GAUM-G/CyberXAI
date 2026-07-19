require("dotenv").config();

const express = require("express");
const cors = require("cors");
const path = require("path");
const fs = require("fs");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const db = require("./db");
const {
  getEventStats,
  insertEvent,
  listEvents,
  validateEventRecord,
} = require("./event_store");
const { requireAuth } = require("./middleware/auth");

const app = express();
const PORT = Number(process.env.PORT || 5000);

app.use(cors({ origin: process.env.FRONTEND_URL || "http://localhost:5173" }));
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
  const line = JSON.stringify({ timestamp: new Date().toISOString(), event, details });
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
  const record = {
    timestamp: new Date().toISOString(),
    source_ip: sourceIp || "127.0.0.1",
    service: "website",
    event,
    attack_type: attackType || "web_activity",
    payload: payload ?? null,
    severity,
    metadata: metadata || {},
  };
  fs.appendFile(honeypotLogFile, `${JSON.stringify(record)}\n`, () => {});
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

function detectAttack(payload) {
  const text = String(payload || "").toLowerCase();
  const findings = [];

  if (/union\s+select|or\s+1\s*=\s*1|drop\s+table|--|information_schema/.test(text)) {
    findings.push("sql_injection");
  }
  if (/<script|javascript:|onerror\s*=|onload\s*=|alert\s*\(/.test(text)) {
    findings.push("xss");
  }
  if (/\.\.\/|etc\/passwd|\.git|phpmyadmin|\.env|wp-admin/.test(text)) {
    findings.push("directory_scanning");
  }

  return findings;
}

app.use((req, res, next) => {
  const startedAt = Date.now();

  res.on("finish", () => {
    if (req.path.startsWith("/logs") || req.path.startsWith("/api/events")) {
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

app.get("/api/events", async (req, res) => {
  try {
    const events = await listEvents(db, {
      limit: req.query.limit,
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

app.get("/api/events/stats", async (_req, res) => {
  try {
    const stats = await getEventStats(db);
    return res.json({ source: "sqlite", ...stats });
  } catch (error) {
    console.error("[Event Store] Stats failed:", error.message);
    return res.status(500).json({ error: "Could not calculate event statistics" });
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
      "/dashboard",
      "/search",
      "/files",
      "/files/:filename",
      "/frontend/log",
      "/logs/backend",
      "/logs/frontend",
      "/api/events",
      "/api/events/stats",
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
      "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
      [username.trim(), email.trim().toLowerCase(), passwordHash],
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
});
