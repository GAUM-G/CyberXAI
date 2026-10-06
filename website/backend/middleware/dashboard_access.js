const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const { requireAuth } = require("./auth");

const DEFAULT_TOKEN_FILE = path.join(
  __dirname,
  "..",
  "..",
  "..",
  "data",
  "runtime",
  "dashboard_internal.token"
);

let cachedToken = null;

function tokenFilePath() {
  return path.resolve(process.env.DASHBOARD_INTERNAL_TOKEN_FILE || DEFAULT_TOKEN_FILE);
}

function loadOrCreateInternalToken() {
  const configured = String(process.env.DASHBOARD_INTERNAL_TOKEN || "").trim();
  if (configured) {
    return configured;
  }
  if (cachedToken) {
    return cachedToken;
  }

  const filePath = tokenFilePath();
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  try {
    const generated = crypto.randomBytes(32).toString("base64url");
    fs.writeFileSync(filePath, `${generated}\n`, { encoding: "utf8", flag: "wx", mode: 0o600 });
  } catch (error) {
    if (error.code !== "EEXIST") {
      throw error;
    }
  }

  cachedToken = fs.readFileSync(filePath, "utf8").trim();
  if (cachedToken.length < 32) {
    throw new Error("Dashboard internal token is missing or invalid");
  }
  return cachedToken;
}

function isLoopbackRequest(req) {
  const address = String(req.socket?.remoteAddress || req.ip || "").toLowerCase();
  return address === "127.0.0.1" || address === "::1" || address === "::ffff:127.0.0.1";
}

function tokensMatch(provided, expected) {
  const left = Buffer.from(String(provided || ""));
  const right = Buffer.from(String(expected || ""));
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

function requireDashboardAccess(req, res, next) {
  const provided = req.get("x-dashboard-internal-token");
  if (provided && isLoopbackRequest(req)) {
    try {
      if (tokensMatch(provided, loadOrCreateInternalToken())) {
        const analystId = req.get("x-dashboard-analyst-id");
        const analystEmail = req.get("x-dashboard-analyst-email");
        const hasIdentity = analystId !== undefined || analystEmail !== undefined;
        if (hasIdentity && (
          !/^[1-9][0-9]*$/.test(String(analystId || "")) ||
          !Number.isSafeInteger(Number(analystId)) ||
          typeof analystEmail !== "string" ||
          !/^[a-z0-9][a-z0-9.+_-]{0,63}@gmail\.com$/.test(analystEmail)
        )) {
          return res.status(403).json({ error: "Invalid dashboard analyst identity" });
        }
        if (!hasIdentity && ["POST", "PUT", "PATCH", "DELETE"].includes(req.method)) {
          return res.status(403).json({ error: "Dashboard analyst identity is required" });
        }
        req.user = {
          userId: hasIdentity ? Number(analystId) : 0,
          username: hasIdentity ? analystEmail : "local-defender",
          email: hasIdentity ? analystEmail : "defender@localhost",
          access: "local-dashboard",
        };
        return next();
      }
    } catch (error) {
      console.error("[Dashboard Access] Internal credential unavailable:", error.message);
      return res.status(503).json({ error: "Local dashboard access is unavailable" });
    }
  }

  // Portal JWTs identify decoy-site accounts, not approved dashboard analysts.
  if (["POST", "PUT", "PATCH", "DELETE"].includes(req.method)) {
    return res.status(401).json({ error: "Dashboard login required for analyst actions" });
  }
  // Keep legacy read-only integration scripts working without granting IPS writes.
  return requireAuth(req, res, next);
}

module.exports = {
  isLoopbackRequest,
  loadOrCreateInternalToken,
  requireDashboardAccess,
};
