const fs = require("node:fs");
const { DEFAULT_STATE_FILE } = require("../ips_response_store");
const { normalizeSourceIp } = require("../common_event");

function createSimulatedIPSMiddleware({ stateFile = DEFAULT_STATE_FILE, recordResponse = () => {} } = {}) {
  let cachedSignature = null;
  let cachedState = null;

  function readState() {
    try {
      const stat = fs.statSync(stateFile, { bigint: true });
      const signature = `${stat.ino}:${stat.mtimeNs}:${stat.ctimeNs}:${stat.size}`;
      if (signature === cachedSignature) return cachedState;
      const state = JSON.parse(fs.readFileSync(stateFile, "utf8"));
      if (state?.mode !== "simulation" || state.automatic_host_blocking !== false || state.host_firewall_changed !== false) {
        return null;
      }
      cachedSignature = signature;
      cachedState = state;
      return state;
    } catch (_error) {
      return null;
    }
  }

  return function simulatedIPS(req, res, next) {
    // Never rate-limit defender controls, telemetry ingestion, or real account APIs.
    const publicDecoy = req.path.startsWith("/api/decoy/") ||
      ["/login", "/signup", "/search", "/files"].includes(req.path) || req.path.startsWith("/files/");
    if (!publicDecoy) return next();
    const state = readState();
    if (!state) return next();
    const sourceIp = normalizeSourceIp(req.socket?.remoteAddress || req.ip);
    const active = key => (Array.isArray(state[key]) ? state[key] : []).filter(entry =>
      entry && typeof entry === "object" && String(entry.service || "").trim().toLowerCase() === "http" &&
      typeof entry.source_ip === "string" && entry.source_ip.trim() &&
      normalizeSourceIp(entry.source_ip) === sourceIp &&
      (!entry.expires_at || Date.parse(entry.expires_at) > Date.now())
    );
    const blocks = active("simulated_blocks");
    const limits = active("rate_limits");
    if (!blocks.length && !limits.length) return next();
    const response = {
      mode: "simulation", automatic_host_blocking: false, host_firewall_changed: false,
      would_have_been_blocked: blocks.length > 0, rate_limited: limits.length > 0,
      session_terminated: false,
      rate_limit_delay_ms: limits.length ? Math.max(0, Math.min(Number(limits.at(-1).rate_limit_delay_ms) || 0, 1000)) : 0,
      action_ids: [...blocks, ...limits].map(entry => entry.action_id).filter(id => Number.isSafeInteger(id) && id > 0),
    };
    recordResponse({
      ip: sourceIp, path: req.path, method: req.method,
      status: limits.length ? "rate_limited" : "observed",
      attackType: "web_activity", ips: response,
    });
    if (limits.length) {
      res.setHeader("Retry-After", "1");
      return res.status(429).json({ error: "Too many requests", ips_mode: "simulation", host_firewall_changed: false });
    }
    // Simulated blocks annotate telemetry; they deliberately do not drop traffic.
    return next();
  };
}

module.exports = { createSimulatedIPSMiddleware };
