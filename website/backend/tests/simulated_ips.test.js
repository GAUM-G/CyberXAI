const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { createSimulatedIPSMiddleware } = require("../middleware/simulated_ips");

function fixture(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "portal-ips-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const stateFile = path.join(directory, "state.json");
  const records = [];
  return {
    records, stateFile,
    middleware: createSimulatedIPSMiddleware({ stateFile, recordResponse: record => records.push(record) }),
    write(overrides = {}) {
      fs.writeFileSync(stateFile, JSON.stringify({ mode: "simulation", automatic_host_blocking: false,
        host_firewall_changed: false, simulated_blocks: [], rate_limits: [], ...overrides }));
    },
  };
}

function request(f, route = "/api/decoy/search", address = "::ffff:127.0.0.1") {
  const res = { statusCode: 200, headers: {}, payload: null,
    setHeader(name, value) { this.headers[name] = value; },
    status(code) { this.statusCode = code; return this; },
    json(payload) { this.payload = payload; return this; },
  };
  let continued = false;
  f.middleware({ path: route, method: "POST", ip: "spoofed-ip", socket: { remoteAddress: address } }, res, () => { continued = true; });
  return { ...res, continued };
}

const httpAction = { action_id: 7, source_ip: "127.0.0.1", service: "http",
  expires_at: "2099-01-01T00:00:00Z", rate_limit_delay_ms: 750 };

test("public decoy routes honor HTTP simulated rate limits and record their source", t => {
  const f = fixture(t);
  f.write({ rate_limits: [httpAction] });
  const result = request(f);
  assert.equal(result.statusCode, 429);
  assert.equal(result.continued, false);
  assert.equal(result.headers["Retry-After"], "1");
  assert.equal(result.payload.host_firewall_changed, false);
  assert.equal(f.records[0].ip, "127.0.0.1");
  assert.equal(f.records[0].ips.rate_limited, true);
  assert.equal(f.records[0].ips.rate_limit_delay_ms, 750);
});

test("simulated block annotates but never drops a public decoy interaction", t => {
  const f = fixture(t);
  f.write({ simulated_blocks: [httpAction] });
  assert.equal(request(f, "/login").continued, true);
  assert.equal(f.records[0].ips.would_have_been_blocked, true);
  assert.equal(f.records[0].ips.host_firewall_changed, false);
});

test("defender, ingestion, and real account endpoints are unaffected", t => {
  const f = fixture(t);
  f.write({ rate_limits: [httpAction] });
  for (const route of ["/api/ips/actions", "/api/events", "/api/ids-results", "/api/analyst-feedback/e1", "/api/auth/login", "/frontend/log"]) {
    assert.equal(request(f, route).continued, true, route);
  }
  assert.equal(f.records.length, 0);
});

test("expired, malformed, different-service, and other-IP actions are ignored", t => {
  const f = fixture(t);
  f.write({ rate_limits: [null, {}, { ...httpAction, source_ip: "10.0.0.9" },
    { ...httpAction, service: "ssh" }, { ...httpAction, expires_at: "2000-01-01" },
    { ...httpAction, expires_at: "not-a-date" }] });
  assert.equal(request(f).continued, true);
  assert.equal(f.records.length, 0);
});

test("missing, invalid, or non-simulation state cannot activate controls", t => {
  const f = fixture(t);
  assert.equal(request(f).continued, true);
  fs.writeFileSync(f.stateFile, "broken-json");
  assert.equal(request(f).continued, true);
  f.write({ rate_limits: [httpAction], automatic_host_blocking: true });
  assert.equal(request(f).continued, true);
  f.write({ rate_limits: [httpAction], mode: "active" });
  assert.equal(request(f).continued, true);
});

test("atomic state replacement is observed even when timestamps and sizes match", t => {
  const f = fixture(t);
  f.write({ rate_limits: [httpAction] });
  assert.equal(request(f).statusCode, 429);
  const original = fs.statSync(f.stateFile);
  const replacement = `${f.stateFile}.replacement`;
  fs.writeFileSync(replacement, fs.readFileSync(f.stateFile, "utf8").replace("127.0.0.1", "127.0.0.2"));
  fs.utimesSync(replacement, original.atime, original.mtime);
  fs.renameSync(replacement, f.stateFile);
  assert.equal(request(f).continued, true);
});
