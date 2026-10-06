const test = require("node:test");
const assert = require("node:assert/strict");
const jwt = require("jsonwebtoken");

const {
  isLoopbackRequest,
  requireDashboardAccess,
} = require("../middleware/dashboard_access");

function responseRecorder() {
  return {
    statusCode: 200,
    payload: null,
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(payload) {
      this.payload = payload;
      return this;
    },
  };
}

test("internal defender access requires both the shared token and loopback", () => {
  process.env.DASHBOARD_INTERNAL_TOKEN = "test-dashboard-token-that-is-at-least-32-characters";
  const req = {
    socket: { remoteAddress: "::ffff:127.0.0.1" },
    headers: {},
    get(name) {
      return name.toLowerCase() === "x-dashboard-internal-token"
        ? process.env.DASHBOARD_INTERNAL_TOKEN
        : undefined;
    },
  };
  const res = responseRecorder();
  let continued = false;

  requireDashboardAccess(req, res, () => {
    continued = true;
  });

  assert.equal(continued, true);
  assert.equal(req.user.username, "local-defender");
  assert.equal(req.user.access, "local-dashboard");
  assert.equal(isLoopbackRequest(req), true);
});

test("an external request cannot use the internal dashboard credential", () => {
  process.env.DASHBOARD_INTERNAL_TOKEN = "test-dashboard-token-that-is-at-least-32-characters";
  const req = {
    socket: { remoteAddress: "198.51.100.22" },
    headers: {},
    get() {
      return process.env.DASHBOARD_INTERNAL_TOKEN;
    },
  };
  const res = responseRecorder();

  requireDashboardAccess(req, res, () => assert.fail("external request was accepted"));

  assert.equal(res.statusCode, 401);
  assert.equal(res.payload.error, "Missing auth token");
});

function internalRequest(identity = {}, method = "POST") {
  const headers = { "x-dashboard-internal-token": process.env.DASHBOARD_INTERNAL_TOKEN, ...identity };
  return { method, socket: { remoteAddress: "127.0.0.1" }, headers,
    get(name) { return headers[name.toLowerCase()]; } };
}

test("trusted proxy mutations use the signed-in analyst rather than ID zero", () => {
  const req = internalRequest({ "x-dashboard-analyst-id": "7", "x-dashboard-analyst-email": "analyst@gmail.com" });
  let continued = false;
  requireDashboardAccess(req, responseRecorder(), () => { continued = true; });
  assert.equal(continued, true);
  assert.equal(req.user.userId, 7);
  assert.equal(req.user.username, "analyst@gmail.com");
});

test("mutations require a complete, valid trusted analyst identity", () => {
  for (const identity of [ {},
    { "x-dashboard-analyst-id": "7" },
    { "x-dashboard-analyst-id": "0", "x-dashboard-analyst-email": "analyst@gmail.com" },
    { "x-dashboard-analyst-id": "7.5", "x-dashboard-analyst-email": "analyst@gmail.com" },
    { "x-dashboard-analyst-id": "9007199254740992", "x-dashboard-analyst-email": "analyst@gmail.com" },
    { "x-dashboard-analyst-id": "7", "x-dashboard-analyst-email": "not-an-email" },
  ]) {
    const res = responseRecorder();
    requireDashboardAccess(internalRequest(identity), res, () => assert.fail("invalid identity accepted"));
    assert.equal(res.statusCode, 403);
  }
});

test("spoofed analyst headers without the proxy token do not authenticate", () => {
  const req = internalRequest({ "x-dashboard-internal-token": "wrong-token",
    "x-dashboard-analyst-id": "7", "x-dashboard-analyst-email": "analyst@gmail.com" });
  const res = responseRecorder();
  requireDashboardAccess(req, res, () => assert.fail("spoofed identity accepted"));
  assert.equal(res.statusCode, 401);
});

test("a valid legacy portal JWT cannot authorize analyst mutations", () => {
  const token = jwt.sign({ userId: 7, username: "portal-user" }, process.env.JWT_SECRET || "dev_secret");
  const req = internalRequest({ "x-dashboard-internal-token": undefined, authorization: `Bearer ${token}` });
  const res = responseRecorder();
  requireDashboardAccess(req, res, () => assert.fail("portal token authorized an analyst action"));
  assert.equal(res.statusCode, 401);
  assert.match(res.payload.error, /Dashboard login required/);
});
