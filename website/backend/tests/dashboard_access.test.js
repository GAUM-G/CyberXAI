const test = require("node:test");
const assert = require("node:assert/strict");

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
