const test = require("node:test");
const assert = require("node:assert/strict");

const { buildCommonEvent } = require("../common_event");
const { validateEventRecord } = require("../event_store");

test("5173 SQL injection telemetry satisfies the shared IDS schema", () => {
  const record = buildCommonEvent({
    sourceIp: "::ffff:127.0.0.1",
    event: "website_decoy_login_sql_injection",
    attackType: "sql_injection",
    severity: "warning",
    payload: "username=admin' OR '1'='1&password=test",
    metadata: {
      username: "admin' OR '1'='1",
      status: "simulated_exposure",
      sourcePort: 49152,
      destinationPort: 5173,
      method: "POST",
      path: "/api/decoy/login",
    },
  });

  assert.deepEqual(validateEventRecord(record), []);
  assert.equal(record.service, "http");
  assert.equal(record.protocol, "http");
  assert.equal(record.event_type, "attack");
  assert.equal(record.destination_port, 5173);
  assert.equal(record.request_method, "POST");
  assert.equal(record.request_path, "/api/decoy/login");
  assert.equal(record.source_ip, "127.0.0.1");
});

test("5173 XSS and directory scanning telemetry are attack events", () => {
  for (const attackType of ["xss", "directory_scanning"]) {
    const record = buildCommonEvent({
      sourceIp: "::1",
      event: `website_decoy_search_${attackType}`,
      attackType,
      severity: "warning",
      payload: attackType === "xss" ? "<svg onload=alert(1)>" : "../../.env",
      metadata: { method: "GET", path: "/api/decoy/search" },
    });

    assert.deepEqual(validateEventRecord(record), []);
    assert.equal(record.event_type, "attack");
    assert.equal(record.attack_type, attackType);
  }
});

test("ordinary portal activity is valid non-attack HTTP telemetry", () => {
  const record = buildCommonEvent({
    sourceIp: "127.0.0.1",
    event: "website_file_access",
    attackType: "file_access",
    payload: "employee-handbook.txt",
    metadata: { method: "GET", path: "/files/employee-handbook.txt" },
  });

  assert.deepEqual(validateEventRecord(record), []);
  assert.equal(record.event_type, "file_access");
  assert.equal(record.severity, "info");
});
