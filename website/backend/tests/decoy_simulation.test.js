const test = require("node:test");
const assert = require("node:assert/strict");

const {
  DECOY_EMPLOYEE_RECORDS,
  buildDecoyExposure,
  detectAttack,
  searchDecoyRecords,
} = require("../decoy_simulation");

test("detectAttack recognizes controlled SQL injection and XSS examples", () => {
  assert.deepEqual(detectAttack("admin' OR 1=1 --"), ["sql_injection"]);
  assert.deepEqual(detectAttack("' OR '1'='1' --"), ["sql_injection"]);
  assert.deepEqual(detectAttack('<img src=x onerror="alert(1)">'), ["xss"]);
  assert.deepEqual(detectAttack("employee handbook"), []);
});

test("SQL injection exposure returns only deterministic fictional records", () => {
  const exposure = buildDecoyExposure("sql_injection", "employee_login");

  assert.equal(exposure.simulation, true);
  assert.equal(exposure.source, "northstar_hr.employee_directory");
  assert.equal(exposure.rows.length, DECOY_EMPLOYEE_RECORDS.length);
  assert.ok(exposure.rows.every((row) => row.email.endsWith("@northstar.example")));
});

test("XSS exposure models browser-readable cache data without executable content", () => {
  const exposure = buildDecoyExposure("xss", "resource_search");

  assert.equal(exposure.simulation, true);
  assert.equal(exposure.attack_type, "xss");
  assert.equal(exposure.rows.length, 4);
  assert.ok(exposure.exposed_items.some((item) => item.label === "Session"));
  assert.equal(JSON.stringify(exposure).includes("<script"), false);
});

test("ordinary portal searches return a small decoy catalog", () => {
  assert.equal(searchDecoyRecords("vpn").length, 1);
  assert.equal(searchDecoyRecords("internal").length, 2);
  assert.deepEqual(searchDecoyRecords("does-not-exist"), []);
});
