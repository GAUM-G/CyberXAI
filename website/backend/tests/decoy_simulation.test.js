const test = require("node:test");
const assert = require("node:assert/strict");

const {
  DECOY_EMPLOYEE_RECORDS,
  buildDecoyExposure,
  buildExposureAudit,
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

test("displayed exposure audit records the exact fictional result and safety controls", () => {
  for (const attackType of ["sql_injection", "xss"]) {
    const exposure = buildDecoyExposure(attackType, "resource_search");
    const audit = buildExposureAudit(exposure);

    assert.equal(audit.displayed, true);
    assert.equal(audit.record_count, exposure.rows.length);
    assert.deepEqual(audit.rows, exposure.rows);
    assert.equal(audit.safety.fictional_data_only, true);
    assert.equal(audit.safety.real_database_access, false);
    assert.equal(audit.safety.unrestricted_javascript, false);
  }
  assert.equal(buildExposureAudit(null), null);
});

test("ordinary portal searches return a small decoy catalog", () => {
  assert.equal(searchDecoyRecords("vpn").length, 1);
  assert.equal(searchDecoyRecords("internal").length, 2);
  assert.deepEqual(searchDecoyRecords("does-not-exist"), []);
});
