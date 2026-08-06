const test = require("node:test");
const assert = require("node:assert/strict");

const { IST_OFFSET_MINUTES, toISTISOString } = require("../time");

test("runtime timestamps use the explicit IST offset", () => {
  assert.equal(IST_OFFSET_MINUTES, 330);
  assert.equal(
    toISTISOString(new Date("2026-08-03T12:00:00.000Z")),
    "2026-08-03T17:30:00.000+05:30"
  );
  assert.match(toISTISOString(), /\+05:30$/);
});

test("invalid timestamps are rejected", () => {
  assert.throws(() => toISTISOString("not-a-date"), /valid date/);
});
