const test = require("node:test");
const assert = require("node:assert/strict");
const sqlite3 = require("sqlite3").verbose();

const {
  getEventStats,
  initializeEventStore,
  insertEvent,
  listEvents,
  validateEventRecord,
} = require("../event_store");

function sampleEvent(overrides = {}) {
  return {
    schema_version: "1.0",
    event_id: "9f7648bc-6797-4db1-b50a-71bb288c0001",
    timestamp: "2026-07-19T10:00:00+00:00",
    source_ip: "127.0.0.1",
    source_port: 51000,
    destination_port: 2222,
    service: "ssh",
    protocol: "ssh",
    event_type: "authentication",
    event: "ssh_login_attempt",
    attack_type: "authentication_probe",
    severity: "info",
    status: "failed",
    username: "test-user",
    session_id: "event-store-test-session",
    request_method: null,
    request_path: null,
    payload: { username: "test-user", password: "fake-test-value" },
    metadata: { attempt_count: 1 },
    ...overrides,
  };
}

function closeDatabase(database) {
  return new Promise((resolve, reject) => {
    database.close((error) => (error ? reject(error) : resolve()));
  });
}

test("central event store validates, deduplicates and retrieves events", async () => {
  const database = new sqlite3.Database(":memory:");
  initializeEventStore(database);

  try {
    const event = sampleEvent();
    assert.deepEqual(validateEventRecord(event), []);

    const inserted = await insertEvent(database, event);
    assert.equal(inserted.inserted, true);
    assert.ok(inserted.id > 0);

    const duplicate = await insertEvent(database, event);
    assert.equal(duplicate.inserted, false);
    assert.equal(duplicate.id, inserted.id);

    const events = await listEvents(database, { service: "ssh", limit: 10 });
    assert.equal(events.length, 1);
    assert.equal(events[0].event_id, event.event_id);
    assert.deepEqual(events[0].payload, event.payload);
    assert.deepEqual(events[0].metadata, event.metadata);

    const stats = await getEventStats(database);
    assert.equal(stats.total_events, 1);
    assert.equal(stats.unique_ips, 1);
    assert.deepEqual(stats.by_service, { ssh: 1 });

    const secondEvent = sampleEvent({
      event_id: "9f7648bc-6797-4db1-b50a-71bb288c0002",
      timestamp: "2026-07-19T10:01:00+00:00",
    });
    await insertEvent(database, secondEvent);

    const firstPage = await listEvents(database, {
      service: "ssh",
      limit: 1,
      offset: 0,
    });
    const secondPage = await listEvents(database, {
      service: "ssh",
      limit: 1,
      offset: 1,
    });
    assert.equal(firstPage.length, 1);
    assert.equal(secondPage.length, 1);
    assert.equal(firstPage[0].event_id, secondEvent.event_id);
    assert.equal(secondPage[0].event_id, event.event_id);

    const invalid = sampleEvent({ service: "smtp" });
    assert.match(validateEventRecord(invalid).join(" "), /service must be ssh, ftp or http/);
    await assert.rejects(insertEvent(database, invalid), /service must be ssh, ftp or http/);
  } finally {
    await closeDatabase(database);
  }
});
