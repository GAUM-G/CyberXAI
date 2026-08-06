const fs = require("fs");
const path = require("path");
const sqlite3 = require("sqlite3").verbose();
const { initializeEventStore } = require("./event_store");
const { initializeIDSResultStore } = require("./ids_result_store");
const {
  initializeAnalystFeedbackStore,
} = require("./analyst_feedback_store");
const {
  initializeIPSResponseStore,
} = require("./ips_response_store");

const dbPath = path.join(__dirname, "data", "honeypot.db");
fs.mkdirSync(path.dirname(dbPath), { recursive: true });
const db = new sqlite3.Database(dbPath);

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TEXT NOT NULL
    )
  `);

  initializeEventStore(db);
  initializeIDSResultStore(db);
  initializeAnalystFeedbackStore(db);
  initializeIPSResponseStore(db);
});

module.exports = db;
