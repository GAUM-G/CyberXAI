const fs = require("fs");
const path = require("path");
const sqlite3 = require("sqlite3").verbose();
const { initializeEventStore } = require("./event_store");

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
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  initializeEventStore(db);
});

module.exports = db;
