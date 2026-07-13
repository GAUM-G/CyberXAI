# Honeypot Security Framework (`honeypot_v2`) — Full Project Analysis & Setup Guide

**Analyzed:** every file in the archive except third‑party `node_modules/` (5,259 files — pure installed dependencies, fully reproducible from `package.json`/`package-lock.json`) and Python `__pycache__/` (compiled bytecode). Everything else — all `.py`, `.js`, `.jsx`, `.json`, `.md`, `.yaml`, `.html`, `.css`, `.ps1`, `.env*`, the SQLite DB, and the log samples — was read in full. Nothing was skipped for size reasons; the whole source tree is only ~1.2 MB.

---

## ⚠️ Read this part first

Two real secrets are sitting in this ZIP right now. Everything else below is important but not urgent — these two are:

1. **A live Telegram bot token is hardcoded in `n8n/alert_sender.json`** (in two `HTTP Request` nodes, as part of the URL `https://api.telegram.org/bot8705505421:AAHPOEZ‑ubaP…/sendMessage`). Anyone with this file can send messages as that bot. Revoke it with **@BotFather → `/revoke`** and generate a new one, then wire it into n8n's own credential store instead of hardcoding it in the workflow JSON.
2. **`website/backend/.env` — which is in this ZIP — contains a real `JWT_SECRET`.** Your `.gitignore` correctly excludes `.env` from *git*, but that doesn't stop it from being included in a plain ZIP export like this one, so the value has already left your machine (it's now in this upload). Rotate it, and going forward, exclude `website/backend/.env` before zipping/sharing the project.

Full detail on both, plus everything else, is in Phase 8 below.

---

## Phase 1 – Project Overview

### Purpose
`honeypot_v2` is a self‑contained **cybersecurity research/demo lab**: a set of fake network services (SSH, FTP, HTTP) that look real enough to attract scanning, brute‑forcing, and web‑attack traffic, log everything an attacker does in structured form, and surface it in a live dashboard. It's explicitly scoped by its own README as a research/demo/local‑testing tool, not a production security product.

### What it actually includes
- A fake **SSH** service (port 2222) that captures every username/password pair typed at it.
- A fake **FTP** service (port 2121, via `pyftpdlib`) that accepts any credentials, serves fabricated "sensitive" bait files, and logs connections/logins/commands.
- A fake **HTTP corporate login portal** (port 8080) that detects SQL injection, XSS, directory scanning, and login brute‑forcing via regex.
- A **live Flask dashboard** (port 5050) with a real‑time feed (Server‑Sent Events), stats, captured‑credential tables, an "IDS" timeline, and a downloadable `.txt` threat report.
- A **second, independent decoy website**, implemented two different ways (see Phase 2/6) — a simple Flask version and a fuller Express + React + SQLite version with *real* signup/login (bcrypt + JWT) sitting behind the decoy.
- **Attack simulation scripts** that throw safe, canned traffic at your own local services so you can see the pipeline work end‑to‑end without needing a real attacker.
- **n8n workflow exports** for routing critical events to Telegram, optionally via a Groq LLM call that writes a short SOC‑style incident summary first.
- A standalone **XAI ("explainable AI") module** — attacker‑profiling and MITRE ATT&CK‑style tagging — that exists as an independent, importable Python package but is *not* currently wired into the live dashboard (more on this in Phase 10).
- A PowerShell script to expose the decoy website through a Cloudflare Tunnel for external/mobile testing.

### Architecture, in one paragraph
This is a **polyglot monorepo**, not one app. The core honeypot engine and dashboard are pure Python (`socketserver` for SSH, `pyftpdlib` for FTP, Flask for HTTP + the dashboard), all launched from one process (`run.py`) as daemon threads sharing one JSONL log file as the single source of truth. Alongside that sits a completely separate second decoy site with two independent implementations (plain Flask, or Express/React/SQLite) that write into the *same* JSONL log so everything still shows up in one dashboard. n8n (an external tool, not bundled) is the alerting/automation layer, driven by webhook POSTs from the Python logger and from the dashboard's "Generate XAI Report" button. Nothing here is containerized — everything runs as local OS processes on demand.

### Tech stack

| Layer | Technology |
|---|---|
| Honeypot core (SSH/FTP/HTTP) | Python 3.10+, `socketserver`, `pyftpdlib`, `Flask` |
| Dashboard | Flask + server‑rendered template + vanilla JS/CSS (no frontend framework) |
| Alternate decoy website #1 | Flask + Jinja2 templates |
| Alternate decoy website #2 (backend) | Node.js, Express 4, SQLite3, bcryptjs, jsonwebtoken, dotenv, cors |
| Alternate decoy website #2 (frontend) | React 18, Vite 5, react-router-dom 6 |
| Logging | Custom JSONL logger + in‑memory queue for SSE |
| Automation/alerting | n8n (external), Telegram Bot API, Groq LLM API (`llama-3.1-8b-instant`) |
| Attacker profiling | Standalone Python module (dataclasses, no external deps besides `requests`) |
| Tunneling | Cloudflare Tunnel (`cloudflared`) via PowerShell |

### Folder structure (verified against the actual archive)

```text
honeypot_v2/
├── core/
│   ├── honeypots/
│   │   ├── ssh_honeypot.py        fake SSH server, port 2222
│   │   ├── ftp_honeypot.py        fake FTP server, port 2121 (pyftpdlib)
│   │   └── http_honeypot.py       fake corporate login portal, port 8080
│   ├── launcher.py                starts all three honeypots in daemon threads
│   └── logger.py                  central JSONL logger + SSE queue + n8n webhook push
├── dashboard/
│   ├── app.py                     Flask dashboard + REST API + SSE stream, port 5050
│   └── templates/index.html       single-page dashboard UI (vanilla JS)
├── website/                       ALTERNATE decoy site — two implementations
│   ├── app.py                     Flask version (run via run_website.py), port 8090
│   ├── templates/index.html       Jinja2 template for the Flask version
│   ├── decoy_files/                bait files served by both website versions
│   ├── frontend/                  React/Vite version of the site
│   ├── backend/                   Express/SQLite version of the site, port 5000
│   └── README_MERN_SETUP.md
├── simulation/
│   ├── sim_ssh.py / sim_ftp.py / sim_http.py    per-service test traffic generators
│   ├── simulate_attacks.py        runs all three together
│   └── n8n.py                     tails the JSONL log and forwards new events to n8n
├── XAI/                           standalone attacker-profiling module (not yet wired in)
│   ├── attack_analyzer.py
│   ├── merger.py
│   └── README.md / QUICKSTART.md / CONFIG_EXAMPLES.md
├── n8n/
│   ├── alert_sender.json          n8n workflow: webhook → severity filter → Telegram
│   └── xai_node.json              n8n workflow: webhook → risk score → Groq → Telegram
├── config/
│   └── config.yaml                ports/thresholds — see Phase 8, this file is currently unused
├── data/
│   ├── raw_logs/                  generated JSONL event logs
│   └── ftp_decoy/                 fabricated bait files for the FTP service
├── scripts/
│   └── start_website_tunnel.ps1   Cloudflare Tunnel launcher (Windows/PowerShell only)
├── temp.html                      dead file, not referenced anywhere — safe to delete
├── requirements.txt
├── run.py                         starts honeypots + dashboard (+ optional simulation)
└── run_website.py                 starts the standalone Flask decoy site only
```

---

## Phase 2 – Deep Analysis (folder by folder)

**`core/`** — The engine room. `logger.py` is the one module everything else depends on: it appends every event to `data/raw_logs/honeypot_events.jsonl`, pushes a copy into a bounded in‑memory queue that the dashboard's SSE endpoint drains, and — only for `severity="critical"` events — spins up a fire‑and‑forget thread to POST a normalized payload to an n8n webhook. `launcher.py` just starts the three honeypot handlers as named daemon threads with a small stagger to avoid port‑bind races. `core/honeypots/` holds the three protocol implementations, each independently importable and independently runnable (`if __name__ == "__main__"` in every file).

**`dashboard/`** — `app.py` is a second Flask app (separate process/port from the honeypots' own HTTP service) that only *reads* `data/raw_logs/honeypot_events.jsonl` — it computes stats, credential extraction, a 24‑bucket timeline, and top‑attacker IPs on every request, in memory, from whatever's currently in the file. `templates/index.html` is a single 729‑line page: no build step, no framework, just hand‑written JS that polls five `/api/*` endpoints and subscribes to `/stream` for live updates.

**`website/`** — This folder is two *independent* decoy sites, not one system split into two halves:
- `app.py` + `templates/index.html` + `decoy_files/` is the simple version: pure Flask, no real backend logic, every login attempt is logged and always shown as "failed."
- `backend/` + `frontend/` is the fuller version: a real Express API with a real SQLite `users` table (bcrypt‑hashed passwords, JWT auth) behind a React UI. Unlike the Flask version, someone can genuinely sign up and log in here — and every attempt (successful or not) is still mirrored into the same honeypot JSONL log.

Both versions serve the *same three* fabricated "sensitive" files from `decoy_files/`.

**`simulation/`** — Safe, local‑only traffic generators. `sim_ssh.py` and `sim_http.py` connect to `127.0.0.1` by default and send a fixed list of common credential pairs / attack payloads (SQLi, XSS, path traversal strings) purely to exercise your own honeypot's detection and logging. `n8n.py` is a separate utility: it tails the JSONL log file (like `tail -f`) and forwards *new* lines to an n8n webhook — useful if you want alerting without running the whole `core/logger.py` push‑on‑critical path.

**`XAI/`** — A self‑contained package with no dependency on anything else in the repo except `requests`. `attack_analyzer.py` builds a rich per‑IP `AttackerProfile` (timeline, MITRE technique tags, a 0–1 risk score, behavioral‑pattern counters) as you feed it events one at a time. `merger.py` wraps that in a CLI: read the JSONL log → build profiles → assemble a report → POST it to an n8n webhook, with retry logic via `urllib3.util.retry.Retry`. See Phase 8 for a real bug in how this module is imported.

**`n8n/`** — Two exported n8n workflows (JSON, meant to be imported into an n8n instance, not run directly): `alert_sender.json` receives raw honeypot events, filters for `warning`/`critical`, formats a message, and POSTs it straight to the Telegram Bot API. `xai_node.json` receives XAI‑style reports, computes a 0–100 risk score in a Code node, calls Groq's chat‑completions endpoint to generate a short SOC‑style writeup, and sends *that* to Telegram via n8n's native Telegram node (safer pattern — credentials live in n8n, not the JSON — see Phase 8).

**`config/config.yaml`** — Declares ports and two brute‑force thresholds. **Nothing in the codebase reads this file** (verified: no `yaml.safe_load`, no `import yaml`, no reference to `config.yaml` anywhere in the Python source). Ports and thresholds are all hardcoded at their call sites instead. Treat this file as aspirational/documentation only until someone wires it up.

**`data/`** — `raw_logs/honeypot_events.jsonl` is the live log (461 lines at time of analysis); `old.jsonl` is an earlier rotated copy from a prior run on a Windows dev machine (path strings inside confirm this: `C:\_MPROJECT\honeypot_v2\...`). `ftp_decoy/` holds four small, entirely fabricated files (fake admin/root passwords, fake finance numbers, fake employee names) that `ftp_honeypot.py` auto‑generates on first run if they don't already exist.

**`scripts/start_website_tunnel.ps1`** — A genuinely well‑written PowerShell helper: checks whether the decoy website is already listening, starts it if not, waits for the port, then launches either an ephemeral Cloudflare "quick tunnel" or sets up a named tunnel with a fixed hostname (handling `cloudflared tunnel login`/`create`/`route dns` for you). Windows‑only as written (`Get-NetTCPConnection`, `$env:USERPROFILE`, etc.).

**Root files** — `run.py` is the main entry point (starts everything except the alternate website). `run_website.py` starts only the simple Flask decoy site. `temp.html` (44 KB) is an earlier draft of the dashboard UI with different theming — it's not referenced by any route in either Flask app and is dead weight; safe to delete.

---

## Phase 3 – Execution Flow

**`python run.py` (no flags):**
1. Prints the banner, then calls `core.launcher.start_all()`.
2. Three daemon threads start, each binding one port: SSH (2222), FTP (2121), HTTP (8080), staggered by 0.3s each to avoid bind races.
3. Main thread sleeps 1s to let sockets bind, then (unless `--no-dashboard`) starts a fourth daemon thread running the Flask dashboard on 127.0.0.1:5050.
4. If `--simulate` was passed, a fifth thread waits 3s then runs all three simulation scripts in sequence against the ports just opened.
5. Main thread then just loops `time.sleep(1)` forever, waiting for Ctrl+C.

**One attacker interaction, end to end (say, an SSH login attempt):**
1. Attacker connects to `:2222`. `SSHHoneypotHandler.handle()` sends a real‑looking OpenSSH banner, prompts for username then password, reads both as plaintext.
2. A per‑IP in‑memory counter increments; at ≥3 attempts from the same IP the event is escalated to `ssh_bruteforce`.
3. `core.logger.log_event(...)` is called: it builds a record, appends one JSON line to `data/raw_logs/honeypot_events.jsonl`, and does a non‑blocking push into the shared `queue.Queue` used for SSE.
4. If `severity == "critical"` (this happens for FTP login *success* and some HTTP attack types, not for the SSH path itself — SSH events are `info`/`warning`, never `critical`), a background thread POSTs a normalized payload to `N8N_WEBHOOK_URL`.
5. Separately, the SSH handler writes `Permission denied, please try again.` back to the socket and closes.
6. Whoever has the dashboard open at `:5050` either receives the event instantly via the open `/stream` SSE connection, or sees it on the next poll of `/api/monitor` (every few seconds, per the frontend's own polling interval).

**The alternate website, run separately:** `python run_website.py` starts an independent Flask process (default port 8090, bound to `0.0.0.0` so it's reachable from your LAN/phone). It writes into the *same* `data/raw_logs/honeypot_events.jsonl`, so its events show up in the same dashboard even though it's a different process. The Node/React version works the same way except `website/backend/server.js` writes honeypot‑format JSON lines to the log file directly with plain `fs.appendFile` (it doesn't import anything from the Python `core.logger` module — it's a parallel, independently‑maintained implementation of the same idea, in JavaScript).

---

## Phase 4 – Database

There is **no relational/document database for the honeypot core itself.** The system of record is a flat file:

**`data/raw_logs/honeypot_events.jsonl`** — append‑only, one JSON object per line, written by `core/logger.py` (Python side) and by `website/backend/server.js` (Node side, independently, same schema by convention). Every dashboard API endpoint re‑reads and re‑parses this file (up to some `limit`) on *every* request — there's no index, no query engine, just `Path.read_text().splitlines()[-limit:]` and in‑memory filtering. Fine at hundreds/low‑thousands of lines; will get linearly slower as it grows, since there's no rotation or archiving logic despite `config.yaml` declaring a `max_queue_size: 500000` that (per Phase 2) is never actually read.

**Record schema** (every line):
```json
{
  "timestamp": "ISO-8601 UTC",
  "source_ip": "string",
  "service": "ssh | ftp | http | website",
  "event": "e.g. ssh_login_attempt",
  "attack_type": "e.g. sql_injection, credential_access, authentication_probe",
  "payload": "string or object — whatever was captured",
  "severity": "info | warning | critical",
  "metadata": { "...event-specific fields..." }
}
```

**`website/backend/data/honeypot.db`** — a real SQLite database, but it only backs the *alternate* Express/React decoy site's fake employee‑portal signup/login, not the honeypot's own event data. Single table:

```sql
CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```
Created automatically by `db.js` on first run (`CREATE TABLE IF NOT EXISTS`) — no migrations, no seed script. At the time of analysis it holds exactly one row (a test signup), and password hashing is genuinely bcrypt (60‑char hash, cost factor 10), not plaintext. No other tables, no foreign keys, no ORM — raw `sqlite3` driver with parameterized `?` placeholders throughout (good — see Phase 8).

The "database" referenced inside `data/ftp_decoy/server_config.conf` (`host=192.168.1.10`, `port=5432`, a fake Postgres password) is **fictional bait content**, not a real connection anywhere in this codebase — see Phase 8.

---

## Phase 5 – APIs

Four separate HTTP servers exist. None of the honeypot‑facing ones require authentication (intentional — attackers need to be able to interact freely); the dashboard and the Express backend are unauthenticated except where noted.

### Dashboard API — `dashboard/app.py`, port 5050 (127.0.0.1 only by default)

| Method | Route | Purpose | Auth |
|---|---|---|---|
| GET | `/` | Serves the dashboard UI | none |
| GET | `/api/monitor` | Last 500 events, computed stats, system stats (CPU/RAM if `psutil` present) | none |
| GET | `/api/honeypot` | Per‑service breakdown + captured credentials (last 2000 events) | none |
| GET | `/api/credentials` | Every captured username/password pair | none |
| GET | `/api/ids` | Stats, 24‑bucket timeline, top‑10 source IPs | none |
| GET | `/api/xai/alerts` | Last 50 warning/critical events | none |
| POST | `/api/xai/report` | Builds a report from recent alerts, POSTs it to `http://localhost:5678/webhook/xai-honeypot` (hardcoded URL) | none |
| GET | `/api/report` | JSON summary report | none |
| GET | `/api/report/download` | Same report as a downloadable `.txt` file | none |
| GET | `/stream` | Server‑Sent Events feed of new events, 15s heartbeat | none |

### Fake HTTP honeypot — `core/honeypots/http_honeypot.py`, port 8080

| Method | Route | Behavior |
|---|---|---|
| GET | `/` | Fake "Company Portal" landing page |
| GET/POST | `/login` | Always fails; logs credentials + runs SQLi/XSS/brute‑force detection on the submission |
| GET | `/search?q=` | Echoes query as empty JSON results; scans `q` for attack patterns |
| GET | `/admin` | Always returns 403; logged as reconnaissance |
| GET/POST | `/upload` | Accepts a file, logs filename + body preview, never actually stores anything |
| GET | `/forgot` | Fake "email sent" response |
| GET/POST | `/<path:path>` | Catch‑all — logs as `directory_scanning` if the path matches known scan patterns |

### Simple decoy website (Flask) — `website/app.py`, port 8090 by default

| Method | Route | Behavior |
|---|---|---|
| GET | `/` | Lists files currently in `decoy_files/` |
| POST | `/login` | Logs the attempt, always returns "Login failed" |
| GET | `/search?q=` | Logs + attack‑pattern scan, returns empty results |
| GET | `/files/<path:filename>` | Serves a decoy file via Flask's `send_from_directory` (traversal‑safe — see Phase 8) |
| GET/POST | `/<path:path>` | Catch‑all, logs and 404s |

### Fuller decoy website (Express) — `website/backend/server.js`, port 5000 by default

| Method | Route | Auth | Behavior |
|---|---|---|---|
| GET | `/` | none | Health/info JSON, lists available routes |
| POST | `/frontend/log` | none | Ingests client‑side events from the React app |
| POST | `/signup` | none | Creates a real user row (bcrypt hash) |
| POST | `/login` | none | Real check against SQLite; issues a JWT (8h expiry) on success |
| GET | `/dashboard` | **JWT required** | Returns fake KPI numbers + `req.user` |
| GET | `/search?q=` | none | Logs + scans, returns empty results |
| GET | `/files` | none | Lists decoy files |
| GET | `/files/:filename` | none | Serves a decoy file — **not** traversal‑safe, see Phase 8 |
| GET | `/logs/backend` | **JWT required** | Returns recent backend log entries |
| GET | `/logs/frontend` | **JWT required** | Returns recent frontend log entries |
| any | `*` | none | 404, logged |

Every route on every one of these four servers writes to the shared JSONL log (directly or via `core.logger`), which is what makes the single dashboard able to show activity from all of them.

---

## Phase 6 – Frontend

There are genuinely **three separate frontends** here, not one:

**1. The dashboard (`dashboard/templates/index.html`)** — 729 lines, no framework, no build step. Sidebar nav switches between five sections (Monitor, Honeypot, Credentials, XAI, IDS) by toggling visibility, each backed by one `fetch()` call to the corresponding `/api/*` route on an interval, plus one persistent `EventSource('/stream')` for the live feed. All dynamic content is inserted via `innerHTML`, but — importantly — every value that could contain attacker‑supplied text (usernames, passwords, attack types, IPs, event names) is run through a small `esc()` helper (`&`, `<`, `>` → entities) before insertion. That matters a lot here specifically because attacker‑submitted strings are the primary data source; it's correctly treated as untrusted throughout.

**2. The alternate decoy site's React app (`website/frontend/`)** — React 18 + Vite 5 + `react-router-dom` 6. Three routes: `/` (login + search + file list), `/signup`, and `/dashboard` (gated client‑side by checking `localStorage.getItem("hp_token")`, not by anything server‑verified — the real gate is the Express `requireAuth` middleware on the API side, which is what actually matters). All rendering goes through normal JSX interpolation, which React escapes by default — no `dangerouslySetInnerHTML` anywhere, so no XSS surface here regardless of what an "attacker" types into the login form.

**3. The Flask‑rendered decoy page (`website/templates/index.html`)** — plain Jinja2, autoescaping on by default in Flask, so the two dynamic values it renders (`message`, and each filename `f` from the decoy directory listing) are safe even though neither is attacker‑controlled anyway (filenames come from your own `decoy_files/` folder).

State management is minimal everywhere: the dashboard uses plain module‑level JS variables; the React app uses component‑local `useState` plus `localStorage` for the JWT (standard, though it means the token is theoretically readable by any injected script — a routine trade‑off, not a defect specific to this project).

---

## Phase 7 – Backend

**Logging is the backbone.** `core/logger.py` is the only place that writes `honeypot_events.jsonl` from the Python side, and it's intentionally simple: a `threading.Lock` around the file append (thread‑safe for the multiple honeypot threads writing concurrently), a bounded `queue.Queue(maxsize=500)` for the dashboard's SSE stream (drops events rather than blocking if the queue fills, which is the right call for a logger — you never want logging to apply backpressure to the thing being logged), and a best‑effort, fire‑and‑forget POST to n8n on critical events only (failures are swallowed — again correct, alerting must never be able to crash or stall the honeypot).

**Error handling philosophy, generally:** honeypot handlers catch broadly (`except (OSError, ConnectionResetError): pass` in the SSH handler, for example) because the entire point is to survive malformed, hostile, or truncated input without crashing — this is appropriate defensive design for this specific kind of application, not sloppiness. The Flask apps run with `debug=False, use_reloader=False` everywhere (the SSH honeypot's `run.py` comment even calls out *why* the reloader is disabled: it spawns a subprocess that breaks the threading model) — correct choice for anything that will ever be reachable from outside localhost.

**Auth exists in exactly one place: the Express backend.** `middleware/auth.js` implements a standard Bearer‑token JWT check (`jwt.verify` against `process.env.JWT_SECRET`, falling back to the literal string `"dev_secret"` if the env var is missing) and gates `/dashboard`, `/logs/backend`, and `/logs/frontend`. Nothing else in the project has any authentication or authorization at all — not the honeypot services (correct, they need to accept anything), and not the main dashboard's own API (see Phase 8 for why that's worth a second look).

---

## Phase 8 – Security Review

### Hardcoded secrets (the two flagged at the top, in detail)

1. **Telegram bot token in `n8n/alert_sender.json`.** Both `HTTP Request` nodes call `https://api.telegram.org/bot8705505421:AAHPOEZ‑ubaP…/sendMessage` with the token embedded directly in the URL string, twice. This is exactly the kind of thing n8n's own credential store exists to prevent (compare with `n8n/xai_node.json`'s Telegram node, which correctly uses n8n's native Telegram credential and has *no* token in the JSON — the two workflows are inconsistent with each other on this point). **Action:** revoke via BotFather, reissue, store the new token as an n8n credential, rebuild `alert_sender.json`'s Telegram step using n8n's Telegram node instead of raw `HTTP Request`.

2. **Real `JWT_SECRET` committed in `website/backend/.env`**, and — because `.env` is in this ZIP — already exposed via this upload regardless of what `.gitignore` says about git. **Action:** rotate the secret (any value from a secure random generator, 32+ bytes), and make sure `.env` is excluded before creating any future ZIP/export of this project, not just excluded from git.

### Other findings

- **Path traversal risk — `website/backend/server.js`, `GET /files/:filename`.** The handler does `path.join(decoyDir, filename)` then serves it with `res.sendFile(safePath)` called on a raw absolute path, with **no `root` option**. Express's `res.sendFile(path, { root })` form is what actually jails the resolved path inside `root`; calling it with a bare absolute path skips that protection entirely. A `filename` value like `..%2F..%2F..%2Fetc%2Fpasswd` gets URL‑decoded to `../../../etc/passwd` *after* Express's router has already matched it as a single path segment, then `path.join` happily walks it outside `decoyDir`. **Fix:** `res.sendFile(filename, { root: decoyDir })`, or explicitly verify `path.resolve(safePath).startsWith(path.resolve(decoyDir))` before serving. For contrast: the Flask equivalent (`website/app.py`'s `/files/<path:filename>`) ultimately calls `send_from_directory(DECOY_DIR, filename)`, which uses Werkzeug's `safe_join` internally and does correctly reject traversal — so this is a Node‑specific gap, not a design flaw shared across both decoy sites.

- **Spoofable source IP.** Both `core/honeypots/http_honeypot.py` and `website/app.py` compute the logged attacker IP as `request.headers.get("X-Forwarded-For", request.remote_addr)` — trusting a client‑supplied header outright. Anyone can set `X-Forwarded-For` to any value and both poison your logs with a fake source IP *and* evade the brute‑force counters that are keyed by that same value. This is only safe if you're always behind a proxy you control that overwrites/strips that header before forwarding; as written, on a directly‑exposed honeypot, it isn't. Same pattern in `website/backend/server.js`'s log fields, though `req.ip` (Express's own resolved value) is logged alongside the raw header there, which is safer.

- **No authentication on the main dashboard or its API.** `/api/credentials`, `/api/report`, `/stream`, etc. return everything the honeypot has captured — including any real passwords a confused legitimate visitor typed — with zero auth, currently mitigated only by the default `127.0.0.1` bind in `dashboard/app.py`. There's nothing in the code stopping someone from changing that bind to `0.0.0.0`; if that's ever done (e.g., to view the dashboard from another machine), everything captured becomes world‑readable with no login. Worth adding at least basic auth before ever binding this anywhere but localhost.

- **Weak fallback JWT secret.** Both `middleware/auth.js` and `server.js` fall back to the literal string `"dev_secret"` if `JWT_SECRET` isn't set. Combined with finding #2 above, this is low real‑world stakes today (it only guards a decoy backend with no real data behind it), but it's the kind of default that's easy to forget about if this code is ever repurposed for something that isn't a honeypot.

- **`config.yaml` vs. code drift.** `config.yaml` declares `ssh.brute_force_threshold: 5`; the actual code (`core/honeypots/ssh_honeypot.py`) hardcodes `threshold=3` and never reads the YAML file at all (confirmed: no `yaml.safe_load`/`import yaml`/`config.yaml` reference anywhere in the Python source, despite `pyyaml` being a declared dependency). The README's own text matches the *code* ("brute‑force threshold in code is 3 attempts"), so `config.yaml` is simply unused — editing it will silently do nothing. Filed here because a security‑relevant threshold that looks configurable but isn't is worth knowing before you rely on it.

- **`XAI/merger.py` import bug.** `merger.py` contains `from attack_analyzer import AttackAnalyzer, AttackerProfile` — a bare, non‑relative import. This only resolves because running `python XAI/merger.py` directly puts `XAI/` on `sys.path[0]` as a side effect of how Python executes scripts. Both `XAI/README.md` and `XAI/QUICKSTART.md` also document a *"Programmatic Usage"* pattern — `from XAI.merger import XAIMerger` — which imports `XAI` as a package instead; under that usage, `merger.py`'s internal `from attack_analyzer import ...` breaks with `ModuleNotFoundError: No module named 'attack_analyzer'`, because now nothing has put `XAI/` itself on `sys.path`. **Fix:** change that one line to `from .attack_analyzer import AttackAnalyzer, AttackerProfile` (relative import) or `from XAI.attack_analyzer import ...` (absolute), either of which works correctly under both usage patterns.

- **Decoy content is confirmed fabricated, not a leak.** `data/ftp_decoy/*` and `website/decoy_files/*` are synthetic bait, generated by `_create_decoy_files()` in `ftp_honeypot.py` or hand‑authored with placeholder data (`corp-example.local`, fictional employee IDs, round‑number fake payroll figures). Nothing here is real. Flagging this explicitly since a "hardcoded secrets" scan would otherwise light up on the fake `server_config.conf`, `credentials_backup.csv`, etc. — those are working as intended.

### What's done well (worth keeping, not just worth noting)

- Every place that renders attacker‑controlled text in the dashboard goes through the `esc()` helper before hitting `innerHTML` — correctly treating attacker input as hostile, which is exactly the right instinct for this specific app.
- React's default JSX escaping and Flask's default Jinja2 autoescaping mean neither of the other two frontends has an XSS gap either, without anyone having to think about it.
- Passwords in the SQLite `users` table are bcrypt‑hashed (cost 10), not plaintext.
- All SQL access (`db.js`, `server.js`) uses parameterized `?` placeholders — no SQL injection risk in the app's *own* data layer, which is a nice detail given the app's whole job is detecting SQL injection thrown *at* it.
- Debug mode and the Werkzeug auto‑reloader are explicitly disabled on both Flask apps, with a comment explaining why for the threading‑sensitive one.

### One operational note, not a bug
Because capturing credentials is the entire point of a honeypot, `honeypot_events.jsonl` and the Express `logs/*.log` files will accumulate plaintext usernames/passwords from *everyone* who interacts with these services — including your own testing. Treat those log files as sensitive artifacts (don't publish them, don't commit them to a shared repo) for the same reason you'd rotate the two secrets above.

---

## Phase 9 – Code Quality

**Overall:** clean, consistently styled, well‑commented Python with sensible module boundaries (`core` / `dashboard` / `simulation` / `website` / `XAI` each do one thing), consistent use of `dataclasses`, type hints, and `from __future__ import annotations` throughout, and defensive `try/except ImportError` guards so the app degrades gracefully (prints a clear message and skips that component) rather than crashing if `pyftpdlib`, `flask`, or `psutil` aren't installed. This is above‑average code quality for a solo/small‑team research project.

**Duplication worth refactoring:**
- The SQLi/XSS/directory‑scan regex lists are independently reimplemented (with slightly different pattern sets each time) in `core/honeypots/http_honeypot.py`, `website/app.py`, and `website/backend/server.js`. A shared `attack_patterns` module (or a JSON file both Python and JS could load) would keep detection logic consistent across all three surfaces instead of three regex lists silently drifting apart over time.
- The n8n‑payload‑normalization logic exists **four times** in near‑identical form: `_build_n8n_payload()` in `core/logger.py`, `normalize_record()` in `simulation/n8n.py`, and again as inline JS inside both `n8n/alert_sender.json`'s Code node and `simulation/honeypot-alert.workflow.json`'s Code node. One canonical implementation (even just documented as "the" shape) would reduce the risk of the four copies diverging.
- `_ip()` / header‑allowlisting helpers are duplicated between `http_honeypot.py` and `website/app.py` almost verbatim.

**Two unconnected "XAI" implementations.** The standalone `XAI/` package (rich `AttackAnalyzer`/`XAIMerger`, MITRE technique tags, weighted risk scoring, generated recommendations) and `dashboard/app.py`'s own inline `_xai_summary()`/`_xai_payload()`/`_xai_alerts()` helpers do overlapping jobs but don't share any code — the dashboard's "Generate XAI Report" button never touches the `XAI/` package at all. These read as two iterations of the same idea that were never merged.

**Two overlapping n8n workflow exports.** `n8n/alert_sender.json` and `simulation/honeypot-alert.workflow.json` both implement a "Honeypot Alert Receiver" webhook at the same path (`honeypot-alert`) with very similar normalization logic — almost certainly an older draft left alongside the current one rather than two workflows meant to both be imported.

**Dead code:** `temp.html` (44 KB, project root) — an earlier dashboard UI draft, unreferenced by any route in either Flask app. Safe to delete.

**Minor items:**
- README heading typo: "## Dashboardd".
- README says the SSH brute‑force threshold is 3 (matches code); `config.yaml` says 5 (doesn't match anything — see Phase 8).
- `website/frontend/src/api.js` hardcodes `API_BASE = "http://localhost:5000"` rather than reading a Vite env var (`import.meta.env.VITE_API_BASE`), so pointing the frontend at any other backend URL currently requires editing source rather than configuring an environment.
- No automated tests anywhere in the repo (no `tests/` folder, no `pytest`/`jest` config) — the `simulation/` scripts are a manual/visual substitute, not a test suite.

---

## Phase 10 – Missing Features

- **No automated tests.** The `simulation/*` scripts are a reasonable manual smoke‑test substitute but there's no `pytest`/`jest`/CI configuration anywhere.
- **`config.yaml` isn't wired up.** Either have `run.py`/`core/launcher.py` load it with the already‑declared `pyyaml` dependency and use its values as defaults, or remove the file so it stops implying a level of configurability that doesn't exist yet.
- **The README's own roadmap is only partially realized.** It lists *"Phase 2: add IDS‑style classification"* and *"Phase 3: add explainability"* as future work — but basic classification already exists (the regex‑based attack detection in the HTTP honeypots) and explainability groundwork already exists (the `XAI/` module) — they're just not fully integrated with each other or with the dashboard yet. Worth treating the roadmap as "in progress," not "not started."
- **`XAI/` isn't connected to anything automatic.** It's a CLI/importable tool you run by hand (`python XAI/merger.py --webhook-url ...`); nothing in `run.py` or the dashboard invokes it. The dashboard's own "Generate XAI Report" button uses a separate, simpler, hand‑rolled implementation instead (see Phase 9).
- **No log rotation/archiving.** `honeypot_events.jsonl` grows forever; every dashboard request re‑reads it from disk. Fine now, will need addressing before this runs unattended for weeks.
- **No server‑side rate limiting** on any login form — brute‑force attempts are *detected and labeled*, never actually throttled or blocked. That's almost certainly intentional (a honeypot wants to keep the attacker engaged, not lock them out), but it's worth being explicit that this is a deliberate choice rather than an oversight, in case a future contributor "fixes" it.
- **No graceful shutdown** for the honeypot service threads — they're daemon threads that simply die when the process exits. Acceptable for a local research tool, would need revisiting for anything long‑running/production‑adjacent.
- **Windows‑first tooling.** The README scopes requirements to Windows 10/11 + PowerShell, and the only tunnel‑automation script is PowerShell‑specific. The Python core itself is cross‑platform (nothing OS‑specific in `core/`, `dashboard/`, `website/app.py`, or `XAI/`), but `scripts/start_website_tunnel.ps1` won't run as‑is on macOS/Linux — someone would need a small bash equivalent.

---

## Phase 11 – Local Setup & Development Guide

### 1. Software Requirements

| Requirement | Version / Notes |
|---|---|
| OS | Windows 10/11 per the README (PowerShell scripts assume this). The Python core itself has nothing Windows‑specific and should run fine on macOS/Linux — only `scripts/start_website_tunnel.ps1` is Windows‑only. |
| IDE | Any — nothing in the repo assumes a specific editor. VS Code is a reasonable default if you don't already have a preference. |
| Python | **3.10+** (as stated in the README; the typing style used would likely also run on 3.9, but there's no reason to deviate from what the project already targets). |
| Node.js | **Not stated in the repo's own docs** — my recommendation, based on the frontend tooling actually used: **Node 18 LTS or newer** (Vite 5, used here, requires Node ^18 or ≥20). Any recent LTS release will work for the Express backend too. |
| PowerShell | Needed only if you use `scripts/start_website_tunnel.ps1`. |
| Git | Any recent version. |
| Database server | **None needed.** The honeypot log is a flat file; the alternate site's database is SQLite, created automatically as a local file. |

### 2. Required Installations

- **Python 3.10+** — https://www.python.org/downloads/
- **Node.js 18 LTS+** (only needed if you're running the alternate Express/React decoy site) — https://nodejs.org/
- **Git** — https://git-scm.com/downloads
- *Optional* — **n8n**, if you want the Telegram/Groq alerting pipeline to actually run: https://docs.n8n.io/hosting/ (self‑hosted) or n8n Cloud.
- *Optional* — **cloudflared**, only if you'll use the tunnel script: `winget install --id Cloudflare.cloudflared -e` (the script itself checks for this and gives you this exact command if it's missing).

### 3. Project Dependencies

```powershell
# From the project root — core honeypot + dashboard
python -m venv .venv
.venv\Scripts\Activate.ps1
# if PowerShell blocks the activation script, run this once first:
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process

pip install -r requirements.txt
```
This installs `flask`, `pyftpdlib`, `pyyaml`, and `requests`. **Note:** `psutil` is mentioned in the README as an "optional dependency" for richer dashboard system stats, but it is **not** in `requirements.txt` — if you want CPU/RAM numbers in the dashboard rather than zeros, install it separately: `pip install psutil`.

```powershell
# Only if you plan to run XAI/merger.py standalone/importable
pip install -r XAI/requirements.txt
```
In practice this is mostly redundant — its only real dependency (`requests`) is already covered by the root `requirements.txt`.

```powershell
# Only if you're running the alternate Express/React decoy site
cd website\backend
npm install
cd ..\frontend
npm install
cd ..\..
```

### 4. Environment Variables

Two completely separate mechanisms are in play here — don't expect one `.env` file to cover everything.

**Python side — no `.env` file at all.** Read directly from the OS environment via `os.getenv()` in `core/logger.py`:

| Variable | Default | Purpose |
|---|---|---|
| `N8N_WEBHOOK_URL` | `http://localhost:5678/webhook/honeypot-alert` | Where critical‑severity events get POSTed |
| `N8N_WEBHOOK_TIMEOUT` | `2.0` | Seconds before giving up on that POST |

Set these in PowerShell **before** launching `run.py`, exactly as the README shows:
```powershell
$env:N8N_WEBHOOK_URL = "http://localhost:5678/webhook/honeypot-alert"
$env:N8N_WEBHOOK_TIMEOUT = "2.0"
python run.py
```

**Node side — `website/backend/.env`**, loaded via `dotenv`:

| Variable | Meaning | Where it comes from |
|---|---|---|
| `PORT` | Port the Express server listens on | Pick freely; `5000` is the project default and what the frontend expects |
| `JWT_SECRET` | Signing key for issued JWTs | **Generate a new one — don't reuse the value currently in the ZIP (see Phase 8).** Any long random string works, e.g. `node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"` |
| `FRONTEND_URL` | Allowed CORS origin | Must match wherever the Vite dev server actually runs — `http://localhost:5173` by default |

Setup:
```powershell
cd website\backend
copy .env.example .env
# then edit .env and replace JWT_SECRET with your own generated value
```

### 5. Database Setup

**Honeypot event log:** nothing to do — `data/raw_logs/` and the JSONL file are created automatically on first event.

**SQLite (`website/backend/data/honeypot.db`):** also automatic — `db.js` runs `CREATE TABLE IF NOT EXISTS users (...)` every time the server starts. No migration tool, no seed data, no manual step. The copy currently in the ZIP already has one test row in it; delete `website/backend/data/honeypot.db` if you'd rather start from a clean table (it'll be recreated empty on next `npm run dev`).

### 6. Running the Project

You're choosing between up to five independent processes depending on what you want live. Realistically, most setup sessions only need the first one or two.

```powershell
# 1) Core lab: SSH + FTP + HTTP honeypots + dashboard, all in ONE process/terminal
python run.py
# → dashboard at http://127.0.0.1:5050

# 2) (optional, separate terminal) Simple decoy website
python run_website.py
# → http://127.0.0.1:8090  (or your LAN IP, since it binds 0.0.0.0 by default)

# 3) (optional, separate terminal) Fuller decoy site — backend
cd website\backend
npm run dev
# → http://localhost:5000

# 4) (optional, separate terminal) Fuller decoy site — frontend
cd website\frontend
npm run dev
# → http://localhost:5173

# 5) (optional) generate test traffic against whatever's running from step 1
python simulation\simulate_attacks.py
```
`run.py --simulate` folds step 5 into step 1 automatically (runs it once, 3 seconds after startup). `run.py --no-dashboard` skips the dashboard thread if you only want the raw honeypots. `run_website.py --host 127.0.0.1 --port 8090` narrows the simple decoy site to localhost‑only if you don't want it LAN‑reachable.

### 7. Common Errors

| Symptom | Cause / Fix |
|---|---|
| `[FTP] pyftpdlib not installed` at startup | `pip install -r requirements.txt` wasn't run in the active venv, or the venv isn't activated. `pyftpdlib` *is* in `requirements.txt` despite the README calling it "optional" — install it and the FTP honeypot works. |
| Dashboard CPU/RAM always show 0 | `psutil` isn't installed (see Phase 3 above) — it's genuinely optional and not in `requirements.txt`. `pip install psutil` if you want real numbers. |
| `OSError: [WinError 10048]` / address already in use | Something else already owns port 2222/2121/8080/5050/5000/5173/8090. Pass `--ssh-port`/`--http-port`/etc. to `run.py`, or free the port. |
| PowerShell refuses to run `Activate.ps1` | Run `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process` once in that terminal session first (exactly as the README says). |
| `cloudflared not found` when running the tunnel script | Install it: `winget install --id Cloudflare.cloudflared -e` (the script's own error message tells you this). |
| `ModuleNotFoundError: No module named 'attack_analyzer'` | You're using `from XAI.merger import XAIMerger` (the "Programmatic Usage" pattern from the XAI docs). This is a real bug — see Phase 8. Workaround until it's fixed: run via the documented CLI form instead (`python XAI/merger.py --webhook-url ...`), which doesn't hit this path. |
| CORS errors in the browser console when using the React site | `FRONTEND_URL` in `website/backend/.env` doesn't match the actual origin Vite is serving from. Confirm the Vite terminal output and align the two. |
| React dashboard route immediately bounces back to `/` | `localStorage` has no `hp_token` — you're not logged in yet (or a previous 401 cleared it). Log in via `/` first. |
| n8n alert never arrives | `N8N_WEBHOOK_URL` env var not set (Python side falls back to `localhost:5678`, which needs an actual n8n instance listening there), or the workflow isn't active in n8n, or (for the Telegram step specifically) the hardcoded bot token in `n8n/alert_sender.json` has since been revoked (it should be, per Phase 8) and nothing's replaced it yet. |

### 8. Verify Setup

1. `python run.py` → confirm all four `[✓]` lines print (SSH, FTP, HTTP, Dashboard) with no `[FTP] Skipping` or `Flask required` errors.
2. Open `http://127.0.0.1:5050` → dashboard should load; "Monitor" tab shows 0 events on a totally fresh log, or the pre‑existing 461 events if you kept the bundled `honeypot_events.jsonl`.
3. In a second terminal: `python simulation\simulate_attacks.py` → watch the dashboard's live feed populate in real time without refreshing (confirms the SSE `/stream` connection works, not just polling).
4. Visit `http://127.0.0.1:8080` directly → you should see the fake "Company Portal" and be able to submit the login form (it will always say invalid credentials — that's correct).
5. *(If running the fuller decoy site)* With backend + frontend both up, open `http://localhost:5173`, sign up with a throwaway username/password, then log in and confirm the `/dashboard` route loads with fake KPI numbers. Then check `website/backend/data/honeypot.db` gained a new row, and that a `website_signup`/`website_login_attempt` pair appears in `data/raw_logs/honeypot_events.jsonl`.
6. Click **Download .txt** on the dashboard's Report section and confirm a readable threat report downloads.

### 9. Development Workflow

- **Detection logic / what counts as an attack** → edit the regex lists in `core/honeypots/http_honeypot.py` (fake corporate portal) or `website/app.py` / `website/backend/server.js` (decoy sites). Remember these three lists are currently independent (Phase 9) — if you tune one, consider whether the others need the same tuning.
- **Dashboard UI** → `dashboard/templates/index.html` for markup/styling/client JS, `dashboard/app.py` for the API it calls. No build step — edit and refresh.
- **The alternate decoy experience** → pick Flask (`website/app.py` + `website/templates/`) for something simple to tweak, or Express/React (`website/backend/` + `website/frontend/`) if you want real auth/DB behavior to play with.
- **Attacker profiling / MITRE tagging** → `XAI/attack_analyzer.py`. Remember it isn't called by the live dashboard yet (Phase 10) — changes here only show up if you run `XAI/merger.py` by hand or wire it in yourself.
- **Alerting behavior** → import `n8n/alert_sender.json` / `n8n/xai_node.json` into your n8n instance and edit there, rather than hand‑editing the exported JSON (much easier, and avoids re‑introducing hardcoded credentials into the file).
- **Testing changes** → there's no automated suite; the practical loop is `python run.py` in one terminal, `python simulation\simulate_attacks.py` (or a single `python simulation\sim_http.py`) in another, and watching the dashboard/log file update.
- **Debugging** → both Flask apps run with `debug=False` on purpose (see Phase 7); for local debugging only, you can temporarily flip that in your own working copy, but never on anything reachable outside localhost. Otherwise, `print()`/log statements and tailing `data/raw_logs/honeypot_events.jsonl` are the primary tools already in use throughout the codebase.
- **Building** → only the React frontend has a build step: `cd website\frontend && npm run build` (outputs to `website/frontend/dist/`, already present in the ZIP from a prior build). The Python side and the Express backend run directly from source, nothing to compile.
- **Deploying** → out of scope as shipped; this is explicitly framed as a research/local‑testing tool. If you do intend to expose any of this beyond your own LAN, address the auth and path‑traversal items in Phase 8 first.

### 10. What's Missing / What to Ask Your Teammate

The ZIP is complete enough to run the entire core honeypot lab (`run.py`) and the simple decoy site (`run_website.py`) with zero external accounts. A few things need input from whoever built the n8n/alerting side:

- **An n8n instance.** n8n itself isn't part of this repo — you need either a self‑hosted instance or n8n Cloud, with `n8n/alert_sender.json` and `n8n/xai_node.json` imported as workflows.
- **A Groq API key.** `n8n/xai_node.json`'s "Groq AI" node has a blank `Authorization` header — it's meant to be filled in via an n8n credential, but no key is bundled here. Ask your teammate for one, or create your own free‑tier key at https://console.groq.com.
- **Clarity on the Telegram bot.** The token hardcoded in `n8n/alert_sender.json` is a real, currently‑live credential — ask whether that's a bot your teammate still wants used (in which case *they* should be the one to rotate it, since it's presumably tied to their BotFather account) or whether you should stand up your own bot instead.
- **`cloudflared`**, if you intend to use the tunnel script — not bundled, needs a separate install, and the named‑tunnel mode needs a Cloudflare account with a domain on it.
- **Nothing else is missing** for the parts that matter for local development — there's no undocumented database, no other unbundled secret, and no build artifact that's referenced but absent (the `frontend/dist/` build output is present, even though it's also easy to regenerate with `npm run build`).
