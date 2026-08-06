# Step 22 — Intelligent Agents, Dashboard Login Gate and IST

Baseline:

- Branch: enhancement/step21-26
- Required starting commit: ec5994c
- Step 21: simulated IPS complete

This update is additive. It does not replace the trained models, retrain any
artifact, edit the normal React portal, expose secrets, or make real firewall
changes.

## 1. Completed Step 22 scope

The live sequence is:

~~~text
Honeypot event
→ Hybrid IDS
→ Detection Agent
→ Event-Correlation Agent
→ Severity Agent
→ Explanation Agent
→ Response Agent
→ Daily-Report Agent
→ JSONL + backend + authenticated dashboard
~~~

### Detection Agent

Reads the final hybrid IDS prediction, attack type, confidence, selected model
and fusion reason. It does not classify the event a second time and cannot
overwrite the protected model result.

### Event-Correlation Agent

Groups causal events from the same source within a five-minute window. It
records the campaign ID, related-event count, affected services, attack types,
first/last time and recent event IDs. Raw source IPs are not copied into the
agent explanation.

### Severity Agent

Reviews the existing Step 14 severity using correlation context. Repeated
activity or activity spanning services can produce a higher recommended
severity. The original threat_level and threat_score remain unchanged for
auditability.

### Explanation Agent

Combines the existing XAI reason, correlation evidence and severity review into
safe analyst-readable text. It excludes raw payloads, source IPs and
credentials.

### Response Agent

Produces only a recommendation:

| Recommended severity | Response |
|---|---|
| Low | Continue monitoring |
| Medium | Rate limit |
| High | Recommend simulated block |
| Critical | Simulate block |

Every active response remains simulation-only and analyst-controlled.
automatic_host_blocking=false, host_firewall_changed=false, and no OS command
path exists.

### Daily-Report Agent

Maintains an IST-calendar-day summary and writes:

~~~text
data/reports/agents/daily_report_YYYY-MM-DD.json
~~~

The report contains aggregate counts only. It does not contain passwords, raw
payloads or source-IP values.

## 2. Correct login protection

The protected page is the Python honeypot monitoring dashboard:

~~~text
http://127.0.0.1:5050
~~~

Before login, it shows only the Honeypot Analyst Login screen. After a valid
portal login, the monitor, honeypot data, captured credentials, IDS, XAI,
intelligent agents, simulated IPS and reports become available.

The dashboard APIs, report download and SSE live stream return 401 Unauthorized
without a valid session.

The centralized backend event and IDS read endpoints also require a valid
Bearer token. The two POST ingestion endpoints remain available to the local
honeypot and real-time IDS producers.

The following are intentionally unchanged:

- The normal React portal on port 5173
- The attacker-facing HTTP decoy on port 8080
- SSH and FTP honeypots on ports 2222 and 2121

The public decoy must remain accessible so attacks can still be captured.

## 3. IST timestamp standard

New runtime timestamps use ISO-8601 with the explicit IST offset:

~~~text
2026-08-03T23:15:00.000000+05:30
~~~

Applied to:

- Common honeypot events
- Real-time IDS processed_at
- Agent completion times and daily reports
- Python dashboard reports
- Backend and frontend event logs
- SQLite receive/create/update times written by the application
- Simulated IPS state and expiry times

Historical rows are not rewritten. UTC conversion remains allowed only as an
internal calculation step for time comparisons and model features.

## 4. Safe extraction

Stop the running services with Ctrl+C, then run:

~~~powershell
cd D:\honeypot_v2
git branch --show-current
git rev-parse --short HEAD
git status --short
~~~

Expected baseline:

~~~text
enhancement/step21-26
ec5994c
~~~

data/ips/ may appear as an untracked runtime directory before extraction. The
Step 22 .gitignore update ignores it. Do not add runtime state to Git.

Extract step22_intelligent_agents_ist_auth_20260803.zip directly into:

~~~text
D:\honeypot_v2
~~~

Use Replace the files in the destination when Windows asks.

## 5. Verification

~~~powershell
cd D:\honeypot_v2
.\.venv\Scripts\Activate.ps1
python -m compileall -q core intelligent_agents machine_learning dashboard XAI
python -m unittest tests.test_step22_intelligent_agents tests.test_step22_dashboard_auth tests.test_event_schema tests.test_step16_integration tests.test_step17_dashboard tests.test_step20_honeypot_dashboard tests.test_step21_simulated_ips
cd .\website\backend
node --check server.js
node --check time.js
npm.cmd test
cd D:\honeypot_v2
git diff --check
git status --short
~~~

The Python command should pass all available tests. The Node test command
should retain the previous passing tests and add the IST/agent storage checks.

## 6. Live verification

Start the system normally:

~~~powershell
cd D:\honeypot_v2
.\.venv\Scripts\Activate.ps1
python run.py
~~~

Verify:

1. http://127.0.0.1:5050 shows only the login gate.
2. A wrong login remains locked.
3. A valid existing portal account unlocks the dashboard.
4. The new AI Agents section shows all six agents after a new attack event.
5. New JSONL/backend timestamps end in +05:30.
6. http://127.0.0.1:8080 remains publicly accessible as the attacker decoy.
7. The IPS page still states host firewall changed: no.

## 7. Commit after verification

~~~powershell
cd D:\honeypot_v2
git add .gitignore STEP22_INTELLIGENT_AGENTS.md config core intelligent_agents machine_learning dashboard XAI run.py tests website/backend
git status --short
git commit -m "feat: add intelligent agent orchestration and IST dashboard auth"
git push
~~~

Do not add data/ips/, data/reports/, node_modules/, database files, logs, .env,
n8n credentials or generated ZIP files.
