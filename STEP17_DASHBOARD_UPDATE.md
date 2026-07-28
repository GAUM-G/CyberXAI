# Step 17 — Additive Dashboard Update

Step 17 extends the existing dashboard without removing, renaming, replacing,
or redesigning teammate-built functionality.

## Exact file allowlist

Modified:

- `dashboard/app.py`
- `dashboard/templates/index.html`

Added:

- `tests/test_step17_dashboard.py`
- `STEP17_DASHBOARD_UPDATE.md`

No Node backend, database, honeypot, logger, n8n, model, model artifact, run
or teammate portal file is changed.

## Preserved dashboard behavior

The Monitor, Honeypot, IDS, XAI and Report sections remain present. Existing
monitor cards, CPU/RAM gauges, port-scan panel, SSE event feed, service cards,
captured-credential tables, IDS attack classification, top attacker IPs,
attack timeline, phase roadmap cards, XAI alert reporter, report preview and
report download remain unchanged and continue using their existing routes.

The Step 16 IDS handoff also remains compatible. `GET /api/ids` still returns:

- `source`
- `stats`
- `timeline`
- `top_ips`
- `recent_results`

## Added Step 17 presentation

The existing IDS section now also displays:

- active attack predictions;
- average model confidence;
- total critical incidents;
- exact Low, Medium, High and Critical distribution;
- service-wise results, attacks, active threats, critical incidents and
  average confidence;
- live final IDS results with source IP, service, prediction, attack type,
  threat level, confidence, model and sanitized XAI explanation;
- search and service, attack-type, severity and model filters;
- recent Critical incident rows; and
- a click/keyboard-accessible detailed event view with sanitized XAI reasons,
  SHAP features, threat factors and model components.

The IDS section refreshes every ten seconds while it is open.

## Active-threat definition

An active threat is a final IDS result where:

- `prediction` is `attack`; and
- `processed_at` (falling back to `timestamp`) is within the most recent
  15 minutes.

The window can be changed without editing code by setting
`IDS_ACTIVE_WINDOW_MINUTES` before starting the dashboard.

## Safety boundary

The detailed view consumes the sanitized Step 16 result only. Raw payloads,
metadata, usernames and passwords are not read or displayed by the Step 17
IDS presentation.
