# Step 18 — Additive React Frontend Update

## Objective

Step 18 improves the existing React portal at port `5173` with clearer
navigation, stronger mobile behavior, and detailed final Hybrid IDS results.
The update preserves the completed Step 16 pipeline, the Step 17 dashboard,
and all existing teammate-built portal behavior.

## Exact file allowlist

Modified:

- `website/frontend/src/components/PortalShell.jsx`
- `website/frontend/src/pages/DashboardPage.jsx`
- `website/frontend/src/styles.css`

Added:

- `website/frontend/src/components/IDSInsights.jsx`
- `tests/test_step18_frontend.py`
- `STEP18_FRONTEND_UPDATE.md`

No backend, database, dashboard, honeypot, logger, n8n, model, model artifact,
`run.py`, API helper, route definition, home page, signup page, package file,
lockfile, or Vite configuration is changed.

## Preserved frontend behavior

The existing `/`, `/signup`, and protected `/dashboard` routes remain.
Login, signup, logout, token storage, resource search, shared files, frontend
logging, the three Security Panel cards, warning/critical XAI alerts, alert
refresh, and the n8n XAI report button remain present.

## Added navigation

Every portal page now has a responsive navigation bar:

- Home;
- Create Account while logged out;
- Security Dashboard while logged in; and
- an IDS Details jump link on the dashboard.

## Added IDS details

The authenticated dashboard now reads the final sanitized results from:

- `GET /api/ids-results?limit=100`; and
- `GET /api/ids-results/stats`.

It displays totals, attacks, Critical results, average confidence, recent
predictions, attack type, service, threat level, model, and a sanitized detail
window. Search and service, threat-level, and prediction filters operate
entirely in the browser. Results refresh every ten seconds.

The detail window displays operational fields already present in the Step 16
sanitized IDS result. It does not request or display raw payloads, metadata,
usernames, passwords, or credentials.

## Responsive behavior

Navigation wraps on narrow screens, dashboard controls stack, summary cards
collapse from four columns to two and then one, tables remain horizontally
scrollable, and the event detail window fits within the mobile viewport.

## Validation

Run the focused test:

```powershell
python -m unittest discover -s tests -p "test_step18_frontend.py" -v
```

Run the complete Python regression suite:

```powershell
python -m unittest discover -s tests -v
```

Build the React frontend:

```powershell
cd website\frontend
npm.cmd run build
```
