# Step 20 — Human-in-the-Loop Feedback and XAI Review Dashboard

## Goal

Step 20 adds an authenticated analyst review loop to both the React IDS portal
and the primary Honeypot Security Dashboard at `http://127.0.0.1:5050`. An
analyst can:

- confirm an attack;
- mark a result as a false positive;
- add a severity override without replacing the IDS severity;
- record investigation notes; and
- inspect the complete feedback history for an event.

The event-review dialogs present confidence, threat score, decision source,
separate decision/threat/feature explanations, SHAP contributions, the SHAP
scope limitation, and privacy/safety indicators.

## Safety contract

- The IDS result stored in `ids_results` is immutable.
- `severity_override` is stored separately from `threat_level`.
- Every review creates a new `analyst_feedback` row; earlier reviews are never
  updated or deleted.
- Analyst identity is read from the verified JWT (`req.user`), not from the
  request body.
- A review is accepted only when its `event_id` exists in `ids_results`.
- Feedback is retained for later offline model evaluation or controlled
  improvement. Step 20 does not train, fit, reload, or modify a model.
- The dashboard displays only the privacy-safe XAI object already produced by
  the hybrid IDS. It does not request or expose raw payloads or credentials.
- The Python dashboard changes are presentation and authenticated feedback
  integration only. Honeypots, IDS decision logic, models, n8n, Telegram, and
  `simulation/n8n.py` are unchanged.
- The `5050` dashboard signs analysts in through the existing Node backend. It
  never accepts an analyst ID or username inside a feedback submission.

## Database

`initializeAnalystFeedbackStore(db)` creates `analyst_feedback` automatically
when the Node backend starts.

Each append-only row stores:

- `event_id`
- authenticated analyst ID and username
- `verdict`: `confirmed_attack` or `false_positive`
- optional `severity_override`: `Low`, `Medium`, `High`, or `Critical`
- analyst notes (maximum 2000 characters)
- snapshots of the original prediction, severity, and attack type
- creation time

Review statistics use only the latest row for each event. The full row history
remains available for audit.

## Authenticated API

All feedback endpoints require:

```text
Authorization: Bearer <portal JWT>
```

### List feedback

```http
GET /api/analyst-feedback?event_id=<event_id>&limit=50
```

Optional filters: `event_id`, `verdict`, `limit`, and `offset`.

### Latest feedback for dashboard rows

```http
GET /api/analyst-feedback/latest?event_ids=<comma-separated-event-ids>
```

At most 100 IDs are accepted in one request.

### Review statistics

```http
GET /api/analyst-feedback/stats
```

Returns reviewed, awaiting-review, confirmed-attack, false-positive, and
severity-override counts.

### Submit a review

```http
POST /api/analyst-feedback/<event_id>
Content-Type: application/json

{
  "verdict": "confirmed_attack",
  "severity_override": "High",
  "notes": "Investigation confirms repeated hostile activity."
}
```

Do not send an analyst ID or username. The server gets both from the verified
session.

## Dashboard workflow

### Primary Honeypot Dashboard (`:5050`)

1. Start the Node backend and the Honeypot Security Dashboard.
2. Open `http://127.0.0.1:5050` and select **Explainable AI**.
3. Sign in with an existing portal account under **Analyst session**.
4. Inspect the live review statistics and select an explainable IDS result.
5. Review the confidence, threat score, decision/threat/feature explanations,
   SHAP contributions, limitation notice, and safety indicators.
6. Confirm the attack or mark it as a false positive.
7. Optionally choose a severity override and record sanitized notes.
8. Save the review and confirm it appears in the append-only audit history.

### React portal (`:5173`)

1. Sign in to the employee portal.
2. Open **Security Dashboard** and scroll to **Live Hybrid IDS Details**.
3. Use the service, threat, prediction, review, or text filters.
4. Select **Review** on an IDS result.
5. Inspect:
   - original event and model decision;
   - confidence and threat score;
   - decision, threat, and feature explanations;
   - supporting/opposing SHAP contributions;
   - SHAP component-scope limitation;
   - privacy and safety indicators.
6. Confirm the attack or mark it as a false positive.
7. Optionally choose a severity override and add notes.
8. Save the review and verify that it appears in **Feedback history**.

## Validation

From the project root:

```powershell
.\.venv\Scripts\Activate.ps1
python -m unittest tests.test_step20_feedback -v
python -m unittest tests.test_step20_honeypot_dashboard -v
python -m unittest discover -s .\tests -p "test_*.py" -v
python -m compileall -q tests
```

From `website\backend`:

```powershell
npm.cmd test
```

From `website\frontend`:

```powershell
npm.cmd run build
```

No new npm dependency or lockfile update is required.

## Expected live check

1. Start the backend, the `5050` dashboard, and the React frontend.
2. In the `5050` dashboard, open **Explainable AI**, sign in, and open an IDS
   result.
3. Submit one `confirmed_attack` review with a severity override.
4. Confirm the table shows the new review status and effective severity.
5. Reopen the event and confirm the feedback history contains the saved row.
6. Submit a second review for the same event.
7. Confirm both history rows remain and the newest review controls the summary.
8. Confirm the original prediction and original threat severity are unchanged.
9. Open the React portal and confirm the same saved review is visible there.
