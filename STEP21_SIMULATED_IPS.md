# Step 21 — Simulation-Only IPS Functionality

## 1. Outcome

Step 21 adds an analyst-controlled IPS demonstration after the existing
honeypot → IDS → severity → XAI → feedback pipeline.

The implementation can:

- recommend blocking a source IP;
- simulate an IP block without dropping telemetry;
- rate-limit repeated attempts inside a honeypot application;
- terminate one selected application-managed honeypot session;
- release or undo active simulations;
- suppress or reverse responses after a false-positive verdict; and
- retain a persistent audit history.

It cannot create a Windows Firewall rule or change host networking.

## 2. Non-negotiable safety contract

```text
IPS mode:                 simulation
Automatic host blocking: disabled
Host firewall changed:    no
```

The runtime contains no call path for `netsh`, PowerShell firewall commands,
`iptables`, operating-system shell execution, or system route changes. The
backend accepts only the following application-level action names:

```text
recommend_block
simulate_block
rate_limit
terminate_session
release
dismiss
```

`real_firewall_block` and every unknown action are rejected.

## 3. Runtime architecture

```text
Final IDS result
→ Step 21 policy engine
→ persistent recommendation in SQLite
→ authenticated analyst action on dashboard :5050
→ persistent IPS audit record
→ simulation state file
→ SSH / FTP / HTTP honeypot application control
```

The Node backend remains the source of truth. It stores recommendations and
audit records in `website/backend/data/honeypot.db`. Active simulation state is
exported to:

```text
data/ips/simulated_ips_state.json
```

Python honeypots read only this restricted state contract. A state file is
ignored unless it explicitly says:

```json
{
  "mode": "simulation",
  "automatic_host_blocking": false,
  "host_firewall_changed": false
}
```

## 4. Response policy

| Final context | Default recommendation |
| --- | --- |
| Normal IDS prediction | Continue monitoring |
| Latest feedback is false positive | Suppress response |
| Low attack severity | Continue monitoring |
| Medium severity | Honeypot-level rate limit |
| High severity | Recommend simulation-only IP block |
| Critical severity | Simulated block plus session review |
| Repeated Low/Medium activity, five or more attempts in five minutes | Honeypot-level rate limit |

The latest Step 20 severity override becomes the effective severity. A
confirmed-attack verdict is included in the policy reason. A false-positive
verdict suppresses the recommendation and reverses active actions related to
that event.

## 5. Application-level behaviour

### 5.1 Simulated block

A simulated block does not refuse or discard later telemetry. Later matching
events continue through the normal logger and receive:

```text
metadata.ips.would_have_been_blocked = true
metadata.ips.host_firewall_changed = false
```

This proves what an IPS would have blocked while preserving honeypot evidence.

### 5.2 Rate limit

Rate limiting is limited to the selected source IP and honeypot service.

- SSH and FTP use a bounded application delay of at most one second.
- HTTP returns a honeypot-level `429 Too Many Requests` response.
- The control expires automatically and can be released early.

### 5.3 Session termination

- FTP checks the exact `session_id` before commands and safely closes only that
  FTP handler session.
- HTTP records and returns a simulation-only session response when an exact
  request session is targeted.
- SSH applies safe state at its per-connection session boundary.
- No service process, unrelated socket, or host process is terminated.

## 6. Persistent data

### `ips_recommendations`

Stores the source event, source IP, service, session, attack, original and
effective severity, confidence, repeat count, response recommendation, reason,
feedback verdict, policy version, and status.

### `ips_actions`

Stores the selected action, analyst identity, duration, expiry, target,
simulation mode, release relationship, status, and safety evidence.

Actions expire automatically. Release adds a new audit record and marks the
original active action as reversed; history is not deleted.

## 7. Backend API

| Method and route | Purpose | Authentication |
| --- | --- | --- |
| `GET /api/ips/safety` | Read immutable safety mode | No |
| `GET /api/ips/status` | Counts and policy | Analyst token |
| `GET /api/ips/recommendations` | Recommendation queue | Analyst token |
| `GET /api/ips/actions` | Append-only audit view | Analyst token |
| `POST /api/ips/actions` | Perform a safe action | Analyst token |

The analyst identity comes from the existing JWT-authenticated Step 20 session;
the browser cannot supply a different analyst identity.

## 8. Dashboard on port 5050

The sidebar now contains `IPS Response`. Its workspace shows:

- IPS mode;
- automatic host-blocking state;
- host-firewall-change state;
- pending recommendations;
- active simulated blocks;
- active rate limits;
- targeted session terminations;
- the recommendation queue; and
- the complete action audit history.

Controls are available only after signing in through:

```text
Explainable AI → Analyst session
```

Every active-action confirmation states that no Windows Firewall rule will be
created.

## 9. Telegram contract

The Step 19 IDS alert adapter now adds:

```text
response_recommendation
ips_mode = simulation
automatic_host_blocking = false
host_firewall_changed = false
```

During live validation, add these lines to the existing n8n Telegram message
without changing its webhook or Telegram destinations:

```javascript
const ipsResponse = compact(
  data.response_recommendation,
  "Simulation-only analyst review recommended.",
  700
);

// Add inside the existing message array:
`Response: ${ipsResponse}`,
`IPS mode: ${data.ips_mode ?? "simulation"}`,
`Automatic host blocking: ${data.automatic_host_blocking === true ? "Enabled" : "Disabled"}`,
`Host firewall changed: ${data.host_firewall_changed === true ? "Yes" : "No"}`,
```

## 10. Exact project allowlist

1. `STEP21_SIMULATED_IPS.md`
2. `config/config.yaml`
3. `core/simulated_ips.py`
4. `core/logger.py`
5. `core/honeypots/ssh_honeypot.py`
6. `core/honeypots/ftp_honeypot.py`
7. `core/honeypots/http_honeypot.py`
8. `dashboard/templates/index.html`
9. `simulation/n8n.py`
10. `tests/test_step21_simulated_ips.py`
11. `website/backend/.env.example`
12. `website/backend/db.js`
13. `website/backend/ips_response_store.js`
14. `website/backend/server.js`
15. `website/backend/tests/ips_response_store.test.js`

No model, dataset, XAI, Step 20 feedback, React frontend, package dependency,
n8n destination, or firewall configuration file is changed.

## 11. Automated verification

```powershell
python -m unittest tests.test_step21_simulated_ips -v

Push-Location .\website\backend
npm.cmd test
Pop-Location

python -m unittest discover -s .\tests -p "test_*.py" -v
python -m compileall -q core dashboard simulation tests
```

The focused tests verify safety defaults, rejection of unsafe state, simulated
block annotations, bounded rate limiting, session targeting, expiry,
false-positive suppression, undo, backend routes, dashboard controls, audit
records, and Telegram safety fields.

## 12. Live demonstration

```text
Controlled repeated attack
→ honeypot event and IDS result
→ Step 21 recommendation appears on :5050
→ analyst confirms the attack in XAI
→ analyst selects Simulate Block or Rate Limit in IPS Response
→ action appears as active with an expiry
→ next matching event is marked would_have_been_blocked or rate-limited
→ Telegram includes the response recommendation
→ dashboard and audit history show host firewall changed: no
→ analyst selects Release / Undo
```
