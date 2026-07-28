# Step 16 — Real-Time IDS Integration

## 1. Objective

Step 16 connects the completed inference stack to the live honeypot system:

`Honeypot event → preprocessing → Hybrid IDS → threat level → SHAP → JSONL → SQLite/API → dashboard and n8n adapter`

The protected inference stack remains:

- deterministic rules;
- the Step 12 selected Decision Tree;
- Isolation Forest;
- the LSTM classifier;
- Step 14 threat reporting; and
- Step 15 SHAP explanations.

No model training, fitting, or artifact replacement is performed.

## 2. Runtime flow

`python run.py` now loads the verified artifacts and starts the real-time IDS
before starting the SSH, FTP, and HTTP event producers. New common events are:

1. validated and preprocessed by the existing Hybrid IDS;
2. classified by rules, Decision Tree, Isolation Forest, and LSTM;
3. assigned a deterministic threat score and level;
4. explained with SHAP and a human-readable reason;
5. appended to `data/detections/hybrid_ids_results.jsonl`; and
6. queued for `POST /api/ids-results`.

The JSONL write occurs before backend delivery. If port `5000` is temporarily
unavailable, honeypot collection and inference continue and queued results are
retried while the process remains running.

## 3. Safe integration result

Each final result includes operational context needed by the dashboard:

- source event ID and timestamp;
- source IP;
- destination port;
- service, event type, event, and status;
- request method and request path when available; and
- processing timestamp.

The source payload, metadata, username, password, and other credentials are not
copied into the IDS result. The Step 15 XAI privacy flags remain false for raw
payload, source IP, and credentials because those values are not placed inside
the explanation.

## 4. Backend storage

The Express backend initializes the `ids_results` SQLite table automatically.

### Store one result

`POST /api/ids-results`

Responses:

- `201` — stored for the first time;
- `200` — duplicate event ID already exists;
- `400` — schema, safety, or privacy validation failed; and
- `500` — storage failure.

### Read results

`GET /api/ids-results`

Optional query parameters:

- `limit` and `offset`;
- `service`;
- `prediction`;
- `threat_level`;
- `attack_type`; and
- `model_used`.

### Read summary

`GET /api/ids-results/stats`

The summary contains total results, attacks detected, unique source IPs, and
counts by service, attack type, threat level, and model.

Duplicate delivery is safe because `event_id` is unique in SQLite.

## 5. Dashboard handoff

The existing dashboard endpoint remains:

`GET http://127.0.0.1:5050/api/ids`

Its existing fields remain compatible:

- `stats`;
- `timeline`; and
- `top_ips`.

It now calculates these values from final Hybrid IDS predictions. It also
returns `recent_results` for Step 17. The endpoint prefers centralized backend
results and falls back to the durable IDS JSONL file if the backend is not yet
available. Step 17 will update the visual presentation.

## 6. n8n adapter

The existing command remains backward compatible and still forwards raw events
by default:

```powershell
python .\simulation\n8n.py --mode local
```

Step 16 adds an explicit final-result source:

```powershell
python .\simulation\n8n.py --mode local --source ids
```

The final-result adapter preserves the existing webhook fields (`severity`,
`ip`, `type`, `attack_type`, `target`, and `timestamp`) and adds the model,
confidence, threat score, and sanitized XAI summary.

Use only one forwarder for a given live verification. Do not activate two n8n
workflows with the same production webhook path. Telegram formatting and the
final workflow change are reserved for Step 19.

## 7. Commands

### Normal automatic start

```powershell
cd D:\honeypot_v2
.\.venv\Scripts\Activate.ps1
python run.py
```

### Diagnostic opt-out

```powershell
python run.py --no-ids
```

### Replay existing events only when intentionally requested

```powershell
python run.py --ids-replay-existing
```

The default follows only newly appended events to avoid replaying historical
attacks on every restart.

### Backend tests

```powershell
cd D:\honeypot_v2\website\backend
npm.cmd test
```

### Python regression

```powershell
cd D:\honeypot_v2
.\.venv\Scripts\Activate.ps1
python -m unittest discover -s .\tests -p "test_*.py" -v
```

### Protected-artifact checks

```powershell
python .\machine_learning\hybrid_ids.py --check
python .\machine_learning\realtime_ids.py --check
```

## 8. Expected live services

Before restarting after an unexpected shutdown, verify that ports `2222`,
`2121`, `8080`, `5050`, `5000`, `5173`, and `5678` are free.

Normal start order:

1. n8n;
2. `python run.py`;
3. Express backend;
4. React frontend; and
5. one selected n8n forwarder mode when needed.

No Telegram token or other credential belongs in project files.

## 9. Step boundaries

Step 16 supplies integrated data and compatible adapters only.

- Step 17: IDS dashboard presentation.
- Step 18: frontend integration.
- Step 19: final n8n and Telegram alert formatting.

The dashboard HTML, React frontend, n8n workflow JSON, protected Hybrid IDS,
SHAP explainer, and Step 12 model artifacts are intentionally unchanged here.
