# Step 19 — High/Critical n8n and Telegram Alerts

## 1. Scope

Step 19 enriches immediate Telegram alerts with:

- severity;
- attack type;
- source IP;
- target service;
- confidence score;
- detection reason;
- recommended action; and
- timestamp.

Only final Hybrid IDS results whose prediction is `attack` and whose threat
level is `High` or `Critical` are eligible for immediate alerts.

The protected Hybrid IDS, model artifacts, backend, dashboard, frontend, raw
event schema, and existing Telegram destinations are unchanged.

## 2. Exact allowlist

Project files:

1. `simulation/n8n.py` — add sanitized, deterministic alert fields.
2. `tests/test_step19_alerts.py` — add focused Step 19 regression tests.
3. `STEP19_N8N_TELEGRAM_ALERTS.md` — record this procedure and contract.

n8n:

- Change only `Honeypot Alert Receiver`.
- Inside that workflow, change only `If`, `Code in JavaScript`, and
  `Edit Fields`.
- Do not change `Webhook`, its `honeypot-alert` path, or any of the three
  Telegram HTTP Request nodes.
- Do not change or activate `Safe Honeypot Receiver Backup`.
- Do not change or deactivate `My workflow 2`.

## 3. Runtime flow

```text
Common honeypot event
→ protected Hybrid IDS
→ sanitized hybrid_ids_results.jsonl
→ simulation/n8n.py --source ids
→ sequential five-minute alert-group suppression
→ Honeypot Alert Receiver
→ exact High/Critical filter
→ best-effort duplicate suppression backup
→ enriched Telegram message
```

Keep direct raw-event n8n delivery disabled when starting the honeypots:

```powershell
$env:N8N_WEBHOOK_URL=""
python run.py
```

Start the Step 19 forwarder with the final IDS source:

```powershell
python .\simulation\n8n.py --mode local --source ids
```

Do not use the default raw source for Step 19 verification because raw events
do not contain final model confidence, threat level, or sanitized XAI reasoning.

## 4. Alert contract

`simulation/n8n.py` preserves the legacy fields used by the current workflow
and adds:

| Field | Meaning |
| --- | --- |
| `alert_schema_version` | Step 19 alert contract version |
| `alert_eligible` | `true` only for High/Critical attack predictions |
| `event_id` | Original IDS detection identifier retained for traceability |
| `severity_label` | Final `High` or `Critical` threat level |
| `source_ip` | Observed source IP |
| `target_service` | SSH, FTP, or HTTP service |
| `confidence_percent` | Model confidence converted to percentage |
| `detection_reason` | Sanitized XAI reason with safe fallback |
| `recommended_action` | Deterministic action based on attack type |
| `privacy` | Confirms raw payload and credentials are excluded |

The nested `record` is recursively copied without exact sensitive keys such as
`payload`, `metadata`, `username`, `password`, `credentials`, `token`,
`authorization`, `secret`, or API keys.

## 5. n8n node settings

Open only `Honeypot Alert Receiver`.

### 5.1 `If`

Replace the existing severity conditions with one Boolean condition:

```text
Left value:  ={{ $json.body.alert_eligible }}
Type:        Boolean
Operation:   is true
```

Keep the true output connected to `Code in JavaScript`. This prevents Medium,
Low, and normal IDS results from reaching Telegram even though the legacy
`severity` field remains backward compatible.

### 5.2 `Code in JavaScript`

Replace only this node's JavaScript with:

```javascript
const data = $json.body ?? $json;

const level = String(
  data.severity_label ?? data.threat_level ?? "Unknown"
);

if (
  data.alert_eligible !== true ||
  !["High", "Critical"].includes(level)
) {
  return [];
}

const now = Date.now();
const state = $getWorkflowStaticData("global");

if (!state.step19Seen) {
  state.step19Seen = {};
}

for (const [key, seenAt] of Object.entries(state.step19Seen)) {
  if (now - Number(seenAt) >= 300000) {
    delete state.step19Seen[key];
  }
}

const eventKey = [
  data.source_ip ?? data.ip ?? "unknown",
  data.attack_type ?? "unknown",
  data.target_service ?? data.service ?? data.type ?? "unknown"
]
  .map((value) => String(value).trim().toLowerCase())
  .join("|");

if (state.step19Seen[eventKey]) {
  return [];
}

state.step19Seen[eventKey] = now;

const compact = (value, fallback, limit = 700) => {
  const text = String(value ?? fallback)
    .replace(/\s+/g, " ")
    .trim();

  if (!text) {
    return fallback;
  }

  return text.length <= limit
    ? text
    : `${text.slice(0, limit - 3)}...`;
};

const readable = (value, fallback) =>
  compact(value, fallback, 160).replaceAll("_", " ");

const confidence = Number(data.confidence_percent);
const confidenceDisplay = Number.isFinite(confidence)
  ? `${confidence.toFixed(2).replace(/\.?0+$/, "")}%`
  : "Not available";

const sourceIp = compact(
  data.source_ip ?? data.ip,
  "unknown",
  120
);

const attackType = readable(
  data.attack_type,
  "unknown"
);

const targetService = readable(
  data.target_service ?? data.service ?? data.type,
  "unknown"
).toUpperCase();

const timestamp = compact(
  data.timestamp,
  "unknown",
  120
);

const detectionReason = compact(
  data.detection_reason ?? data.xai_summary,
  "Hybrid IDS detected suspicious activity.",
  700
);

const recommendedAction = compact(
  data.recommended_action,
  "Review the sanitized IDS evidence and contain the source IP according to policy.",
  700
);

const icon = "\u{1F6A8}";
const message = [
  `${icon} ${level.toUpperCase()} HONEYPOT ALERT`,
  "",
  `Severity: ${level}`,
  `Attack type: ${attackType}`,
  `Source IP: ${sourceIp}`,
  `Target service: ${targetService}`,
  `Confidence: ${confidenceDisplay}`,
  `Detection reason: ${detectionReason}`,
  `Recommended action: ${recommendedAction}`,
  `Timestamp: ${timestamp}`
].join("\n");

return [
  {
    json: {
      ...data,
      severity_display: level,
      attack_type_display: attackType,
      target_service_display: targetService,
      confidence_display: confidenceDisplay,
      message
    }
  }
];
```

The primary duplicate gate now runs sequentially in `simulation/n8n.py` before
webhook delivery. It groups eligible alerts for five minutes by source IP,
attack type, and target service. The n8n copy of the same grouping rule remains
as a best-effort backup, but it is not relied upon for webhook executions that
start concurrently. A different attack type or target service can still
produce its own alert immediately.

### 5.3 `Edit Fields`

Keep the field name `message`. Replace only its value with:

```text
={{ $json.message }}
```

Do not change the three outgoing Telegram connections.

## 6. Expected message

```text
🚨 CRITICAL HONEYPOT ALERT

Severity: Critical
Attack type: sql injection
Source IP: 127.0.0.1
Target service: HTTP
Confidence: 93%
Detection reason: A sanitized SQL security pattern matched.
Recommended action: Temporarily block the source IP and review the affected web route and database-facing input controls.
Timestamp: 2026-07-28T08:15:00+00:00
```

## 7. Automated verification

```powershell
python -m unittest tests.test_step19_alerts -v
python -m unittest discover -s .\tests -p "test_*.py" -v
python -m compileall -q simulation tests
```

The focused tests verify:

- all eight required alert fields;
- exact High/Critical eligibility;
- exclusion of Medium, Low, and normal results;
- confidence formatting;
- deterministic attack-specific actions;
- sanitized fallback reasons;
- recursive removal of raw and credential-bearing fields; and
- preservation of the existing raw adapter contract;
- suppression of the same eligible alert group within five minutes;
- immediate allowance for a different attack type or service;
- expiry of the suppression window; and
- exclusion of ineligible results from duplicate state.

## 8. Live verification

1. Keep the Git working tree limited to the three allowlisted project files.
2. Start n8n and save the three permitted node changes.
3. Start `python run.py` with `N8N_WEBHOOK_URL` empty.
4. Start the backend and frontend normally.
5. Start `simulation/n8n.py --mode local --source ids`.
6. Generate one controlled attack that the final IDS rates High or Critical.
7. Confirm one Telegram alert contains all eight fields.
8. Confirm repeated IDS detections with the same source IP, attack type, and
   target service produce one Telegram alert and a
   `[SKIP] duplicate_alert window=300s` adapter line.
9. Confirm a Medium/Low or normal result does not generate an immediate alert.
10. Confirm no raw payload, username, password, token, credential, or
   authorization value appears in the n8n execution data or Telegram message.
11. Confirm the dashboard and frontend continue to work.

Do not commit or push until the focused tests, full regression suite, n8n
execution, Telegram message, dashboard, frontend, exact-file check, and
credential checks all pass.

## 9. Workflow export safety

The earlier inspection sanitizer removed Telegram bot tokens but did not remove
chat IDs stored as `name: "chat_id"` plus a sibling `value`. Treat that
inspection ZIP as private and do not share it.

Before sharing any later sanitized export, require all of these checks:

- no Telegram bot-token pattern;
- no n8n `credentials` object;
- no `chatId` property with a literal value;
- no parameter object whose `name` is `chat_id` and whose `value` is literal;
- no API authorization or secret value; and
- no raw workflow export in the archive.

Project files and Git commits must never contain Telegram tokens, chat IDs,
credential references, raw workflow exports, or the n8n database.
