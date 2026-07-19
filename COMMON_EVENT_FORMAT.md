# Common Honeypot Event Format

Schema version: `1.0`

This format standardizes SSH, FTP, and HTTP records written to:

```text
data/raw_logs/honeypot_events.jsonl
```

Each line remains an independent JSON object. The original fields used by the dashboard, n8n forwarder, Telegram workflow, reports, and XAI code are preserved.

## Field definitions

| Field | Type | Required | Description |
|---|---|---|---|
| `schema_version` | string | Yes | Current format version, `1.0` |
| `event_id` | string | Yes | Unique UUID for the individual record |
| `timestamp` | string | Yes | UTC ISO-8601 event time |
| `source_ip` | string | Yes | Address that initiated the activity |
| `source_port` | integer or null | Yes | Remote client port when available |
| `destination_port` | integer or null | Yes | Local service port |
| `service` | string | Yes | `ssh`, `ftp`, or `http` |
| `protocol` | string | Yes | Application protocol used by the event |
| `event_type` | string | Yes | Common category such as `connection`, `authentication`, `command`, `request`, or `attack` |
| `event` | string | Yes | Existing detailed event name retained for compatibility |
| `attack_type` | string | Yes | Detected activity or attack classification |
| `severity` | string | Yes | `info`, `warning`, or `critical` |
| `status` | string | Yes | Outcome such as `opened`, `observed`, `failed`, `success`, or `detected` |
| `username` | string or null | Yes | Submitted account name when available |
| `session_id` | string or null | Yes | Identifier linking records from one connection or request |
| `request_method` | string or null | Yes | HTTP method when applicable |
| `request_path` | string or null | Yes | HTTP path or target when applicable |
| `payload` | any JSON value | Yes | Original captured content |
| `metadata` | object | Yes | Service-specific context and legacy downstream fields |

The keys are always present. Fields that do not apply to a service use `null` instead of being omitted.

## Backward compatibility

The following original fields remain unchanged:

```text
timestamp
source_ip
service
event
attack_type
payload
severity
metadata
```

Therefore:

- the dashboard can continue reading existing and new JSONL lines;
- `simulation/n8n.py --mode local` can continue forwarding events;
- the current n8n webhook remains `honeypot-alert`;
- Telegram filtering can continue using `severity`, `source_ip`, `attack_type`, `event`, and `metadata`;
- old JSONL records do not need to be rewritten.

## SSH example

```json
{
  "schema_version": "1.0",
  "event_id": "7dd70a9e-988d-4ce4-961a-bb0df3840001",
  "timestamp": "2026-07-19T06:30:00+00:00",
  "source_ip": "127.0.0.1",
  "source_port": 50101,
  "destination_port": 2222,
  "service": "ssh",
  "protocol": "ssh",
  "event_type": "authentication",
  "event": "ssh_login_attempt",
  "attack_type": "authentication_probe",
  "severity": "info",
  "status": "failed",
  "username": "test-user",
  "session_id": "69b2ec1e-55fb-46a0-a1c5-33c116780001",
  "request_method": null,
  "request_path": null,
  "payload": {
    "username": "test-user",
    "password": "fake-test-password"
  },
  "metadata": {
    "attempt_count": 1,
    "threshold": 3,
    "source_port": 50101,
    "destination_port": 2222,
    "session_id": "69b2ec1e-55fb-46a0-a1c5-33c116780001"
  }
}
```

## FTP example

```json
{
  "schema_version": "1.0",
  "event_id": "7dd70a9e-988d-4ce4-961a-bb0df3840002",
  "timestamp": "2026-07-19T06:31:00+00:00",
  "source_ip": "127.0.0.1",
  "source_port": 50102,
  "destination_port": 2121,
  "service": "ftp",
  "protocol": "ftp",
  "event_type": "authentication",
  "event": "ftp_login_failed",
  "attack_type": "ftp_bruteforce",
  "severity": "warning",
  "status": "failed",
  "username": "test-user",
  "session_id": "69b2ec1e-55fb-46a0-a1c5-33c116780002",
  "request_method": null,
  "request_path": null,
  "payload": {
    "username": "test-user",
    "password": "fake-test-password"
  },
  "metadata": {
    "failed_attempts": 1,
    "source_port": 50102,
    "destination_port": 2121,
    "session_id": "69b2ec1e-55fb-46a0-a1c5-33c116780002"
  }
}
```

## HTTP example

```json
{
  "schema_version": "1.0",
  "event_id": "7dd70a9e-988d-4ce4-961a-bb0df3840003",
  "timestamp": "2026-07-19T06:32:00+00:00",
  "source_ip": "127.0.0.1",
  "source_port": 50103,
  "destination_port": 8080,
  "service": "http",
  "protocol": "http",
  "event_type": "attack",
  "event": "http_login_sql_injection",
  "attack_type": "sql_injection",
  "severity": "warning",
  "status": "detected",
  "username": "test-user",
  "session_id": "69b2ec1e-55fb-46a0-a1c5-33c116780003",
  "request_method": "POST",
  "request_path": "/login",
  "payload": "username=test-user&password=fake-test-value",
  "metadata": {
    "username": "test-user",
    "path": "/login"
  }
}
```

## Validation command

From the project root with the Python virtual environment activated:

```powershell
python -m unittest discover -s tests -v
```

The tests confirm that all three honeypot services use the same keys and that an old `log_event(...)` call still produces a valid new record.
