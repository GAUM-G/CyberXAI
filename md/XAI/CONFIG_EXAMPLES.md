# XAI Module Configuration Examples

## N8N Webhook Configuration

### Local N8N Setup
```yaml
webhook_url: "http://localhost:5678/webhook/xai-report"
timeout_seconds: 30
max_retries: 3
```

### Remote N8N Setup
```yaml
webhook_url: "https://your-n8n-instance.com/webhook/xai-report"
timeout_seconds: 60
max_retries: 5
```

## Usage Examples

### Example 1: Basic Report Generation and Sending

```bash
python merger.py \
  --webhook-url "http://localhost:5678/webhook/xai-report" \
  --log-file "../data/raw_logs/honeypot_events.jsonl"
```

### Example 2: Generate Report and Save Locally

```bash
python merger.py \
  --webhook-url "http://localhost:5678/webhook/xai-report" \
  --log-file "../data/raw_logs/honeypot_events.jsonl" \
  --output-file "xai_report_2026-05-19.json"
```

### Example 3: Dry-Run Mode (No Webhook Send)

```bash
python merger.py \
  --webhook-url "http://localhost:5678/webhook/xai-report" \
  --log-file "../data/raw_logs/honeypot_events.jsonl" \
  --dry-run
```

### Example 4: Using with Environment Variables

```bash
export XAI_WEBHOOK_URL="http://localhost:5678/webhook/xai-report"
python merger.py --webhook-url $XAI_WEBHOOK_URL
```

## Python API Usage Examples

### Example 1: Complete Workflow

```python
from pathlib import Path
from XAI.merger import XAIMerger

# Create merger with webhook URL
merger = XAIMerger(webhook_url="http://localhost:5678/webhook/xai-report")

# Process and send in one call
log_file = Path("../data/raw_logs/honeypot_events.jsonl")
success = merger.process_and_send(log_file)

if success:
    print("✓ XAI report sent successfully!")
else:
    print("✗ Failed to send XAI report")
```

### Example 2: Step-by-Step Processing

```python
from pathlib import Path
from XAI.merger import XAIMerger
import json

# Initialize
merger = XAIMerger(webhook_url="http://localhost:5678/webhook/xai-report")

# Load events
log_file = Path("../data/raw_logs/honeypot_events.jsonl")
events = merger.load_events_from_jsonl(log_file)
print(f"Loaded {len(events)} events")

# Process events
merger.process_events(events)
profiles = merger.analyzer.get_all_profiles()
print(f"Identified {len(profiles)} unique attackers")

# Build report
report = merger.build_xai_report()
print(f"Report generated at {report['report_metadata']['generated_at']}")

# Save locally
with open("local_report.json", "w") as f:
    json.dump(report, f, indent=2)
print("Report saved locally")

# Send to webhook
success = merger.send_to_webhook(report)
```

### Example 3: Analyze Specific Attacker

```python
from pathlib import Path
from XAI.merger import XAIMerger

# Process events
merger = XAIMerger(webhook_url="http://localhost:5678/webhook/xai-report")
events = merger.load_events_from_jsonl(Path("../data/raw_logs/honeypot_events.jsonl"))
merger.process_events(events)

# Get specific attacker profile
attacker_ip = "127.0.0.1"
profile = merger.analyzer.get_attacker_profile(attacker_ip)

if profile:
    print(f"IP: {profile.source_ip}")
    print(f"Events: {profile.total_events}")
    print(f"Attack Types: {profile.attack_types}")
    print(f"Services: {profile.services_targeted}")
    print(f"Risk Score: {max(s.risk_score for s in profile.attack_signatures)}")
```

### Example 4: Filter High-Risk Attackers

```python
from pathlib import Path
from XAI.merger import XAIMerger

# Process events
merger = XAIMerger(webhook_url="http://localhost:5678/webhook/xai-report")
events = merger.load_events_from_jsonl(Path("../data/raw_logs/honeypot_events.jsonl"))
merger.process_events(events)

# Get high-risk attackers
high_risk = merger.analyzer.get_high_risk_attackers(threshold=0.7)

print(f"High-Risk Attackers: {len(high_risk)}")
for attacker in high_risk:
    print(f"  - {attacker.source_ip}: {attacker.total_events} events, "
          f"Severity: {attacker.severity_distribution}")
```

### Example 5: Generate Report with Custom Webhook

```python
from pathlib import Path
from XAI.merger import XAIMerger

merger = XAIMerger(webhook_url="http://default.webhook.com")

# Override webhook URL for specific send
success = merger.process_and_send(
    log_file=Path("../data/raw_logs/honeypot_events.jsonl"),
    webhook_url="http://override.webhook.com"
)
```

### Example 6: Custom Analysis with Error Handling

```python
from pathlib import Path
from XAI.merger import XAIMerger
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)

try:
    merger = XAIMerger(webhook_url="http://localhost:5678/webhook/xai-report")
    
    log_file = Path("../data/raw_logs/honeypot_events.jsonl")
    events = merger.load_events_from_jsonl(log_file)
    merger.process_events(events)
    
    report = merger.build_xai_report()
    success = merger.send_to_webhook(report)
    
except FileNotFoundError as e:
    print(f"Log file not found: {e}")
except Exception as e:
    print(f"Error: {e}")
```

## Report Fields Explained

### Severity Levels
- `critical`: Highly suspicious activity, immediate investigation required
- `warning`: Suspicious activity requiring investigation
- `info`: Normal/benign activity

### Attack Types
- `connection_probe`: Network reconnaissance
- `credential_access`: Login/authentication attempts
- `command_activity`: Command execution attempts
- `sql_injection`: SQL injection attacks
- `web_activity`: Web application access
- `authentication_probe`: Auth scanning

### Risk Scores
- 0.0-0.3: Low risk
- 0.3-0.7: Medium risk
- 0.7-1.0: High risk

## Webhook Response

The webhook should return a success status code (2xx) to indicate successful receipt.

Example n8n Webhook Response:
```json
{
  "status": "success",
  "message": "XAI report received and queued for processing",
  "report_id": "abc123xyz"
}
```

## Troubleshooting

### Issue: "Connection refused"
- Check that n8n webhook URL is correct
- Ensure n8n server is running
- Check firewall rules

### Issue: "Timeout error"
- Increase timeout_seconds parameter
- Check network connectivity
- Verify webhook endpoint is responsive

### Issue: "JSON parsing error"
- Check that honeypot_events.jsonl is valid
- Each line should be a complete JSON object
- No extra newlines or trailing commas

### Issue: "No attackers found"
- Check that honeypot_events.jsonl has content
- Verify the log file path is correct

## Performance Tips

1. Process logs regularly (e.g., hourly) rather than large batches
2. Use `--dry-run` to test without sending
3. Archive old log files to separate directory
4. Monitor n8n webhook endpoint performance
