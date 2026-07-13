# XAI (Explainable AI) Module

This module extracts comprehensive attack information from honeypot logs and sends detailed analysis reports to n8n webhooks for backend processing.

## Overview

The XAI module provides:

- **Attack Analysis**: Deep inspection of attack patterns, techniques, and behaviors
- **Attacker Profiling**: Comprehensive profiles of individual attackers including attack history, targeted services, and behavioral patterns
- **Risk Assessment**: Risk scoring and threat classification
- **Threat Intelligence**: Extraction of indicators of compromise (IoCs) and threat indicators
- **XAI Report Generation**: Structured reports explaining detected attacks with actionable insights

## Module Structure

### `attack_analyzer.py`

Core analysis engine that processes honeypot events and builds attacker profiles.

**Main Classes:**
- `AttackSignature`: Represents a detected attack pattern with techniques and risk score
- `AttackerProfile`: Complete profile of an attacker including all activities, patterns, and behaviors
- `AttackAnalyzer`: Main analyzer that processes events and maintains profiles

**Key Methods:**
- `analyze_event()`: Process individual honeypot events
- `get_attacker_profile()`: Retrieve profile for specific IP
- `get_high_risk_attackers()`: Identify high-risk threats
- `export_profile_to_dict()`: Export profiles as dictionaries

### `merger.py`

Merges analyzed attack data and sends it to n8n webhook with comprehensive XAI reports.

**Main Classes:**
- `XAIMerger`: Orchestrates event loading, analysis, and webhook transmission

**Key Methods:**
- `load_events_from_jsonl()`: Load events from JSONL log files
- `process_events()`: Run all events through analyzer
- `build_xai_report()`: Generate comprehensive XAI report
- `send_to_webhook()`: Send report to n8n webhook
- `process_and_send()`: Complete workflow in one call

## Usage

### Command Line

```bash
# Basic usage with webhook URL
python merger.py --webhook-url http://localhost:5678/webhook/xai-report

# Save report locally before sending
python merger.py --webhook-url http://localhost:5678/webhook/xai-report --output-file xai_report.json

# Dry-run mode (generate report without sending)
python merger.py --webhook-url http://localhost:5678/webhook/xai-report --dry-run

# Custom log file
python merger.py --webhook-url http://localhost:5678/webhook/xai-report --log-file /path/to/custom/logs.jsonl
```

### Programmatic Usage

```python
from XAI.merger import XAIMerger
from pathlib import Path

# Initialize merger
merger = XAIMerger(webhook_url="http://localhost:5678/webhook/xai-report")

# Load and process events
events = merger.load_events_from_jsonl(Path("data/raw_logs/honeypot_events.jsonl"))
merger.process_events(events)

# Build report
report = merger.build_xai_report()

# Send to webhook
success = merger.send_to_webhook(report)

# Or do it all at once
success = merger.process_and_send(
    log_file=Path("data/raw_logs/honeypot_events.jsonl"),
    webhook_url="http://localhost:5678/webhook/xai-report"
)
```

## XAI Report Structure

The generated XAI report contains:

```json
{
  "report_metadata": {
    "generated_at": "ISO timestamp",
    "total_attackers": "number",
    "high_risk_attackers": "number",
    "analyzer_version": "version"
  },
  "summary": {
    "total_events": "number",
    "total_attackers": "number",
    "unique_attack_types": "number",
    "services_targeted": ["list"],
    "severity_distribution": {"severity": "count"}
  },
  "attackers": [
    {
      "source_ip": "IP address",
      "first_seen": "timestamp",
      "last_seen": "timestamp",
      "total_events": "number",
      "attack_profile": {
        "attack_types": ["list"],
        "services_targeted": ["list"],
        "credentials_attempted": ["list"],
        "files_accessed": ["list"],
        "commands_executed": ["list"],
        "severity_distribution": {"severity": "count"}
      },
      "attack_signatures": [
        {
          "pattern_type": "pattern name",
          "severity_level": "level",
          "techniques": ["MITRE ATT&CK techniques"],
          "risk_score": "0.0-1.0"
        }
      ],
      "behavioral_patterns": {
        "persistence_attempts": "count",
        "credential_guesses": "count",
        "reconnaissance_scans": "count",
        "data_exfiltration": "count"
      },
      "timeline_events": ["recent events"],
      "extracted_payloads": ["attack payloads"]
    }
  ],
  "high_risk_threats": [
    {
      "source_ip": "IP address",
      "threat_level": "critical|high",
      "critical_events": "count",
      "warning_events": "count",
      "primary_attack_types": ["types"],
      "compromised_services": ["services"],
      "extracted_credentials": ["credentials"],
      "accessed_resources": ["resources"],
      "risk_indicators": ["indicators"]
    }
  ],
  "attack_statistics": {
    "attack_type_distribution": {"type": "count"},
    "service_targeting_distribution": {"service": "count"},
    "events_per_attacker": {
      "average": "number",
      "max": "number",
      "min": "number"
    }
  },
  "recommendations": ["security recommendations"]
}
```

## Extracted Information

The XAI module extracts the following information about attacks:

### Per Attack Event
- Event timestamp and type
- Source IP and service targeted
- Attack type and severity level
- Payload information
- Metadata (commands, arguments, etc.)

### Per Attacker (Aggregated)
- Complete attack timeline
- Attack patterns and signatures
- MITRE ATT&CK technique mappings
- Behavioral patterns
- Extracted credentials and usernames
- Accessed files and resources
- Executed commands
- Risk scoring

### Threat Intelligence
- High-risk attacker identification
- Threat level classification
- Indicators of compromise
- Credential extraction
- Resource access patterns
- Persistence indicators

## Integration with n8n

The XAI module is designed to work seamlessly with n8n:

1. **Webhook Endpoint**: Configure an n8n webhook to receive XAI reports
2. **JSON Payload**: Reports are sent as structured JSON for easy processing
3. **Retry Logic**: Built-in retry mechanism for reliable delivery
4. **Error Handling**: Comprehensive logging for debugging

### n8n Setup Example

In n8n, create a webhook node that receives POST requests from the XAI merger:

1. Create a Webhook node with POST method
2. Get the webhook URL from n8n
3. Use that URL with the XAI merger
4. Process the received XAI report data in your n8n workflow

## Configuration

### Logging

The module uses Python's standard logging. Configure logging levels:

```python
import logging
logging.getLogger('XAI').setLevel(logging.DEBUG)
```

### Retry Strategy

The merger automatically retries failed webhook requests:
- Max retries: 3 (configurable)
- Backoff factor: 1 second
- Retryable status codes: 429, 500, 502, 503, 504

### Timeout

Default timeout for webhook requests: 30 seconds (configurable)

## Features

✅ Comprehensive attack analysis
✅ Individual attacker profiling
✅ MITRE ATT&CK technique mapping
✅ Risk scoring and threat classification
✅ Behavioral pattern analysis
✅ Credential and resource extraction
✅ Timeline visualization
✅ Actionable security recommendations
✅ Webhook integration with n8n
✅ Retry logic and error handling
✅ Detailed logging
✅ Dry-run mode for testing
✅ Local report export

## Error Handling

The module includes comprehensive error handling:
- Connection errors to webhook
- Timeout handling with retries
- JSON parsing errors for malformed logs
- Missing or invalid file paths
- Webhook communication failures

All errors are logged with detailed messages for debugging.

## Example Output

See `xai_report_example.json` for a sample generated report.

## Performance

- Processes events sequentially for reliability
- Memory efficient - profiles kept in memory
- Suitable for medium-sized log files (up to GB range)
- Scales with number of unique attackers

## Dependencies

- requests
- urllib3
- Python 3.8+

## Author

XAI Module - Honeypot Analysis System

## License

Same as parent project
