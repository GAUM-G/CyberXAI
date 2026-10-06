# XAI Module - Quick Start Guide

## What is XAI?

The **XAI (Explainable AI)** module analyzes honeypot attack data and generates comprehensive reports that are sent to your n8n backend for processing.

## Installation

1. The XAI folder is already created in your project root
2. Install dependencies:
   ```bash
   pip install -r XAI/requirements.txt
   ```

## Quick Start

### Option 1: Command Line (Recommended for first use)

```bash
# Navigate to project root
cd honeypot_v2

# Run the merger to analyze attacks and send to n8n
python XAI/merger.py --webhook-url "http://localhost:5678/webhook/xai-report"

# Generate report without sending (test mode)
python XAI/merger.py --webhook-url "http://localhost:5678/webhook/xai-report" --dry-run

# Save report to file
python XAI/merger.py --webhook-url "http://localhost:5678/webhook/xai-report" --output-file "my_report.json"
```

### Option 2: Python Code

```python
from pathlib import Path
from XAI.merger import XAIMerger

# Initialize
merger = XAIMerger(webhook_url="http://localhost:5678/webhook/xai-report")

# Process and send
success = merger.process_and_send(
    log_file=Path("data/raw_logs/honeypot_events.jsonl")
)

print("✓ Success!" if success else "✗ Failed!")
```

## File Structure

```
XAI/
├── __init__.py                 # Package initialization
├── attack_analyzer.py          # Core analysis engine
├── merger.py                   # Webhook integration & sending
└── requirements.txt            # Python dependencies

md/XAI/
├── README.md                   # Full documentation
├── CONFIG_EXAMPLES.md          # Configuration examples
└── QUICKSTART.md              # This file
```

## What Gets Extracted?

The XAI module extracts:

✅ **Per Attacker:**
- Complete attack timeline
- Attack types and patterns
- Credentials attempted
- Files accessed
- Commands executed
- Risk scoring

✅ **Attack Intelligence:**
- MITRE ATT&CK technique mappings
- Behavioral patterns
- Threat indicators
- Severity classification
- Actionable recommendations

✅ **Statistics:**
- Attack distribution by type
- Services targeted
- Event statistics per attacker

## Report Output Format

The XAI report is a structured JSON sent to n8n containing:

```json
{
  "report_metadata": {...},
  "summary": {...},
  "attackers": [...],
  "high_risk_threats": [...],
  "attack_statistics": {...},
  "recommendations": [...]
}
```

## N8N Integration

1. Create a webhook in n8n
2. Get your webhook URL: `http://your-n8n-instance.com/webhook/xai-report`
3. Use it with the XAI merger:
   ```bash
   python XAI/merger.py --webhook-url "http://your-n8n-instance.com/webhook/xai-report"
   ```

## Common Commands

```bash
# Help
python XAI/merger.py --help

# Basic usage
python XAI/merger.py --webhook-url "http://localhost:5678/webhook/xai-report"

# With custom log file
python XAI/merger.py --webhook-url "http://localhost:5678/webhook/xai-report" \
  --log-file "data/raw_logs/honeypot_events.jsonl"

# Save locally first
python XAI/merger.py --webhook-url "http://localhost:5678/webhook/xai-report" \
  --output-file "report.json"

# Dry run (no webhook send)
python XAI/merger.py --webhook-url "http://localhost:5678/webhook/xai-report" --dry-run

# Show report in terminal
python XAI/merger.py --webhook-url "http://localhost:5678/webhook/xai-report" \
  --dry-run | python -m json.tool
```

## Features

- 🔍 **Deep Attack Analysis**: Extract all attack details and patterns
- 👤 **Attacker Profiling**: Build complete profiles of each attacker
- ⚠️ **Risk Scoring**: Automatic risk assessment and threat classification
- 🎯 **MITRE Mapping**: Automatic MITRE ATT&CK technique identification
- 📊 **Statistics**: Comprehensive attack statistics and trends
- 💡 **Recommendations**: Actionable security recommendations
- 🚀 **N8N Ready**: Structured JSON output for n8n processing
- 🔄 **Retry Logic**: Automatic retry on webhook failure
- 📝 **Detailed Logging**: Track every step of processing
- 💾 **Local Export**: Save reports locally for backup/analysis

## Troubleshooting

**Q: "Connection refused" error?**
- Check your n8n webhook URL
- Ensure n8n server is running

**Q: "File not found" error?**
- Verify the honeypot_events.jsonl path exists
- Check file permissions

**Q: Want to test without sending to webhook?**
- Use `--dry-run` flag to generate report only

**Q: Want to keep a copy of the report?**
- Use `--output-file` to save locally

## Next Steps

1. ✅ XAI folder created
2. ➡️ Install dependencies: `pip install -r XAI/requirements.txt`
3. ➡️ Set up your n8n webhook
4. ➡️ Run the merger with your webhook URL
5. ➡️ Configure n8n to receive and process the XAI report

## Support

For detailed documentation, see:
- [README.md](README.md) - Full documentation
- [CONFIG_EXAMPLES.md](CONFIG_EXAMPLES.md) - Configuration examples

## File Purposes

| File | Purpose |
|------|---------|
| `XAI/attack_analyzer.py` | Core analysis engine that processes events and builds attacker profiles |
| `XAI/merger.py` | Merges data and sends to n8n webhook |
| `md/XAI/README.md` | Comprehensive documentation |
| `md/XAI/CONFIG_EXAMPLES.md` | Usage examples and configurations |
| `XAI/requirements.txt` | Python dependencies |
| `md/XAI/QUICKSTART.md` | This file |

## Example Workflow

```
1. Honeypot captures attacks
   ↓
2. Events logged to honeypot_events.jsonl
   ↓
3. Run: python XAI/merger.py --webhook-url "..."
   ↓
4. XAI Analyzer processes all events
   ↓
5. XAI Report generated with attack intelligence
   ↓
6. Report sent to n8n webhook
   ↓
7. N8N receives and processes the report
   ↓
8. Further analysis/alerts in n8n
```

---

**Ready to go!** Start with:
```bash
python XAI/merger.py --webhook-url "http://localhost:5678/webhook/xai-report" --dry-run
```

This will generate and display a sample report without sending it anywhere, so you can see what the output looks like.
