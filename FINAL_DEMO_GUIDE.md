# Final Demonstration Guide

Use this guide for a clear 8-10 minute project demonstration.

## Completion statement

Say:

> The full 26-step academic roadmap has been implemented in the prototype. The complete live flow works from multi-service honeypot capture through hybrid IDS, severity, XAI, intelligent agents, dashboards, Telegram, analyst feedback, simulated IPS, and an offline continuous-learning pipeline with safe model promotion and rollback. It is complete as an academic prototype, while production deployment and validation on larger external datasets remain future work.

Do not say that the system automatically blocks real IPs, is production-ready, or continuously changes the live model by itself.

## Before the demonstration

- Pull the latest branch and confirm `git status -sb` is clean.
- Keep the validated `data\ml_ready` artifacts on the demo computer.
- Start all five terminals from `howtostart.md`.
- Confirm seven ports are running.
- Log in once to the React portal and Flask dashboard.
- Keep the dashboard IDS section, Telegram chat, and n8n executions ready in separate tabs.
- Wait five minutes after rehearsal or use a different scenario so alert deduplication does not suppress the live message.
- Close any screen that exposes `.env`, Telegram credentials, tokens, chat IDs, captured passwords, or n8n secrets.

## Demonstration sequence

### 1. Introduce the problem

Explain that ordinary IDS alerts often say only that something was detected. This framework captures suspicious activity in decoy services, combines rules and learning models, explains the decision, prioritizes severity, and keeps a human analyst in control.

### 2. Show the architecture

Open the architecture in `README.md` or the final PPT. Briefly identify:

- SSH, FTP, and HTTP honeypots.
- Common event schema and centralized storage.
- Rules, Decision Tree/Random Forest, Isolation Forest, and LSTM.
- Severity, SHAP, human explanation, and six intelligent agents.
- Flask/React dashboards, n8n/Telegram, feedback, simulated IPS, and continuous learning.

### 3. Show that services are healthy

Display the port table from PowerShell. Mention ports 2222, 2121, 8080, 5050, 5000, 5173, and 5678.

### 4. Generate one controlled attack

Open:

```text
http://127.0.0.1:8080
```

Submit:

```text
Username: admin' OR '1'='1
Password: test
```

This is fake local test input.

### 5. Show real-time analysis

In the `run.py` terminal, point to:

- `sql_injection` attack type.
- `attack` prediction.
- High/Critical threat level and score.
- Final model/fusion information.
- XAI status.
- Intelligent-agent completion.

Explain that rules have priority for an obvious SQL signature, while ML, anomaly detection, and sequence context handle broader known, unusual, and time-based behaviour.

### 6. Show the dashboard

Open the incident details and show:

- Attack type, source, service, and timestamp.
- Prediction, confidence, severity, and threat score.
- Detection reason and feature contribution.
- Agent correlation and response recommendation.

Make clear that raw credentials are excluded from IDS/XAI output.

### 7. Show Telegram

Show the enriched alert containing severity, attack type, source IP, target service, confidence, reason, recommended action, simulated IPS safety, and timestamp.

The forwarder must be running with:

```powershell
python .\simulation\n8n.py --mode local --source ids
```

### 8. Show human feedback

In the dashboard, confirm the attack or mark a prepared sample as false positive. Show optional severity override, notes, and audit history. Explain that the original IDS decision is preserved and feedback is append-only.

### 9. Show simulated prevention

Choose a safe response such as recommend block, simulate block, rate limit, or terminate a selected honeypot session. Show:

```text
IPS mode: simulation
Automatic host blocking: disabled
Host firewall changed: no
```

### 10. Show continuous learning

Run:

```powershell
python -m continuous_learning.pipeline status
```

Explain the implemented flow:

```text
new events + latest analyst feedback
-> sanitized versioned dataset
-> preprocessing and retraining
-> evaluation and model comparison
-> explicit promotion only if quality gates pass
-> previous active model retained for rollback
```

Do not run a 20-epoch retraining during the main live demo unless it was rehearsed and time is available. A prepared candidate manifest is enough to show the version, metrics, gate decision, and rollback design.

### 11. Finish with verification

Show the last successful `final_system_test.json` or run:

```powershell
python .\scripts\final_system_test.py --runtime
```

State that the full attack exercise can verify all seven scenarios, IDS/XAI/agent contracts, SQLite persistence, services, and n8n webhook acceptance.

## Short technical explanation

> Each honeypot emits the same JSON event schema. The preprocessing pipeline removes missing values and duplicates, encodes categories, normalizes numerical values, and creates causal sequences. Eight behavioural features include failed attempts, request rate, payload length, session duration, suspicious keywords, username repetition, time between requests, and SQLi/XSS pattern count. Rules detect obvious signatures, the selected tree classifier detects known attacks, Isolation Forest finds unusual behaviour, and LSTM analyzes sequences. The hybrid engine fuses them, assigns severity, produces SHAP-supported and human-readable explanations, then agents correlate and recommend a safe response. Final records go to the dashboards and High/Critical alerts go through n8n to Telegram.

## If something fails during the demonstration

### Telegram is delayed

Show the successful n8n execution and Terminal 5 `[POST] status=200`. Explain that detection and alert handoff succeeded and Telegram is an external delivery channel. Do not keep submitting the same event because the five-minute deduplication rule may suppress it.

### Frontend is unavailable

Use the Flask dashboard at `http://127.0.0.1:5050`; it exposes the complete IDS, XAI, agents, feedback, and simulated IPS workflow.

### One honeypot port is unavailable

Demonstrate HTTP SQL injection, which covers the complete pipeline. Show the latest saved complete-system report for the other controlled scenarios.

### Continuous retraining is too slow

Show `status`, the version registry, candidate manifest, evaluation gate decision, and rollback entry. Explain that training is intentionally offline so a live detection process is never changed halfway through inference.

## Likely questions

### Why hybrid IDS?

Rules are precise for known signatures, tree models classify learned patterns, Isolation Forest detects unknown anomalies, and LSTM captures time-based sequences. Combining them covers more behaviour than one model alone.

### Why SHAP and not only an LLM explanation?

SHAP links a tree-model decision to feature contributions. The project also creates deterministic human-readable reasoning. An external language model is not trusted to change the prediction.

### Is continuous learning automatic?

Data collection and candidate preparation are automated, but model promotion is analyst-approved. Quality gates and rollback protect the working IDS.

### Does the IPS really block an attacker?

No. It safely demonstrates recommendations and application-level simulated actions. Host firewall modification is hard-disabled.

### What remains as future scope?

Production hardening, external datasets, real network sensors, role-based administration, TLS deployment, long-term log retention, independent security testing, and carefully authorized active response.
