# Windows Setup and Recovery Guide

Project: A Secure and Intelligent Framework for Detecting and Understanding Malicious Digital Activities

This guide installs the complete local prototype on Windows 10/11. Commands assume `D:\honeypot_v2`.

## 1. Required software

- Git for Windows
- Python 3.12, 64-bit
- Node.js 22 LTS with npm
- n8n installed globally
- Visual Studio Code, optional
- Cloudflared, optional and only for the standalone decoy portal

Confirm versions:

```powershell
git --version
py -3.12 --version
node --version
npm.cmd --version
$n8n = Join-Path (npm.cmd prefix -g) 'n8n.cmd'
& $n8n --version
```

Install n8n only if it is missing:

```powershell
npm.cmd install -g n8n
```

## 2. Repository and branch

Clone the authorized private repository and select the current working branch:

```powershell
git clone https://github.com/GAUM-G/majorproject.git D:\honeypot_v2
cd D:\honeypot_v2
git switch main
git status -sb
```

The GitHub account must already have permission to the private repository.

## 3. Python environment

```powershell
cd D:\honeypot_v2
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install psutil shap
```

PyTorch is installed from the CPU index declared in `requirements.txt`.
On the current workstation, the existing `.venv` points to a removed Python
installation. The startup commands below use the working local runtime at
`data\runtime\python312\python.exe` instead. A fresh clone must create a new
virtual environment with the commands above because `data/runtime` is not in Git.

## 4. Backend

```powershell
cd D:\honeypot_v2\website\backend
npm.cmd ci
Copy-Item .env.example .env
notepad .env
```

Set private local values:

```dotenv
PORT=5000
JWT_SECRET=replace_with_a_long_random_private_value
FRONTEND_URL=http://localhost:5173
IPS_MODE=simulation
AUTOMATIC_HOST_BLOCKING=false
```

Do not commit `.env`.

## 5. Frontend

```powershell
cd D:\honeypot_v2\website\frontend
npm.cmd ci
npm.cmd run build
```

## 6. Model artifacts

Runtime model files are generated and intentionally excluded from Git. The active computer must contain:

```text
data/ml_ready/preprocessor.joblib
data/ml_ready/feature_names.json
data/ml_ready/label_mapping.json
data/ml_ready/models/decision_tree.joblib
data/ml_ready/models/random_forest.joblib
data/ml_ready/models/isolation_forest.joblib
data/ml_ready/models/lstm_classifier.pt
data/ml_ready/models/lstm_metrics.json
data/ml_ready/evaluation/model_selection.json
```

Safely copy the already validated `data\ml_ready` directory from the working project computer, or rebuild it from a sanitized dataset using the documented dataset, preprocessing, training, and evaluation commands. Do not copy captured raw logs or credentials unless they are approved synthetic data.

Verify artifacts:

```powershell
cd D:\honeypot_v2
$py = if (Test-Path .\data\runtime\python312\python.exe) { (Resolve-Path .\data\runtime\python312\python.exe).Path } else { (Resolve-Path .\.venv\Scripts\python.exe).Path }
$env:PYTHONIOENCODING="utf-8"
$env:PYTHONUTF8="1"
& $py -m machine_learning.realtime_ids --check
```

## 7. n8n and Telegram

The working n8n workflow and Telegram credential are stored outside Git. Restore the authorized `%USERPROFILE%\.n8n` state only while n8n is stopped, or import the sanitized workflow and reconnect the Telegram credential privately.

Required webhook path:

```text
honeypot-alert
```

Expected local webhook:

```text
http://localhost:5678/webhook/honeypot-alert
```

The active workflow must accept enriched IDS records and immediately alert only High/Critical attack predictions. Never expose bot tokens, chat IDs, n8n encryption keys, or credentials in Git or screenshots.

## 8. First startup

Use five PowerShell terminals.

### Terminal 1: n8n

```powershell
cd D:\honeypot_v2
$n8n = Join-Path (npm.cmd prefix -g) 'n8n.cmd'
& $n8n start
```

### Terminal 2: backend

```powershell
cd D:\honeypot_v2\website\backend
npm.cmd run dev
```

### Terminal 3: frontend

```powershell
cd D:\honeypot_v2\website\frontend
npm.cmd run dev:local
```

### Terminal 4: honeypots, real-time IDS, agents, and dashboard

```powershell
cd D:\honeypot_v2
$py = if (Test-Path .\data\runtime\python312\python.exe) { (Resolve-Path .\data\runtime\python312\python.exe).Path } else { (Resolve-Path .\.venv\Scripts\python.exe).Path }
$env:PYTHONIOENCODING="utf-8"
$env:PYTHONUTF8="1"
$env:N8N_WEBHOOK_URL=""
Remove-Item Env:DASHBOARD_SECRET_KEY -ErrorAction SilentlyContinue
Remove-Item Env:EVENT_COLLECTOR_URL -ErrorAction SilentlyContinue
Remove-Item Env:PORT_SCAN_THRESHOLD -ErrorAction SilentlyContinue
Remove-Item Env:PORT_SCAN_WINDOW_SECONDS -ErrorAction SilentlyContinue
& $py run.py
```

### Terminal 5: enriched IDS-to-n8n forwarder

```powershell
cd D:\honeypot_v2
$py = if (Test-Path .\data\runtime\python312\python.exe) { (Resolve-Path .\data\runtime\python312\python.exe).Path } else { (Resolve-Path .\.venv\Scripts\python.exe).Path }
$env:PYTHONIOENCODING="utf-8"
$env:PYTHONUTF8="1"
& $py .\simulation\n8n.py --mode local --source ids
```

Expected forwarder configuration:

```text
[CONFIG] source=ids
[CONFIG] log_file=D:\honeypot_v2\data\detections\hybrid_ids_results.jsonl
```

## 9. Dashboard access

Before signup, copy `dashboard/dashboard_mail.example.json` to the ignored
`data/runtime/dashboard_mail.json`. In that private file, set the sender Gmail,
and its 16-character app password once. The application restricts that file to
the Windows account running the dashboard and refuses to use it if the file
cannot be protected. A managed deployment may instead set both
`DASHBOARD_SENDER_GMAIL` and `DASHBOARD_GMAIL_APP_PASSWORD`; the environment
values take precedence. Never store the password in source code, a tracked
`.env` file, logs, screenshots, or documentation. The old
`allowed_gmail_addresses` field, if present, is ignored; new users do not
require a file edit. There are no Gmail IDs or app-password prompts in the
startup commands. A Gmail app password requires 2-Step Verification; see
[Google's instructions](https://support.google.com/accounts/answer/185833).

Open the defender dashboard at `http://127.0.0.1:5050`. It immediately shows
the login page with a **Sign up with Gmail** link. Enter your Gmail ID, click
**Send OTP**, enter the emailed code (or click **Resend OTP**), and verify.
The next page asks you to choose and confirm a password with uppercase,
lowercase, number, and special symbol. First sign up with the sender Gmail;
after OTP verification, that account becomes the initial administrator. Other
verified accounts wait for approval in **Manage users** before they can sign
in. The admin can see and remove accounts and appoint subadmins; subadmins
may approve or remove ordinary users but cannot assign roles or remove admins.
There are no preset login credentials.

The dashboard remains restricted to localhost. Verified dashboard users are
stored as password hashes in the ignored `data\runtime\dashboard_users.db`,
separate from decoy website users. Any Gmail address may request an OTP, but
only administrator-approved accounts may access the dashboard.
Gmail dot variants and `+tag` aliases resolve to one dashboard identity. OTP
sends are limited by Gmail inbox, requesting IP, and a local global ceiling.
Its protected backend requests use a server-side internal credential; the
attacker-facing React portal at `http://localhost:5173` does not expose
defender controls. For a future HTTPS reverse-proxy deployment, set
`DASHBOARD_COOKIE_SECURE=1` and keep the dashboard service bound to loopback.

## 10. Verification

```powershell
cd D:\honeypot_v2
$py = if (Test-Path .\data\runtime\python312\python.exe) { (Resolve-Path .\data\runtime\python312\python.exe).Path } else { (Resolve-Path .\.venv\Scripts\python.exe).Path }
$env:PYTHONIOENCODING="utf-8"
$env:PYTHONUTF8="1"
& $py .\scripts\final_system_test.py --runtime
```

For a complete controlled local exercise:

```powershell
& $py .\scripts\final_system_test.py --runtime --simulate-attacks --n8n-check
```

Confirm the final `FAIL=0` line and visually confirm the Telegram message.

## 11. Shutdown and recovery

Stop each foreground service using `Ctrl+C`. Stop `run.py` before any model promotion or rollback.

Normal restart order:

1. n8n
2. Express backend
3. React frontend
4. `& $py run.py` after setting `$py` in Terminal 4
5. `& $py .\simulation\n8n.py --mode local --source ids` after setting `$py` in Terminal 5

JSONL files and SQLite preserve completed records across restarts. The forwarder starts at the end of the IDS log by default, preventing historical alerts from being resent.

## 12. Troubleshooting

### PowerShell blocks activation

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
.\.venv\Scripts\Activate.ps1
```

### npm or n8n `.ps1` is blocked

Use `npm.cmd`; resolve n8n's `.cmd` launcher with
`$n8n = Join-Path (npm.cmd prefix -g) 'n8n.cmd'` and run `& $n8n start`.

### Frontend cannot connect

Confirm ports 5000 and 5173, `FRONTEND_URL=http://localhost:5173`, and that both use the same hostname style (`localhost` in the React flow). The React portal should expose no IDS, IPS, XAI, analyst-feedback, signup, or security-dashboard navigation.

### Dashboard cannot load backend data

Confirm the backend is running and `PORTAL_API_URL` has not been changed from
`http://127.0.0.1:5000`. No analyst login is needed for the localhost dashboard.

### n8n receives data but the Code node returns no output

Restart Terminal 5 with `--source ids`. Raw events do not have `alert_eligible` or final `severity_label` fields.

### Telegram does not arrive

Open the latest n8n execution. Confirm the event is an attack with High/Critical severity, the `If` true path reaches the Code and Telegram nodes, the five-minute deduplication window is not suppressing it, and the existing Telegram credential is connected.

### Model artifact check fails

Restore the complete validated `data\ml_ready` directory. Do not mix preprocessors, model bundles, or selection files from different training runs.

### A port is occupied

```powershell
Get-NetTCPConnection -LocalPort 5050 -ErrorAction SilentlyContinue
```

Stop the duplicate project process from its original terminal; do not terminate unrelated applications.
