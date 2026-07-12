# sem7majorproject — Laptop Setup Guide

This guide sets up `honeypot_v2` on a Windows 10/11 laptop.

Follow the sections in order. First get the Python honeypot and dashboard working. After that, add the React/Node portal and finally n8n.

## 1. Install the required software

Install:

1. [Python for Windows](https://www.python.org/downloads/windows/) — Python 3.12, 64-bit.
   - During installation, select **Add Python to PATH**.
2. [Node.js](https://nodejs.org/en/download) — Node.js 22 LTS.
3. [VS Code](https://code.visualstudio.com/download).
4. [Git for Windows](https://git-scm.com/install/windows/) — recommended for teamwork.

Restart VS Code after installing everything.

Open PowerShell and verify:

```powershell
python --version
node --version
npm.cmd --version
git --version
```

Expected versions should look approximately like:

```text
Python 3.12.x
Node v22.x.x
npm 10.x or newer
git version 2.x
```

Java, MySQL, MongoDB, and XAMPP are not required.

## 2. Extract and open the project

Create this folder:

```text
C:\Projects\sem7majorproject
```

Extract `honeypot_v2.zip` there. The resulting project path should be:

```text
C:\Projects\sem7majorproject\honeypot_v2
```

In VS Code:

1. Select **File → Open Folder**.
2. Select `C:\Projects\sem7majorproject\honeypot_v2`.
3. Select **Terminal → New Terminal**.

Confirm the terminal location:

```powershell
Get-Location
```

## 3. Remove bundled dependency folders

The ZIP contains machine-specific `node_modules` folders. Remove them and install clean copies:

```powershell
Remove-Item -Recurse -Force .\website\backend\node_modules -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force .\website\frontend\node_modules -ErrorAction SilentlyContinue
```

These folders are generated again later using `npm.cmd ci`.

## 4. Create the Python environment

Make sure the terminal is in the project root:

```powershell
cd C:\Projects\sem7majorproject\honeypot_v2
```

Create a virtual environment:

```powershell
py -3.12 -m venv .venv
```

Allow activation for the current PowerShell window:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
```

Activate the environment:

```powershell
.\.venv\Scripts\Activate.ps1
```

The terminal should now start with `(.venv)`:

```text
(.venv) PS C:\Projects\sem7majorproject\honeypot_v2>
```

Install the Python packages:

```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install -r XAI\requirements.txt
python -m pip install psutil
```

`psutil` is optional, but it enables real CPU, RAM, and connection information in the dashboard.

Verify the installation:

```powershell
python -c "import flask, pyftpdlib, yaml, requests, psutil; print('Python setup successful')"
```

Expected output:

```text
Python setup successful
```

## 5. Run the Python honeypot system

For the first test, disable n8n because it is not configured yet:

```powershell
$env:N8N_WEBHOOK_URL = ""
```

Start the system:

```powershell
python run.py
```

You should see these services:

```text
SSH honeypot   → port 2222
FTP honeypot   → port 2121
HTTP honeypot  → port 8080
Dashboard      → port 5050
```

Open:

- Dashboard: `http://127.0.0.1:5050`
- Fake HTTP portal: `http://127.0.0.1:8080`

If Windows Firewall asks for permission, do not allow public-network access. Localhost should still work.

Stop all services with `Ctrl+C`.

## 6. Generate safe test attacks

Keep `python run.py` running. Open a second VS Code terminal and activate the same environment:

```powershell
cd C:\Projects\sem7majorproject\honeypot_v2
.\.venv\Scripts\Activate.ps1
```

Test HTTP:

```powershell
python simulation\simulate_attacks.py --http-only
```

Test SSH:

```powershell
python simulation\simulate_attacks.py --ssh-only
```

Test FTP:

```powershell
python simulation\simulate_attacks.py --ftp-only
```

Refresh `http://127.0.0.1:5050`. Events and test credentials should appear.

Check the most recent JSONL records:

```powershell
Get-Content .\data\raw_logs\honeypot_events.jsonl -Tail 5
```

Use only fake test credentials. The current project stores captured credentials in plaintext logs.

## 7. Set up the Node.js backend

Open another terminal:

```powershell
cd C:\Projects\sem7majorproject\honeypot_v2\website\backend
```

Install backend dependencies:

```powershell
npm.cmd ci
```

Create a fresh `.env` file:

```powershell
Copy-Item .env.example .env -Force
```

Generate a new JWT secret:

```powershell
node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"
```

Copy the generated text, then open `.env`:

```powershell
notepad .env
```

Configure it as follows:

```dotenv
PORT=5000
JWT_SECRET=PASTE_YOUR_NEW_GENERATED_SECRET_HERE
FRONTEND_URL=http://localhost:5173
```

Save the file. Do not reuse or share the `.env` included in the ZIP.

### Start with a clean database

The included database contains a teammate-created user. Preserve it as a backup:

```powershell
cd data
Rename-Item honeypot.db honeypot.teammate-backup.db
cd ..
```

The backend creates a new `honeypot.db` automatically.

### Apply the known invalid-login fix

Open:

```text
website/backend/server.js
```

Inside the failed-login `logEvent()` block, find and remove this line:

```javascript
email,
```

That variable is undefined and can crash failed logins.

### Start the backend

```powershell
npm.cmd run dev
```

Expected output:

```text
[Backend] Running on http://localhost:5000
```

Test it from another terminal:

```powershell
Invoke-RestMethod http://localhost:5000/
```

## 8. Set up the React frontend

Open another terminal:

```powershell
cd C:\Projects\sem7majorproject\honeypot_v2\website\frontend
```

Install dependencies:

```powershell
npm.cmd ci
```

Start React:

```powershell
npm.cmd run dev
```

Expected address:

```text
http://localhost:5173
```

Use the page in this order:

1. Select **Create account**.
2. Create a fake test account.
3. Return to the login page.
4. Log in with the same username and password.
5. Open the dashboard.

The new SQLite database will be created at:

```text
website\backend\data\honeypot.db
```

The React XAI button will not work until n8n, Groq, and Telegram are configured.

## 9. Run the primary components together

Use separate VS Code terminals.

### Terminal 1 — Python system

```powershell
cd C:\Projects\sem7majorproject\honeypot_v2
.\.venv\Scripts\Activate.ps1
$env:N8N_WEBHOOK_URL = ""
python run.py
```

### Terminal 2 — Node backend

```powershell
cd C:\Projects\sem7majorproject\honeypot_v2\website\backend
npm.cmd run dev
```

### Terminal 3 — React frontend

```powershell
cd C:\Projects\sem7majorproject\honeypot_v2\website\frontend
npm.cmd run dev
```

Available components:

| Component | Address |
| --- | --- |
| Python security dashboard | `http://127.0.0.1:5050` |
| Python HTTP honeypot | `http://127.0.0.1:8080` |
| Express backend | `http://localhost:5000` |
| React portal | `http://localhost:5173` |
| FTP honeypot | Port `2121` |
| SSH-like honeypot | Port `2222` |

Do not run `run_website.py` initially. It starts a separate alternative Flask portal and is not required for the React version.

## 10. Optional n8n setup

Set this up only after the Python and React/Express components work.

Install n8n:

```powershell
npm.cmd install n8n -g
```

Start it:

```powershell
n8n.cmd
```

Open:

```text
http://localhost:5678
```

Important precautions:

- Do not activate workflows using the Telegram token included in the ZIP.
- Ask your teammate to revoke that token.
- Create a new Telegram bot token and configure the destination chat ID.
- Create a Groq API key and configure it securely in n8n.
- The workflow for `/webhook/xai-report` is missing.
- Do not activate two workflows using the same `honeypot-alert` webhook path.

You can test the Python XAI report without sending data:

```powershell
cd C:\Projects\sem7majorproject\honeypot_v2
.\.venv\Scripts\Activate.ps1

python XAI\merger.py `
  --webhook-url "http://localhost:5678/webhook/xai-report" `
  --dry-run
```

## 11. Verify the complete setup

Check the Python ports:

```powershell
Test-NetConnection 127.0.0.1 -Port 5050
Test-NetConnection 127.0.0.1 -Port 8080
Test-NetConnection 127.0.0.1 -Port 2121
Test-NetConnection 127.0.0.1 -Port 2222
```

Check the Python dashboard API:

```powershell
Invoke-RestMethod http://127.0.0.1:5050/api/monitor
```

Check the Node backend:

```powershell
Invoke-RestMethod http://localhost:5000/
Invoke-RestMethod http://localhost:5000/files
```

Final verification:

1. Create a fake React account.
2. Log in successfully.
3. Confirm `website/backend/data/honeypot.db` exists.
4. Run an HTTP attack simulation.
5. Confirm new records appear in `data/raw_logs/honeypot_events.jsonl`.
6. Confirm they appear on the Python dashboard.

## 12. Common errors

### `npm.ps1 cannot be loaded`

Use the `.cmd` executable:

```powershell
npm.cmd ci
npm.cmd run dev
```

### Virtual environment activation is blocked

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
.\.venv\Scripts\Activate.ps1
```

### `ModuleNotFoundError`

```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m pip install -r XAI\requirements.txt
```

### Port already in use

For example, check port 5000:

```powershell
Get-NetTCPConnection -LocalPort 5000
```

Stop the other application or configure a different port.

### SQLite or `node-gyp` installation error

Confirm Node.js 22 is installed:

```powershell
node --version
```

Then clean and reinstall:

```powershell
Remove-Item -Recurse -Force node_modules
npm.cmd cache clean --force
npm.cmd ci
```

If SQLite still compiles from source, install Visual Studio Build Tools with the **Desktop development with C++** workload.

### Frontend cannot connect to the backend

Confirm both URLs open:

```text
http://localhost:5000
http://localhost:5173
```

Confirm the backend `.env` contains:

```dotenv
FRONTEND_URL=http://localhost:5173
```

### n8n connection refused

Start n8n:

```powershell
n8n.cmd
```

Then verify `http://localhost:5678` opens.

## Recommended setup order

1. Install Python, Node.js, VS Code, and Git.
2. Extract and open the project.
3. Remove bundled `node_modules`.
4. Create the Python virtual environment.
5. Run `python run.py` and verify port 5050.
6. Run the safe attack simulations.
7. Configure and run the Express backend.
8. Configure and run the React frontend.
9. Repair and configure n8n, Telegram, and Groq.
10. Configure Cloudflare only after the security problems are fixed.

Your first milestone is a working Python dashboard at `http://127.0.0.1:5050`. Do not move to React/Express until that works correctly.
