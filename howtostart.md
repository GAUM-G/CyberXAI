# Daily Startup and Demo Commands

Use five PowerShell terminals. Keep every terminal open.
These daily commands use this workstation's working `data\runtime\python312\python.exe`;
the existing `.venv` is broken. If the local runtime is unavailable on another
machine, create a fresh virtual environment using [md/SETUP.md](md/SETUP.md).

## Dashboard Gmail signup setup

Opening port 5050 shows the login page and a **Sign up with Gmail** link.
Signup asks for a Gmail address, sends a six-digit OTP, shows an
OTP entry and **Resend OTP** button, then opens a separate password page after
verification. New accounts wait for administrator approval before they can
sign in. There are no preset dashboard credentials. Dashboard accounts are
separate from the attacker-facing website accounts.

Before the first signup, copy `dashboard\dashboard_mail.example.json` to the
ignored `data\runtime\dashboard_mail.json` and edit the copy in your IDE. Set
`sender_gmail` to a Gmail sender, `gmail_app_password` to its 16-character app
password. The application restricts this secret file to the Windows account
running the dashboard and refuses to use it if that protection cannot be
applied. For a managed deployment, the equivalent
`DASHBOARD_SENDER_GMAIL` and `DASHBOARD_GMAIL_APP_PASSWORD` environment
variables take precedence over the file. Never put either value in source
code, a tracked `.env` file, screenshots, logs, or documentation. This is a
one-time sender setup, not a per-user Gmail list. The old
`allowed_gmail_addresses` field, if present in your private file, is ignored.
Do not commit or share the private JSON file. The sender
must have 2-Step Verification and a Gmail app password; see
[Google's app-password instructions](https://support.google.com/accounts/answer/185833).
First, sign up with the **same Gmail address as `sender_gmail`** and verify its
OTP. That verified account becomes the first administrator. Other Gmail users
can then sign up without editing any file; after they verify their OTP and set
a password, use **Manage users** on the dashboard to grant access. The admin
can see all accounts, remove accounts, and grant or revoke subadmin access.
Subadmins can approve and remove ordinary users but cannot assign roles or
remove admins and other subadmins. OTP
verification alone never grants them defender access.
Gmail dot variants and `+tag` aliases are treated as the same inbox, so they
cannot create duplicate accounts or bypass OTP limits. OTP sends are also
limited per requesting IP and across the local dashboard.

## Terminal 1 - n8n

```powershell
cd D:\honeypot_v2
$n8n = Join-Path (npm.cmd prefix -g) 'n8n.cmd'
& $n8n start
```

## Terminal 2 - Express backend

```powershell
cd D:\honeypot_v2\website\backend
npm.cmd run dev
```

## Terminal 3 - attacker-facing React company portal

```powershell
cd D:\honeypot_v2\website\frontend
npm.cmd run dev:local
```

## Terminal 4 - honeypots, IDS, XAI, agents, and Flask dashboard

```powershell
cd D:\honeypot_v2
$py = (Resolve-Path .\data\runtime\python312\python.exe).Path
$env:PYTHONIOENCODING="utf-8"
$env:PYTHONUTF8="1"
$env:N8N_WEBHOOK_URL=""
Remove-Item Env:DASHBOARD_SECRET_KEY -ErrorAction SilentlyContinue
Remove-Item Env:EVENT_COLLECTOR_URL -ErrorAction SilentlyContinue
Remove-Item Env:PORT_SCAN_THRESHOLD -ErrorAction SilentlyContinue
Remove-Item Env:PORT_SCAN_WINDOW_SECONDS -ErrorAction SilentlyContinue
& $py run.py
```

## Terminal 5 - enriched IDS alerts to n8n

```powershell
cd D:\honeypot_v2
$py = (Resolve-Path .\data\runtime\python312\python.exe).Path
$env:PYTHONIOENCODING="utf-8"
$env:PYTHONUTF8="1"
& $py .\simulation\n8n.py --mode local --source ids
```

Confirm Terminal 5 displays:

```text
[CONFIG] source=ids
[CONFIG] log_file=D:\honeypot_v2\data\detections\hybrid_ids_results.jsonl
```

## Open in browser

```text
HTTP honeypot: http://127.0.0.1:8080
Flask dashboard: http://127.0.0.1:5050
React decoy portal: http://localhost:5173
n8n: http://localhost:5678
```

Open port 5050, click **Sign up with Gmail**, enter a Gmail address, click
**Send OTP**, then enter the emailed code.
Use **Resend OTP** if needed (one minute between sends). After **Verify OTP**,
create a password with at least 12 characters, uppercase, lowercase, number,
and special symbol; re-enter it to confirm. The first verified sender-Gmail
account can sign in immediately as administrator. All other accounts wait for
approval under **Manage users** before they can sign in. A pending user who
tries to sign in sees an approval-pending pop-up. Password fields on the
dashboard signup and login pages have a show/hide button. The Gmail sender app
password only sends email; it is
not your dashboard password. Dashboard password hashes are stored in ignored
`data\runtime\dashboard_users.db`. The dashboard remains bound to localhost and
relays protected analyst requests to port 5000
with a separate server-side internal credential that is never exposed to the
port 5173 attacker portal. Session signing uses a private key generated in
`data\runtime\dashboard_session.key`; preserve that file across restarts. The
session key and dashboard/backend internal token receive the same private file
protection as the Gmail sender configuration. For a
future HTTPS reverse-proxy deployment, set `DASHBOARD_COOKIE_SECURE=1` and keep
the dashboard itself bound to loopback.

## Simulated IPS controls

After signing in on port 5050, open **Simulated IPS Response**. Actions are
recorded under your dashboard Gmail identity; portal login tokens cannot
submit IPS actions or analyst feedback. Normal events, false positives, and
dismissed recommendations do not allow response actions.

**Simulate Block** marks later events as "would have been blocked" without
dropping traffic or changing Windows Firewall. **Rate Limit** returns HTTP 429
on the Python HTTP honeypot and public React decoy API routes; FTP and SSH
apply a bounded application delay. **Terminate Session** works only on the
selected persistent FTP session, on its next command. **Release / Undo**
removes an active response; expired responses are removed automatically.
Release active responses before dismissing their recommendation. Use
**Refresh** if a runtime-state synchronization error is reported; the audit
record is retained. If testing from localhost, rate limiting `127.0.0.1` also
affects your own requests to those HTTP decoy routes, not the dashboard or
pipeline ingestion APIs.

After IPS code changes, restart Terminal 2 and Terminal 4 using the commands
above. If you customize `IPS_STATE_FILE`, use the same absolute path in both
terminals.

## Confirm all ports

```powershell
$services = @(
    @{Name="SSH"; Port=2222},
    @{Name="FTP"; Port=2121},
    @{Name="HTTP"; Port=8080},
    @{Name="Dashboard"; Port=5050},
    @{Name="Backend"; Port=5000},
    @{Name="Frontend"; Port=5173},
    @{Name="n8n"; Port=5678}
)
$services | ForEach-Object {
    [PSCustomObject]@{
        Service = $_.Name
        Port = $_.Port
        Running = Test-NetConnection 127.0.0.1 -Port $_.Port -InformationLevel Quiet
    }
} | Format-Table -AutoSize
```

## Final readiness check

```powershell
cd D:\honeypot_v2
$py = (Resolve-Path .\data\runtime\python312\python.exe).Path
$env:PYTHONIOENCODING="utf-8"
$env:PYTHONUTF8="1"
& $py .\scripts\final_system_test.py --runtime
```

## Terminal 6 - controlled localhost attack simulations

Start Terminals 1-5 and confirm the ports above before opening a new PowerShell
terminal. Run these commands only against this project's services on `127.0.0.1`.
Set `$py` once in Terminal 6 using the working local Python runtime.

```powershell
cd D:\honeypot_v2
$py = (Resolve-Path .\data\runtime\python312\python.exe).Path
$env:PYTHONIOENCODING="utf-8"
$env:PYTHONUTF8="1"
```

Run one scenario at a time:

```powershell
# SSH brute force - port 2222
& $py .\simulation\sim_ssh.py --host 127.0.0.1 --port 2222

# FTP brute force and controlled decoy login - port 2121
& $py .\simulation\sim_ftp.py --host 127.0.0.1 --port 2121

# Port scan across the three local honeypots
& $py .\simulation\sim_port_scan.py --host 127.0.0.1 --ssh-port 2222 --ftp-port 2121 --http-port 8080

# HTTP login brute force - port 8080
& $py -c "from simulation.sim_http import sim_login_bruteforce; sim_login_bruteforce('http://127.0.0.1:8080', 0.25)"

# SQL injection - port 8080
& $py -c "from simulation.sim_http import sim_sql_injection; sim_sql_injection('http://127.0.0.1:8080', 0.25)"

# XSS - port 8080
& $py -c "from simulation.sim_http import sim_xss; sim_xss('http://127.0.0.1:8080', 0.25)"

# Directory scanning and path traversal - port 8080
& $py -c "from simulation.sim_http import sim_directory_scan; sim_directory_scan('http://127.0.0.1:8080', 0.25)"

# Normal HTTP traffic baseline - port 8080
& $py -c "from simulation.sim_http import sim_normal_traffic; sim_normal_traffic('http://127.0.0.1:8080', 0.25)"
```

To run all of those scenarios in one controlled sequence instead, use:

```powershell
& $py .\simulation\simulate_attacks.py
```

The HTTP-only group (normal traffic, login brute force, SQL injection, XSS,
and directory scanning) is available with
`& $py .\simulation\simulate_attacks.py --http-only`. Do not run the individual
commands and the full suite back-to-back unless you want duplicate events;
Terminal 5 suppresses repeated Telegram alerts for five minutes.

## One SQL-injection demonstration

Open `http://localhost:5173` and submit the following in the employee sign-in form:

```text
Username: admin' OR '1'='1
Password: test
```

Then show, in order:

1. Terminal 4 final IDS line with attack type, severity, XAI, and agents.
2. The fictional employee rows shown safely in the React response console.
3. Flask dashboard captured activity and incident details, including the recorded fictional result.
4. Telegram enriched High/Critical alert.
5. Analyst feedback panel.
6. Simulated IPS recommendation/action showing host firewall unchanged.

## Controlled port 5173 attack checks

Use only against the local React decoy portal. Wait five minutes before repeating
the same attack type because Terminal 5 intentionally suppresses duplicate alerts.

SQL injection in the employee sign-in form:

```text
Username: admin' OR '1'='1
Password: test
```

XSS in the resource-search field:

```text
<img src=x onerror=alert(1)>
```

Directory traversal in the resource-search field:

```text
../../etc/passwd
```

HTTP brute force: submit any three different invalid username/password pairs in
the employee sign-in form within five minutes. The third failed authentication
triggers the repeated-login rule.

For each attack, verify the port 5173 event in the Flask dashboard, the final IDS
classification and threat level, Terminal 5's `[POST] status=200`, and the
corresponding Telegram message.

## All controlled attack scenarios

Run only against the local project:

```powershell
cd D:\honeypot_v2
$py = (Resolve-Path .\data\runtime\python312\python.exe).Path
$env:PYTHONIOENCODING="utf-8"
$env:PYTHONUTF8="1"
& $py .\scripts\final_system_test.py --runtime --simulate-attacks
```

Add `--n8n-check` only when you want one additional Telegram workflow test.

## Continuous-learning status

```powershell
cd D:\honeypot_v2
$py = (Resolve-Path .\data\runtime\python312\python.exe).Path
$env:PYTHONIOENCODING="utf-8"
$env:PYTHONUTF8="1"
& $py -m continuous_learning.pipeline status
```

Do not promote or roll back models while `run.py` is running.

## Model accuracy

```powershell
cd D:\honeypot_v2
$py = (Resolve-Path .\data\runtime\python312\python.exe).Path
$env:PYTHONIOENCODING="utf-8"
$env:PYTHONUTF8="1"
& $py -m machine_learning.evaluate_models
```
