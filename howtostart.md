# Daily Startup and Demo Commands

Use five PowerShell terminals. Keep every terminal open.

## Terminal 1 - n8n

```powershell
cd D:\honeypot_v2
n8n.cmd start
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
.\.venv\Scripts\Activate.ps1
$env:N8N_WEBHOOK_URL=""
$env:DASHBOARD_SECRET_KEY="replace_with_your_private_local_value"
Remove-Item Env:EVENT_COLLECTOR_URL -ErrorAction SilentlyContinue
Remove-Item Env:PORT_SCAN_THRESHOLD -ErrorAction SilentlyContinue
Remove-Item Env:PORT_SCAN_WINDOW_SECONDS -ErrorAction SilentlyContinue
python run.py
```

## Terminal 5 - enriched IDS alerts to n8n

```powershell
cd D:\honeypot_v2
.\.venv\Scripts\Activate.ps1
python .\simulation\n8n.py --mode local --source ids
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

The port 5050 defender dashboard has no login or signup screen. It is bound to
localhost and relays protected analyst requests to port 5000 with a server-side
internal credential that is never exposed to the port 5173 attacker portal.

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
.\.venv\Scripts\Activate.ps1
python .\scripts\final_system_test.py --runtime
```

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
Username: admin' 
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
python .\scripts\final_system_test.py --runtime --simulate-attacks
```

Add `--n8n-check` only when you want one additional Telegram workflow test.

## Continuous-learning status

```powershell
python -m continuous_learning.pipeline status
```

Do not promote or roll back models while `run.py` is running.

## for model accuracy
cd D:\honeypot_v2
.\.venv\Scripts\Activate.ps1
python -m machine_learning.evaluate_models