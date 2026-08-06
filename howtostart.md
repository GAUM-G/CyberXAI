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

## Terminal 3 - React frontend

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
React portal: http://localhost:5173
n8n: http://localhost:5678
```

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

Open `http://127.0.0.1:8080` and submit:

```text
Username: admin' OR '1'='1
Password: test
```

Then show, in order:

1. Terminal 4 final IDS line with attack type, severity, XAI, and agents.
2. Flask or React dashboard incident details.
3. Telegram enriched High/Critical alert.
4. Analyst feedback panel.
5. Simulated IPS recommendation/action showing host firewall unchanged.

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
