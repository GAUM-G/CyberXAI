# Honeypot Security Framework

This project is a modular honeypot lab for observing common attack patterns against SSH, FTP, and HTTP services. It captures login attempts, brute-force activity, web probing, command usage, and suspicious payloads, then stores everything in structured logs and exposes it in a live dashboard.

The goal is to provide a realistic security research and demo environment on Windows without needing privileged ports or complex infrastructure.

## What It Includes

- A fake SSH service that records usernames and passwords from login attempts.
- A fake FTP service with decoy files and logging for failed logins, successful logins, and commands.
- A fake HTTP login portal that detects SQL injection, XSS, directory scanning, and brute-force activity.
- A live Flask dashboard for viewing events, stats, captured credentials, and system status.
- A standalone decoy website for isolated testing and mobile/LAN access.
- Built-in simulations for generating safe test traffic against each service.
- JSONL logging plus optional n8n webhook alerts for critical events.


## Project Layout

```text
honeypot_v2/
├── core/
│   ├── honeypots/
│   │   ├── ssh_honeypot.py     fake SSH server on port 2222
│   │   ├── ftp_honeypot.py     fake FTP server on port 2121
│   │   └── http_honeypot.py    fake login portal on port 8080
│   ├── launcher.py             starts all honeypots in threads
│   └── logger.py               central JSONL logger and SSE queue
├── dashboard/
│   ├── app.py                  live monitoring dashboard
│   └── templates/index.html    dashboard UI
├── website/
│   ├── app.py                  standalone decoy website
│   ├── templates/index.html    website UI
│   ├── decoy_files/            bait files exposed by the site
│   ├── frontend/               optional React/Vite frontend
│   └── backend/                optional Express/SQLite backend
├── simulation/
│   ├── sim_ssh.py              SSH attack simulation
│   ├── sim_ftp.py              FTP attack simulation
│   ├── sim_http.py             HTTP attack simulation
│   └── simulate_attacks.py     runs all simulations together
├── config/
│   └── config.yaml             ports and thresholds
├── data/
│   ├── raw_logs/               generated honeypot events
│   └── ftp_decoy/              bait files for the FTP service
├── scripts/
│   └── start_website_tunnel.ps1
├── requirements.txt
├── run.py                      starts honeypots and dashboard
└── run_website.py              starts the standalone website only
```

## Requirements


- Windows 11 or Windows 10
- Python 3.10+
- PowerShell

Optional dependencies:
- `psutil` for richer dashboard system stats
- `pyftpdlib` for the FTP honeypot
- `flask` for the web apps


## Quick Start


1. Open PowerShell in the project folder.
2. Create and activate a virtual environment:

``powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
``

If PowerShell blocks script execution, run this once in the same session:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
```

3. Install dependencies:

```powershell
pip install -r requirements.txt
```

4. Start the full honeypot stack:

```powershell
python run.py
```

5. Open the dashboard:

```text
http://127.0.0.1:5050
```

## Running Individual Components

Start only the standalone decoy website:

```powershell
python run_website.py
```

The default website port is `8090`.

You can also change the bind address and port:

```powershell
python run_website.py --host 127.0.0.1 --port 8090
```

Start the full stack without the dashboard:

```powershell
python run.py --no-dashboard
```

Run the full stack and launch the built-in simulation after startup:

```powershell
python run.py --simulate
```

## Built-In Simulations

Use the simulation scripts to generate safe test traffic and verify logging:

```powershell
python simulation\simulate_attacks.py
python simulation\simulate_attacks.py --ssh-only
python simulation\simulate_attacks.py --ftp-only
python simulation\simulate_attacks.py --http-only
python simulation\sim_http.py --port 8090
```

## What Each Service Detects

SSH on port `2222`:

- Captures every username/password pair entered.
- Escalates to `ssh_bruteforce` after repeated failures from the same IP.
- The current brute-force threshold in code is 3 attempts.

FTP on port `2121`:

- Logs connection probes and failed logins.
- Logs successful logins as credential access events.
- Logs FTP commands issued after login.
- Serves decoy files such as fake finance, employee, and config data.

HTTP on port `8080`:

- Logs login attempts as authentication probes.
- Detects SQL injection payloads.
- Detects XSS payloads.
- Detects directory traversal and common scanning patterns.
- Flags rapid login attempts as brute force.

## Logging and Alerts

All events are written to:

```text
data/raw_logs/honeypot_events.jsonl
```

Each line is a JSON event containing fields like timestamp, source IP, service, attack type, severity, payload, and metadata.

Critical events can also be forwarded to n8n by setting these environment variables before launching the app:

```powershell
$env:N8N_WEBHOOK_URL = "http://localhost:5678/webhook/honeypot-alert"
$env:N8N_WEBHOOK_TIMEOUT = "2.0"
```

Install N8N in your local and then run it on your host


## Dashboardd

The dashboard at `http://127.0.0.1:5050` provides:

- Live event summaries
- Per-service counts
- Threat and severity breakdowns
- Captured credentials
- IDS-style timeline and top source IPs
- System stats such as uptime, CPU, RAM, and active connections


It also exposes API endpoints under `/api/*` for monitoring and reporting.

## Configuration

Default settings live in `config/config.yaml`.

Main defaults:

| Service | Port | Purpose |
| --- | ---: | --- |
| SSH honeypot | 2222 | Fake SSH login trap |
| FTP honeypot | 2121 | Fake FTP server and decoy files |
| HTTP honeypot | 8080 | Fake web login portal |
| Dashboard | 5050 | Real-time monitoring UI |

The HTTP login threshold in `config.yaml` is `10` attempts in `60` seconds.

## Standalone Website and Tunnel

The `website/` folder contains a separate decoy website that can be run independently for local testing or shared over a tunnel.

For a temporary Cloudflare tunnel:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\start_website_tunnel.ps1
```

For a named tunnel with a fixed hostname:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\start_website_tunnel.ps1 -UseNamedTunnel -TunnelName honeypot-site -Hostname honeypot.yourdomain.com
```

## Notes

- SSH uses port `2222` instead of `22` so it can run without admin privileges.
- The project is designed for research, demos, and local security testing.
- The `website/frontend` and `website/backend` folders contain an alternate React/Express/SQLite setup described in `website/README_MERN_SETUP.md`.

## Roadmap

- Phase 2: add IDS-style classification on top of collected logs
- Phase 3: add explainability for flagged events
