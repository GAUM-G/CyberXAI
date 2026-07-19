cd D:\honeypot_v2
n8n.cmd start


cd D:\honeypot_v2\website\backend
npm.cmd run dev



cd D:\honeypot_v2\website\frontend
npm.cmd run dev:local



cd D:\honeypot_v2
.\.venv\Scripts\Activate.ps1
$env:N8N_WEBHOOK_URL=""
Remove-Item Env:EVENT_COLLECTOR_URL -ErrorAction SilentlyContinue
Remove-Item Env:PORT_SCAN_THRESHOLD -ErrorAction SilentlyContinue
Remove-Item Env:PORT_SCAN_WINDOW_SECONDS -ErrorAction SilentlyContinue
python run.py



cd D:\honeypot_v2
.\.venv\Scripts\Activate.ps1
python .\simulation\n8n.py --mode local



$services = @(
    @{Name="SSH";       Port=2222},
    @{Name="FTP";       Port=2121},
    @{Name="HTTP";      Port=8080},
    @{Name="Dashboard"; Port=5050},
    @{Name="Backend";   Port=5000},
    @{Name="Frontend";  Port=5173},
    @{Name="n8n";       Port=5678}
)
$services | ForEach-Object {
    [PSCustomObject]@{
        Service = $_.Name
        Port = $_.Port
        Running = Test-NetConnection `
            127.0.0.1 `
            -Port $_.Port `
            -InformationLevel Quiet
    }
} | Format-Table -AutoSize



cd D:\honeypot_v2
.\.venv\Scripts\Activate.ps1
python .\simulation\verify_attack_scenarios.py



$stats = Invoke-RestMethod `
    -Uri "http://127.0.0.1:5000/api/events/stats"
$stats | ConvertTo-Json -Depth 5


$monitor = Invoke-RestMethod `
    -Uri "http://127.0.0.1:5050/api/monitor"

[PSCustomObject]@{
    TotalEvents = $monitor.total_events
    Threats = $monitor.threats_detected
    PortScans = $monitor.port_scans_detected
    LatestScan = $monitor.latest_port_scan.attack_type
    ScanPorts = $monitor.latest_port_scan.observed_ports -join ", "
} | Format-List


Invoke-RestMethod `
    -Uri "http://127.0.0.1:5000/files" |
ConvertTo-Json