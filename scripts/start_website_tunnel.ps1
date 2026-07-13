param(
    [int]$Port = 8090,
    [string]$BindHost = "0.0.0.0",
    [string]$PythonCmd = "python",
    [switch]$WebsiteAlreadyRunning,
    [switch]$UseNamedTunnel,
    [string]$TunnelName = "honeypot-site",
    [string]$Hostname = ""
)

$ErrorActionPreference = "Stop"

function Test-PortListening {
    param([int]$LocalPort)
    $conn = Get-NetTCPConnection -State Listen -LocalPort $LocalPort -ErrorAction SilentlyContinue
    return $null -ne $conn
}

function Wait-ForPort {
    param([int]$LocalPort, [int]$TimeoutSeconds = 20)
    $start = Get-Date
    while (((Get-Date) - $start).TotalSeconds -lt $TimeoutSeconds) {
        if (Test-PortListening -LocalPort $LocalPort) {
            return $true
        }
        Start-Sleep -Milliseconds 500
    }
    return $false
}

function Get-CloudflaredPath {
    $cmd = Get-Command cloudflared -ErrorAction SilentlyContinue
    if ($cmd) {
        return $cmd.Source
    }

    $fallbacks = @(
        "C:\Program Files (x86)\cloudflared\cloudflared.exe",
        "C:\Program Files\cloudflared\cloudflared.exe"
    )
    foreach ($p in $fallbacks) {
        if (Test-Path $p) {
            return $p
        }
    }

    throw "cloudflared not found. Install it with: winget install --id Cloudflare.cloudflared -e"
}

function Ensure-NamedTunnel {
    param(
        [string]$CloudflaredPath,
        [string]$Name,
        [string]$DnsHostname,
        [int]$LocalPort
    )

    if ([string]::IsNullOrWhiteSpace($DnsHostname)) {
        throw "For named tunnel mode, provide -Hostname (for example: honeypot.example.com)."
    }

    $configDir = Join-Path $env:USERPROFILE ".cloudflared"
    if (-not (Test-Path $configDir)) {
        New-Item -ItemType Directory -Path $configDir | Out-Null
    }

    $certPath = Join-Path $configDir "cert.pem"
    if (-not (Test-Path $certPath)) {
        Write-Host "[NamedTunnel] Cloudflare login required (one-time)."
        Write-Host "              A browser page will open."
        & $CloudflaredPath tunnel login
        if ($LASTEXITCODE -ne 0) {
            throw "Cloudflare login failed."
        }
    }

    $tunnelList = & $CloudflaredPath tunnel list 2>$null
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to list tunnels. Check cloudflared installation and Cloudflare account access."
    }

    if ($tunnelList -notmatch [regex]::Escape($Name)) {
        Write-Host "[NamedTunnel] Creating tunnel '$Name' ..."
        & $CloudflaredPath tunnel create $Name
        if ($LASTEXITCODE -ne 0) {
            throw "Tunnel creation failed."
        }
    } else {
        Write-Host "[NamedTunnel] Tunnel '$Name' already exists."
    }

    Write-Host "[NamedTunnel] Routing DNS '$DnsHostname' -> tunnel '$Name' ..."
    & $CloudflaredPath tunnel route dns $Name $DnsHostname
    if ($LASTEXITCODE -ne 0) {
        throw "DNS route setup failed. Ensure the domain is in your Cloudflare account and hostname is valid."
    }

    $configPath = Join-Path $configDir "config.yml"
    $configContent = @"
tunnel: $Name
credentials-file: $configDir\\$Name.json

ingress:
  - hostname: $DnsHostname
    service: http://127.0.0.1:$LocalPort
  - service: http_status:404
"@

    Set-Content -Path $configPath -Value $configContent -Encoding UTF8
    Write-Host "[NamedTunnel] Wrote config: $configPath"
}

Write-Host "[1/4] Checking website on port $Port ..."
if (-not $WebsiteAlreadyRunning) {
    if (-not (Test-PortListening -LocalPort $Port)) {
        Write-Host "[2/4] Starting website server in a new PowerShell window ..."
        $cmd = "cd '$PSScriptRoot\..'; $PythonCmd run_website.py --host $BindHost --port $Port"
        Start-Process powershell -ArgumentList "-NoExit", "-Command", $cmd | Out-Null
    } else {
        Write-Host "[2/4] Website already listening on port $Port."
    }
} else {
    Write-Host "[2/4] Skipping website start (-WebsiteAlreadyRunning provided)."
}

Write-Host "[3/4] Waiting for website to be reachable ..."
if (-not (Wait-ForPort -LocalPort $Port -TimeoutSeconds 25)) {
    throw "Website did not start on port $Port in time."
}

$cf = Get-CloudflaredPath
if ($UseNamedTunnel) {
    Write-Host "[4/4] Starting Cloudflare named tunnel ..."
    Ensure-NamedTunnel -CloudflaredPath $cf -Name $TunnelName -DnsHostname $Hostname -LocalPort $Port
    Write-Host "      Fixed URL: https://$Hostname"
    Write-Host "      Keep this terminal open. Press Ctrl+C to stop tunnel."
    Write-Host ""
    & $cf tunnel run $TunnelName
} else {
    Write-Host "[4/4] Starting Cloudflare quick tunnel ..."
    Write-Host "      Keep this terminal open. Press Ctrl+C to stop tunnel."
    Write-Host ""
    Write-Host "Mobile note: quick tunnel requires internet on phone (to resolve *.trycloudflare.com)."
    Write-Host "If phone shows 'No internet', use local hotspot URL instead: http://192.168.137.1:$Port"
    Write-Host ""

    & $cf tunnel --url "http://127.0.0.1:$Port" --no-autoupdate
}
