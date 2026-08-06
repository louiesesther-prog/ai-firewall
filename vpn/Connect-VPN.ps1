# AI Firewall VPN — one-click connect
# Usage:
#   powershell -ExecutionPolicy Bypass -File vpn/Connect-VPN.ps1
#   powershell -ExecutionPolicy Bypass -File vpn/Connect-VPN.ps1 -Disconnect
#
# Does everything in one click (after your one-time server setup):
#   1. Finds your WireGuard client config (vpn-out/client1.conf or -Config)
#   2. Brings up the tunnel if it's not already active
#   3. Starts the SOCKS5 bridge on 127.0.0.1:1080 if it's not running
#   4. Verifies the bridge + tunnel with the HTTP status probe
#   5. Tells you to hit "Connect VPN" in the extension popup

param(
    [string]$Config = "",          # path to a client .conf (default: vpn-out/client1.conf)
    [switch]$Disconnect,           # tear down tunnel + bridge instead
    [switch]$AutoStart,            # install a Startup shortcut (runs Connect-VPN at login)
    [switch]$RemoveAutoStart,      # remove the Startup shortcut
    [int]$BridgePort = 1080
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)  # repo root
if ($Config -eq "") { $Config = Join-Path $root "vpn-out\client1.conf" }
$bridge = Join-Path $root "vpn\socks5-bridge.mjs"

function Write-Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Write-OK($m)   { Write-Host "    $m" -ForegroundColor Green }
function Write-Err($m)  { Write-Host "    $m" -ForegroundColor Red }
function Write-Warn($m) { Write-Host "    $m" -ForegroundColor Yellow }

# ── auto-start management ──
$startupDir = [Environment]::GetFolderPath('Startup')
$shortcutPath = Join-Path $startupDir "AI-Firewall-VPN.lnk"
$wsh = New-Object -ComObject WScript.Shell

if ($AutoStart) {
    $sc = $wsh.CreateShortcut($shortcutPath)
    $sc.TargetPath = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
    $sc.Arguments = "-ExecutionPolicy Bypass -NoProfile -WindowStyle Minimized -File `"$($MyInvocation.MyCommand.Path)`""
    $sc.WorkingDirectory = $root
    $sc.Description = "AI Firewall VPN — connect tunnel + bridge at login"
    $sc.Save()
    Write-OK "Auto-start installed: $shortcutPath"
    Write-OK "Tunnel + bridge will connect automatically at login."
    exit 0
}
if ($RemoveAutoStart) {
    if (Test-Path $shortcutPath) { Remove-Item $shortcutPath -Force; Write-OK "Auto-start removed." }
    else { Write-Warn "No auto-start shortcut found." }
    exit 0
}

# ── locate wg / WireGuard ──
$wg = Get-Command wg -ErrorAction SilentlyContinue
$wgExe = "$env:ProgramFiles\WireGuard\wg.exe"
$wgCli = if ($wg) { $wg.Source } elseif (Test-Path $wgExe) { $wgExe } else { $null }
$wgQuick = if ($wgCli) {
    $q = Get-Command wg-quick -ErrorAction SilentlyContinue
    if ($q) { $q.Source }
    elseif ($wgCli -match "\.exe$") { $wgCli -replace "wg\.exe$", "wg-quick.exe" }
    elseif ($wgCli -match "\.cmd$") { $wgCli -replace "wg\.cmd$", "wg-quick.cmd" }
    else { "wg-quick" }
} else { $null }

if ($Disconnect) {
    Write-Step "Disconnecting..."
    if ($wgQuick -and (Test-Path $Config)) {
        & $wgQuick down $Config 2>$null
        Write-OK "WireGuard tunnel down."
    }
    Get-Process -Name "node" -ErrorAction SilentlyContinue | Where-Object {
        $_.Path -match "node" -and $_.CommandLine -match "socks5-bridge" -or $_.MainWindowTitle -eq ""
    } | ForEach-Object { Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue }
    Write-OK "Bridge stopped. Done."
    exit 0
}

# ── 1. config present? ──
if (-not (Test-Path $Config)) {
    Write-Err "No client config found at: $Config"
    Write-Err "Generate one first:  node vpn/generate.mjs --endpoint YOUR_VPS_IP --clients 1"
    Write-Err "Then run setup:       node vpn/setup.mjs --host YOUR_VPS_IP"
    exit 1
}

# ── 2. bring up tunnel ──
Write-Step "Checking WireGuard tunnel..."
if ($wgCli) {
    $up = & $wgCli show interfaces 2>$null
    $tunnelActive = ($up -join ",") -match "wg"
    if (-not $tunnelActive) {
        Write-OK "Starting tunnel with:  $Config"
        & $wgQuick up $Config
        Write-OK "Tunnel is up."
    } else {
        Write-OK "Tunnel already active."
    }
} else {
    Write-Warn "wg CLI not found. Make sure the WireGuard app is running and the tunnel is connected (import $Config)."
}

# ── 3. start bridge if not running ──
Write-Step "Checking SOCKS5 bridge on 127.0.0.1:$BridgePort ..."
$alreadyRunning = $false
try {
    $probe = Invoke-RestMethod -Uri "http://127.0.0.1:$BridgePort/" -TimeoutSec 3 -ErrorAction Stop
    $alreadyRunning = $true
    if ($probe.tunnel -eq "up") {
        Write-OK "Bridge already running, tunnel verified UP ($($probe.tunnelAdapter))."
    } else {
        Write-OK "Bridge running but tunnel adapter not detected by it — ensure WireGuard is connected."
    }
} catch {
    $alreadyRunning = $false
}

if (-not $alreadyRunning) {
    Write-OK "Starting bridge:  node $bridge"
    $node = Get-Command node -ErrorAction SilentlyContinue
    if (-not $node) { Write-Err "Node.js not found on PATH — install Node then re-run."; exit 1 }
    Start-Process -FilePath $node.Source -ArgumentList @($bridge, "--port", "$BridgePort") -WorkingDirectory $root -WindowStyle Minimized
    Start-Sleep -Seconds 1
}

# ── 4. verify ──
Write-Step "Verifying..."
$verified = $false
for ($i = 0; $i -lt 10; $i++) {
    try {
        $probe = Invoke-RestMethod -Uri "http://127.0.0.1:$BridgePort/" -TimeoutSec 2 -ErrorAction Stop
        $verified = $true
        if ($probe.tunnel -eq "up") {
            Write-OK "Bridge OK + tunnel UP on adapter '$($probe.tunnelAdapter)'. "
        } else {
            Write-OK "Bridge OK. Tunnel adapter not detected — make sure WireGuard is connected."
        }
        break
    } catch {
        Start-Sleep -Milliseconds 500
    }
}
if (-not $verified) { Write-Err "Bridge did not come up. Check for a port conflict or Node install."; exit 1 }

Write-Host ""
Write-Host "  ──────────────────────────────────────────────" -ForegroundColor DarkGray
Write-Host "  DONE. Open the extension popup and hit  Connect VPN" -ForegroundColor Green
Write-Host "    host: 127.0.0.1   port: $BridgePort   protocol: SOCKS5" -ForegroundColor Cyan
Write-Host "  ──────────────────────────────────────────────" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  (Keep this window or the background node process running.)"
Write-Host ""
