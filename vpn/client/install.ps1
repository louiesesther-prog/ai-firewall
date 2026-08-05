# AI Firewall VPN — Windows native client installer
# Installs the official WireGuard for Windows (native, wintun-based),
# imports a generated client.conf, and connects to your VPN server.
#
# Usage (Run as Administrator):
#   powershell -ExecutionPolicy Bypass -File vpn/client/install.ps1 -Config client1.conf
#
# Options:
#   -Config <path>    Path to a client .conf from vpn/generate.mjs (required)
#   -SkipInstall      Skip installing WireGuard (assume it's already installed)
#   -Connect          Auto-connect after import (default: yes)
#
# This is a REAL native VPN: WireGuard creates a kernel TUN/TAP adapter
# (wintun) and routes your traffic through an encrypted tunnel. It is the
# same engine used by Mullvad/Proton commercial VPNs.

param(
    [Parameter(Mandatory=$true)]
    [string]$Config,
    [switch]$SkipInstall,
    [switch]$NoConnect
)

$ErrorActionPreference = 'Stop'

function Write-Step($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }
function Write-OK($msg)   { Write-Host "    $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "    $msg" -ForegroundColor Yellow }

$wg = Get-Command wg -ErrorAction SilentlyContinue
$wgExe = "$env:ProgramFiles\WireGuard\wg.exe"
$wireGuardInstalled = $wg -or (Test-Path $wgExe)

if (-not $wireGuardInstalled -and -not $SkipInstall) {
    Write-Step "Installing WireGuard for Windows (native wintun driver)..."
    $installer = "$env:TEMP\wireguard-installer.exe"
    $url = "https://download.wireguard.com/windows-client/wireguard-installer.exe"
    Write-OK "Downloading from $url"
    Invoke-WebRequest -Uri $url -OutFile $installer -UseBasicParsing
    Write-OK "Running installer (follow the on-screen prompts)..."
    Start-Process -FilePath $installer -Wait
    Remove-Item $installer -Force -ErrorAction SilentlyContinue
}

# Re-locate wg after install
if (-not $wg) {
    $wg = Get-Command wg -ErrorAction SilentlyContinue
    if (-not $wg) {
        $wg = [pscustomobject]@{ Source = $wgExe }
    }
}

if (-not (Test-Path $Config)) {
    Write-Host "ERROR: config file not found: $Config" -ForegroundColor Red
    Write-Host "Generate one first: node vpn/generate.mjs --endpoint YOUR_VPS_IP"
    exit 1
}

Write-Step "Validating config"
$confText = Get-Content $Config -Raw
if ($confText -notmatch '\[Interface\]' -or $confText -notmatch '\[Peer\]') {
    Write-Host "ERROR: $Config does not look like a valid WireGuard config." -ForegroundColor Red
    exit 1
}
$endpoint = ([regex]::Match($confText, 'Endpoint\s*=\s*(\S+)')).Groups[1].Value
Write-OK "Endpoint: $endpoint"
Write-OK "Config is valid."

Write-Step "Importing config into WireGuard (admin required)"
& $wg.Source quick strip "$Config" | Out-Null
$baseName = [System.IO.Path]::GetFileNameWithoutExtension($Config)
& $wg.Source quick add "$baseName" "$Config"
if ($LASTEXITCODE -ne 0) {
    # Config may already be imported under this name; try adding anyway
    & $wg.Source quick add "$baseName" "$Config" 2>&1 | Out-Null
}

if (-not $NoConnect) {
    Write-Step "Connecting to VPN"
    & $wg.Source quick up "$baseName"
    if ($LASTEXITCODE -eq 0) {
        Write-OK "Connected! Tunnel is up."
    } else {
        Write-Warn "WireGuard may not be running yet. Open the WireGuard app to connect."
    }
}

Write-Step "Tunnel status"
& $wg.Source show "$baseName" 2>&1 | Select-Object -First 8

Write-Host ""
Write-Host "Done." -ForegroundColor Green
Write-Host "  - Manage the tunnel: open 'WireGuard' app (tray icon) or:"
Write-Host "      wg-quick up $baseName / wg-quick down $baseName"
Write-Host "  - Kill-switch: run vpn/client/kill-switch.ps1 -On to block all traffic"
Write-Host "    outside the VPN tunnel (prevents leaks if the VPN drops)."
Write-Host "  - Extension tie-in: set 'Privacy Route' in the AI Firewall popup to the"
Write-Host "    tunnel's local SOCKS5 bridge (see vpn/socks5-bridge.mjs)."
