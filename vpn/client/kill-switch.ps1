# AI Firewall VPN — Kill Switch (Windows)
# Blocks ALL network traffic except through the WireGuard tunnel adapter.
# Prevents real-IP/DNS leaks if the VPN connection drops.
#
# Usage (Run as Administrator):
#   powershell -ExecutionPolicy Bypass -File vpn/client/kill-switch.ps1 -On
#   powershell -ExecutionPolicy Bypass -File vpn/client/kill-switch.ps1 -Off
#
# Requires the WireGuard tunnel to be up BEFORE enabling the kill switch.

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet('On','Off')]
    [string]$Action
)

$ErrorActionPreference = 'Stop'
$gInterface = 'WireGuard Tunnel'

if ($Action -eq 'On') {
    Write-Host "==> Enabling kill switch" -ForegroundColor Cyan

    # Verify tunnel is actually up
    $wgTun = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceDescription -like '*WireGuard*' }
    if (-not $wgTun) {
        Write-Host "ERROR: No WireGuard adapter found. Start the VPN first." -ForegroundColor Red
        exit 1
    }
    Write-Host "    Found adapter: $($wgTun.Name) (ifIndex $($wgTun.ifIndex))" -ForegroundColor Green

    # Remove any existing kill-switch rules
    Remove-NetFirewallRule -DisplayName 'AI Firewall VPN Kill Switch' -ErrorAction SilentlyContinue

    # Block outbound on EVERY adapter EXCEPT the WireGuard tunnel.
    # Allows VPN traffic (and loopback), blocks anything that could leak.
    $nonVpn = Get-NetAdapter -ErrorAction SilentlyContinue |
        Where-Object { $_.Status -eq 'Up' -and $_.ifIndex -ne $wgTun.ifIndex }

    foreach ($adapter in $nonVpn) {
        New-NetFirewallRule -DisplayName 'AI Firewall VPN Kill Switch' `
            -Direction Outbound -Action Block `
            -InterfaceAlias $adapter.Name `
            -ErrorAction SilentlyContinue | Out-Null
        Write-Host "    Blocked: $($adapter.Name)" -ForegroundColor Green
    }
    Write-Host ""
    Write-Host "    NOTE: Some setups block DNS separately. If DNS breaks," -ForegroundColor Yellow
    Write-Host "    add an allow rule for your DNS servers, or use tunnel DNS." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Kill switch ACTIVE — all traffic now requires the VPN tunnel." -ForegroundColor Green
}
else {
    Write-Host "==> Disabling kill switch" -ForegroundColor Cyan
    Remove-NetFirewallRule -DisplayName 'AI Firewall VPN Kill Switch' -ErrorAction SilentlyContinue
    Write-Host "    Kill switch removed." -ForegroundColor Green
}
