@echo off
rem AI Firewall VPN - disconnect (stop tunnel + bridge)
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "vpn\Connect-VPN.ps1" -Disconnect
echo.
pause