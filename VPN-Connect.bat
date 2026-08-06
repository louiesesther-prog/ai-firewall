@echo off
rem AI Firewall VPN - one-click connect (double-click me)
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "vpn\Connect-VPN.ps1"
echo.
pause