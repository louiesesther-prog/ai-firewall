@echo off
rem AI Firewall VPN - install auto-start at login
rem (tunnel + bridge connect automatically every time you log in)
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "vpn\Connect-VPN.ps1" -AutoStart
echo.
pause