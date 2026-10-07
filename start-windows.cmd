@echo off
setlocal
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0start-windows.ps1" %*
set "gateway_exit=%ERRORLEVEL%"
if not "%gateway_exit%"=="0" pause
exit /b %gateway_exit%
