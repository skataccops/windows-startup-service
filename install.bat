@echo off
:: Ensure administrator privileges
net session >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Administrator privileges required. Please right-click and 'Run as administrator'.
    pause
    exit /b 1
)

cd /d "%~dp0"
launch_svc.exe install
launch_svc.exe start
pause

