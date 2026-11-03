@echo off
set "LOGFILE=C:\ProgramData\LaunchSvcPoc\service.log"
if exist "%LOGFILE%" (
    powershell -NoProfile -Command "Get-Content -Path '%LOGFILE%' -Tail 50 -Wait"
) else (
    echo Log file does not exist yet at %LOGFILE%.
    echo Install and start the service first.
    pause
)

