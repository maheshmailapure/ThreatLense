@echo off
title ThreatLense - Desktop Setup & Installation
color 0A
cls
echo ===============================================================================
echo             THREATLENSE - ENDPOINT SECURITY INSTALLATION
echo ===============================================================================
echo  [+] Installing ThreatLense Desktop Application to your Windows PC...
echo.

set SCRIPT_DIR=%~dp0
set EXE_PATH=%SCRIPT_DIR%backend\dist\ThreatLense\ThreatLense.exe
if not exist "%EXE_PATH%" (
    set EXE_PATH=%SCRIPT_DIR%ThreatLense.exe
)

if not exist "%EXE_PATH%" (
    echo [ERROR] Could not locate ThreatLense.exe.
    echo Please make sure all files are extracted.
    pause
    exit /b 1
)

:: Create Desktop Shortcut using Windows PowerShell & WScript.Shell
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "$ws = New-Object -ComObject WScript.Shell; " ^
    "$s = $ws.CreateShortcut([System.IO.Path]::Combine([Environment]::GetFolderPath('Desktop'), 'ThreatLense.lnk')); " ^
    "$s.TargetPath = '%EXE_PATH%'; " ^
    "$s.WorkingDirectory = [System.IO.Path]::GetDirectoryName('%EXE_PATH%'); " ^
    "$s.Description = 'ThreatLense - Autonomous AI Threat Defense & Security Operations'; " ^
    "$s.Save();"

echo  [SUCCESS] Desktop Shortcut created successfully!
echo  [+] You can now launch ThreatLense directly from your Windows Desktop.
echo.
echo ===============================================================================
echo Launching ThreatLense Desktop Application now...
start "" "%EXE_PATH%"
timeout /t 2 /nobreak >nul
exit /b 0
