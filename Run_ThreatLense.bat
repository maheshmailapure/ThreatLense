@echo off
title ThreatLense - Autonomous AI Threat Protection System
color 0B
cls
echo ===============================================================================
echo          THREATLENSE - AUTONOMOUS AI ENDPOINT DEFENSE & MONITORING
echo ===============================================================================
echo  [+] Operating System:  Microsoft Windows
echo  [+] Threat Engine:     Atria-Dawn-Preview Autonomous AI Sentinel
echo  [+] Architecture:      Native Desktop Security Application (Zero Browser)
echo ===============================================================================
echo.

set SCRIPT_DIR=%~dp0
set STANDALONE_EXE=%SCRIPT_DIR%backend\dist\ThreatLense\ThreatLense.exe
if not exist "%STANDALONE_EXE%" (
    set STANDALONE_EXE=%SCRIPT_DIR%ThreatLense.exe
)

:: If standalone executable exists, launch it directly in native window mode
if exist "%STANDALONE_EXE%" (
    echo [*] Launching Native ThreatLense Desktop Application Window...
    start "" "%STANDALONE_EXE%"
    exit /b 0
)

:: Fallback to running python desktop launcher
echo [*] Launching ThreatLense Desktop System via Python engine...
cd /d "%SCRIPT_DIR%backend"
python desktop_launcher.py
exit /b 0
