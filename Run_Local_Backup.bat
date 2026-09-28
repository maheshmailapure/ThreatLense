@echo off
title ThreatLense - Autonomous AI Security Engine [Local Backup Runner]
color 0A
cls
echo ===============================================================================
echo          THREATLENSE - AUTONOMOUS AI CYBER DEFENSE SYSTEM
echo                       [LOCAL BACKUP RUNNER]
echo ===============================================================================
echo  [+] Engine:        Atria AI Autonomous Neural Sentinel (Real-Time Ingress ^& Downloads)
echo  [+] Mode:          Direct Local Host Defense Engine
echo  [+] Local URL:     http://127.0.0.1:8000
echo ===============================================================================
echo.

:: 1. Navigate to project backend directory
if exist "%~dp0backend" (
    cd /d "%~dp0backend"
) else if exist "c:\Users\shivl\Documents\Antigravity Projects\backend" (
    cd /d "c:\Users\shivl\Documents\Antigravity Projects\backend"
) else (
    echo [-] Error: Could not locate ThreatLense backend directory.
    pause
    exit /b 1
)

:: 2. Terminate any stale processes on port 8000 to prevent port conflicts
echo [*] Checking network port 8000...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":8000" ^| findstr "LISTENING"') do (
    echo [*] Clearing stale process on port 8000 (PID: %%a)...
    taskkill /f /pid %%a >nul 2>&1
)

:: 3. Launch the native desktop launcher with python
echo [*] Starting ThreatLense AI Sentinels ^& Desktop Security Suite...
echo.
python desktop_launcher.py

:: 4. If window closes or fails, fallback cleanly
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [-] Native window closed or error occurred. Launching Localhost Fallback...
    start http://127.0.0.1:8000
    python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
)

pause
