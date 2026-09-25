@echo off
title AI Endpoint Intrusion Detection System (AI-IDS)
color 0B
cls
echo ===============================================================================
echo        AI ENDPOINT INTRUSION DETECTION & SYSTEM PROTECTION SOFTWARE
echo ===============================================================================
echo  [+] Host Architecture: %COMPUTERNAME%
echo  [+] Operating System:  Microsoft Windows
echo  [+] Engine:            Real-Time Behavioral Anomaly Detector (Isolation Forest)
echo  [+] Stream Interval:   1.0 Second In-Memory Pulse (0ms Database Delay)
echo ===============================================================================
echo.

:: Check Python installation
where python >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Python 3 is not installed or not in system PATH.
    echo Please install Python 3.10+ from python.org and re-run this tool.
    pause
    exit /b 1
)

:: Check Node.js installation
where npm >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Node.js is not installed or not in system PATH.
    echo Please install Node.js 18+ from nodejs.org and re-run this tool.
    pause
    exit /b 1
)

echo [*] Starting Autonomous AI-IDS Backend Engine on http://127.0.0.1:8000 ...
start "AI-IDS Backend Engine" /min cmd /c "cd /d backend && python -m uvicorn app.main:app --host 127.0.0.1 --port 8000"

echo [*] Waiting for Backend Kernel Initialization...
timeout /t 3 /nobreak >nul

echo [*] Starting Real-Time SOC Desktop Console on http://localhost:5173 ...
start "AI-IDS SOC Console" /min cmd /c "cd /d frontend && npm.cmd run dev"

timeout /t 2 /nobreak >nul

echo.
echo ===============================================================================
echo  [SUCCESS] AI-IDS System Software is Active and Protecting this Computer!
echo  - SOC Console URL:   http://localhost:5173
echo  - Backend API URL:   http://127.0.0.1:8000/docs
echo  - Standalone Exec:   backend\dist\AI-IDS-Shield\AI-IDS-Shield.exe
echo  - Telemetry Stream:  ws://127.0.0.1:8000/api/ws/agent
echo ===============================================================================
echo.
echo Launching Default Browser to SOC Console...
start http://localhost:5173

pause
