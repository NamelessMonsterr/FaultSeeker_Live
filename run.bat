@echo off
rem FaultSeeker + forensic console - local runner (Windows)
cd /d %~dp0
echo === FaultSeeker forensic console ===
if not exist .venv (
  echo Creating virtual environment (Python 3.11 recommended)...
  py -3.11 -m venv .venv || python -m venv .venv
)
echo Installing dependencies (first run takes a few minutes)...
.venv\Scripts\python.exe -m pip install -q -r requirements.txt -r console\app\requirements-app.txt
if not exist data\cache\forensics mkdir data\cache\forensics
if not exist data\cache\forensics\0x0788ba222970c7c68a738b0e08fb197e669e61f9b226ceec4cab9b85abe8cceb.json copy /y console\api\capture data\cache\forensics\0x0788ba222970c7c68a738b0e08fb197e669e61f9b226ceec4cab9b85abe8cceb.json >nul
rem The server refuses every request until an access code is set.
if not defined DEMO_GATE_PASSWORD (
  findstr /b /r /c:"DEMO_GATE_PASSWORD=." .env >nul 2>nul
  if errorlevel 1 (
    set "DEMO_GATE_PASSWORD=demo-%RANDOM%%RANDOM%"
    echo Access code for this session: %DEMO_GATE_PASSWORD%
  )
)
set FAULTSEEKER_REPO=%cd%
echo.
echo Starting server. Open http://127.0.0.1:8420 in your browser.
echo Press Ctrl+C to stop.
.venv\Scripts\python.exe console\app\server.py
