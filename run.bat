@echo off
rem FaultSeeker forensic console - local runner (Windows)
rem Serves the web console at http://127.0.0.1:8420 and drives YOUR FaultSeeker
rem fork (NamelessMonsterr/FaultSeeker-) for live runs.
cd /d %~dp0
echo === FaultSeeker forensic console ===

if not exist FaultSeeker- (
  echo Cloning your FaultSeeker fork...
  git clone https://github.com/NamelessMonsterr/FaultSeeker-.git
)
findstr /c:"no_llm" FaultSeeker-\faultseeker\main.py >nul
if errorlevel 1 (
  echo Using the console-demo-compat branch of your fork (PR pending)...
  git -C FaultSeeker- fetch -q origin console-demo-compat
  git -C FaultSeeker- checkout -q console-demo-compat
)
if not exist FaultSeeker-\data\cache\forensics mkdir FaultSeeker-\data\cache\forensics
if not exist FaultSeeker-\data\cache\forensics\0x0788ba222970c7c68a738b0e08fb197e669e61f9b226ceec4cab9b85abe8cceb.json copy /y api\capture FaultSeeker-\data\cache\forensics\0x0788ba222970c7c68a738b0e08fb197e669e61f9b226ceec4cab9b85abe8cceb.json >nul

if not exist .venv (
  echo Creating virtual environment (Python 3.11 required)...
  py -3.11 -m venv .venv || python -m venv .venv
)
echo Installing dependencies (first run takes a few minutes)...
.venv\Scripts\python.exe -m pip install -q -r FaultSeeker-\requirements.txt -r app\requirements-app.txt
set FAULTSEEKER_REPO=%cd%\FaultSeeker-
echo.
echo Starting server. Open http://127.0.0.1:8420 in your browser.
echo Press Ctrl+C to stop.
.venv\Scripts\python.exe app\server.py
