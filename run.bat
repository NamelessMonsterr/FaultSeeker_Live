@echo off
rem FaultSeeker forensic console - local runner (Windows)
rem Serves the web console at http://127.0.0.1:8420 and drives YOUR FaultSeeker
rem fork (NamelessMonsterr/FaultSeeker-) for live runs.
cd /d %~dp0
echo === FaultSeeker forensic console ===

set "PIPELINE_SHA="
for /f %%s in ('python tools\pipeline_pin.py') do set "PIPELINE_SHA=%%s"
if not defined PIPELINE_SHA exit /b 1
if not exist FaultSeeker- (
  git clone --no-checkout https://github.com/NamelessMonsterr/FaultSeeker-.git
  if errorlevel 1 exit /b 1
)
git -C FaultSeeker- diff --quiet
if errorlevel 1 exit /b 1
git -C FaultSeeker- diff --cached --quiet
if errorlevel 1 exit /b 1
git -C FaultSeeker- cat-file -e %PIPELINE_SHA%^{commit} 2>nul
if errorlevel 1 git -C FaultSeeker- fetch --depth 1 origin %PIPELINE_SHA%
if errorlevel 1 exit /b 1
git -C FaultSeeker- checkout --detach %PIPELINE_SHA%
if errorlevel 1 exit /b 1
for /f %%s in ('git -C FaultSeeker- rev-parse HEAD') do if not "%%s"=="%PIPELINE_SHA%" exit /b 1
if not exist data\cache\forensics mkdir data\cache\forensics
if not exist data\cache\forensics\0x0788ba222970c7c68a738b0e08fb197e669e61f9b226ceec4cab9b85abe8cceb.json copy /y api\capture data\cache\forensics\0x0788ba222970c7c68a738b0e08fb197e669e61f9b226ceec4cab9b85abe8cceb.json >nul

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
