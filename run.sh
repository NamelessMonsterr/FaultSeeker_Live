#!/usr/bin/env bash
# FaultSeeker + forensic console - local runner (Linux/macOS).
# Serves the console at http://127.0.0.1:8420 and runs the pipeline in this repo.
set -euo pipefail
cd "$(dirname "$0")"
PY=python3.11
command -v "$PY" >/dev/null || PY=python3
[ -d .venv ] || "$PY" -m venv .venv
.venv/bin/pip install -q -r requirements.txt -r console/app/requirements-app.txt
# Offline replay cache for the bundled Zunami capture.
mkdir -p data/cache/forensics
[ -f data/cache/forensics/0x0788ba222970c7c68a738b0e08fb197e669e61f9b226ceec4cab9b85abe8cceb.json ] || cp console/api/capture data/cache/forensics/0x0788ba222970c7c68a738b0e08fb197e669e61f9b226ceec4cab9b85abe8cceb.json
# The server refuses every request until an access code is set. Use .env or
# the environment if provided, otherwise generate a one-off code for this run.
if [ -z "${DEMO_GATE_PASSWORD:-}" ] && ! grep -qs '^DEMO_GATE_PASSWORD=.\+' .env; then
  DEMO_GATE_PASSWORD="$(.venv/bin/python -c 'import secrets;print(secrets.token_urlsafe(9))')"
  export DEMO_GATE_PASSWORD
  echo "Access code for this session: $DEMO_GATE_PASSWORD"
fi
export FAULTSEEKER_REPO="$(pwd)"
echo "Open http://127.0.0.1:8420"
exec .venv/bin/python console/app/server.py
