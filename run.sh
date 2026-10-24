#!/usr/bin/env bash
# FaultSeeker forensic console - local runner (Linux/Mac)
# Serves the web console at http://127.0.0.1:8420 and drives YOUR FaultSeeker
# fork (NamelessMonsterr/FaultSeeker-) for live runs. No code from any other
# FaultSeeker repo is bundled here.
set -euo pipefail
cd "$(dirname "$0")"
PY=python3.11
command -v "$PY" >/dev/null || PY=python3
PIPELINE_SHA=$("$PY" tools/pipeline_pin.py)
if [ ! -d FaultSeeker- ]; then
  git clone --no-checkout https://github.com/NamelessMonsterr/FaultSeeker-.git
fi
if ! git -C FaultSeeker- diff --quiet || ! git -C FaultSeeker- diff --cached --quiet; then
  echo "Pipeline checkout has local changes; preserve them before bootstrapping." >&2
  exit 1
fi
git -C FaultSeeker- cat-file -e "${PIPELINE_SHA}^{commit}" 2>/dev/null || git -C FaultSeeker- fetch --depth 1 origin "$PIPELINE_SHA"
git -C FaultSeeker- checkout --detach "$PIPELINE_SHA"
test "$(git -C FaultSeeker- rev-parse HEAD)" = "$PIPELINE_SHA"
# Seed the offline replay cache so `--offline` and the console fallback work.
mkdir -p "data/cache/forensics"
cp -n api/capture "data/cache/forensics/0x0788ba222970c7c68a738b0e08fb197e669e61f9b226ceec4cab9b85abe8cceb.json" 2>/dev/null

PY=python3.11
command -v $PY >/dev/null || PY=python3
[ -d .venv ] || $PY -m venv .venv
.venv/bin/pip install -q -r FaultSeeker-/requirements.txt -r app/requirements-app.txt
export FAULTSEEKER_REPO="$(pwd)/FaultSeeker-"
echo "Open http://127.0.0.1:8420"
.venv/bin/python app/server.py
