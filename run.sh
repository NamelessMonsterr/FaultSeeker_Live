#!/usr/bin/env bash
# FaultSeeker forensic console - local runner (Linux/Mac)
# Serves the web console at http://127.0.0.1:8420 and drives YOUR FaultSeeker
# fork (NamelessMonsterr/FaultSeeker-) for live runs. No code from any other
# FaultSeeker repo is bundled here.
cd "$(dirname "$0")"

if [ ! -d FaultSeeker- ]; then
  echo "Cloning your FaultSeeker fork..."
  git clone https://github.com/NamelessMonsterr/FaultSeeker-.git
fi
# Until the console-compat PR is merged into main, use its branch.
if ! grep -q "no_llm" FaultSeeker-/faultseeker/main.py; then
  echo "Using the console-demo-compat branch of your fork (PR pending)..."
  git -C FaultSeeker- fetch -q origin console-demo-compat
  git -C FaultSeeker- checkout -q console-demo-compat
fi
# Seed the offline replay cache so `--offline` and the console fallback work.
mkdir -p "FaultSeeker-/data/cache/forensics"
cp -n api/capture "FaultSeeker-/data/cache/forensics/0x0788ba222970c7c68a738b0e08fb197e669e61f9b226ceec4cab9b85abe8cceb.json" 2>/dev/null

PY=python3.11
command -v $PY >/dev/null || PY=python3
[ -d .venv ] || $PY -m venv .venv
.venv/bin/pip install -q -r FaultSeeker-/requirements.txt -r app/requirements-app.txt
export FAULTSEEKER_REPO="$(pwd)/FaultSeeker-"
echo "Open http://127.0.0.1:8420"
.venv/bin/python app/server.py
