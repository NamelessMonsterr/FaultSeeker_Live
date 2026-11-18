#!/usr/bin/env bash
# Runs the Python suite, then the browser-level UI suite. Run from anywhere; uses the active Python environment.
set -euo pipefail
cd "$(dirname "$0")/.."
PY="${PYTHON:-$(command -v python3)}"
echo "== Python tests"; "$PY" -m pytest tests -q
echo "== UI tests"
cd tests/ui
[ -d node_modules ] || npm install --silent
PYTHON="$PY" npm test
