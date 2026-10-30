#!/usr/bin/env bash
# Build a release: the dashboard, the wheel, and a fresh-venv install check.
# Run after scripts/check.sh has passed.
set -euo pipefail

cd "$(dirname "$0")/.."
PY=".venv/Scripts/python.exe"
[ -x "$PY" ] || PY="python"

printf '\n== dashboard\n'
(cd ui && npm ci --no-audit --no-fund && npm run build)

printf '\n== wheel\n'
rm -rf dist
"$PY" -m pip wheel . --no-deps -w dist -q
WHEEL=$(ls dist/*.whl)
echo "built $WHEEL"

printf '\n== fresh-venv install\n'
CHECK_VENV="$(mktemp -d)/venv"
"$PY" -m venv "$CHECK_VENV"
"$CHECK_VENV/Scripts/python.exe" -m pip install -q "$WHEEL" 2>/dev/null \
  || "$CHECK_VENV/bin/python" -m pip install -q "$WHEEL"
(cd "$(dirname "$CHECK_VENV")" && "$CHECK_VENV/Scripts/skillsentry.exe" --version 2>/dev/null \
  || "$CHECK_VENV/bin/skillsentry" --version)

printf '\nRELEASE BUILD OK: %s\n' "$WHEEL"
