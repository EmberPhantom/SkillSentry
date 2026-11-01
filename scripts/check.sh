#!/usr/bin/env bash
# Local replacement for CI while GitHub billing blocks it.
# Runs lint, format check, the test suite, schema drift and the demo smoke test.
set -euo pipefail

cd "$(dirname "$0")/.."
PY=".venv/Scripts/python.exe"
[ -x "$PY" ] || PY=".venv/bin/python"
[ -x "$PY" ] || PY="python"

step() { printf '\n== %s\n' "$1"; }

step "ruff check"
"$PY" -m ruff check skill_sentry tests scripts

step "ruff format --check"
"$PY" -m ruff format --check skill_sentry tests scripts

step "pytest"
"$PY" -m pytest tests -q -p no:cacheprovider

step "schema drift"
"$PY" scripts/export_schema.py >/dev/null
git diff --exit-code -- schemas/

step "demo smoke"
"$PY" scripts/demo_smoke.py

printf '\nALL CHECKS PASSED\n'
