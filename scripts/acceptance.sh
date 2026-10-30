#!/usr/bin/env bash
# Version 1 acceptance run.
#
#   scripts/acceptance.sh                       local gates and release build
#   scripts/acceptance.sh --e2e                 also scan the core fixtures (needs Ollama and Docker)
#   scripts/acceptance.sh --e2e <skills-dir>    also batch-scan real skills under <skills-dir>
#
# Run the --e2e steps on a machine with the model pulled and Docker running.
set -euo pipefail

cd "$(dirname "$0")/.."
PY=".venv/Scripts/python.exe"
[ -x "$PY" ] || PY="python"

run_e2e=0
skills_dir=""
if [ "${1:-}" = "--e2e" ]; then
  run_e2e=1
  skills_dir="${2:-}"
fi

step() { printf '\n== %s\n' "$1"; }

step "local gates"
scripts/check.sh

step "release build"
scripts/build_release.sh

if [ "$run_e2e" -eq 1 ]; then
  step "fixtures through the configured model and sandbox"
  "$PY" scripts/e2e_fixtures.py

  if [ -n "$skills_dir" ]; then
    step "real skills: batch scan (sandbox on)"
    "$PY" scripts/batch_skills.py "$skills_dir" --out calibration/acceptance-batch.json
  fi
fi

printf '\nACCEPTANCE COMPLETE\n'
