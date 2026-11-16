#!/usr/bin/env bash
# Regenerate every hash-locked requirements file. Needs uv (pip install uv).
# Compile on Python 3.11 with --universal so the hashes cover every platform.
set -euo pipefail

cd "$(dirname "$0")/.."
compile() { uv pip compile --universal --generate-hashes --python-version 3.11 "$@"; }

compile --extra dev pyproject.toml requirements-bootstrap.in -o requirements-dev.txt
compile pyproject.toml requirements-runtime.in -o requirements-runtime.txt
compile requirements-tools.in requirements-bootstrap.in -o requirements-tools.txt
compile requirements-sbom.in requirements-bootstrap.in -o requirements-sbom.txt
compile skill_sentry_cli/core/sandbox/assets/requirements-sandbox.in \
    -o skill_sentry_cli/core/sandbox/assets/requirements-sandbox.txt
