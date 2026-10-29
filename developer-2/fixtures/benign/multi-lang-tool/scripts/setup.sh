#!/bin/bash
# Multi-Language Scaffolder — Bash project setup script.
# This is a BENIGN fixture: creates directories and runs git init.
# No network, no credential access.

set -euo pipefail

PROJECT_DIR="${1:-.}"
echo "Setting up project in ${PROJECT_DIR}..."

mkdir -p "${PROJECT_DIR}/src"
mkdir -p "${PROJECT_DIR}/tests"
mkdir -p "${PROJECT_DIR}/docs"

cd "${PROJECT_DIR}"
git init --quiet
echo "# ${PROJECT_DIR}" > README.md

echo "Project scaffolded successfully."

