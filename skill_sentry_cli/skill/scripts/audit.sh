#!/usr/bin/env bash
# audit.sh — bundled entrypoint for the SkillSentry Agent Skill (skill_sentry_cli/skill/)
#
# Usage:
#   scripts/audit.sh <path-to-skill-directory> [extra skill-sentry-cli flags]
#
# Examples:
#   scripts/audit.sh ./some-downloaded-skill
#   scripts/audit.sh ./some-downloaded-skill --sarif-out report.sarif
#   scripts/audit.sh ./some-downloaded-skill --demo-mode
#
# Exit codes (CI contract, docs/07-cli-reference.md §7.5):
#   0  all skills within --fail-on threshold (default: no MALICIOUS)
#   1  verdict above threshold found  -> DO NOT INSTALL
#   2  usage error
#   3  operational error (Docker down, DB locked) — not a verdict
#   4  model unavailable and no fallback enabled
set -euo pipefail

SKILL_DIR="${1:-}"
[ $# -gt 0 ] && shift || true

if [ -z "${SKILL_DIR}" ]; then
  echo "usage: audit.sh <skill-directory> [extra skill-sentry-cli flags]" >&2
  exit 2
fi

if [ ! -d "${SKILL_DIR}" ]; then
  echo "error: '${SKILL_DIR}' is not a directory" >&2
  exit 2
fi

if [ ! -f "${SKILL_DIR}/SKILL.md" ] && [ -z "$(find "${SKILL_DIR}" -maxdepth 2 -name SKILL.md -print -quit 2>/dev/null)" ]; then
  echo "warning: no SKILL.md found under '${SKILL_DIR}' — scanning anyway (spec validation will flag it)" >&2
fi

if ! command -v skill-sentry-cli >/dev/null 2>&1; then
  echo "error: skill-sentry-cli CLI not found — install with: pip install skill-sentry-cli" >&2
  exit 3
fi

# Warn (don't fail) when sandbox dependencies are missing: the engine degrades
# to static-only analysis and marks the verdict accordingly (fail-safe rule).
command -v docker >/dev/null 2>&1 || echo "warning: Docker not found — sandbox stages will be skipped (verdict flagged 'sandbox-unavailable')" >&2
curl -sf --max-time 2 "${OLLAMA_HOST:-http://localhost:11434}/api/tags" >/dev/null 2>&1 \
  || echo "warning: Ollama not reachable — set --backend cloud or --demo-mode, otherwise semantic/vision stages degrade" >&2

exec skill-sentry-cli scan "${SKILL_DIR}" --fail-on malicious "$@"
