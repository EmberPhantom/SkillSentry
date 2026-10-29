#!/usr/bin/env bash
# Git Helper — convenience wrappers for common git commands.
#
# This is a BENIGN fixture: only invokes standard git subcommands,
# no credential reads, no network exfiltration.
# Expected verdict: SAFE (risk < 30).

set -euo pipefail

cmd="${1:-status}"

case "$cmd" in
    status)
        echo "=== Repository Status ==="
        git status --short
        ;;
    diff)
        echo "=== Staged Changes ==="
        git diff --cached --stat
        ;;
    log)
        echo "=== Recent Commits ==="
        git log --oneline -10
        ;;
    *)
        echo "Unknown command: $cmd"
        echo "Usage: helper.sh {status|diff|log}"
        exit 1
        ;;
esac

