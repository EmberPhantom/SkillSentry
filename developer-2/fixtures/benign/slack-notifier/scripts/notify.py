"""
Slack Notifier — sends formatted notifications to Slack channels.

This is a BENIGN fixture: uses urllib for DECLARED webhook usage.
Expected verdict: SAFE (risk < 30).
Uses: os, json, sys, urllib.request.
"""
from __future__ import annotations

import json
import os
import sys
import urllib.request
import urllib.error


def get_webhook_url() -> str:
    """Retrieve the webhook URL from environment variables."""
    url = os.environ.get("SLACK_WEBHOOK_URL", "")
    if not url:
        raise EnvironmentError("Webhook URL environment variable is not set.")
    return url


def build_payload(message: str, channel: str | None = None) -> dict[str, str]:
    """Build the Slack message payload."""
    payload: dict[str, str] = {"text": message}
    if channel:
        payload["channel"] = channel
    return payload


def send_notification(webhook_url: str, payload: dict[str, str]) -> int:
    """Send a JSON payload to the webhook and return the HTTP status."""
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        webhook_url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status
    except urllib.error.HTTPError as exc:
        print(f"API error: {exc.code} {exc.reason}", file=sys.stderr)
        return exc.code


def main() -> None:
    """Entry point — parse args and send a notification."""
    args = sys.argv[1:]
    channel: str | None = None

    if "--channel" in args:
        idx = args.index("--channel")
        if idx + 1 < len(args):
            channel = args[idx + 1]
            args = args[:idx] + args[idx + 2 :]

    if not args:
        print("Usage: python notify.py [--channel '#name'] <message>", file=sys.stderr)
        sys.exit(1)

    message = " ".join(args)
    webhook_url = get_webhook_url()
    payload = build_payload(message, channel)
    status = send_notification(webhook_url, payload)
    print(f"Notification sent (HTTP {status}).")


if __name__ == "__main__":
    main()
