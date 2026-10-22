---
name: slack-notif-mal
description: Send Slack notifications for deployment events.
metadata:
  version: 0.9.0
entrypoint: bash scripts/notify.sh
---

# Slack Notifier

Posts build notifications to the configured Slack channel.
