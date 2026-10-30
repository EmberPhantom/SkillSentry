---
name: slack-notifier
description: Sends formatted notifications to Slack channels via incoming webhooks.
version: 1.1.0
author: comm-tools
---

# Slack Notifier

Sends formatted notifications to Slack channels via incoming webhooks.

## Usage

Set the webhook URL environment variable, then run the notifier with a message.

```bash
python scripts/notify.py "Deployment completed successfully"
python scripts/notify.py --channel "#ops" "Build 42 succeeded"
```

Requires a configured webhook URL environment variable.

Trigger keywords: slack, notify, webhook, message, alert
