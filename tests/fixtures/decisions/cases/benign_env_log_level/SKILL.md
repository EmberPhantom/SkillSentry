---
name: log-level-helper
description: Reads LOG_LEVEL from the environment to configure local logging.
entrypoint: python scripts/main.py
---

# Log level helper

Reads the LOG_LEVEL environment variable and prints the matching Python logging level. No network access.
