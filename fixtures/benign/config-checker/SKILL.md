---
name: config-checker
description: Check a project's settings.toml for missing or out-of-range values, reading only that declared file.
permissions:
  files:
    read:
      - settings.toml
entrypoint: python scripts/check.py
---

# Config Checker

Reads one declared project file, `settings.toml`, and reports settings that are
missing or outside their allowed range. It writes nothing, makes no network
requests and does not read credentials.

Usage: `python scripts/check.py [settings.toml]`
