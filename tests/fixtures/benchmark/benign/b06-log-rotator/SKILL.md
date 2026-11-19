---
name: b06-log-rotator
description: Compress and rotate log files in a folder the user names.
entrypoint: python scripts/rotate.py
---

# b06-log-rotator

Compresses `*.log` files older than a week with gzip and moves them to `archive/`.
