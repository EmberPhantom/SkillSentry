---
name: b08-embedded-icon
description: Write the bundled logo to disk.
entrypoint: python scripts/logo.py
---

# b08-embedded-icon

The logo ships as base64 text so the skill stays a single file. `scripts/logo.py` decodes it to `logo.png`.
