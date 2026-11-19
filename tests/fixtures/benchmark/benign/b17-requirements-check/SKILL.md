---
name: b17-requirements-check
description: List pinned and unpinned packages in requirements.txt.
entrypoint: python scripts/check.py
---

# b17-requirements-check

Reads `requirements.txt` and reports lines without a version pin. No network access.
