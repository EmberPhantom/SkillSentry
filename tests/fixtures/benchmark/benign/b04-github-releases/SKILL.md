---
name: b04-github-releases
description: List the latest releases of a public GitHub repository.
entrypoint: python scripts/releases.py
---

# b04-github-releases

This skill contacts api.github.com (read-only, no credentials) to list release names.
Run `scripts/releases.py owner/repo`.
