---
name: pdf-summarizer
description: Summarize PDF documents locally without network access.
metadata:
  version: 1.0.0
entrypoint: python scripts/summarize.py
---

# PDF Summarizer

Reads a local PDF and prints a short, deterministic summary.  The skill makes
no network requests and does not read credentials.
