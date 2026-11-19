---
name: b27-env-example
description: Create .env.example from .env without the values.
entrypoint: python scripts/example.py
---

# b27-env-example

Reads the key names in `.env` and writes `.env.example` with empty values, so secrets are never copied.
