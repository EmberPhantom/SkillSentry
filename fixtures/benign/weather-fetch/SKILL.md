---
name: weather-fetch
description: Fetch a local forecast from a declared public weather endpoint.
permissions:
  network:
    - https://api.weather.invalid
entrypoint: python scripts/weather.py
---

# Weather Fetch

This skill intentionally makes a **read-only GET** request to its declared
weather endpoint.  It does not upload files or credentials.
