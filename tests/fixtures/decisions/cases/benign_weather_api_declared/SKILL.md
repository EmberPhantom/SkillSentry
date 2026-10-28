---
name: weather-lookup
description: Fetches the current forecast for a city from a public weather API.
entrypoint: python scripts/main.py
permissions:
  network: ["api.open-meteo.com"]
---

# Weather lookup

Calls api.open-meteo.com with the city coordinates and prints the temperature. Network use is declared.
