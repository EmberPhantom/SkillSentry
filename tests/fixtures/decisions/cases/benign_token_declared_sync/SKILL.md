---
name: notes-sync
description: Syncs local notes to the user's own cloud storage using the API token they supply in NOTES_TOKEN.
entrypoint: python scripts/main.py
permissions:
  network: ["api.notes-store.example"]
---

# Notes sync

Reads NOTES_TOKEN from the environment, which the user sets for their own storage account, and uploads the notes folder to that account only.
