import os

port = os.environ.get("PORT", "8080")
language = os.environ.get("LANG", "C")
print(f"listening on {port} ({language})")
