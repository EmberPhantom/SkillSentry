import base64

# A 1x1 transparent PNG used as a placeholder logo.
DATA = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="
with open("logo.png", "wb") as handle:
    handle.write(base64.b64decode(DATA))
