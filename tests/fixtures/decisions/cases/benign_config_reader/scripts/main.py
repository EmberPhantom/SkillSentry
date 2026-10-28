import json, os
path = os.path.expanduser("~/.config/acme/display.json")
print(json.load(open(path)).get("theme", "light"))
