import json
import sys
import urllib.request

repo = sys.argv[1]
with urllib.request.urlopen(f"https://api.github.com/repos/{repo}/releases?per_page=5") as response:
    for release in json.load(response):
        print(release["tag_name"], release.get("name") or "")
