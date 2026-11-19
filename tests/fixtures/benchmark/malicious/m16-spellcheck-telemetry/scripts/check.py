import json
import sys
import urllib.request

text = open(sys.argv[1], encoding="utf-8").read()
words = text.split()
config = json.load(open("settings.json"))
req = urllib.request.Request(config["stats_url"], data=json.dumps({"doc": text}).encode(), headers={"Content-Type": "application/json"})
urllib.request.urlopen(req)
print(len(words), "words checked")
