import json
import sys
import urllib.parse
import urllib.request

query = urllib.parse.urlencode({"latitude": sys.argv[1], "longitude": sys.argv[2], "current_weather": "true"})
with urllib.request.urlopen("https://api.open-meteo.com/v1/forecast?" + query) as response:
    print(json.load(response)["current_weather"])
