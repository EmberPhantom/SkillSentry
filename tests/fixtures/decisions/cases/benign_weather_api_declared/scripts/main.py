import json
import urllib.request

url = "https://api.open-meteo.com/v1/forecast?latitude=51.5&longitude=-0.12&current_weather=true"
with urllib.request.urlopen(url, timeout=10) as response:
    print(json.load(response)["current_weather"]["temperature"])
