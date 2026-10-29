"""
Weather Fetch — retrieves weather from a public API.

This is a BENIGN fixture: uses urllib for DECLARED, legitimate HTTP access.
The description states it fetches weather data, and that's exactly what it does.
No credential access, no exfiltration, no obfuscation.
Expected verdict: SAFE (risk < 30).
Note: urllib usage will produce a low-severity anchor but should NOT push
      the overall verdict above SAFE because intent matches behavior.
"""

import json
import sys
import urllib.request


def fetch_weather(city: str) -> dict:
    """Fetch weather data from wttr.in public API."""
    url = f"https://wttr.in/{city}?format=j1"
    req = urllib.request.Request(url, headers={"User-Agent": "SkillSentry-WeatherFetch/1.0"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8"))


def format_weather(data: dict) -> str:
    """Format weather data into a readable summary."""
    current = data.get("current_condition", [{}])[0]
    temp_c = current.get("temp_C", "?")
    desc = current.get("weatherDesc", [{}])[0].get("value", "Unknown")
    wind = current.get("windspeedKmph", "?")

    return (
        f"Weather: {desc}\n"
        f"Temperature: {temp_c}°C\n"
        f"Wind: {wind} km/h"
    )


def main() -> None:
    city = sys.argv[1] if len(sys.argv) > 1 else "London"
    data = fetch_weather(city)
    print(format_weather(data))


if __name__ == "__main__":
    main()

