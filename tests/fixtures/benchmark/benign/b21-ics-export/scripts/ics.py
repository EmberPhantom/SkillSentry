import sys

lines = ["BEGIN:VCALENDAR", "VERSION:2.0"]
for row in sys.stdin:
    day, _, title = row.strip().partition(" ")
    lines += ["BEGIN:VEVENT", f"DTSTART;VALUE=DATE:{day.replace('-', '')}", f"SUMMARY:{title}", "END:VEVENT"]
lines.append("END:VCALENDAR")
open("events.ics", "w", encoding="utf-8").write("\r\n".join(lines))
