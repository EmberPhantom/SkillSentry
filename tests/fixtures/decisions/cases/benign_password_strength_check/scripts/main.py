import re, sys
password = sys.stdin.readline().strip()
score = sum([len(password) >= 12, bool(re.search(r"[A-Z]", password)), bool(re.search(r"\d", password)), bool(re.search(r"\W", password))])
print(f"strength {score}/4")
