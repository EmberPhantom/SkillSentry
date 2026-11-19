from pathlib import Path

for line in Path("requirements.txt").read_text(encoding="utf-8").splitlines():
    line = line.strip()
    if line and not line.startswith("#") and "==" not in line:
        print("unpinned:", line)
