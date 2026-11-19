from pathlib import Path

keys = [line.split("=", 1)[0] for line in Path(".env").read_text(encoding="utf-8").splitlines() if "=" in line and not line.startswith("#")]
Path(".env.example").write_text("\n".join(f"{key}=" for key in keys) + "\n", encoding="utf-8")
