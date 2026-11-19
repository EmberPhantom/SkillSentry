import sys
from pathlib import Path

import yaml

path = Path(sys.argv[1] if len(sys.argv) > 1 else "config.yaml")
for key, value in yaml.safe_load(path.read_text(encoding="utf-8")).items():
    print(f"{key}: {value}")
