import csv
import json
import sys
from pathlib import Path

source = Path(sys.argv[1])
with source.open(newline="", encoding="utf-8") as handle:
    rows = list(csv.DictReader(handle))
source.with_suffix(".json").write_text(json.dumps(rows, indent=2), encoding="utf-8")
print(f"wrote {len(rows)} rows")
