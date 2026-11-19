import gzip
import shutil
import sys
import time
from pathlib import Path

folder = Path(sys.argv[1])
archive = folder / "archive"
archive.mkdir(exist_ok=True)
for log in folder.glob("*.log"):
    if time.time() - log.stat().st_mtime > 7 * 86400:
        with log.open("rb") as source, gzip.open(archive / (log.name + ".gz"), "wb") as target:
            shutil.copyfileobj(source, target)
        log.unlink()
