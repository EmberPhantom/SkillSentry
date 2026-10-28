"""
Backup Tool — creates compressed ZIP backups of local directories.

This is a BENIGN fixture: uses only stdlib (zipfile, shutil, pathlib).
No network access, no shell commands, no credentials.
Expected verdict: SAFE (risk < 30).
"""
from __future__ import annotations

import sys
import zipfile
from datetime import datetime
from pathlib import Path


def create_backup(source_dir: Path, backup_dir: Path) -> Path:
    """Create a ZIP backup of source_dir in backup_dir."""
    backup_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_name = f"{source_dir.name}_{timestamp}.zip"
    backup_path = backup_dir / backup_name

    with zipfile.ZipFile(backup_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for file_path in sorted(source_dir.rglob("*")):
            if file_path.is_file():
                arcname = file_path.relative_to(source_dir)
                zf.write(file_path, arcname)

    print(f"Backup created: {backup_path}")
    return backup_path


def rotate_backups(backup_dir: Path, prefix: str, keep: int = 5) -> int:
    """Remove oldest backups beyond the keep limit. Returns count removed."""
    pattern = f"{prefix}_*.zip"
    backups = sorted(backup_dir.glob(pattern), key=lambda p: p.stat().st_mtime)

    removed = 0
    while len(backups) > keep:
        oldest = backups.pop(0)
        oldest.unlink()
        removed += 1
        print(f"  Rotated out: {oldest.name}")
    return removed


def main() -> None:
    if len(sys.argv) < 3:
        print("Usage: python backup.py <source_dir> <backup_dir> [--keep N]", file=sys.stderr)
        sys.exit(1)

    source_dir = Path(sys.argv[1])
    backup_dir = Path(sys.argv[2])

    keep = 5
    if "--keep" in sys.argv:
        idx = sys.argv.index("--keep")
        if idx + 1 < len(sys.argv):
            keep = int(sys.argv[idx + 1])

    if not source_dir.is_dir():
        print(f"Error: {source_dir} is not a directory.", file=sys.stderr)
        sys.exit(1)

    create_backup(source_dir, backup_dir)
    removed = rotate_backups(backup_dir, source_dir.name, keep)
    if removed:
        print(f"Rotated {removed} old backup(s).")


if __name__ == "__main__":
    main()

