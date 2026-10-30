"""Scan every distinct skill under a folder and summarise the results.

Skills are found by SKILL.md, de-duplicated by content hash, and copied to a
scratch directory before scanning, so the sandbox never runs against the source
tree.  The summary records verdicts, timing, degraded stages and crashes.

    python scripts/batch_skills.py <root> --out calibration/batch.json [--no-sandbox]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import tempfile
import time
from pathlib import Path

from skillsentry.core.cache import SQLiteStore
from skillsentry.core.config import load_config
from skillsentry.core.contracts import ScanOptions
from skillsentry.core.engine import ScanEngine


def _content_hash(skill_dir: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(skill_dir.rglob("*")):
        if path.is_file() and not path.is_symlink():
            digest.update(path.relative_to(skill_dir).as_posix().encode("utf-8"))
            digest.update(path.read_bytes())
    return digest.hexdigest()


def discover(root: Path) -> list[Path]:
    """One representative directory per distinct content hash."""

    seen: dict[str, Path] = {}
    for skill_md in sorted(root.rglob("SKILL.md")):
        skill_dir = skill_md.parent
        seen.setdefault(_content_hash(skill_dir), skill_dir)
    return list(seen.values())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("root", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--no-sandbox", action="store_true")
    args = parser.parse_args()

    skills = discover(args.root)
    config = load_config()
    rows: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory() as scratch_root:
        store = SQLiteStore(Path(scratch_root) / "batch.sqlite")
        engine = ScanEngine(config, store=store)
        try:
            for index, source in enumerate(skills):
                staged = Path(scratch_root) / f"skill-{index}"
                shutil.copytree(source, staged, symlinks=True)
                started = time.monotonic()
                row: dict[str, object] = {"source": str(source), "name": source.name}
                try:
                    outcome = engine.scan(
                        staged,
                        options=ScanOptions(
                            sandbox=not args.no_sandbox,
                            no_cache=True,
                            timeout_s=config.sandbox.timeout_s,
                        ),
                    )
                    row.update(
                        {
                            "verdict": outcome.verdict.verdict.value,
                            "risk": outcome.verdict.risk_score,
                            "degraded_stages": [
                                result.stage.value
                                for result in outcome.stage_results
                                if result.degraded
                            ],
                            "finding_count": len(outcome.verdict.findings),
                        }
                    )
                except Exception as exc:  # a crash is data for the report, not a stop
                    row.update({"verdict": "CRASH", "error": f"{type(exc).__name__}: {exc}"[:300]})
                row["seconds"] = round(time.monotonic() - started, 2)
                rows.append(row)
                print(json.dumps(row), flush=True)
        finally:
            engine.close()
            store.close()

    summary = {
        "root": str(args.root),
        "distinct_skills": len(skills),
        "verdicts": {
            verdict: sum(1 for row in rows if row.get("verdict") == verdict)
            for verdict in ("SAFE", "SUSPICIOUS", "MALICIOUS", "CRASH")
        },
        "rows": rows,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"wrote {args.out}: {len(skills)} distinct skills, {summary['verdicts']}")
    return 0 if summary["verdicts"]["CRASH"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
