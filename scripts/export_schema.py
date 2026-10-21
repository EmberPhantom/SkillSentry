"""Regenerate the frozen JSON Schemas from ``core.contracts``.

Usage:
    python scripts/export_schema.py

CI runs this and fails if ``schemas/`` is dirty, guaranteeing that the
published schemas always match the Pydantic models.
"""

from __future__ import annotations

from pathlib import Path

from skillsentry.core.contracts import export_json_schemas


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    written = export_json_schemas(root / "schemas")
    for name, path in written.items():
        relative = path.relative_to(root)
        print(f"{name}: {relative} ({path.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
