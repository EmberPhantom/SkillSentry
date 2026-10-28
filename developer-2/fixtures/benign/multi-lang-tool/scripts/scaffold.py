"""
Multi-Language Scaffolder — generates project starter files.

This is a BENIGN fixture: pure pathlib/sys operations.
No network access, no shell commands, no credentials.
Expected verdict: SAFE (risk < 30).
"""
from __future__ import annotations

import sys
from pathlib import Path


TEMPLATES: dict[str, dict[str, str]] = {
    "python": {
        "main.py": '"""Main entry point."""\n\ndef main() -> None:\n    print("Hello, world!")\n\nif __name__ == "__main__":\n    main()\n',
        "requirements.txt": "# Add dependencies here\n",
    },
    "bash": {
        "main.sh": '#!/bin/bash\nset -euo pipefail\necho "Hello, world!"\n',
    },
    "javascript": {
        "index.js": '"use strict";\nconsole.log("Hello, world!");\n',
        "package.json": '{\n  "name": "project",\n  "version": "1.0.0",\n  "main": "index.js"\n}\n',
    },
}


def scaffold(project_dir: Path, language: str) -> list[Path]:
    """Create project files from templates and return created paths."""
    if language not in TEMPLATES:
        raise ValueError(f"Unsupported language: {language}. Options: {', '.join(TEMPLATES)}")

    project_dir.mkdir(parents=True, exist_ok=True)
    created: list[Path] = []

    for filename, content in TEMPLATES[language].items():
        file_path = project_dir / filename
        file_path.write_text(content, encoding="utf-8")
        created.append(file_path)

    return created


def main() -> None:
    if len(sys.argv) < 3:
        print("Usage: python scaffold.py <project_dir> <language>", file=sys.stderr)
        sys.exit(1)

    project_dir = Path(sys.argv[1])
    language = sys.argv[2].lower()

    created = scaffold(project_dir, language)
    for path in created:
        print(f"  Created: {path}")


if __name__ == "__main__":
    main()

