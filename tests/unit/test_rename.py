"""The old module and command name must not come back in shipped code or current docs.

The package is ``skill_sentry_cli`` and the command is ``skill-sentry-cli``.  The bare
word ``skillsentry`` is still allowed where it names something else on purpose:
runtime contracts (labels, SARIF and STIX identifiers, the sandbox image and
its container paths), the config and data folder, the bundled skill's own name,
repository URLs, and historical records.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]

# Files that record history or contract data, not the current name.
HISTORICAL = (
    "docs/13-",
    "docs/14-",
    "docs/15-",
    "docs/checklists/",
    "docs/CHANGELOG.md",
    "skill_sentry_cli/data/known_skills_v1.json",
    "tests/ground_truth/anchor_citations.json",
    "tests/unit/test_rename.py",
)

# Old-name patterns that would be wrong in current text.
OLD_NAME = re.compile(
    r"\bskillsentry\.(?:core|data|server|cli|skill|ui|rules|version|__main__)\b"
    r"|^\s*(?:from|import)\s+skillsentry\b"
    r"|(?<![\w./:\-])skillsentry/(?:core|data|server|cli|skill|ui|rules|tests|scripts)/"
    r"|(?<![\w./\-])skillsentry(?=\s+(?:scan|doctor|init|serve|sandbox|cache|export|self-audit|setup)\b)"
    r"|pip install skillsentry\b"
    r"|\bskill_sentry\.(?:core|data|server|cli)\b"
    r"|(?<![\w-])skill-sentry(?=\s+(?:scan|doctor|init|serve|sandbox|cache|export|self-audit|setup)\b)",
    re.MULTILINE,
)


def _tracked_text_files() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout.split()
    result = []
    for name in out:
        if name.startswith(HISTORICAL) or name.endswith((".png", ".gif", ".jpg", ".ico", ".woff2")):
            continue
        result.append(name)
    return result


@pytest.mark.skipif(
    not (ROOT / ".git").exists(), reason="the rename gate reads tracked files of a checkout"
)
def test_old_module_and_command_names_are_gone():
    offenders = []
    for name in _tracked_text_files():
        try:
            text = (ROOT / name).read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for match in OLD_NAME.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            offenders.append(f"{name}:{line}: {match.group(0)}")
    assert not offenders, offenders[:20]


def test_installed_package_and_command_use_the_new_names():
    from skill_sentry_cli import cli

    assert cli.app.info.name == "skill-sentry-cli"
    import importlib.metadata as metadata

    from skill_sentry_cli.core.version import __version__

    assert metadata.version("skill-sentry-cli") == __version__
