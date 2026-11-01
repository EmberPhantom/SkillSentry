"""Parser hardening: YAML structure limits, reserved device names and alternate streams."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from skill_sentry_cli.core.parser import parse_skill
from skill_sentry_cli.core.parser import skill_parser as parser_module


def _write_skill(root: Path, frontmatter: str, body: str = "Body\n") -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "SKILL.md").write_text(f"---\n{frontmatter}\n---\n{body}", encoding="utf-8")
    return root


def test_yaml_aliases_are_rejected_before_expansion(tmp_path: Path) -> None:
    bomb = "name: demo\ndescription: &a x\nextra: *a\n"

    package = parse_skill(_write_skill(tmp_path / "skill", bomb))

    # The bomb is refused as a high issue (which floors the verdict) and is never expanded.
    assert any(issue.severity == "high" and "aliases" in issue.message for issue in package.issues)


def test_deep_yaml_nesting_is_rejected(tmp_path: Path) -> None:
    depth = parser_module.MAX_YAML_DEPTH + 2
    nested = "name: demo\ndescription: deep\nextra: " + "[" * depth + "x" + "]" * depth

    package = parse_skill(_write_skill(tmp_path / "skill", nested))

    assert any(
        issue.severity == "high" and "nests deeper" in issue.message for issue in package.issues
    )


def test_ordinary_frontmatter_still_parses(tmp_path: Path) -> None:
    ok = "name: demo\ndescription: A harmless skill\nmetadata:\n  tags: [a, b]\n"

    package = parse_skill(_write_skill(tmp_path / "skill", ok))

    assert package.name == "demo"
    assert package.description == "A harmless skill"


@pytest.mark.parametrize(
    "relative, expected",
    [
        ("scripts/aux.py", "reserved device name"),
        ("scripts/CON.txt", "reserved device name"),
        ("scripts/com1", "reserved device name"),
        ("scripts/lpt9.sh", "reserved device name"),
        ("scripts/run.py:hidden", "alternate data stream"),
        ("scripts/run.py", None),
        ("scripts/console.py", None),
        ("scripts/nullable.py", None),
    ],
)
def test_path_name_issue(relative: str, expected: str | None) -> None:
    message = parser_module._path_name_issue(relative)
    if expected is None:
        assert message is None
    else:
        assert message is not None and expected in message


@pytest.mark.skipif(sys.platform == "win32", reason="Windows cannot create reserved device names")
def test_reserved_name_file_is_reported_and_still_analysed(tmp_path: Path) -> None:
    root = _write_skill(tmp_path / "skill", "name: demo\ndescription: A skill\n")
    (root / "scripts").mkdir()
    (root / "scripts" / "aux.py").write_text("print('still scanned')\n", encoding="utf-8")

    package = parse_skill(root)

    assert any("reserved device name" in issue.message for issue in package.issues)
    assert any(text.relative == "scripts/aux.py" for text in package.text_files)
