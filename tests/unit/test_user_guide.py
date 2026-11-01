"""The user guide only documents commands and flags the CLI really has.

Every ``skillsentry`` command and ``--flag`` in the guide's shell examples must
appear in ``--help``.  The guide also follows the documentation gates: no model
names, no machine-specific paths, and no hand-typed pass counts.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from skillsentry import cli
from typer.testing import CliRunner

ROOT = Path(__file__).resolve().parents[2]
GUIDE = ROOT / "docs" / "16-user-guide.md"
runner = CliRunner()

SUBCOMMAND_GROUPS = {"cache", "sandbox"}
FORBIDDEN_MODEL_NAMES = re.compile(r"\b(?:gemma|gemini|qwen|llama|mistral)\w*|\bphi-\d", re.IGNORECASE)
DRIVE_PATH = re.compile(r"\b[A-Za-z]:\\")
FILE_URL = re.compile(r"file:///")
PASS_COUNT = re.compile(r"\b\d+\s+passed\b")


def _guide() -> str:
    return GUIDE.read_text(encoding="utf-8")


def _bash_blocks(text: str) -> list[str]:
    return re.findall(r"```bash\n(.*?)```", text, flags=re.DOTALL)


def _skillsentry_commands(text: str) -> list[list[str]]:
    commands: list[list[str]] = []
    for block in _bash_blocks(text):
        for raw in block.splitlines():
            line = raw.strip()
            if not line.startswith("skillsentry "):
                continue
            line = line.split("#", 1)[0].strip()
            commands.append(line.split()[1:])
    return commands


def _help_for(words: list[str]) -> str:
    result = runner.invoke(cli.app, [*words, "--help"])
    assert result.exit_code == 0, result.output
    return result.output


def test_guide_exists():
    assert GUIDE.is_file()


def test_every_documented_command_exists():
    commands = _skillsentry_commands(_guide())
    assert commands, "the guide has no skillsentry examples"
    for words in commands:
        if not words or words[0].startswith("-"):
            _help_for(words[:1] or [])  # top-level flags such as --version are checked separately
            continue
        head = [words[0]]
        if words[0] in SUBCOMMAND_GROUPS and len(words) > 1 and not words[1].startswith("-"):
            head.append(words[1])
        _help_for(head)


def test_every_documented_flag_exists_for_its_command():
    missing: list[str] = []
    for words in _skillsentry_commands(_guide()):
        if not words or words[0].startswith("-"):
            continue
        head = [words[0]]
        if words[0] in SUBCOMMAND_GROUPS and len(words) > 1 and not words[1].startswith("-"):
            head.append(words[1])
        help_text = _help_for(head)
        for token in words:
            if token.startswith("--"):
                flag = token.split("=", 1)[0]
                if flag not in help_text and flag != "--version":
                    missing.append(f"{' '.join(head)} {flag}")
    assert not missing, sorted(set(missing))


def test_version_flag_is_documented_and_works():
    result = runner.invoke(cli.app, ["--version"])
    assert result.exit_code == 0
    assert "--version" in _guide()


@pytest.mark.parametrize(
    "pattern, label",
    [
        (FORBIDDEN_MODEL_NAMES, "model name"),
        (DRIVE_PATH, "drive-letter path"),
        (FILE_URL, "file:/// URL"),
        (PASS_COUNT, "hand-typed pass count"),
    ],
)
def test_guide_follows_the_documentation_gates(pattern: re.Pattern[str], label: str):
    match = pattern.search(_guide())
    assert match is None, f"{label}: {match.group(0) if match else ''}"
