"""The bundled audit.sh entrypoint and SKILL.md must default to --fail-on suspicious."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SKILL_DIR = ROOT / "skill_sentry_cli" / "skill"
AUDIT = SKILL_DIR / "scripts" / "audit.sh"
BASH = shutil.which("bash")

pytestmark = pytest.mark.skipif(
    BASH is None or os.name == "nt", reason="audit.sh needs bash on a POSIX system"
)


def _run_audit(tmp_path: Path, *args: str) -> list[str]:
    """Run audit.sh with a fake skill-sentry-cli that prints its argv, one per line."""

    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake = fake_bin / "skill-sentry-cli"
    fake.write_text('#!/usr/bin/env bash\nprintf "%s\\n" "$@"\n', encoding="utf-8")
    fake.chmod(0o755)
    skill = tmp_path / "skill"
    skill.mkdir()
    (skill / "SKILL.md").write_text("---\nname: x\n---\n", encoding="utf-8")
    env = {**os.environ, "PATH": f"{fake_bin}{os.pathsep}{os.environ.get('PATH', '')}"}
    result = subprocess.run(
        [BASH, str(AUDIT), str(skill), *args],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout.splitlines()


def test_audit_script_defaults_to_fail_on_suspicious(tmp_path: Path):
    argv = _run_audit(tmp_path)
    assert argv[0] == "scan"
    assert argv[argv.index("--fail-on") + 1] == "suspicious"
    assert "malicious" not in argv


def test_audit_script_passes_extra_flags_through_after_the_default(tmp_path: Path):
    argv = _run_audit(tmp_path, "--fail-on", "malicious", "--demo-mode")
    # Click/Typer keeps the last occurrence, so the caller's override wins.
    fail_on_values = [argv[i + 1] for i, item in enumerate(argv) if item == "--fail-on"]
    assert fail_on_values == ["suspicious", "malicious"]
    assert "--demo-mode" in argv


def test_skill_doc_matches_the_script_default():
    text = (SKILL_DIR / "SKILL.md").read_text(encoding="utf-8")
    assert "--fail-on suspicious" in text
    # The only remaining mention of malicious is the opt-in advice, not a command line.
    assert "--fail-on malicious\n" not in text
