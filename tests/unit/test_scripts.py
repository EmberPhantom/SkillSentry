"""Shell scripts parse, and every one finds the project venv on Linux as well as Windows."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = sorted((ROOT / "scripts").glob("*.sh"))
BASH = shutil.which("bash")


@pytest.mark.parametrize("script", SCRIPTS, ids=lambda p: p.name)
def test_script_has_a_linux_venv_fallback(script: Path):
    text = script.read_text(encoding="utf-8")
    if "PY=" not in text:
        pytest.skip(f"{script.name} does not select an interpreter")
    assert '[ -x "$PY" ] || PY=".venv/bin/python"' in text, script.name


@pytest.mark.skipif(BASH is None, reason="bash is not available")
@pytest.mark.parametrize("script", SCRIPTS, ids=lambda p: p.name)
def test_script_parses(script: Path):
    result = subprocess.run([BASH, "-n", str(script)], capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr


def _tracked_modes(*folders: str) -> dict[str, str]:
    """Map each tracked file under the folders to the mode recorded in the git index."""
    git = shutil.which("git")
    if git is None or not (ROOT / ".git").exists():
        pytest.skip("not inside a git checkout")
    result = subprocess.run(
        [git, "ls-files", "-s", "--", *folders],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        pytest.skip("git could not read the index")
    modes: dict[str, str] = {}
    for line in result.stdout.splitlines():
        meta, _, path = line.partition("\t")
        modes[path] = meta.split()[0]
    return modes


def test_scripts_with_a_shebang_are_executable_in_git():
    # The index records the mode on every platform, so this does not depend on core.fileMode.
    modes = _tracked_modes("scripts", "skill_sentry_cli/skill/scripts")
    wrong = []
    for path, mode in modes.items():
        with (ROOT / path).open("rb") as handle:
            if handle.read(2) == b"#!" and mode != "100755":
                wrong.append(f"{path} is {mode}")
    assert not wrong, (
        "scripts with a shebang must be mode 100755 (git update-index --chmod=+x): "
        + ", ".join(wrong)
    )
