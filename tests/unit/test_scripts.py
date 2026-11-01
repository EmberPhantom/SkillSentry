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
