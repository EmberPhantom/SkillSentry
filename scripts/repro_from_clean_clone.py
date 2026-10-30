#!/usr/bin/env python
"""Reproduce the reviewer's run: fresh clone, fresh venv, committed code only."""
import pathlib
import subprocess
import sys
import tempfile
import venv


def run(cmd, cwd=None):
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    print(" ".join(map(str, cmd)), "->", p.returncode)
    return p


def main(repo_url: str, branch: str, extras: str = "dev"):
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="ss-repro-"))
    run(["git", "clone", "--branch", branch, repo_url, str(tmp / "repo")])
    repo = tmp / "repo"
    venv.create(tmp / "venv", with_pip=True)
    py = tmp / "venv" / ("Scripts" if sys.platform == "win32" else "bin") / "python"
    run([str(py), "-m", "pip", "install", "-e", f".[{extras}]"], cwd=repo)
    p = run([str(py), "scripts/verify_all.py"], cwd=repo)
    print((repo / "docs" / "evidence").as_posix())
    return p.returncode


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1], sys.argv[2], *(sys.argv[3:4] or ["dev"])))
