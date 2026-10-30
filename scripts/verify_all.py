#!/usr/bin/env python
"""Run every verification step and write docs/evidence/verify-<UTC date>.md. Adjust the
commands marked ADJUST to match this repo; do not change how results are recorded."""
from __future__ import annotations
import datetime as dt, pathlib, platform, re, shutil, subprocess, sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "evidence"
PY = sys.executable


def run(cmd, cwd=ROOT, timeout=3600):
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    return p.returncode, (p.stdout + p.stderr)


def summary(text):
    m = re.findall(r"(=+\s+)?(.*?(?:passed|failed|skipped|error).*?\s+in\s+[\d.]+s)", text)
    if m:
        return m[-1][1].strip()
    return text.strip().splitlines()[-1] if text.strip() else "no pytest summary found"


def docker_up():
    return bool(shutil.which("docker")) and run(["docker", "info"], timeout=30)[0] == 0


def laya_installed():
    return run([PY, "-c", "import laya"])[0] == 0


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d")
    rows, failed = [], False

    def record(name, cmd, cwd=ROOT, expect_zero=True, parse=False):
        nonlocal failed
        code, out = run(cmd, cwd)
        ok = (code == 0) if expect_zero else (code != 0)
        failed |= not ok
        rows.append((name, " ".join(map(str, cmd)).replace(PY, "python"), code, ok,
                     summary(out) if parse else out.strip().splitlines()[-1] if out.strip() else ""))
        return out

    head = run(["git", "rev-parse", "HEAD"])[1].strip()
    record("branch contains origin/main", ["git", "merge-base", "--is-ancestor", "origin/main", "HEAD"])
    record("working tree clean", ["git", "diff", "--quiet"])
    record("no mocks in runtime", [PY, "-m", "pytest", "tests/unit/test_no_mocks_in_runtime.py", "-q"], parse=True)
    record("docs hygiene", [PY, "-m", "pytest", "tests/unit/test_docs_hygiene.py", "-q"], parse=True)
    record("ROOT suite", [PY, "-m", "pytest", "tests", "-q", "-rs", "-p", "no:cacheprovider"], parse=True)
    # ADJUST: how the Developer 2 suite is run per developer-2/10-developer-operating-guide.md
    record("DEV2 suite", [PY, "-m", "pytest", "developer-2/tests", "-q", "-p", "no:cacheprovider"], parse=True)
    # ADJUST: expected-verdict gates
    record("root static verdict gate", [PY, "tests/check_expected_verdicts.py", "--static-only"])
    record("dev2 20-fixture gate", [PY, "developer-2/tests/check_expected_verdicts.py"])

    lines = [f"# Verification run ({stamp})", "",
             f"- Commit: `{head}`", f"- OS: {platform.platform()}", f"- Python: {platform.python_version()}",
             f"- Docker daemon up: {docker_up()}", f"- optional `laya` extra installed: {laya_installed()}",
             "- Suites are reported separately and are never summed.", "",
             "| Step | Command | Exit | OK | Result |", "|---|---|---|---|---|"]
    lines += [f"| {n} | `{c}` | {code} | {ok} | {res} |" for n, c, code, ok, res in rows]
    path = OUT / f"verify-{stamp}.md"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(path.relative_to(ROOT), "FAILED" if failed else "OK")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
