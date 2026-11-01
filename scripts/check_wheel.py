"""Fail the build if a wheel is missing anything the installed command needs.

    python scripts/check_wheel.py dist/skill_sentry-2.0.0-py3-none-any.whl

The checks are deliberately about what runs after install: the dashboard the
server serves, the sandbox sources the image is built from, the credential rules
and the packaged known-name list, and the bundled skill.  Metadata is checked
too, so the distribution name and the command name cannot drift apart.
"""

from __future__ import annotations

import sys
import zipfile

REQUIRED_PREFIXES = (
    "skill_sentry/ui/dist/index.html",
    "skill_sentry/core/sandbox/assets/Dockerfile.sandbox",
    "skill_sentry/core/sandbox/assets/masquerade.c",
    "skill_sentry/core/sandbox/assets/run_skill.sh",
    "skill_sentry/rules/credential_rules.toml",
    "skill_sentry/data/known_skills_v1.json",
    "skill_sentry/skill/SKILL.md",
    "skill_sentry/cli.py",
)


def check(path: str) -> list[str]:
    with zipfile.ZipFile(path) as wheel:
        names = set(wheel.namelist())
        problems = [
            f"missing {required}" for required in REQUIRED_PREFIXES if required not in names
        ]
        metadata = [n for n in names if n.endswith(".dist-info/METADATA")]
        if len(metadata) != 1:
            return [*problems, "expected exactly one METADATA file"]
        text = wheel.read(metadata[0]).decode("utf-8")
        if "\nName: skill-sentry\n" not in text:
            problems.append("distribution name is not skill-sentry")
        entry = [n for n in names if n.endswith("entry_points.txt")]
        scripts = wheel.read(entry[0]).decode("utf-8") if entry else ""
        if "skill-sentry = skill_sentry.cli:app" not in scripts:
            problems.append("console script skill-sentry is not declared")
        top = {n.split("/")[0] for n in names}
        stray = sorted(t for t in top if t != "skill_sentry" and not t.endswith(".dist-info"))
        if stray:
            problems.append(f"unexpected top-level entries: {stray}")
    return problems


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    problems = check(argv[1])
    for problem in problems:
        print(f"wheel check: {problem}", file=sys.stderr)
    if problems:
        return 1
    print(f"wheel check OK: {argv[1]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
