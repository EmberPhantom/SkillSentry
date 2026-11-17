"""The credential-store anchor: a skill that reads a user credential store.

Every string here is inert: it names a well-known file or command but nothing in this
module runs or reads any of them.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from skill_sentry_cli.core.parser import parse_skill
from skill_sentry_cli.core.semantic import scan_anchors

SKILL_MD = "---\nname: demo\ndescription: Demo\n---\nBody\n"


def _scan(tmp_path: Path, script: str, name: str = "run.sh") -> list[tuple[str, int, str]]:
    root = tmp_path / "skill"
    (root / "scripts").mkdir(parents=True)
    (root / "SKILL.md").write_text(SKILL_MD, encoding="utf-8")
    (root / "scripts" / name).write_text(script, encoding="utf-8")
    stage = scan_anchors(parse_skill(root))
    return [
        (finding.evidence.file or "", finding.evidence.line or 0, finding.severity.value)
        for finding in stage.findings
        if finding.finding_type == "credential-store"
    ]


@pytest.mark.parametrize(
    "line",
    [
        "cp ~/.netrc /tmp/x",
        'cat "$HOME/.docker/config.json"',
        "cat ${HOME}/.kube/config",
        "cp /home/someone/.git-credentials /tmp/x",
        "cat /root/.pypirc",
        "cat ~/.npmrc",
        "ls ~/.config/gcloud/",
        "security find-generic-password -s demo -w",
        "x=$(security dump-keychain)",
        "sudo secret-tool lookup service demo",
        "cmdkey /list",
        'cp "$HOME/.config/google-chrome/Default/Login Data" /tmp/x',
        "cp ~/.mozilla/firefox/abc.default/logins.json /tmp/x",
    ],
)
def test_reading_a_credential_store_is_flagged_at_its_line(tmp_path: Path, line: str) -> None:
    hits = _scan(tmp_path, f"#!/bin/sh\nmkdir -p /tmp/work\n{line}\necho done\n")

    assert hits == [("scripts/run.sh", 3, "high")]


def test_python_script_is_covered_too(tmp_path: Path) -> None:
    hits = _scan(tmp_path, "import os\nopen(os.path.expanduser('~/.netrc')).read()\n", "run.py")

    assert hits == [("scripts/run.py", 2, "high")]


@pytest.mark.parametrize(
    "line",
    [
        "echo 'the netrc file is not used here'",  # the word, no home path
        "cat ./.npmrc",  # a project config, not the user's store
        "cat .docker/config.json",  # relative, not under the home folder
        "echo 'security find the best option'",  # prose; the command is not in command position
        "echo 'run security updates, then cmdkey is unrelated'",
        "cat /etc/hosts",
        "echo 'Login Data export is disabled'",  # no path separator before the name
        "cat ~/.gitconfig",  # a real user file, but not a credential store
    ],
)
def test_look_alikes_are_not_flagged(tmp_path: Path, line: str) -> None:
    assert _scan(tmp_path, f"#!/bin/sh\n{line}\n") == []


def test_benign_skill_with_ordinary_files_is_clean(tmp_path: Path) -> None:
    script = "#!/bin/sh\ngit status\ncat README.md\nls ~/projects\n"

    assert _scan(tmp_path, script) == []
