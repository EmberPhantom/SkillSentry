"""AST anchors: aliased calls are resolved; unparseable Python degrades the stage."""

from __future__ import annotations

from pathlib import Path

from skill_sentry_cli.core.parser import parse_skill
from skill_sentry_cli.core.semantic import scan_anchors
from skill_sentry_cli.core.semantic.ast_python import scan_python_ast


def _types(source: str) -> list[str]:
    findings, error = scan_python_ast("scripts/t.py", source)
    assert error is None, error
    return [item.finding_type for item in findings]


def test_aliased_subprocess_with_shell_true_is_detected() -> None:
    source = "from subprocess import run as r\nr('ls', shell=True)\n"

    assert "shell-exec" in _types(source)


def test_module_alias_for_pickle_is_detected() -> None:
    source = "import pickle as p\np.loads(data)\n"

    assert "unsafe-deserialization" in _types(source)


def test_os_system_is_detected() -> None:
    assert "shell-exec" in _types("import os\nos.system('id')\n")


def test_eval_and_exec_are_detected() -> None:
    assert "dynamic-code" in _types("eval(payload)\n")
    assert "dynamic-code" in _types("exec(payload)\n")


def test_yaml_load_without_safe_loader_is_detected_but_safe_loader_is_not() -> None:
    assert "unsafe-deserialization" in _types("import yaml\nyaml.load(text)\n")
    assert "unsafe-deserialization" not in _types(
        "import yaml\nyaml.load(text, Loader=yaml.SafeLoader)\n"
    )


def test_subprocess_without_shell_is_not_flagged() -> None:
    assert "shell-exec" not in _types("import subprocess\nsubprocess.run(['ls'])\n")


def test_urlopen_without_data_is_not_flagged_as_exfiltration() -> None:
    assert "exfil-http-post" not in _types(
        "import urllib.request\nurllib.request.urlopen('https://x')\n"
    )


def test_unparseable_file_returns_an_error_not_silence() -> None:
    findings, error = scan_python_ast("scripts/bad.py", "def broken(:\n")

    assert findings == []
    assert error is not None and "could not parse" in error


def test_scan_anchors_degrades_on_unparseable_python(tmp_path: Path) -> None:
    root = tmp_path / "skill"
    (root / "scripts").mkdir(parents=True)
    (root / "SKILL.md").write_text(
        "---\nname: demo\ndescription: Demo\n---\nBody\n", encoding="utf-8"
    )
    (root / "scripts" / "bad.py").write_text("def broken(:\n", encoding="utf-8")

    stage = scan_anchors(parse_skill(root))

    assert stage.degraded is True
    assert stage.error is not None and "bad.py" in stage.error


def test_ast_and_regex_findings_are_not_duplicated(tmp_path: Path) -> None:
    root = tmp_path / "skill"
    (root / "scripts").mkdir(parents=True)
    (root / "SKILL.md").write_text(
        "---\nname: demo\ndescription: Demo\n---\nBody\n", encoding="utf-8"
    )
    (root / "scripts" / "run.py").write_text("import os\nos.system('id')\n", encoding="utf-8")

    stage = scan_anchors(parse_skill(root))

    shell_lines = [
        item.evidence.line
        for item in stage.findings
        if item.finding_type == "shell-exec" and item.evidence.file == "scripts/run.py"
    ]
    assert len(shell_lines) == len(set(shell_lines))
