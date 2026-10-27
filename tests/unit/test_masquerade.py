"""Masquerade configuration, shim assets, and fail-closed verification."""

from __future__ import annotations

import base64
from dataclasses import dataclass

import pytest
from skillsentry.core.sandbox.masquerade import (
    DOCKERENV_PATH,
    FAKE_CGROUP_CONTENT,
    FAKE_MOUNTINFO_CONTENT,
    MasqueradeConfig,
    MasqueradeError,
    MasqueradeUnavailable,
    compile_shim,
    parse_verification_output,
    require_masquerade,
    run_script_text,
    source_text,
    verification_script,
    verify_container,
    verify_outputs,
)


def _output(*, dockerenv: str, cgroup: str, mountinfo: str, shim: str) -> str:
    return "\n".join(
        [
            f"SKILLSENTRY_DOCKERENV={dockerenv}",
            f"SKILLSENTRY_SHIM={shim}",
            f"SKILLSENTRY_CGROUP={base64.b64encode(cgroup.encode()).decode()}",
            f"SKILLSENTRY_MOUNTINFO={base64.b64encode(mountinfo.encode()).decode()}",
        ]
    )


def test_config_hides_dockerenv_and_provides_shim_environment():
    config = MasqueradeConfig()
    assert config.environment() == {"LD_PRELOAD": "/opt/skillsentry/masquerade.so"}
    assert config.volumes()["/dev/null"] == {"bind": DOCKERENV_PATH, "mode": "ro"}
    assert config.tmpfs() == {}
    # Newer Docker rejects bind mounts into /proc.  The shim redirects reads of
    # /proc/{1,self}/{cgroup,mountinfo} to the per-scan fake files instead.
    assert all(spec.get("bind") != "/proc/1/cgroup" for spec in config.volumes().values())


def test_good_verification_output_is_ok():
    check = parse_verification_output(
        _output(
            dockerenv="absent",
            cgroup=FAKE_CGROUP_CONTENT,
            mountinfo=FAKE_MOUNTINFO_CONTENT,
            shim="present",
        )
    )
    assert check.ok is True
    assert check.dockerenv_hidden is True
    assert check.cgroup_fake is True
    assert check.mountinfo_clean is True
    assert check.shim_present is True
    assert check.errors == ()
    assert check.to_dict()["ok"] is True


def test_bad_verification_output_is_fail_closed():
    check = parse_verification_output(
        _output(
            dockerenv="present",
            cgroup="0::/docker/abc\n",
            mountinfo="overlay / overlay rw 0 0\n",
            shim="missing",
        )
    )
    assert check.ok is False
    assert check.dockerenv_hidden is False
    assert check.cgroup_fake is False
    assert check.mountinfo_clean is False
    assert len(check.errors) == 4
    with pytest.raises(MasqueradeError):
        require_masquerade(check)


def test_missing_verification_output_fails_closed():
    check = parse_verification_output("")
    assert check.ok is False
    assert check.dockerenv_hidden is False
    assert check.shim_present is False
    with pytest.raises(MasqueradeError):
        require_masquerade(check)


def test_shim_can_be_optional_for_development():
    check = verify_outputs(
        dockerenv_exists=False,
        cgroup="0::/",
        mountinfo=FAKE_MOUNTINFO_CONTENT,
        shim_present=False,
        require_shim=False,
    )
    assert check.ok is True
    assert check.shim_present is False


def test_verification_script_contains_all_probes():
    script = verification_script()
    assert "SKILLSENTRY_DOCKERENV" in script
    assert "/.dockerenv" in script
    assert "/proc/1/cgroup" in script
    assert "/proc/self/mountinfo" in script
    assert "/opt/skillsentry/masquerade.so" in script


def test_source_and_runner_assets_are_present():
    source = source_text()
    assert "canary_read" in source
    assert "probe_detected" in source
    assert "getenv" in source
    assert "openat" in source
    runner = run_script_text()
    assert "scripts/run.sh" in runner
    assert "main.py" in runner


def test_compile_shim_reports_missing_compiler(tmp_path):
    with pytest.raises(MasqueradeUnavailable):
        compile_shim(
            source=tmp_path / "missing.c",
            output=tmp_path / "missing.so",
            compiler=str(tmp_path / "no-such-compiler"),
        )


@dataclass
class _ExecResult:
    exit_code: int
    output: bytes


class _Container:
    def __init__(self, result: _ExecResult) -> None:
        self.result = result
        self.calls: list[dict] = []

    def exec_run(self, cmd, **kwargs):
        self.calls.append({"cmd": cmd, **kwargs})
        return self.result


def test_verify_container_passes_ld_preload_and_user():
    container = _Container(
        _ExecResult(
            exit_code=0,
            output=_output(
                dockerenv="absent",
                cgroup=FAKE_CGROUP_CONTENT,
                mountinfo=FAKE_MOUNTINFO_CONTENT,
                shim="present",
            ).encode(),
        )
    )
    check = verify_container(container)
    assert check.ok is True
    assert container.calls[0]["user"] == "65534:65534"
    assert container.calls[0]["environment"] == {"LD_PRELOAD": "/opt/skillsentry/masquerade.so"}
    assert container.calls[0]["cmd"][0] == "/bin/sh"


def test_verify_container_nonzero_exit_is_an_error():
    container = _Container(_ExecResult(exit_code=2, output=b"boom"))
    check = verify_container(container)
    assert check.ok is False
    assert "exited 2" in check.errors[0]
