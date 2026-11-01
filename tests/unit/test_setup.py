"""``skill-sentry setup``: every prompt is a choice, and nothing is downloaded or built without a yes."""

from __future__ import annotations

from pathlib import Path

import pytest
from skill_sentry import cli
from skill_sentry.core.models.gemma_local import GemmaLocal, ProbeResult
from typer.testing import CliRunner

runner = CliRunner()


def _check(name: str, ok: bool, required: bool = True) -> cli.ReadinessCheck:
    return cli.ReadinessCheck(name, ok, required, f"{name} detail")


def _ready() -> list[cli.ReadinessCheck]:
    return [
        _check("model", True),
        _check("dashboard", True),
        _check("database", True),
        _check("docker", True, required=False),
        _check("sandbox image", True, required=False),
    ]


def _script(monkeypatch: pytest.MonkeyPatch, *results: list[cli.ReadinessCheck]) -> None:
    queue = list(results)

    def fake(cfg):
        return queue.pop(0) if len(queue) > 1 else queue[0]

    monkeypatch.setattr(cli, "readiness_checks", fake)


@pytest.fixture
def config_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "skillsentry.toml"
    path.write_text(
        '[model]\nbackend = "local"\nollama_url = "http://127.0.0.1:9"\n'
        'ollama_model = "example:latest"\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("SKILLSENTRY_CONFIG", str(path))
    return path


def test_ready_machine_needs_no_prompts(config_file, monkeypatch):
    _script(monkeypatch, _ready())
    result = runner.invoke(cli.app, ["setup"])
    assert result.exit_code == 0, result.output
    assert "ready for a full scan" in result.output


def test_declined_model_download_is_not_run(config_file, monkeypatch):
    missing = [_check("model", False), *_ready()[1:]]
    _script(monkeypatch, missing)
    monkeypatch.setattr(GemmaLocal, "probe", lambda self: ProbeResult.NO_MODEL)
    calls = []
    monkeypatch.setattr(cli.subprocess, "run", lambda *a, **k: calls.append(a))

    result = runner.invoke(cli.app, ["setup"], input="n\n")

    assert calls == []
    assert result.exit_code == 3
    assert "Setup is not complete yet" in result.output


def test_accepted_model_download_runs_ollama_pull(config_file, monkeypatch):
    missing = [_check("model", False), *_ready()[1:]]
    _script(monkeypatch, missing, _ready())
    monkeypatch.setattr(GemmaLocal, "probe", lambda self: ProbeResult.NO_MODEL)
    calls = []

    class Done:
        returncode = 0

    monkeypatch.setattr(cli.subprocess, "run", lambda args, **k: (calls.append(args), Done())[1])

    result = runner.invoke(cli.app, ["setup"], input="y\n")

    assert calls == [["ollama", "pull", "example:latest"]]
    assert result.exit_code == 0, result.output


def test_yes_flag_answers_the_model_prompt(config_file, monkeypatch):
    missing = [_check("model", False), *_ready()[1:]]
    _script(monkeypatch, missing, _ready())
    monkeypatch.setattr(GemmaLocal, "probe", lambda self: ProbeResult.NO_MODEL)
    calls = []

    class Done:
        returncode = 0

    monkeypatch.setattr(cli.subprocess, "run", lambda args, **k: (calls.append(args), Done())[1])
    result = runner.invoke(cli.app, ["setup", "--yes"])
    assert calls == [["ollama", "pull", "example:latest"]]
    assert result.exit_code == 0


def test_failed_pull_is_reported(config_file, monkeypatch):
    missing = [_check("model", False), *_ready()[1:]]
    _script(monkeypatch, missing, missing)
    monkeypatch.setattr(GemmaLocal, "probe", lambda self: ProbeResult.NO_MODEL)

    class Failed:
        returncode = 1

    monkeypatch.setattr(cli.subprocess, "run", lambda *a, **k: Failed())
    result = runner.invoke(cli.app, ["setup", "--yes"])
    assert "failed (exit 1)" in result.output
    assert result.exit_code == 3


def test_unreachable_model_server_says_how_to_start_it(config_file, monkeypatch):
    _script(monkeypatch, [_check("model", False), *_ready()[1:]])
    monkeypatch.setattr(GemmaLocal, "probe", lambda self: ProbeResult.UNREACHABLE)
    monkeypatch.setattr(cli.subprocess, "run", lambda *a, **k: pytest.fail("must not run"))
    result = runner.invoke(cli.app, ["setup", "--yes"])
    assert "not reachable" in result.output
    assert "ollama serve" in result.output


def test_docker_down_is_explained_not_installed(config_file, monkeypatch):
    down = [_check("model", True), _check("docker", False, required=False)]
    _script(monkeypatch, down)
    monkeypatch.setattr(GemmaLocal, "probe", lambda self: ProbeResult.READY)
    monkeypatch.setattr(cli, "build_sandbox_image", lambda cfg: pytest.fail("must not build"))
    result = runner.invoke(cli.app, ["setup", "--yes"])
    assert "docker ps" in result.output


def test_missing_sandbox_image_is_built_only_when_accepted(config_file, monkeypatch):
    no_image = [
        _check("model", True),
        _check("docker", True, False),
        _check("sandbox image", False, False),
    ]
    _script(monkeypatch, no_image)
    monkeypatch.setattr(GemmaLocal, "probe", lambda self: ProbeResult.READY)
    built = []
    monkeypatch.setattr(cli, "build_sandbox_image", lambda cfg: built.append(cfg))

    runner.invoke(cli.app, ["setup"], input="n\n")
    assert built == []

    runner.invoke(cli.app, ["setup"], input="y\n")
    assert len(built) == 1


def test_skip_flags_do_not_touch_model_or_sandbox(config_file, monkeypatch):
    _script(monkeypatch, _ready())
    monkeypatch.setattr(GemmaLocal, "probe", lambda self: pytest.fail("model must be skipped"))
    monkeypatch.setattr(cli, "build_sandbox_image", lambda cfg: pytest.fail("sandbox skipped"))
    result = runner.invoke(cli.app, ["setup", "--skip-model", "--skip-sandbox"])
    assert result.exit_code == 0, result.output


def test_default_config_is_written_only_with_consent(tmp_path, monkeypatch):
    monkeypatch.delenv("SKILLSENTRY_CONFIG", raising=False)
    monkeypatch.chdir(tmp_path)
    _script(monkeypatch, _ready())
    monkeypatch.setattr(GemmaLocal, "probe", lambda self: ProbeResult.READY)

    declined = runner.invoke(cli.app, ["setup"], input="n\n")
    assert not (tmp_path / "skillsentry.toml").exists()
    assert declined.exit_code == 0, declined.output

    runner.invoke(cli.app, ["setup"], input="y\n")
    assert (tmp_path / "skillsentry.toml").exists()


class _FakeImages:
    def __init__(self, fail: bool) -> None:
        self.fail = fail
        self.pulled: list[str] = []
        self.tagged: list[str] = []

    def pull(self, reference: str):
        import docker

        if self.fail:
            raise docker.errors.DockerException("registry unreachable")
        self.pulled.append(reference)
        outer = self

        class Image:
            def tag(self, name: str) -> None:
                outer.tagged.append(name)

        return Image()


class _FakeDocker:
    def __init__(self, images: _FakeImages) -> None:
        self.images = images

    def close(self) -> None:
        pass


def test_pinned_image_is_pulled_by_digest_and_tagged(config_file, monkeypatch):
    from skill_sentry import cli as cli_module

    images = _FakeImages(fail=False)
    monkeypatch.setattr(
        cli_module, "pinned_sandbox_digest", lambda: ("ghcr.io/x/sandbox", "sha256:abc")
    )
    import docker

    monkeypatch.setattr(docker, "from_env", lambda: _FakeDocker(images))
    cfg = cli_module._load_config_or_exit()

    assert cli_module.pull_pinned_sandbox(cfg) is True
    assert images.pulled == ["ghcr.io/x/sandbox@sha256:abc"]
    assert images.tagged == [cfg.sandbox.base_image]


def test_failed_pinned_pull_falls_back_to_a_local_build(config_file, monkeypatch):
    from skill_sentry import cli as cli_module

    monkeypatch.setattr(
        cli_module, "pinned_sandbox_digest", lambda: ("ghcr.io/x/sandbox", "sha256:abc")
    )
    import docker

    monkeypatch.setattr(docker, "from_env", lambda: _FakeDocker(_FakeImages(fail=True)))
    cfg = cli_module._load_config_or_exit()
    assert cli_module.pull_pinned_sandbox(cfg) is False


def test_source_checkout_has_no_pinned_digest():
    from skill_sentry import cli as cli_module

    assert cli_module.pinned_sandbox_digest() is None
