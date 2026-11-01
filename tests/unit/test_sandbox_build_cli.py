"""`skill-sentry sandbox build`: builds from packaged sources and fails with exit 3."""

from __future__ import annotations

import docker
import pytest
from skill_sentry import cli
from typer.testing import CliRunner

runner = CliRunner()


class _FakeImages:
    def __init__(self, fail: bool) -> None:
        self.fail = fail
        self.calls: list[dict[str, object]] = []

    def build(self, **kwargs: object) -> tuple[object, list[object]]:
        self.calls.append(kwargs)
        if self.fail:
            raise docker.errors.DockerException("engine not running")
        return object(), []


class _FakeClient:
    def __init__(self, images: _FakeImages) -> None:
        self.images = images


def test_build_uses_packaged_dockerfile_and_configured_tag(monkeypatch: pytest.MonkeyPatch) -> None:
    images = _FakeImages(fail=False)
    monkeypatch.setattr(docker, "from_env", lambda: _FakeClient(images))

    result = runner.invoke(cli.app, ["sandbox", "build"])

    assert result.exit_code == 0, result.output
    assert len(images.calls) == 1
    call = images.calls[0]
    assert call["dockerfile"] == "Dockerfile.sandbox"
    assert str(call["path"]).replace("\\", "/").endswith("core/sandbox/assets")
    assert call["tag"]


def test_docker_failure_is_reported_as_operational_error(monkeypatch: pytest.MonkeyPatch) -> None:
    images = _FakeImages(fail=True)
    monkeypatch.setattr(docker, "from_env", lambda: _FakeClient(images))

    result = runner.invoke(cli.app, ["sandbox", "build"])

    assert result.exit_code == 3
    assert "could not build the sandbox image" in result.output
