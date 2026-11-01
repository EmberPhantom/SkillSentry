"""`skill-sentry doctor`: required checks fail the command; optional ones only warn."""

from __future__ import annotations

from pathlib import Path

import pytest
from skill_sentry import cli
from skill_sentry.core.cache import SQLiteStore
from skill_sentry.core.models import gemma_local
from typer.testing import CliRunner

runner = CliRunner()


@pytest.fixture
def temp_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> SQLiteStore:
    store = SQLiteStore(tmp_path / "doctor.sqlite")
    monkeypatch.setattr(cli, "_store", lambda: store)
    return store


def test_missing_model_fails_the_command(
    temp_store: SQLiteStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(gemma_local.GemmaLocal, "preflight", lambda self: False)

    result = runner.invoke(cli.app, ["doctor"])

    assert result.exit_code == 3
    assert "FAIL  model" in result.output
    assert "ollama pull" in result.output


def test_unreachable_docker_is_a_warning_not_a_failure(
    temp_store: SQLiteStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(gemma_local.GemmaLocal, "preflight", lambda self: True)
    import docker

    def _no_engine() -> None:
        raise docker.errors.DockerException("no engine")

    monkeypatch.setattr(docker, "from_env", _no_engine)

    result = runner.invoke(cli.app, ["doctor"])

    assert "WARN  docker" in result.output
    assert "FAIL  docker" not in result.output
    assert "--no-sandbox" in result.output
