"""Binding the API beyond loopback prints a warning, except inside the official container."""

from __future__ import annotations

import pytest
from skill_sentry_cli import cli
from typer.testing import CliRunner

runner = CliRunner()


@pytest.fixture
def no_server(monkeypatch):
    # Record the bind instead of starting uvicorn.
    calls = []
    monkeypatch.setattr("uvicorn.run", lambda *args, **kwargs: calls.append(kwargs))
    return calls


def test_non_loopback_host_warns(no_server, monkeypatch):
    monkeypatch.delenv("SKILLSENTRY_CONTAINER", raising=False)
    result = runner.invoke(cli.app, ["serve", "--host", "0.0.0.0", "--demo-mode"])
    assert result.exit_code == 0
    assert "warning: binding to 0.0.0.0 exposes the API" in result.output
    assert no_server and no_server[0]["host"] == "0.0.0.0"


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "::1"])
def test_loopback_host_is_silent(no_server, monkeypatch, host):
    monkeypatch.delenv("SKILLSENTRY_CONTAINER", raising=False)
    result = runner.invoke(cli.app, ["serve", "--host", host, "--demo-mode"])
    assert result.exit_code == 0
    assert "warning" not in result.output


def test_official_container_does_not_warn(no_server, monkeypatch):
    monkeypatch.setenv("SKILLSENTRY_CONTAINER", "1")
    result = runner.invoke(cli.app, ["serve", "--host", "0.0.0.0", "--demo-mode"])
    assert result.exit_code == 0
    assert "warning" not in result.output
