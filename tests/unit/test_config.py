"""Configuration precedence and defaults."""

from __future__ import annotations

from pathlib import Path

import pytest
from skill_sentry_cli.core.config import (
    ConfigError,
    default_config,
    load_config,
    write_default_config,
)
from skill_sentry_cli.core.version import engine_version, weights_fingerprint


def test_defaults_match_docs():
    config = default_config()
    assert config.model.backend == "auto"
    assert config.model.ollama_model == "gemma4:e4b-it-qat"
    assert config.model.image_max_px == 768
    assert config.sandbox.enabled is True
    assert config.poisoned_well.enabled is True
    assert config.poisoned_well.correlation_window_s == 10.0
    assert config.scoring.weights == {
        "anchors": 0.15,
        "semantic": 0.20,
        "vision": 0.20,
        "sandbox": 0.25,
    }
    assert config.cache.db_path.endswith("skillsentry.db")


def test_partial_file_uses_defaults(tmp_path: Path):
    path = tmp_path / "skillsentry.toml"
    path.write_text('[model]\nbackend = "local"\n', encoding="utf-8")
    config = load_config(path)
    assert config.model.backend == "local"
    assert config.model.ollama_url == "http://localhost:11434"
    assert config.sandbox.timeout_s == 60


def test_environment_overrides_file(tmp_path: Path, monkeypatch):
    path = tmp_path / "skillsentry.toml"
    path.write_text('[model]\nbackend = "local"\n', encoding="utf-8")
    monkeypatch.setenv("SKILLSENTRY_BACKEND", "cloud")
    monkeypatch.setenv("SKILLSENTRY_NO_SANDBOX", "1")
    monkeypatch.setenv("SKILLSENTRY_DB", str(tmp_path / "custom.db"))
    config = load_config(path)
    assert config.model.backend == "cloud"
    assert config.sandbox.enabled is False
    assert config.db_path == (tmp_path / "custom.db").resolve()


def test_explicit_missing_file_raises(tmp_path: Path):
    with pytest.raises(ConfigError):
        load_config(tmp_path / "missing.toml")


def test_missing_default_file_is_not_an_error(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("SKILLSENTRY_CONFIG", raising=False)
    config = load_config()
    assert config.model.backend == "auto"


def test_invalid_toml_raises(tmp_path: Path):
    path = tmp_path / "skillsentry.toml"
    path.write_text("[model\nbackend =", encoding="utf-8")
    with pytest.raises(ConfigError, match="could not read"):
        load_config(path)


def test_write_default_config_roundtrip(tmp_path: Path):
    path = tmp_path / "nested" / "skillsentry.toml"
    written = write_default_config(path)
    assert written == path
    assert path.is_file()
    config = load_config(path)
    assert config.ci.fail_on == "malicious"
    with pytest.raises(ConfigError, match="already exists"):
        write_default_config(path)
    write_default_config(path, force=True)


def test_engine_version_tracks_weights():
    first = engine_version({"anchors": 0.15, "semantic": 0.20})
    same = engine_version({"semantic": 0.20, "anchors": 0.15})
    changed = engine_version({"anchors": 0.15, "semantic": 0.30})
    assert first == same
    assert first != changed
    assert weights_fingerprint() == weights_fingerprint()


def test_db_path_expands_home():
    config = default_config()
    config.cache.db_path = "~/custom/skillsentry.db"
    assert "~" not in str(config.db_path)
    assert str(config.db_path).endswith("skillsentry.db")
