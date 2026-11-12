"""Scan history is private to the user, and dead config keys are no longer written."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest
from skill_sentry_cli.core.cache.sqlite_store import SQLiteStore
from skill_sentry_cli.core.config import DEFAULT_CONFIG_TOML, load_config

posix_only = pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


@posix_only
def test_new_store_directory_is_0700_and_database_is_0600(tmp_path: Path):
    db = tmp_path / "home" / ".skillsentry" / "skillsentry.db"
    store = SQLiteStore(db)
    try:
        assert _mode(db.parent) == 0o700
        assert _mode(db) == 0o600
    finally:
        store.close()


@posix_only
def test_existing_world_readable_database_is_tightened(tmp_path: Path):
    db = tmp_path / "skillsentry.db"
    db.touch()
    os.chmod(db, 0o644)
    store = SQLiteStore(db)
    try:
        assert _mode(db) == 0o600
    finally:
        store.close()


@posix_only
def test_wal_sidecar_files_do_not_widen_access(tmp_path: Path):
    db = tmp_path / "private" / "skillsentry.db"
    store = SQLiteStore(db)
    try:
        store.cache_stats()
        for sidecar in db.parent.glob("skillsentry.db-*"):
            assert _mode(sidecar) & 0o077 == 0, sidecar
    finally:
        store.close()


def test_init_no_longer_writes_unread_sandbox_or_ci_keys():
    assert "max_parallel" not in DEFAULT_CONFIG_TOML
    assert "[ci]" not in DEFAULT_CONFIG_TOML


def test_legacy_config_with_unread_keys_still_loads(tmp_path: Path):
    path = tmp_path / "skillsentry.toml"
    path.write_text(
        "[sandbox]\nmax_parallel = 4\n\n[ci]\nfail_on = 'malicious'\nupload_sarif = true\n",
        encoding="utf-8",
    )
    config = load_config(path)
    assert config.sandbox.max_parallel == 4
    assert config.ci.upload_sarif is True
