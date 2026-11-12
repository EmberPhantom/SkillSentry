"""Deterministic, bounded, symlink-safe skill discovery."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from skill_sentry_cli.core.cache import SQLiteStore
from skill_sentry_cli.core.config import SkillsEntryConfig
from skill_sentry_cli.core.engine import MAX_DISCOVERED_SKILLS, ScanEngine, ScanError


def _manifest(root: Path, name: str | None = None) -> Path:
    skill = root / name if name is not None else root
    skill.mkdir(parents=True, exist_ok=True)
    (skill / "SKILL.md").write_text(
        f"---\nname: {skill.name}\ndescription: discovery test\n---\n",
        encoding="utf-8",
    )
    return skill


def _engine(tmp_path: Path) -> tuple[ScanEngine, SQLiteStore]:
    store = SQLiteStore(tmp_path / "discover.sqlite")
    engine = ScanEngine(SkillsEntryConfig(), store=store)
    return engine, store


def test_discovery_recurses_and_sorts(tmp_path: Path):
    _manifest(tmp_path / "corpus" / "zeta")
    _manifest(tmp_path / "corpus" / "alpha")
    _manifest(tmp_path / "corpus" / "nested" / "middle")
    _manifest(tmp_path / "corpus" / "nested" / "beta")
    engine, store = _engine(tmp_path)
    try:
        found = engine.discover(tmp_path / "corpus")
        assert [item.name for item in found] == ["alpha", "beta", "middle", "zeta"]
        assert found == sorted(found, key=lambda item: item.as_posix())
    finally:
        engine.close()
        store.close()


def test_root_skill_wins_over_nested_skills(tmp_path: Path):
    root = tmp_path / "root-skill"
    _manifest(root)
    _manifest(root / "nested", "nested-skill")
    engine, store = _engine(tmp_path)
    try:
        assert engine.discover(root) == [root]
    finally:
        engine.close()
        store.close()


def test_discovery_skips_ignored_and_symlinked_directories(tmp_path: Path):
    corpus = tmp_path / "corpus"
    _manifest(corpus / "real")
    _manifest(corpus / ".git" / "hidden")
    _manifest(corpus / "node_modules" / "hidden")
    outside = _manifest(tmp_path / "outside", "outside")
    link = corpus / "link"
    try:
        os.symlink(outside, link, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("this platform/user cannot create directory symlinks")
    engine, store = _engine(tmp_path)
    try:
        found = engine.discover(corpus)
        assert [item.name for item in found] == ["real"]
        assert link not in found
    finally:
        engine.close()
        store.close()


def test_discovery_rejects_a_symlinked_manifest(tmp_path: Path):
    corpus = tmp_path / "corpus"
    skill = corpus / "linked-manifest"
    skill.mkdir(parents=True)
    target = tmp_path / "outside-SKILL.md"
    target.write_text("---\nname: outside\ndescription: outside\n---\n", encoding="utf-8")
    try:
        os.symlink(target, skill / "SKILL.md")
    except (OSError, NotImplementedError):
        pytest.skip("this platform/user cannot create file symlinks")
    engine, store = _engine(tmp_path)
    try:
        with pytest.raises(ScanError) as excinfo:
            engine.discover(corpus)
        assert excinfo.value.code == "no_skill_manifest"
    finally:
        engine.close()
        store.close()


def test_discovery_bounds_hostile_corpora(tmp_path: Path):
    corpus = tmp_path / "many"
    for index in range(MAX_DISCOVERED_SKILLS + 1):
        _manifest(corpus / f"skill-{index:04d}")
    engine, store = _engine(tmp_path)
    try:
        with pytest.raises(ScanError) as excinfo:
            engine.discover(corpus)
        assert excinfo.value.code == "too_many_skills"
        assert str(MAX_DISCOVERED_SKILLS) in str(excinfo.value)
    finally:
        engine.close()
        store.close()


def test_discovery_rejects_missing_and_empty_roots(tmp_path: Path):
    empty = tmp_path / "empty"
    empty.mkdir()
    engine, store = _engine(tmp_path)
    try:
        with pytest.raises(ScanError) as missing:
            engine.discover(tmp_path / "does-not-exist")
        assert missing.value.code == "no_skill_manifest"
        with pytest.raises(ScanError) as no_manifest:
            engine.discover(empty)
        assert no_manifest.value.code == "no_skill_manifest"
        with pytest.raises(ScanError):
            engine.discover(empty / "file.txt")
    finally:
        engine.close()
        store.close()


def test_nested_skill_inside_node_modules_is_warned_about(tmp_path: Path, caplog):
    engine, store = _engine(tmp_path)
    try:
        _manifest(tmp_path / "repo" / "node_modules" / "dep")
        _manifest(tmp_path / "repo" / "real-skill")
        with caplog.at_level("WARNING"):
            found = engine.discover(tmp_path / "repo")
    finally:
        engine.close()
        store.close()

    assert [path.name for path in found] == ["real-skill"]
    assert any("node_modules" in record.getMessage() for record in caplog.records)


def test_discovery_walk_is_bounded(tmp_path: Path, monkeypatch):
    from skill_sentry_cli.core import engine as engine_module

    monkeypatch.setattr(engine_module, "MAX_DISCOVERY_DIRECTORIES", 5)
    engine, store = _engine(tmp_path)
    try:
        root = tmp_path / "wide"
        for index in range(10):
            (root / f"dir{index}").mkdir(parents=True)
        _manifest(root / "dir0")
        with pytest.raises(ScanError) as excinfo:
            engine.discover(root, recursive=True)
    finally:
        engine.close()
        store.close()

    assert excinfo.value.code == "too_many_directories"


def test_recursion_error_in_parsing_becomes_a_scan_error(tmp_path: Path, monkeypatch):
    from skill_sentry_cli.core import engine as engine_module

    def _too_deep(path):
        raise RecursionError("maximum recursion depth exceeded")

    monkeypatch.setattr(engine_module, "parse_skill", _too_deep)
    engine, store = _engine(tmp_path)
    try:
        skill = _manifest(tmp_path / "deep-skill")
        with pytest.raises(ScanError) as excinfo:
            engine.scan(skill)
    finally:
        engine.close()
        store.close()

    assert excinfo.value.code == "invalid_skill"
    assert "nested too deeply" in str(excinfo.value)


def test_skipped_directory_listing_is_capped_and_closed(tmp_path: Path, monkeypatch):
    from skill_sentry_cli.core import engine as engine_module

    deps = tmp_path / "repo" / "node_modules"
    for index in range(1000):
        (deps / f"pkg-{index:04d}").mkdir(parents=True)
    _manifest(deps / "vendored")

    real_scandir = os.scandir
    opened: list[object] = []

    class Tracking:
        def __init__(self, path):
            self._it = real_scandir(path)
            self.examined = 0
            self.closed = False
            opened.append(self)

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            self.close()
            return False

        def __iter__(self):
            for entry in self._it:
                self.examined += 1
                yield entry

        def close(self):
            self.closed = True
            self._it.close()

    monkeypatch.setattr(engine_module.os, "scandir", Tracking)
    engine_module._WARNED_SKIPPED_DIRS.discard(str(deps))
    engine_module._warn_if_skills_skipped(deps)

    assert len(opened) == 1
    assert opened[0].closed is True
    assert opened[0].examined <= engine_module._SKIPPED_DIR_ENTRY_CAP


def test_skipped_directory_warning_is_once_per_process(tmp_path: Path, caplog):
    from skill_sentry_cli.core import engine as engine_module

    deps = tmp_path / "repo" / "node_modules"
    _manifest(deps / "dep")
    engine_module._WARNED_SKIPPED_DIRS.discard(str(deps))
    with caplog.at_level("WARNING"):
        engine_module._warn_if_skills_skipped(deps)
        engine_module._warn_if_skills_skipped(deps)
    warnings = [r for r in caplog.records if "not scanning" in r.getMessage()]
    assert len(warnings) == 1
