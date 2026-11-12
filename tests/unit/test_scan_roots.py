"""The API scans only inside ``[server] allowed_scan_roots`` when it is set.

The default (no roots) keeps the old behaviour. With roots, a path must resolve, with
symlinks followed, to a folder inside one of them. A refused path gets the same answer
whether or not it exists, so the API does not reveal the filesystem outside the roots.
"""

from __future__ import annotations

import os
import threading
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from skill_sentry_cli.core.cache import SQLiteStore
from skill_sentry_cli.core.config import ConfigError, SkillsEntryConfig, load_config
from skill_sentry_cli.core.engine import ScanEngine
from skill_sentry_cli.core.models.mock import MockGemma
from skill_sentry_cli.server import live_backend
from skill_sentry_cli.server.app import create_app
from skill_sentry_cli.server.live_backend import LiveBackend

BASE = "http://localhost"
ENV = "SKILLSENTRY_ALLOWED_SCAN_ROOTS"


def _skill(folder: Path) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "SKILL.md").write_text(
        f"---\nname: {folder.name}\ndescription: test skill\n---\nHi.\n", encoding="utf-8"
    )
    return folder


@pytest.fixture()
def layout(tmp_path: Path) -> dict[str, Path]:
    """A scan root with skills inside it, and a sibling tree outside it."""

    root = tmp_path / "skills"
    outside = tmp_path / "private"
    evil = tmp_path / "skills-evil"
    root.mkdir()
    outside.mkdir()
    evil.mkdir()
    return {
        "tmp": tmp_path,
        "root": root,
        "inside": _skill(root / "alpha"),
        "outside": _skill(outside / "secret"),
        "evil": _skill(evil / "beta"),
    }


@pytest.fixture()
def make_client(tmp_path, monkeypatch):
    """Build a live backend with the given allowed roots, scans held open by a gate.

    The semantic stage waits on the gate, so an accepted scan stays running until the
    test ends, and no scan runs to completion.
    """

    gate = threading.Event()
    original = ScanEngine._semantic_stage

    def held(self, *args, **kwargs):
        gate.wait(timeout=30)
        return original(self, *args, **kwargs)

    monkeypatch.setattr(ScanEngine, "_semantic_stage", held)
    monkeypatch.setattr(live_backend, "_CANCEL_GRACE_S", 0.05)
    stores: list[SQLiteStore] = []
    backends: list[LiveBackend] = []
    clients: list[TestClient] = []

    def build(roots: list[str]) -> TestClient:
        store = SQLiteStore(tmp_path / f"scan-roots-{len(stores)}.sqlite")
        stores.append(store)
        config = SkillsEntryConfig()
        config.server.allowed_scan_roots = roots
        engine = ScanEngine(store=store, model=MockGemma(profile="benign"))
        backend = LiveBackend(config=config, engine=engine)
        backends.append(backend)
        client = TestClient(create_app(backend), base_url=BASE)
        clients.append(client)
        client.__enter__()
        return client

    try:
        yield build
    finally:
        gate.set()
        for client in clients:
            client.__exit__(None, None, None)
        for client_backend in backends:
            client_backend.close()
        for store in stores:
            store.close()


def _post(client: TestClient, path: str | Path):
    return client.post("/scan", json={"path": str(path), "options": {"sandbox": False}})


def _refused(response) -> dict:
    assert response.status_code == 403, response.text
    error = response.json()["error"]
    assert error["code"] == "path_not_allowed"
    return error


# -- the default is unchanged ------------------------------------------------


def test_no_roots_configured_accepts_any_skill_folder(layout, make_client):
    client = make_client([])
    response = _post(client, layout["outside"])
    assert response.status_code == 202, response.text


# -- inside the roots ----------------------------------------------------------


def test_skill_inside_a_root_is_accepted(layout, make_client):
    client = make_client([str(layout["root"])])
    assert _post(client, layout["inside"]).status_code == 202


def test_the_root_itself_is_accepted_when_it_is_a_skill(layout, make_client):
    skill_root = _skill(layout["tmp"] / "single")
    client = make_client([str(skill_root)])
    assert _post(client, skill_root).status_code == 202


def test_a_symlinked_root_still_admits_paths_under_its_target(layout, make_client):
    link = layout["tmp"] / "link-to-skills"
    link.symlink_to(layout["root"], target_is_directory=True)
    client = make_client([str(link)])
    assert _post(client, layout["inside"]).status_code == 202
    # A second skill, reached through the link, so it is not the folder already scanning.
    _skill(layout["root"] / "gamma")
    assert _post(client, link / "gamma").status_code == 202


def test_a_symlink_inside_a_root_that_points_inside_it_is_accepted(layout, make_client):
    alias = layout["root"] / "alias"
    alias.symlink_to(layout["inside"], target_is_directory=True)
    client = make_client([str(layout["root"])])
    assert _post(client, alias).status_code == 202


# -- outside the roots -----------------------------------------------------------


def test_skill_outside_every_root_is_refused_and_not_recorded(layout, make_client):
    client = make_client([str(layout["root"])])
    _refused(_post(client, layout["outside"]))
    assert client.get("/scans").json()["scans"] == []


def test_dotdot_traversal_out_of_a_root_is_refused(layout, make_client):
    client = make_client([str(layout["root"])])
    traversal = layout["root"] / ".." / "private" / "secret"
    _refused(_post(client, traversal))


def test_symlink_escape_from_a_root_is_refused(layout, make_client):
    escape = layout["root"] / "escape"
    escape.symlink_to(layout["outside"], target_is_directory=True)
    client = make_client([str(layout["root"])])
    _refused(_post(client, escape))


def test_prefix_confusion_is_refused(layout, make_client):
    # /…/skills-evil starts with the characters of /…/skills but is a different folder.
    client = make_client([str(layout["root"])])
    _refused(_post(client, layout["evil"]))


def test_a_refused_existing_path_and_a_missing_one_get_the_same_answer(layout, make_client):
    client = make_client([str(layout["root"])])
    existing = _refused(_post(client, layout["outside"]))
    missing = _refused(_post(client, layout["tmp"] / "private" / "does-not-exist"))
    assert existing == missing
    # The message does not echo the path, so it does not confirm what is on disk.
    assert "secret" not in existing["message"]
    assert str(layout["tmp"]) not in existing["message"]


def test_nul_byte_in_the_path_is_refused_not_a_server_error(layout, make_client):
    client = make_client([str(layout["root"])])
    _refused(_post(client, f"{layout['root']}/alpha\x00"))


# -- configuration -------------------------------------------------------------


def test_env_variable_sets_the_roots_with_os_pathsep(layout, monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(ENV, f"{layout['root']}{os.pathsep}{layout['tmp'] / 'other'}")
    config = load_config()
    assert config.server.allowed_scan_roots == [
        str(layout["root"]),
        str(layout["tmp"] / "other"),
    ]


def test_env_variable_overrides_the_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    file = tmp_path / "skillsentry.toml"
    file.write_text('[server]\nallowed_scan_roots = ["/from/file"]\n', encoding="utf-8")
    monkeypatch.setenv(ENV, "/from/env")
    assert load_config(file).server.allowed_scan_roots == ["/from/env"]


def test_empty_env_variable_leaves_the_file_setting(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    file = tmp_path / "skillsentry.toml"
    file.write_text('[server]\nallowed_scan_roots = ["/from/file"]\n', encoding="utf-8")
    monkeypatch.setenv(ENV, "")
    assert load_config(file).server.allowed_scan_roots == ["/from/file"]


def test_env_roots_are_enforced_by_the_live_backend(layout, monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(ENV, str(layout["root"]))
    store = SQLiteStore(tmp_path / "env.sqlite")
    engine = ScanEngine(store=store, model=MockGemma(profile="benign"))
    backend = LiveBackend(engine=engine)
    try:
        with TestClient(create_app(backend), base_url=BASE) as client:
            _refused(_post(client, layout["outside"]))
    finally:
        backend.close()
        store.close()


@pytest.mark.parametrize("value", ["relative/path", "./skills", "~nobody-here-", " "])
def test_relative_or_blank_roots_are_refused_at_load(tmp_path, value):
    file = tmp_path / "skillsentry.toml"
    file.write_text(f"[server]\nallowed_scan_roots = [{value!r}]\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(file)


def test_unknown_server_key_is_still_rejected(tmp_path):
    file = tmp_path / "skillsentry.toml"
    file.write_text("[server]\nallowed_roots = []\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(file)


def test_resolution_failure_counts_as_outside(monkeypatch, layout):
    def boom(self, strict=False):
        raise RuntimeError("symlink loop")

    monkeypatch.setattr(live_backend.Path, "resolve", boom)
    assert live_backend._inside_scan_roots(layout["inside"], [str(layout["root"])]) is False
