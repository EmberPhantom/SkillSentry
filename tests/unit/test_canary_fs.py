"""Canary tar construction and local test materialisation."""

from __future__ import annotations

import io
import tarfile
from dataclasses import replace
from uuid import UUID

import pytest
from skill_sentry.core.poisoned_well.canary_gen import generate_canary_set
from skill_sentry.core.sandbox.canary_fs import (
    build_canary_tar,
    canary_for_path,
    canary_paths,
    materialise_directory,
    validate_relative_path,
)

SCAN_ID = UUID("22222222-2222-4222-8222-222222222222")
MARKER = "SKS-0123abcd"


def _canaries():
    return generate_canary_set(
        SCAN_ID,
        "Slack workspace",
        marker=MARKER,
        secondary_marker="SKS-ffffffff",
    )


def test_tar_is_deterministic_and_contains_expected_metadata():
    canaries = _canaries()
    first = build_canary_tar(canaries)
    second = build_canary_tar(canaries)
    assert first == second

    with tarfile.open(fileobj=io.BytesIO(first), mode="r:") as archive:
        members = {member.name: member for member in archive.getmembers()}
        assert "./.config" in members
        assert "./.config/slack" in members
        assert "./.config/slack/token" in members
        assert members["./.config/slack/token"].mode == 0o600
        assert members["./.config/slack/token"].uid == 65534
        assert members["./.config/slack/token"].gid == 65534
        assert members["./.config/slack/token"].isfile()
        assert members["./.config"].isdir()
        assert all(member.issym() is False for member in members.values())
        payload = archive.extractfile("./.config/slack/token")
        assert payload is not None
        assert MARKER in payload.read().decode("utf-8")


def test_materialise_directory_writes_relative_files(tmp_path):
    canaries = _canaries()
    written = materialise_directory(tmp_path / "home", canaries)
    assert written
    assert (tmp_path / "home" / ".config" / "slack" / "token").is_file()
    assert MARKER in (tmp_path / "home" / ".config" / "slack" / "token").read_text(encoding="utf-8")
    assert (tmp_path / "home" / ".env").is_file()


def test_canary_paths_and_lookup():
    canaries = _canaries()
    paths = canary_paths(canaries)
    assert "/home/sandbox/.config/slack/token" in paths
    assert canary_for_path(canaries, "/home/sandbox/.config/slack/token") is not None
    assert canary_for_path(canaries, "~/.config/slack/token") is not None
    assert canary_for_path(canaries, "/home/sandbox/nope") is None


@pytest.mark.parametrize(
    "path",
    ["/absolute", "../escape", "a/../b", "", "a\\b"],
)
def test_unsafe_relative_paths_are_rejected(path):
    with pytest.raises(ValueError):
        validate_relative_path(path)


def test_tar_builder_rejects_a_tampered_canary_set():
    canaries = _canaries()
    malicious_file = replace(canaries.files[0], relative_path="../escape")
    tampered = replace(canaries, files=(malicious_file,))
    with pytest.raises(ValueError):
        build_canary_tar(tampered)
