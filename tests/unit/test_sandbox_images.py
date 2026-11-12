"""The sidecar base image is pinned by digest, in one place, and matches the sandbox Dockerfile."""

from __future__ import annotations

import re
from pathlib import Path

from skill_sentry_cli.core.sandbox.images import SIDECAR_BASE_IMAGE
from skill_sentry_cli.core.sandbox.runner import SandboxConfig
from skill_sentry_cli.core.sandbox.sidecar import SinkholeConfig

ROOT = Path(__file__).resolve().parents[2]
PKG = ROOT / "skill_sentry_cli"
DOCKERFILE = PKG / "core" / "sandbox" / "assets" / "Dockerfile.sandbox"


def test_sidecar_base_image_is_pinned_by_digest():
    repository, _, digest = SIDECAR_BASE_IMAGE.partition("@")
    assert repository == "python:3.11-slim"
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", digest)


def test_sidecar_digest_matches_the_sandbox_dockerfile_base():
    froms = re.findall(r"^FROM (\S+)", DOCKERFILE.read_text(encoding="utf-8"), re.MULTILINE)
    assert froms, "Dockerfile.sandbox has no FROM lines"
    assert all(ref == SIDECAR_BASE_IMAGE for ref in froms)


def test_runtime_defaults_read_the_shared_reference():
    assert SandboxConfig().sidecar_image == SIDECAR_BASE_IMAGE
    assert SinkholeConfig().image == SIDECAR_BASE_IMAGE


def test_no_unpinned_python_base_image_in_source():
    offenders = []
    for path in PKG.rglob("*.py"):
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if re.search(r"python:3\.\d+(-slim)?[\"'\s]", line) and "@sha256:" not in line:
                offenders.append(f"{path.relative_to(ROOT)}:{lineno}")
    assert offenders == []
