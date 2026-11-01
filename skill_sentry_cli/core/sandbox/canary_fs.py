"""Materialise canary files into a tar stream or a local test directory.

The production path never writes fake credentials to the host: the tar stream is
uploaded into the container with ``put_archive`` after its tmpfs HOME exists.
``materialise_directory`` exists for unit tests and local debugging only.
"""

from __future__ import annotations

import contextlib
import io
import tarfile
from pathlib import Path, PurePosixPath

from skill_sentry_cli.core.poisoned_well.canary_gen import CANARY_ROOT, CanaryFile, CanarySet

_NOBODY = 65534
_NOGROUP = 65534


def validate_relative_path(relative_path: str) -> str:
    path = PurePosixPath(relative_path)
    if path.is_absolute() or not path.parts:
        raise ValueError(f"canary path must be relative: {relative_path!r}")
    if any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError(f"unsafe canary path: {relative_path!r}")
    if "\\" in relative_path:
        raise ValueError(f"canary path must use forward slashes: {relative_path!r}")
    return path.as_posix()


def _tarinfo(name: str, *, mode: int, is_dir: bool) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name=name)
    info.type = tarfile.DIRTYPE if is_dir else tarfile.REGTYPE
    info.mode = mode
    info.uid = _NOBODY
    info.gid = _NOGROUP
    info.uname = "nobody"
    info.gname = "nogroup"
    info.mtime = 0
    return info


def build_canary_tar(canary_set: CanarySet) -> bytes:
    """Return a deterministic tar archive rooted at ``CANARY_ROOT``.

    Directory entries are created explicitly so extraction does not depend on
    the destination's umask.  Files are regular files only; no symlinks or
    device nodes are ever emitted.
    """

    buffer = io.BytesIO()
    directories: set[str] = set()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for canary in canary_set.files:
            rel = validate_relative_path(canary.relative_path)
            parent = PurePosixPath(rel).parent
            if parent != PurePosixPath("."):
                parts = parent.parts
                for index in range(1, len(parts) + 1):
                    directory = PurePosixPath(*parts[:index]).as_posix()
                    if directory in directories:
                        continue
                    directories.add(directory)
                    info = _tarinfo(f"./{directory}", mode=0o700, is_dir=True)
                    archive.addfile(info)

            payload = canary.content.encode("utf-8")
            info = _tarinfo(f"./{rel}", mode=canary.mode, is_dir=False)
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))

    return buffer.getvalue()


def materialise_directory(root: str | Path, canary_set: CanarySet) -> list[Path]:
    """Write canary files under *root* (tests/local debugging only).

    The caller must pass an explicit scratch directory; this function never
    touches a user's real home directory.
    """

    base = Path(root)
    base.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for canary in canary_set.files:
        rel = validate_relative_path(canary.relative_path)
        target = base / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(canary.content, encoding="utf-8")
        # Windows test hosts may not implement POSIX modes; content and layout
        # are still verified.  The container path uses tar metadata.
        with contextlib.suppress(OSError):
            target.chmod(canary.mode)
        written.append(target)
    return written


def canary_paths(canary_set: CanarySet) -> list[str]:
    """Container-absolute paths for monitor event mapping."""

    return [
        f"{CANARY_ROOT}/{validate_relative_path(item.relative_path)}" for item in canary_set.files
    ]


def canary_for_path(canary_set: CanarySet, path: str) -> CanaryFile | None:
    return canary_set.file_for(path)
