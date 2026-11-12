"""Deterministic package hashing used by the verdict cache.

The algorithm is documented in ``docs/developer/database.md``: every regular file
is visited in sorted POSIX-relative-path order and contributes its path, Unix mode
bits and the SHA-256 of its bytes.  Directory entries are included as well so
adding or removing an empty directory invalidates the cache.

Nothing is excluded.  The parser reads every file under the package root, including
dependency, virtualenv, VCS and cache directories, so the cache key must cover all of
it.  A package cannot hide content from the key, and it cannot do so through its own
ignore file either.

Symlinks are rejected.  A skill must never be able to make the scanner hash (or
later read) a file outside the package root, and following links would also
make a package's identity depend on mutable host state.

The walk uses an explicit stack rather than recursion, so a deeply nested package
cannot exhaust the interpreter's recursion limit.
"""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path

MAX_FILES = 5_000
MAX_TOTAL_BYTES = 64 * 1024 * 1024
CHUNK_SIZE = 128 * 1024


class HashError(RuntimeError):
    """The package cannot be hashed safely or exceeds a hard limit."""


@dataclass(frozen=True)
class SkillHash:
    digest: str
    file_count: int
    total_bytes: int
    root: Path

    @property
    def short(self) -> str:
        return self.digest[:12]


def hash_bytes(data: bytes) -> str:
    """Return the lower-case SHA-256 hex digest of ``data``."""

    return hashlib.sha256(data).hexdigest()


def _mode(path: Path) -> int:
    """Return stable permission bits.

    Windows does not expose Unix execute bits meaningfully; masking the mode to
    ``0o777`` keeps hashes stable across checkouts while still changing when a
    POSIX file becomes executable.
    """

    try:
        return stat.S_IMODE(path.stat(follow_symlinks=False).st_mode)
    except OSError as exc:
        raise HashError(f"could not stat {path}: {exc}") from exc


def hash_skill_dir(path: str | Path) -> SkillHash:
    """Hash a skill directory without following symlinks.

    Symlinks are hashed as links (name and target), never followed.  Raises
    :class:`HashError` for a missing directory, unreadable files, or packages
    over the file/size caps.
    """

    root = Path(path).expanduser()
    try:
        root = root.resolve(strict=True)
    except OSError as exc:
        raise HashError(f"skill directory does not exist: {path}") from exc
    if not root.is_dir():
        raise HashError(f"not a directory: {root}")

    digest = hashlib.sha256()
    file_count = 0
    total_bytes = 0

    # Pending entries, popped from the end.  Each directory's children are pushed in
    # reverse name order when the directory is reached, so the visit order is the
    # same pre-order a recursive walk would produce: a directory's record, then its
    # whole subtree, then its next sibling.
    pending: list[tuple[os.DirEntry[str], str]] = []

    def push_children(directory: Path, prefix: str) -> None:
        try:
            entries = sorted(os.scandir(directory), key=lambda entry: entry.name)
        except OSError as exc:
            raise HashError(f"could not read {directory}: {exc}") from exc
        for entry in reversed(entries):
            rel = f"{prefix}/{entry.name}" if prefix else entry.name
            pending.append((entry, rel))

    push_children(root, "")
    while pending:
        entry, rel = pending.pop()
        entry_path = Path(entry.path)
        if entry.is_symlink():
            # Never followed.  The link and its target text are part of the
            # key, and the parser reports the link as a HIGH finding, so a
            # skill with a link is still scanned and reported.
            digest.update(b"link\0")
            digest.update(rel.encode("utf-8", "surrogateescape"))
            digest.update(b"\0")
            digest.update(os.readlink(entry_path).encode("utf-8", "surrogateescape"))
            digest.update(b"\n")
            continue
        try:
            if entry.is_dir(follow_symlinks=False):
                digest.update(b"dir\0")
                digest.update(rel.encode("utf-8", "surrogateescape"))
                digest.update(f"\0{_mode(entry_path):o}\n".encode())
                push_children(entry_path, rel)
                continue
            if not entry.is_file(follow_symlinks=False):
                raise HashError(f"unsupported file type in skill package: {rel}")
        except OSError as exc:
            raise HashError(f"could not inspect {rel}: {exc}") from exc

        file_count += 1
        if file_count > MAX_FILES:
            raise HashError(f"skill package exceeds {MAX_FILES} files")
        size = entry.stat(follow_symlinks=False).st_size
        total_bytes += size
        if total_bytes > MAX_TOTAL_BYTES:
            raise HashError(f"skill package exceeds {MAX_TOTAL_BYTES // (1024 * 1024)} MiB")

        digest.update(b"file\0")
        digest.update(rel.encode("utf-8", "surrogateescape"))
        digest.update(f"\0{_mode(entry_path):o}\0".encode())
        file_digest = hashlib.sha256()
        try:
            with open(entry_path, "rb") as handle:
                while chunk := handle.read(CHUNK_SIZE):
                    file_digest.update(chunk)
        except OSError as exc:
            raise HashError(f"could not read {rel}: {exc}") from exc
        digest.update(file_digest.digest())
        digest.update(b"\n")

    return SkillHash(
        digest=digest.hexdigest(),
        file_count=file_count,
        total_bytes=total_bytes,
        root=root,
    )


__all__ = [
    "MAX_FILES",
    "MAX_TOTAL_BYTES",
    "HashError",
    "SkillHash",
    "hash_bytes",
    "hash_skill_dir",
]
