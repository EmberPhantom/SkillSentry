"""Deterministic package hashing used by the verdict cache.

The algorithm is documented in ``docs/03-database.md``: every regular file is
visited in sorted POSIX-relative-path order and contributes its path, Unix mode
bits and the SHA-256 of its bytes.  Directory entries are included as well so
adding or removing an empty directory invalidates the cache.

Symlinks are rejected.  A skill must never be able to make the scanner hash (or
later read) a file outside the package root, and following links would also
make a package's identity depend on mutable host state.
"""

from __future__ import annotations

import fnmatch
import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path

DEFAULT_IGNORE_PATTERNS: tuple[str, ...] = (
    ".git",
    ".git/*",
    ".hg",
    ".svn",
    "__pycache__",
    "__pycache__/*",
    "*.pyc",
    ".pytest_cache",
    ".pytest_cache/*",
    ".ruff_cache",
    ".ruff_cache/*",
    ".mypy_cache",
    ".mypy_cache/*",
    ".venv",
    ".venv/*",
    "venv",
    "venv/*",
    "node_modules",
    "node_modules/*",
    ".DS_Store",
    "Thumbs.db",
)

MAX_FILES = 5_000
MAX_TOTAL_BYTES = 64 * 1024 * 1024
CHUNK_SIZE = 128 * 1024
IGNORE_FILE = ".skillsentryignore"


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


def _load_ignore_patterns(root: Path) -> tuple[str, ...]:
    patterns = list(DEFAULT_IGNORE_PATTERNS)
    ignore_file = root / IGNORE_FILE
    if ignore_file.is_file() and not ignore_file.is_symlink():
        try:
            text = ignore_file.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:  # pragma: no cover - unusual filesystem error
            raise HashError(f"could not read {IGNORE_FILE}: {exc}") from exc
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            patterns.append(line)
    return tuple(patterns)


def _ignored(rel: str, patterns: tuple[str, ...]) -> bool:
    # A pattern matching any parent directory excludes the whole subtree.
    parts = rel.split("/")
    candidates = ["/".join(parts[: i + 1]) for i in range(len(parts))]
    return any(
        fnmatch.fnmatchcase(candidate, pattern)
        for pattern in patterns
        for candidate in candidates
    )


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

    Raises :class:`HashError` for a missing directory, a symlink anywhere in
    the package, unreadable files, or packages over the file/size caps.
    """

    root = Path(path).expanduser()
    try:
        root = root.resolve(strict=True)
    except OSError as exc:
        raise HashError(f"skill directory does not exist: {path}") from exc
    if not root.is_dir():
        raise HashError(f"not a directory: {root}")

    patterns = _load_ignore_patterns(root)
    digest = hashlib.sha256()
    file_count = 0
    total_bytes = 0

    def walk(directory: Path, prefix: str) -> None:
        nonlocal file_count, total_bytes
        try:
            entries = sorted(os.scandir(directory), key=lambda entry: entry.name)
        except OSError as exc:
            raise HashError(f"could not read {directory}: {exc}") from exc

        for entry in entries:
            rel = f"{prefix}/{entry.name}" if prefix else entry.name
            if _ignored(rel, patterns):
                continue
            entry_path = Path(entry.path)
            if entry.is_symlink():
                raise HashError(f"symlink not allowed in skill package: {rel}")
            try:
                if entry.is_dir(follow_symlinks=False):
                    digest.update(b"dir\0")
                    digest.update(rel.encode("utf-8", "surrogateescape"))
                    digest.update(f"\0{_mode(entry_path):o}\n".encode())
                    walk(entry_path, rel)
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
                raise HashError(
                    f"skill package exceeds {MAX_TOTAL_BYTES // (1024 * 1024)} MiB"
                )

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

    walk(root, "")
    return SkillHash(
        digest=digest.hexdigest(),
        file_count=file_count,
        total_bytes=total_bytes,
        root=root,
    )


__all__ = [
    "DEFAULT_IGNORE_PATTERNS",
    "HashError",
    "MAX_FILES",
    "MAX_TOTAL_BYTES",
    "SkillHash",
    "hash_bytes",
    "hash_skill_dir",
]
