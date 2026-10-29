"""
Deterministic Directory Hashing (Stage 0 support).

Computes a canonical SHA-256 hash of a skill package directory for use
as the cache key. The hash is deterministic across platforms.

CL-D2-4 · REQ-CACHE-01 · Source: docs/03-database.md §3.2.
"""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path, PurePosixPath

# Directories and files to exclude from hashing
HASH_EXCLUDED_DIRS: frozenset[str] = frozenset({
    ".git", "__pycache__", ".mypy_cache", ".pytest_cache", "node_modules", ".venv", "venv",
})
HASH_EXCLUDED_FILES: frozenset[str] = frozenset({".DS_Store"})
HASH_EXCLUDED_EXTENSIONS: frozenset[str] = frozenset({".pyc", ".pyo"})


def _should_exclude(
    rel_path: str,
    name: str,
    is_dir: bool,
) -> bool:
    """Check if a path should be excluded from hashing.
    
    Security: Untrusted packages must never control hash exclusions (DEF-02).
    Only fixed system directories and files are excluded.
    """
    if is_dir and name in HASH_EXCLUDED_DIRS:
        return True
    if not is_dir:
        if name in HASH_EXCLUDED_FILES:
            return True
        ext = os.path.splitext(name)[1].lower()
        if ext in HASH_EXCLUDED_EXTENSIONS:
            return True

    return False


def compute_directory_hash(skill_dir: str | Path) -> str:
    """Compute a deterministic SHA-256 hash of a skill directory.

    Algorithm per docs/03-database.md §3.2:
    1. Walk recursively, filtering excluded paths.
    2. Sort by relative POSIX path in lexicographic byte order.
    3. For each file: path\\0mode\\0sha256(content)\\n
    4. Final digest: sha256(concatenation) → 64-char lowercase hex.

    Args:
        skill_dir: Path to the skill package directory.

    Returns:
        64-character lowercase hex SHA-256 digest.

    Raises:
        FileNotFoundError: If skill_dir does not exist.
        NotADirectoryError: If skill_dir is not a directory.
    """
    root = Path(skill_dir).resolve()

    if not root.exists():
        raise FileNotFoundError(f"Directory does not exist: {root}")
    if not root.is_dir():
        raise NotADirectoryError(f"Not a directory: {root}")

    # Collect all file entries
    entries: list[tuple[str, str, str]] = []  # (posix_path, octal_mode, content_hash)

    for dirpath_str, dirnames, filenames in os.walk(root, followlinks=False):
        dirpath = Path(dirpath_str)

        # Get relative path for exclusion check
        try:
            rel_dir = str(PurePosixPath(dirpath.relative_to(root)))
        except ValueError:
            continue

        # Filter excluded directories in-place
        dirnames[:] = sorted([
            d for d in dirnames
            if not _should_exclude(
                str(PurePosixPath(rel_dir) / d) if rel_dir != "." else d,
                d, True,
            )
        ])

        for fname in sorted(filenames):
            file_path = dirpath / fname

            # Compute relative POSIX path
            try:
                rel_posix = str(PurePosixPath(file_path.relative_to(root)))
            except ValueError:
                continue

            if _should_exclude(rel_posix, fname, False):
                continue

            # Skip symlinks that escape root
            if file_path.is_symlink():
                try:
                    resolved = file_path.resolve()
                    if os.path.commonpath([str(root), str(resolved)]) != str(root):
                        continue
                except (ValueError, OSError):
                    continue

            # Get file mode bits (octal)
            try:
                file_stat = file_path.stat()
                mode_octal = oct(stat.S_IMODE(file_stat.st_mode))
            except OSError:
                continue

            # Compute content SHA-256
            try:
                content_hash = hashlib.sha256(file_path.read_bytes()).hexdigest()
            except OSError:
                continue

            entries.append((rel_posix, mode_octal, content_hash))

    # Sort by POSIX path in byte order
    entries.sort(key=lambda e: e[0].encode("utf-8"))

    # Build the final hash input
    hasher = hashlib.sha256()
    for posix_path, mode_octal, content_hash in entries:
        entry_line = f"{posix_path}\0{mode_octal}\0{content_hash}\n"
        hasher.update(entry_line.encode("utf-8"))

    return hasher.hexdigest()

