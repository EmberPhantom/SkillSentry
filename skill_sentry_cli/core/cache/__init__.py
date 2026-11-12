"""Persistent cache and scan-history storage.

The cache is deliberately content-addressed and *never* stores arbitrary user
files.  Only the hash, the verdict, and the evidence needed to redisplay it are
written to SQLite.  A cached verdict is only reused when the engine version,
model version, backend and scoring weights all match (docs/developer/database.md).
"""

from __future__ import annotations

from skill_sentry_cli.core.cache.hash_utils import (
    HashError,
    SkillHash,
    hash_bytes,
    hash_skill_dir,
)
from skill_sentry_cli.core.cache.sqlite_store import (
    CachedResult,
    ScanRecord,
    SQLiteStore,
    StoreError,
)

__all__ = [
    "CachedResult",
    "HashError",
    "SQLiteStore",
    "ScanRecord",
    "SkillHash",
    "StoreError",
    "hash_bytes",
    "hash_skill_dir",
]
