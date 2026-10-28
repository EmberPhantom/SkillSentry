"""
SQLite Cache Store (Stage 0 persistence).

Manages the scan_cache and schema_meta tables in the local SQLite
database. Provides the repository interface consumed by Dev 1's
orchestrator for cache lookup (Stage 0) and write (Stage 6).

CL-D2-4 · REQ-CACHE-02 · Source: docs/03-database.md §3.4–3.6,
developer-2/03-functional-specifications.md Cap E.
"""

from __future__ import annotations

import os
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

# ── Constants ───────────────────────────────────────────────────────────

DEFAULT_DB_DIR = os.path.expanduser("~/.skillsentry")
DEFAULT_DB_NAME = "skillsentry.db"
CURRENT_SCHEMA_VERSION = "1"


# ── Schema DDL ──────────────────────────────────────────────────────────

SCHEMA_DDL = """\
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_cache (
    content_hash        TEXT PRIMARY KEY,
    skill_name          TEXT NOT NULL,
    verdict             TEXT NOT NULL CHECK (verdict IN ('SAFE','SUSPICIOUS','MALICIOUS')),
    risk_score          INTEGER NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
    confidence          REAL,
    verdict_json        TEXT NOT NULL,
    sarif_json          TEXT NOT NULL,
    active_defense_json TEXT,
    engine_version      TEXT NOT NULL,
    model_backend       TEXT NOT NULL,
    model_version       TEXT NOT NULL,
    scan_duration_ms    INTEGER,
    created_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
"""


# ── Data Classes ────────────────────────────────────────────────────────

@dataclass
class CacheStats:
    """Summary statistics for the cache store."""
    total_entries: int
    db_size_bytes: int
    engine_version: str
    model_version: str
    oldest_entry: Optional[str] = None
    newest_entry: Optional[str] = None


# ── Cache Store Implementation ──────────────────────────────────────────

class CacheStore:
    """SQLite-backed scan cache repository.

    Interface INT-2 consumed by Dev 1's orchestrator (Stage 0 read, Stage 6 write)
    and CLI commands (skillsentry cache).
    """

    def __init__(self, db_path: Optional[str | Path] = None) -> None:
        """Initialize the cache store.

        Args:
            db_path: Path to the SQLite database file. If None, uses the
                     default location (~/.skillsentry/skillsentry.db).
        """
        if db_path is None:
            db_dir = Path(DEFAULT_DB_DIR)
            db_dir.mkdir(parents=True, exist_ok=True)
            self._db_path = db_dir / DEFAULT_DB_NAME
        else:
            self._db_path = Path(db_path)
            self._db_path.parent.mkdir(parents=True, exist_ok=True)

        self._conn: Optional[sqlite3.Connection] = None
        self._initialize()

    def _initialize(self) -> None:
        """Initialize the database connection and schema."""
        self._conn = sqlite3.connect(
            str(self._db_path),
            timeout=10.0,
            check_same_thread=False,
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode = WAL")
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        """Create tables if they don't exist and check schema version."""
        cursor = self._conn.cursor()

        # Create tables
        cursor.executescript(SCHEMA_DDL)

        # Check/set schema version
        cursor.execute(
            "SELECT value FROM schema_meta WHERE key = 'schema_version'"
        )
        row = cursor.fetchone()

        if row is None:
            # First run: set schema version
            cursor.execute(
                "INSERT INTO schema_meta (key, value) VALUES ('schema_version', ?)",
                (CURRENT_SCHEMA_VERSION,),
            )
            self._conn.commit()
        else:
            existing_version = row["value"]
            if existing_version > CURRENT_SCHEMA_VERSION:
                raise RuntimeError(
                    f"Database schema version {existing_version} is newer than "
                    f"supported version {CURRENT_SCHEMA_VERSION}. "
                    f"Please upgrade SkillSentry."
                )

    def get_cached(
        self,
        content_hash: str,
        engine_version: str,
        model_version: str,
        backend_strict: bool = False,
        model_backend: Optional[str] = None,
    ) -> Optional[tuple[str, str]]:
        """Look up a cached verdict by content hash.

        Cache hit requires matching content_hash, engine_version, and model_version.
        If backend_strict=True and model_backend is provided, the backend must also match.

        Args:
            content_hash: SHA-256 hash of the skill directory.
            engine_version: Current engine version string.
            model_version: Current model version string.
            backend_strict: If True, require exact backend match.
            model_backend: Model backend name (required if backend_strict).

        Returns:
            Tuple of (verdict_json, sarif_json) on hit; None on miss.
        """
        if backend_strict and model_backend:
            query = (
                "SELECT verdict_json, sarif_json FROM scan_cache "
                "WHERE content_hash = ? AND engine_version = ? "
                "AND model_version = ? AND model_backend = ?"
            )
            params = (content_hash, engine_version, model_version, model_backend)
        else:
            query = (
                "SELECT verdict_json, sarif_json FROM scan_cache "
                "WHERE content_hash = ? AND engine_version = ? "
                "AND model_version = ?"
            )
            params = (content_hash, engine_version, model_version)

        cursor = self._conn.execute(query, params)
        row = cursor.fetchone()

        if row is None:
            return None
        return (row["verdict_json"], row["sarif_json"])

    def put(
        self,
        content_hash: str,
        skill_name: str,
        verdict: str,
        risk_score: int,
        confidence: float,
        verdict_json: str,
        sarif_json: str,
        engine_version: str,
        model_backend: str,
        model_version: str,
        scan_duration_ms: int,
        active_defense_json: Optional[str] = None,
    ) -> None:
        """Insert or update a scan cache entry.

        Upserts atomically per docs/03-database.md §3.5.
        """
        self._conn.execute(
            """\
            INSERT INTO scan_cache (
                content_hash, skill_name, verdict, risk_score, confidence,
                verdict_json, sarif_json, active_defense_json,
                engine_version, model_backend, model_version, scan_duration_ms
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(content_hash) DO UPDATE SET
                skill_name = excluded.skill_name,
                verdict = excluded.verdict,
                risk_score = excluded.risk_score,
                confidence = excluded.confidence,
                verdict_json = excluded.verdict_json,
                sarif_json = excluded.sarif_json,
                active_defense_json = excluded.active_defense_json,
                engine_version = excluded.engine_version,
                model_backend = excluded.model_backend,
                model_version = excluded.model_version,
                scan_duration_ms = excluded.scan_duration_ms,
                created_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
            """,
            (
                content_hash, skill_name, verdict, risk_score, confidence,
                verdict_json, sarif_json, active_defense_json,
                engine_version, model_backend, model_version, scan_duration_ms,
            ),
        )
        self._conn.commit()

    def prune(self, older_than_days: int) -> int:
        """Delete cache entries older than the specified number of days.

        Returns the count of deleted entries.
        """
        cursor = self._conn.execute(
            """\
            DELETE FROM scan_cache
            WHERE created_at < strftime('%Y-%m-%dT%H:%M:%fZ',
                                        'now', ? || ' days')
            """,
            (f"-{older_than_days}",),
        )
        self._conn.commit()
        return cursor.rowcount

    def stats(self) -> CacheStats:
        """Return summary statistics for the cache store."""
        cursor = self._conn.execute("SELECT COUNT(*) as cnt FROM scan_cache")
        total = cursor.fetchone()["cnt"]

        cursor = self._conn.execute(
            "SELECT MIN(created_at) as oldest, MAX(created_at) as newest "
            "FROM scan_cache"
        )
        row = cursor.fetchone()

        # Get engine/model version from most recent entry
        cursor = self._conn.execute(
            "SELECT engine_version, model_version FROM scan_cache "
            "ORDER BY created_at DESC LIMIT 1"
        )
        version_row = cursor.fetchone()

        db_size = self._db_path.stat().st_size if self._db_path.exists() else 0

        return CacheStats(
            total_entries=total,
            db_size_bytes=db_size,
            engine_version=version_row["engine_version"] if version_row else "",
            model_version=version_row["model_version"] if version_row else "",
            oldest_entry=row["oldest"] if row else None,
            newest_entry=row["newest"] if row else None,
        )

    def verify(self, sample_size: int = 10) -> list[dict]:
        """Verify cache entries by checking their stored data integrity.

        Sampling strategy (CL-D2-8):
            sample_size=10 (default) provides a quick spot-check suitable for
            CLI ``skillsentry cache verify`` in interactive mode.  CI pipelines
            should pass sample_size=0 to verify ALL entries (the query uses
            ``LIMIT ?`` with 0 meaning no limit in SQLite).

            The method validates that each sampled entry contains a legal
            verdict value ('SAFE', 'SUSPICIOUS', 'MALICIOUS') and that the
            required fields are non-NULL.  Future integration with Dev 1's
            orchestrator may add content-hash re-computation.

        Args:
            sample_size: Number of random entries to verify.  Use 10 for fast
                spot-checks, 0 for exhaustive verification, or any positive
                integer for custom sampling.

        Returns:
            List of verification result dicts, each with keys:
            ``content_hash``, ``skill_name``, ``verdict``, ``risk_score``,
            ``valid`` (bool).
        """
        if sample_size == 0:
            cursor = self._conn.execute(
                "SELECT content_hash, skill_name, verdict, risk_score "
                "FROM scan_cache ORDER BY RANDOM()",
            )
        else:
            cursor = self._conn.execute(
                "SELECT content_hash, skill_name, verdict, risk_score "
                "FROM scan_cache ORDER BY RANDOM() LIMIT ?",
                (sample_size,),
            )
        results = []
        for row in cursor.fetchall():
            results.append({
                "content_hash": row["content_hash"],
                "skill_name": row["skill_name"],
                "verdict": row["verdict"],
                "risk_score": row["risk_score"],
                "valid": row["verdict"] in ("SAFE", "SUSPICIOUS", "MALICIOUS"),
            })
        return results

    def clear(self) -> int:
        """Delete all cache entries. Returns count deleted."""
        cursor = self._conn.execute("DELETE FROM scan_cache")
        self._conn.commit()
        return cursor.rowcount

    def close(self) -> None:
        """Close the database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None

    def __enter__(self) -> "CacheStore":
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

