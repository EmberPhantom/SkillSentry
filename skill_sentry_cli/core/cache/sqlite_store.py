"""SQLite-backed cache, scan history, and Poisoned Well evidence store.

The store is intentionally synchronous: scans run in a worker thread and the
API calls small methods through ``asyncio.to_thread``.  A single connection is
guarded by a re-entrant lock, which keeps in-memory test databases and SQLite's
``check_same_thread`` rules simple.

Schema version 1 mirrors ``docs/developer/database.md``.  Two additive columns/tables
are used to keep the live API fully functional without mutating the frozen
verdict contract:

* ``scans.skill_id`` makes ``GET /skills/{id}`` addressable;
* ``scan_results`` stores the full ``SkillDetail`` payload and stage results.
"""

from __future__ import annotations

import json
import re
import sqlite3
import threading
from collections.abc import Sequence
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from skill_sentry_cli.core.cache.hash_utils import hash_bytes
from skill_sentry_cli.core.contracts import (
    ScanStatus,
    SkillDetail,
    StageResult,
    Verdict,
    VerdictTier,
    format_utc,
    utc_now,
)

SCHEMA_VERSION = 1
CACHE_KEY_VERSION = 1

_SCHEMA = """
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
    detail_json         TEXT,
    active_defense_json TEXT,
    engine_version      TEXT NOT NULL,
    model_backend       TEXT NOT NULL,
    model_version       TEXT NOT NULL,
    scan_duration_ms    INTEGER,
    created_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE IF NOT EXISTS scans (
    scan_id      TEXT PRIMARY KEY,
    skill_name   TEXT NOT NULL,
    skill_path   TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'running'
                 CHECK (status IN ('queued','running','completed','failed','cached-hit')),
    verdict      TEXT,
    risk_score   INTEGER,
    confidence   REAL,
    cached       INTEGER NOT NULL DEFAULT 0,
    backend      TEXT,
    skill_id     TEXT,
    started_at   TEXT NOT NULL,
    finished_at  TEXT,
    duration_ms  INTEGER,
    error        TEXT
);
CREATE INDEX IF NOT EXISTS idx_scans_hash    ON scans(content_hash);
CREATE INDEX IF NOT EXISTS idx_scans_started ON scans(started_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_skill   ON scans(skill_id);

CREATE TABLE IF NOT EXISTS scan_results (
    scan_id           TEXT PRIMARY KEY REFERENCES scans(scan_id) ON DELETE CASCADE,
    verdict_json      TEXT NOT NULL,
    detail_json       TEXT NOT NULL,
    stage_results_json TEXT,
    created_at        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id       TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    stage         TEXT NOT NULL
                  CHECK (stage IN ('cache','spec','typosquat','deterministicAnchor',
                                   'semantic','vision','sandbox','poisonedWell',
                                   'evasion','verdict')),
    severity      TEXT NOT NULL CHECK (severity IN ('low','medium','high','critical','note')),
    message       TEXT NOT NULL,
    file          TEXT,
    line          INTEGER,
    evidence_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);

CREATE TABLE IF NOT EXISTS active_defense (
    scan_id             TEXT PRIMARY KEY REFERENCES scans(scan_id) ON DELETE CASCADE,
    triggered           INTEGER NOT NULL DEFAULT 0,
    targeted_assets     TEXT,
    exfil_channel       TEXT CHECK (exfil_channel IN
                          ('DNS_TUNNELING','HTTP_POST','RAW_SOCKET',NULL)),
    canary_marker       TEXT,
    secondary_canary    TEXT,
    c2_indicators       TEXT,
    encoding            TEXT,
    sandbox_evasion_detected INTEGER NOT NULL DEFAULT 0,
    declared_intent     TEXT,
    actual_behavior     TEXT,
    context_canary      TEXT,
    ioc_export_path     TEXT
);

CREATE TABLE IF NOT EXISTS canary_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    ts              TEXT NOT NULL,
    event_type      TEXT NOT NULL CHECK (event_type IN
                      ('canary_seeded','canary_read','fake_served','probe_detected',
                       'exfil_raw','exfil_decoded','marker_matched','secondary_served')),
    path_or_channel TEXT,
    marker          TEXT,
    process         TEXT,
    detail_json     TEXT
);
CREATE INDEX IF NOT EXISTS idx_canary_scan_ts ON canary_events(scan_id, ts);

CREATE TABLE IF NOT EXISTS sandbox_net_logs (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id          TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    ts               TEXT NOT NULL,
    protocol         TEXT NOT NULL CHECK (protocol IN ('dns','http')),
    query_or_url     TEXT NOT NULL,
    body_b64         TEXT,
    responder_action TEXT
);
CREATE INDEX IF NOT EXISTS idx_net_scan_ts ON sandbox_net_logs(scan_id, ts);

CREATE TABLE IF NOT EXISTS iocs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    ioc_type    TEXT NOT NULL CHECK (ioc_type IN
                  ('domain-name','ipv4-addr','url','hostname-pattern')),
    value       TEXT NOT NULL,
    channel     TEXT,
    first_seen  TEXT NOT NULL,
    confirmed   INTEGER NOT NULL DEFAULT 0,
    UNIQUE (scan_id, ioc_type, value)
);
CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(value);

CREATE TABLE IF NOT EXISTS attacker_profiles (
    id              TEXT PRIMARY KEY,
    scan_id         TEXT NOT NULL UNIQUE REFERENCES scans(scan_id) ON DELETE CASCADE,
    profile_json    TEXT NOT NULL,
    stix_bundle_path TEXT,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
"""


class StoreError(RuntimeError):
    """The database is unavailable or an operation would corrupt evidence."""


@dataclass(frozen=True)
class CachedResult:
    content_hash: str
    skill_name: str
    verdict: Verdict
    detail: SkillDetail
    sarif_json: str
    engine_version: str
    model_backend: str
    model_version: str
    scan_duration_ms: int
    created_at: str


@dataclass(frozen=True)
class ScanRecord:
    scan_id: UUID
    skill_name: str
    skill_path: str
    content_hash: str
    status: ScanStatus
    verdict: VerdictTier | None
    risk_score: int | None
    confidence: float | None
    cached: bool
    backend: str | None
    skill_id: UUID | None
    started_at: datetime
    finished_at: datetime | None
    duration_ms: int | None
    error: str | None


def cache_key(
    content_hash: str,
    engine_version: str,
    model_version: str,
    *,
    backend: str | None = None,
    backend_strict: bool = False,
) -> str:
    """Return a stable diagnostic key (the DB query uses the individual fields)."""

    backend_part = backend or "*" if not backend_strict else ""
    return hash_bytes(
        f"{CACHE_KEY_VERSION}\0{content_hash}\0{engine_version}\0{model_version}\0{backend_part}".encode()
    )


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


_DURATION_RE = re.compile(r"^\s*(\d+)\s*([smhdw])\s*$", re.IGNORECASE)


def _parse_age(value: str | None) -> timedelta | None:
    if value is None:
        return None
    match = _DURATION_RE.match(value)
    if not match:
        raise StoreError(f"invalid duration {value!r}; use e.g. 30d, 12h, 30m")
    amount = int(match.group(1))
    unit = match.group(2).lower()
    factor = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}[unit]
    return timedelta(seconds=amount * factor)


class SQLiteStore:
    """One SQLite connection with serialized access."""

    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        self._lock = threading.RLock()
        self._closed = False
        if self.path != ":memory:":
            target = Path(self.path).expanduser()
            target.parent.mkdir(parents=True, exist_ok=True)
            self._path = target
        else:
            self._path = None
        try:
            self._conn = sqlite3.connect(
                self.path,
                check_same_thread=False,
                timeout=10.0,
                isolation_level=None,
            )
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA foreign_keys = ON")
            if self.path != ":memory:":
                self._conn.execute("PRAGMA journal_mode = WAL")
            self._conn.executescript(_SCHEMA)
            self._migrate()
        except sqlite3.Error as exc:
            raise StoreError(f"could not open database {self.path}: {exc}") from exc

    # -- lifecycle ---------------------------------------------------------
    def _migrate(self) -> None:
        columns = {row["name"] for row in self._conn.execute("PRAGMA table_info(scans)").fetchall()}
        if "skill_id" not in columns:
            self._conn.execute("ALTER TABLE scans ADD COLUMN skill_id TEXT")
        cache_columns = {
            row["name"] for row in self._conn.execute("PRAGMA table_info(scan_cache)").fetchall()
        }
        if "detail_json" not in cache_columns:
            self._conn.execute("ALTER TABLE scan_cache ADD COLUMN detail_json TEXT")
        self._conn.execute(
            "INSERT OR REPLACE INTO schema_meta(key, value) VALUES('schema_version', ?)",
            (str(SCHEMA_VERSION),),
        )
        row = self._conn.execute(
            "SELECT value FROM schema_meta WHERE key='created_version'"
        ).fetchone()
        if row is None:
            self._conn.execute(
                "INSERT INTO schema_meta(key, value) VALUES('created_version', ?)",
                (str(SCHEMA_VERSION),),
            )

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._conn.close()
                self._closed = True

    def __enter__(self) -> SQLiteStore:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    @contextmanager
    def _tx(self):
        with self._lock:
            try:
                self._conn.execute("BEGIN IMMEDIATE")
                yield self._conn
            except Exception:
                self._conn.execute("ROLLBACK")
                raise
            else:
                self._conn.execute("COMMIT")

    def ping(self) -> bool:
        try:
            with self._lock:
                self._conn.execute("SELECT 1").fetchone()
            return True
        except sqlite3.Error:
            return False

    @property
    def size_bytes(self) -> int:
        if self._path is None:
            return 0
        total = 0
        for suffix in ("", "-wal", "-shm"):
            candidate = Path(str(self._path) + suffix)
            with suppress(OSError):
                total += candidate.stat().st_size
        return total

    @property
    def schema_version(self) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT value FROM schema_meta WHERE key='schema_version'"
            ).fetchone()
        return int(row["value"]) if row else 0

    # -- scan lifecycle ----------------------------------------------------
    def create_scan(
        self,
        scan_id: UUID,
        *,
        skill_name: str,
        skill_path: str,
        content_hash: str,
        backend: str,
        skill_id: UUID | None = None,
        status: ScanStatus = ScanStatus.RUNNING,
        started_at: datetime | None = None,
    ) -> None:
        started_at = started_at or utc_now()
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO scans(scan_id, skill_name, skill_path, content_hash, status,
                                  backend, skill_id, started_at)
                VALUES(?,?,?,?,?,?,?,?)
                """,
                (
                    str(scan_id),
                    skill_name,
                    skill_path,
                    content_hash,
                    status.value,
                    backend,
                    str(skill_id) if skill_id else None,
                    format_utc(started_at),
                ),
            )

    def update_status(
        self,
        scan_id: UUID,
        status: ScanStatus,
        *,
        error: str | None = None,
    ) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE scans SET status=?, error=? WHERE scan_id=?",
                (status.value, error, str(scan_id)),
            )

    def fail_scan(self, scan_id: UUID, error: str) -> None:
        now = utc_now()
        with self._lock:
            row = self._conn.execute(
                "SELECT started_at FROM scans WHERE scan_id=?", (str(scan_id),)
            ).fetchone()
            if row is None:
                return
            started = _parse_ts(row["started_at"]) or now
            self._conn.execute(
                """
                UPDATE scans SET status='failed', error=?, finished_at=?, duration_ms=?
                WHERE scan_id=?
                """,
                (
                    error[:2000],
                    format_utc(now),
                    max(0, int((now - started).total_seconds() * 1000)),
                    str(scan_id),
                ),
            )

    def finish_scan(
        self,
        verdict: Verdict,
        detail: SkillDetail,
        *,
        stage_results: Sequence[StageResult] = (),
        sarif_json: str = "",
        cache: bool = True,
    ) -> None:
        """Persist a completed scan atomically.

        ``cache=False`` is used for ``--no-cache``: evidence and history are
        still recorded, but the reusable content-addressed row is not written.
        """

        scan_id = verdict.scan_id
        finished = utc_now()
        with self._tx() as conn:
            row = conn.execute(
                "SELECT started_at, content_hash, backend, skill_path, skill_name FROM scans "
                "WHERE scan_id=?",
                (str(scan_id),),
            ).fetchone()
            if row is None:
                raise StoreError(f"scan row missing for {scan_id}")
            started = _parse_ts(row["started_at"]) or finished
            duration = verdict.scan_duration_ms
            status = "cached-hit" if verdict.cached else "completed"
            conn.execute(
                """
                UPDATE scans SET status=?, verdict=?, risk_score=?, confidence=?, cached=?,
                    skill_name=?, skill_id=?, finished_at=?, duration_ms=?, error=NULL
                WHERE scan_id=?
                """,
                (
                    status,
                    verdict.verdict.value,
                    verdict.risk_score,
                    verdict.confidence,
                    1 if verdict.cached else 0,
                    verdict.skill,
                    str(verdict.skill_id),
                    format_utc(finished),
                    duration,
                    str(scan_id),
                ),
            )
            verdict_json = verdict.model_dump_json(by_alias=True)
            detail_json = detail.model_dump_json(by_alias=True)
            conn.execute(
                """
                INSERT OR REPLACE INTO scan_results(scan_id, verdict_json, detail_json,
                                                     stage_results_json, created_at)
                VALUES(?,?,?,?,?)
                """,
                (
                    str(scan_id),
                    verdict_json,
                    detail_json,
                    _json(
                        [result.model_dump(by_alias=True, mode="json") for result in stage_results]
                    ),
                    format_utc(finished),
                ),
            )
            self._write_findings(conn, scan_id, verdict)
            self._write_active_defense(conn, scan_id, verdict)
            self._write_trace(conn, scan_id, detail)
            self._write_iocs(conn, scan_id, verdict, detail)

            if cache:
                sarif = sarif_json or ""
                conn.execute(
                    """
                    INSERT INTO scan_cache(content_hash, skill_name, verdict, risk_score,
                        confidence, verdict_json, sarif_json, detail_json,
                        active_defense_json, engine_version, model_backend, model_version,
                        scan_duration_ms, created_at)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(content_hash) DO UPDATE SET
                        skill_name=excluded.skill_name,
                        verdict=excluded.verdict,
                        risk_score=excluded.risk_score,
                        confidence=excluded.confidence,
                        verdict_json=excluded.verdict_json,
                        sarif_json=excluded.sarif_json,
                        detail_json=excluded.detail_json,
                        active_defense_json=excluded.active_defense_json,
                        engine_version=excluded.engine_version,
                        model_backend=excluded.model_backend,
                        model_version=excluded.model_version,
                        scan_duration_ms=excluded.scan_duration_ms,
                        created_at=excluded.created_at
                    """,
                    (
                        row["content_hash"],
                        verdict.skill,
                        verdict.verdict.value,
                        verdict.risk_score,
                        verdict.confidence,
                        verdict_json,
                        sarif,
                        detail_json,
                        (
                            verdict.active_defense.model_dump_json(by_alias=True)
                            if verdict.active_defense
                            else None
                        ),
                        self._engine_version,
                        self._model_backend,
                        self._model_version,
                        duration,
                        format_utc(finished),
                    ),
                )
            del started

    # Values used when a result is finalized; set by the engine immediately
    # before ``finish_scan``.  Kept as attributes so the public method stays
    # small and the cache rule lives in one place.
    _engine_version = "unknown"
    _model_backend = "unknown"
    _model_version = "unknown"

    def set_cache_identity(
        self, *, engine_version: str, model_backend: str, model_version: str
    ) -> None:
        self._engine_version = engine_version
        self._model_backend = model_backend
        self._model_version = model_version

    def _write_findings(self, conn: sqlite3.Connection, scan_id: UUID, verdict: Verdict) -> None:
        for finding in verdict.findings:
            conn.execute(
                """
                INSERT INTO findings(scan_id, stage, severity, message, file, line, evidence_json)
                VALUES(?,?,?,?,?,?,?)
                """,
                (
                    str(scan_id),
                    finding.stage.value,
                    finding.severity.value,
                    finding.message,
                    finding.evidence.file,
                    finding.evidence.line,
                    finding.evidence.model_dump_json(by_alias=True, exclude_none=True),
                ),
            )

    def _write_active_defense(
        self, conn: sqlite3.Connection, scan_id: UUID, verdict: Verdict
    ) -> None:
        active = verdict.active_defense
        if active is None:
            return
        conn.execute(
            """
            INSERT OR REPLACE INTO active_defense(scan_id, triggered, targeted_assets,
                exfil_channel, canary_marker, secondary_canary, c2_indicators, encoding,
                sandbox_evasion_detected, declared_intent, actual_behavior, context_canary,
                ioc_export_path)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                str(scan_id),
                1 if active.triggered else 0,
                _json(active.targeted_assets),
                active.exfil_channel.value if active.exfil_channel else None,
                active.canary_marker,
                active.secondary_canary,
                _json(active.c2_indicators),
                active.encoding,
                1 if active.sandbox_evasion_detected else 0,
                active.declared_intent,
                active.actual_behavior,
                active.context_aware_canary.value if active.context_aware_canary else None,
                active.ioc_export,
            ),
        )

    def _write_trace(self, conn: sqlite3.Connection, scan_id: UUID, detail: SkillDetail) -> None:
        for event in detail.sandbox_trace.events:
            conn.execute(
                """
                INSERT INTO canary_events(scan_id, ts, event_type, path_or_channel, marker,
                                          process, detail_json)
                VALUES(?,?,?,?,?,?,?)
                """,
                (
                    str(scan_id),
                    format_utc(event.ts),
                    event.event_type,
                    event.path_or_channel,
                    event.marker,
                    event.process,
                    _json(event.detail or {}),
                ),
            )
        for net in detail.sandbox_trace.net_logs:
            conn.execute(
                """
                INSERT INTO sandbox_net_logs(scan_id, ts, protocol, query_or_url, body_b64,
                                             responder_action)
                VALUES(?,?,?,?,?,?)
                """,
                (
                    str(scan_id),
                    format_utc(net.ts),
                    net.protocol,
                    net.query_or_url,
                    net.body_b64,
                    net.responder_action,
                ),
            )

    def _write_iocs(
        self, conn: sqlite3.Connection, scan_id: UUID, verdict: Verdict, detail: SkillDetail
    ) -> None:
        profile = detail.poisoned_well
        if profile.active_defense is None:
            return
        active = profile.active_defense
        confirmed = bool(profile.confirmed or active.triggered)
        seen = format_utc(utc_now())
        values: set[tuple[str, str, str | None]] = set()
        for indicator in active.c2_indicators:
            ioc_type = _classify_ioc(indicator)
            if ioc_type:
                values.add((ioc_type, indicator, "dns" if _looks_domain(indicator) else "http"))
        for node in profile.graph.nodes:
            if node.kind not in {"c2", "channel"}:
                continue
            if node.kind == "c2" and node.label and ("." in node.label or ":" in node.label):
                ioc_type = _classify_ioc(node.label)
                if ioc_type:
                    values.add((ioc_type, node.label, "graph"))
        for ioc_type, value, channel in sorted(values):
            conn.execute(
                """
                INSERT OR IGNORE INTO iocs(scan_id, ioc_type, value, channel, first_seen, confirmed)
                VALUES(?,?,?,?,?,?)
                """,
                (str(scan_id), ioc_type, value[:2048], channel, seen, 1 if confirmed else 0),
            )
        if values:
            profile_id = str(uuid4())
            profile_json = _json(
                {
                    "scan_id": str(scan_id),
                    "triggered": active.triggered,
                    "targeted_assets": active.targeted_assets,
                    "channel": active.exfil_channel.value if active.exfil_channel else None,
                    "marker": active.canary_marker,
                    "secondary": active.secondary_canary,
                    "c2": active.c2_indicators,
                    "encoding": active.encoding,
                    "declared_intent": active.declared_intent,
                    "actual_behavior": active.actual_behavior,
                    "context_canary": (
                        active.context_aware_canary.value if active.context_aware_canary else None
                    ),
                }
            )
            conn.execute(
                """
                INSERT OR REPLACE INTO attacker_profiles(id, scan_id, profile_json, created_at)
                VALUES(?,?,?,?)
                """,
                (profile_id, str(scan_id), profile_json, seen),
            )
        del verdict

    # -- reads -------------------------------------------------------------
    def lookup_cache(
        self,
        content_hash: str,
        *,
        engine_version: str,
        model_version: str,
        model_backend: str | None = None,
        backend_strict: bool = False,
    ) -> CachedResult | None:
        sql = (
            "SELECT * FROM scan_cache WHERE content_hash=? AND engine_version=? AND model_version=?"
        )
        params: list[Any] = [content_hash, engine_version, model_version]
        if backend_strict and model_backend:
            sql += " AND model_backend=?"
            params.append(model_backend)
        with self._lock:
            row = self._conn.execute(sql, params).fetchone()
        if row is None:
            return None
        try:
            verdict = Verdict.model_validate_json(row["verdict_json"])
            if row["detail_json"]:
                detail = SkillDetail.model_validate_json(row["detail_json"])
            else:  # old rows: rebuild a minimal detail payload
                detail = SkillDetail(
                    verdict=verdict,
                    report_links={
                        "sarif": f"/skills/{verdict.skill_id}/export?format=sarif",
                        "markdown": f"/skills/{verdict.skill_id}/export?format=markdown",
                    },
                )
        except Exception as exc:
            raise StoreError(f"cached verdict is corrupt: {exc}") from exc
        return CachedResult(
            content_hash=row["content_hash"],
            skill_name=row["skill_name"],
            verdict=verdict,
            detail=detail,
            sarif_json=row["sarif_json"],
            engine_version=row["engine_version"],
            model_backend=row["model_backend"],
            model_version=row["model_version"],
            scan_duration_ms=int(row["scan_duration_ms"] or 0),
            created_at=row["created_at"],
        )

    def get_scan(self, scan_id: UUID) -> ScanRecord | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM scans WHERE scan_id=?", (str(scan_id),)
            ).fetchone()
        return _scan_record(row) if row else None

    def list_scans(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        status: ScanStatus | None = None,
    ) -> list[dict[str, Any]]:
        sql = """
            SELECT s.*, (
                SELECT f.message FROM findings f
                WHERE f.scan_id=s.scan_id
                ORDER BY CASE f.severity
                    WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                    WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END
                LIMIT 1
            ) AS key_finding
            FROM scans s
        """
        params: list[Any] = []
        if status is not None:
            sql += " WHERE s.status=?"
            params.append(status.value)
        sql += " ORDER BY s.started_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            record = _scan_record(row)
            result.append(
                {
                    "scan_id": record.scan_id,
                    "skill_id": record.skill_id,
                    "skill": record.skill_name,
                    "verdict": record.verdict,
                    "risk_score": record.risk_score,
                    "cached": record.cached,
                    "status": record.status,
                    "started_at": record.started_at,
                    "duration_ms": record.duration_ms,
                    "key_finding": row["key_finding"],
                }
            )
        return result

    def get_result(
        self, scan_id: UUID
    ) -> tuple[Verdict, SkillDetail, list[StageResult], bool] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM scan_results WHERE scan_id=?", (str(scan_id),)
            ).fetchone()
        if row is None:
            return None
        verdict = Verdict.model_validate_json(row["verdict_json"])
        detail = SkillDetail.model_validate_json(row["detail_json"])
        stages: list[StageResult] = []
        if row["stage_results_json"]:
            try:
                stages = [
                    StageResult.model_validate(item)
                    for item in json.loads(row["stage_results_json"])
                ]
            except Exception:
                stages = []
        return verdict, detail, stages, bool(verdict.cached)

    def get_result_for_skill(
        self, skill_id: UUID
    ) -> tuple[Verdict, SkillDetail, list[StageResult], bool] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT scan_id FROM scans WHERE skill_id=? AND verdict IS NOT NULL "
                "ORDER BY started_at DESC LIMIT 1",
                (str(skill_id),),
            ).fetchone()
        if row is None:
            return None
        return self.get_result(UUID(row["scan_id"]))

    # -- cache administration ---------------------------------------------
    def cache_stats(self) -> tuple[int, float]:
        with self._lock:
            entries = int(
                self._conn.execute("SELECT COUNT(*) AS n FROM scan_cache").fetchone()["n"]
            )
            total = int(
                self._conn.execute(
                    "SELECT COUNT(*) AS n FROM scans WHERE status IN ('completed','cached-hit')"
                ).fetchone()["n"]
            )
            hits = int(
                self._conn.execute(
                    "SELECT COUNT(*) AS n FROM scans WHERE cached=1 AND status IN "
                    "('completed','cached-hit')"
                ).fetchone()["n"]
            )
        rate = (hits / total) if total else 0.0
        return entries, round(rate, 3)

    def clear_cache(self, older_than: str | None = None) -> tuple[int, int]:
        age = _parse_age(older_than)
        with self._lock:
            total = int(self._conn.execute("SELECT COUNT(*) AS n FROM scan_cache").fetchone()["n"])
            if age is None:
                deleted = int(self._conn.execute("DELETE FROM scan_cache").rowcount)
            else:
                cutoff = format_utc(utc_now() - age)
                deleted = int(
                    self._conn.execute(
                        "DELETE FROM scan_cache WHERE created_at < ?", (cutoff,)
                    ).rowcount
                )
        return deleted, max(0, total - deleted)


def _looks_domain(value: str) -> bool:
    return "." in value and " " not in value and "/" not in value


def _classify_ioc(value: str) -> str | None:
    value = value.strip()
    if not value:
        return None
    if value.startswith(("http://", "https://")):
        return "url" if len(value) <= 2048 else None
    if _looks_domain(value):
        return "domain-name"
    import ipaddress

    try:
        ipaddress.ip_address(value)
    except ValueError:
        return "hostname-pattern" if "*" in value else None
    return "ipv4-addr" if ":" not in value else None


def _scan_record(row: sqlite3.Row) -> ScanRecord:
    return ScanRecord(
        scan_id=UUID(row["scan_id"]),
        skill_name=row["skill_name"],
        skill_path=row["skill_path"],
        content_hash=row["content_hash"],
        status=ScanStatus(row["status"]),
        verdict=VerdictTier(row["verdict"]) if row["verdict"] else None,
        risk_score=row["risk_score"],
        confidence=row["confidence"],
        cached=bool(row["cached"]),
        backend=row["backend"],
        skill_id=UUID(row["skill_id"]) if row["skill_id"] else None,
        started_at=_parse_ts(row["started_at"]) or utc_now(),
        finished_at=_parse_ts(row["finished_at"]),
        duration_ms=row["duration_ms"],
        error=row["error"],
    )


__all__ = [
    "CACHE_KEY_VERSION",
    "SCHEMA_VERSION",
    "CachedResult",
    "SQLiteStore",
    "ScanRecord",
    "StoreError",
    "cache_key",
]
