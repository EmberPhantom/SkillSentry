"""Live REST/WebSocket backend backed by :class:`ScanEngine`.

The backend owns only scheduling and presentation.  All analysis is performed
by the synchronous engine on a worker thread; events are replayed to every
WebSocket subscriber from a bounded in-memory log.  Completed results are read
from SQLite so history survives a server restart.
"""

from __future__ import annotations

import asyncio
import contextlib
import threading
from collections.abc import AsyncGenerator
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from skill_sentry_cli.core.cache.sqlite_store import StoreError
from skill_sentry_cli.core.config import SkillsEntryConfig, load_config
from skill_sentry_cli.core.contracts import (
    CacheStatsResponse,
    DeleteCacheResponse,
    ExportFormat,
    HealthResponse,
    MetaResponse,
    ScanListResponse,
    ScanRequest,
    ScanStartResponse,
    ScanStatus,
    ScanStatusResponse,
    ScanSummary,
    SkillDetail,
    Stage,
    Verdict,
    VerdictsResponse,
    WSEventType,
    WSMessage,
    utc_now,
)
from skill_sentry_cli.core.engine import ScanEngine, ScanError, ScanOutcome
from skill_sentry_cli.core.reports import RenderedReport, render_report
from skill_sentry_cli.core.verdict.stix_report import NoIOCsError
from skill_sentry_cli.core.version import (
    CONTRACT_VERSION,
    __version__,
    badge_for_backend,
    engine_version,
)
from skill_sentry_cli.server.errors import ApiError

_MAX_EVENTS = 5_000
_STREAM_HEARTBEAT_S = 20.0
# How long a cancel waits for the engine to reach its next checkpoint before the
# scan is recorded as cancelled without it.
_CANCEL_GRACE_S = 2.0


@dataclass
class _LiveScan:
    scan_id: UUID
    path: Path
    started_at: datetime
    status: ScanStatus = ScanStatus.QUEUED
    current_stage: Stage | None = None
    events: list[WSMessage] = field(default_factory=list)
    changed: asyncio.Event = field(default_factory=asyncio.Event)
    done: asyncio.Event = field(default_factory=asyncio.Event)
    cancel_event: threading.Event = field(default_factory=threading.Event)
    outcome: ScanOutcome | None = None
    error: str | None = None
    task: asyncio.Task[None] | None = None
    elapsed_ms: int = 0
    # Set once a terminal status is recorded. The first writer wins, so a cancelled
    # scan cannot later be overwritten by its worker's completion or error.
    final: bool = False
    cancel_requested: bool = False
    # True while the engine thread may still be running, even after the scan has been
    # recorded as cancelled. A second scan of the same path waits for this to clear.
    worker_running: bool = False


def _inside_scan_roots(path: Path, roots: list[str]) -> bool:
    """True when ``path``, with symlinks resolved, is one of ``roots`` or inside one.

    ``is_relative_to`` compares whole path components, so ``/srv/skills-evil`` is not
    inside ``/srv/skills``. Any failure to resolve counts as not inside.
    """

    try:
        target = path.expanduser().resolve()
        return any(target.is_relative_to(Path(root).expanduser().resolve()) for root in roots)
    except (OSError, RuntimeError, ValueError):
        # RuntimeError: a symlink loop. ValueError: an embedded NUL byte.
        return False


def _path_not_allowed() -> ApiError:
    # The message names neither the path nor the roots, so it reveals nothing about the
    # filesystem outside the allowed folders.
    return ApiError(
        403,
        "path_not_allowed",
        "scan path is outside the folders this server may scan (server.allowed_scan_roots)",
        stage=Stage.SPEC,
        degraded=True,
    )


def _ollama_ready(config: SkillsEntryConfig) -> bool:
    """True only when the local server answers and the configured model is pulled."""

    from skill_sentry_cli.core.models.gemma_local import GemmaLocal

    with GemmaLocal(base_url=config.model.ollama_url, model=config.model.ollama_model) as model:
        return model.health()


class LiveBackend:
    """Production backend.  ``demo_mode`` is always false."""

    demo_mode = False

    def __init__(
        self,
        config: SkillsEntryConfig | None = None,
        *,
        engine: ScanEngine | None = None,
        store: Any | None = None,
    ) -> None:
        self.config = config or load_config()
        self._engine = engine
        self._store = store
        self._engines: dict[str, ScanEngine] = {}
        self._scans: dict[UUID, _LiveScan] = {}
        self._by_skill: dict[UUID, UUID] = {}
        self._loop: asyncio.AbstractEventLoop | None = None
        if engine is not None:
            self._store = engine.store

    @property
    def engine(self) -> ScanEngine:
        if self._engine is None:
            self._engine = ScanEngine(self.config)
            self._store = self._engine.store
        return self._engine

    @property
    def store(self) -> Any:
        if self._store is None:
            self._store = self.engine.store
        return self._store

    def close(self) -> None:
        if self._engine is not None:
            self._engine.close()
        for engine in self._engines.values():
            engine.close()
        self._engines.clear()

    # -- scan lifecycle ----------------------------------------------------
    async def start_scan(self, request: ScanRequest) -> ScanStartResponse:
        if request.path is None or not request.path.strip():
            raise ApiError(
                422,
                "missing_path",
                "a skill path is required for live scans",
                stage=Stage.SPEC,
                degraded=True,
            )
        roots = self.config.server.allowed_scan_roots
        path = Path(request.path).expanduser()
        # The allowlist check runs before the existence check, so a refused path gets the
        # same answer whether or not it exists.
        if roots and not _inside_scan_roots(path, roots):
            raise _path_not_allowed()
        try:
            path = path.resolve(strict=True)
        except OSError as exc:
            raise ApiError(
                404,
                "no_skill_manifest",
                f"skill path does not exist: {request.path}",
                stage=Stage.SPEC,
                degraded=True,
            ) from exc
        if roots and not _inside_scan_roots(path, roots):
            # The first check looked at the path as written. This one looks at the resolved
            # path, the one that will be scanned, so a symlink swapped in between is refused.
            raise _path_not_allowed()
        if not path.is_dir():
            raise ApiError(
                422,
                "invalid_skill",
                f"skill path is not a directory: {path}",
                stage=Stage.SPEC,
                degraded=True,
            )
        if not (path / "SKILL.md").is_file():
            # The API scans one skill folder per request and returns one scan_id.
            # Scanning one child of a folder of skills would report success for
            # packages the caller never asked about, so refuse and name them.
            children = sorted(
                child.name
                for child in path.iterdir()
                if child.is_dir() and (child / "SKILL.md").is_file()
            )
            if not children:
                raise ApiError(
                    404,
                    "no_skill_manifest",
                    f"no SKILL.md found in {path}",
                    stage=Stage.SPEC,
                    degraded=True,
                )
            shown = ", ".join(children[:10]) + (" ..." if len(children) > 10 else "")
            raise ApiError(
                422,
                "folder_of_skills",
                f"{path} is a folder of {len(children)} skills ({shown}). Scan one skill "
                "folder per request.",
                stage=Stage.SPEC,
                degraded=True,
            )

        for existing in self._scans.values():
            if existing.path == path and existing.worker_running:
                raise ApiError(
                    409,
                    "scan_in_progress",
                    f"a scan of {path} is already running",
                    stage=Stage.CACHE,
                    degraded=True,
                    scan_id=existing.scan_id,
                )

        scan_id = uuid4()
        item = _LiveScan(scan_id=scan_id, path=path, started_at=utc_now(), worker_running=True)
        self._scans[scan_id] = item
        self._loop = asyncio.get_running_loop()
        item.task = asyncio.create_task(self._run_scan(item, request))
        return ScanStartResponse(
            scan_id=scan_id,
            status=ScanStatus.QUEUED,
            stream=f"/scan/{scan_id}/stream",
        )

    async def _run_scan(self, item: _LiveScan, request: ScanRequest) -> None:
        loop = self._loop or asyncio.get_running_loop()

        def callback(message: WSMessage) -> None:
            loop.call_soon_threadsafe(self._on_event, item, message)

        try:
            self._finish(item, ScanStatus.RUNNING, stage=None)
            engine = self._engine_for(request)
            outcome = await asyncio.to_thread(
                engine.scan,
                item.path,
                options=request.options,
                scan_id=item.scan_id,
                callback=callback,
                cancel=item.cancel_event,
            )
            if not item.final:
                item.outcome = outcome
                item.elapsed_ms = outcome.duration_ms
                self._by_skill[outcome.skill_id] = item.scan_id
                self._finish(item, outcome.status, stage=Stage.VERDICT)
        except ScanError as exc:
            if not item.final:
                self._finish(item, ScanStatus.FAILED, stage=exc.stage or Stage.VERDICT)
                item.error = str(exc)
                self._on_event(
                    item,
                    WSMessage(
                        stage=exc.stage or Stage.VERDICT,
                        skill=item.path.name,
                        event=WSEventType.ERROR,
                        ts=utc_now(),
                        detail={
                            "code": exc.code,
                            "message": str(exc),
                            "degraded": exc.degraded,
                        },
                    ),
                )
        except Exception as exc:  # pragma: no cover - defensive
            if not item.final:
                self._finish(item, ScanStatus.FAILED, stage=Stage.VERDICT)
                item.error = f"internal scan error: {exc}"
                self._on_event(
                    item,
                    WSMessage(
                        stage=Stage.VERDICT,
                        skill=item.path.name,
                        event=WSEventType.ERROR,
                        ts=utc_now(),
                        detail={"code": "internal_error", "message": str(exc), "degraded": True},
                    ),
                )
        finally:
            item.worker_running = False
            item.elapsed_ms = max(
                item.elapsed_ms,
                int((utc_now() - item.started_at).total_seconds() * 1000),
            )
            item.done.set()
            item.changed.set()

    @staticmethod
    def _finish(item: _LiveScan, status: ScanStatus, *, stage: Stage | None) -> None:
        """Record a status unless a terminal one is already recorded."""

        if item.final:
            return
        item.status = status
        item.current_stage = stage or item.current_stage
        if status in {ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CACHED_HIT}:
            item.final = True

    def _engine_for(self, request: ScanRequest) -> ScanEngine:
        if self._engine is not None:
            return self._engine
        backend = request.options.backend.value
        if backend == "auto":
            return self.engine
        # A non-auto backend override is a per-request choice.  Keep one
        # engine per backend so repeated API scans do not leak a new store
        # owner/thread pool on every request, and close them with the backend.
        engine = self._engines.get(backend)
        if engine is None:
            cfg = self.config.model_copy(deep=True)
            cfg.model.backend = backend
            engine = ScanEngine(cfg, store=self.store)
            self._engines[backend] = engine
        return engine

    def _on_event(self, item: _LiveScan, message: WSMessage) -> None:
        if len(item.events) >= _MAX_EVENTS or item.done.is_set():
            return
        item.events.append(message)
        item.current_stage = message.stage
        if item.status is ScanStatus.QUEUED:
            item.status = ScanStatus.RUNNING
        item.changed.set()

    async def get_scan(self, scan_id: UUID) -> ScanStatusResponse:
        item = self._scans.get(scan_id)
        if item is not None:
            elapsed = item.elapsed_ms
            if not item.done.is_set():
                elapsed = max(0, int((utc_now() - item.started_at).total_seconds() * 1000))
            return ScanStatusResponse(
                scan_id=scan_id,
                status=item.status,
                stage=item.current_stage,
                skill=item.outcome.skill_name if item.outcome else item.path.name,
                started_at=item.started_at,
                elapsed_ms=elapsed,
                error=item.error,
            )
        record = await asyncio.to_thread(self.store.get_scan, scan_id)
        if record is None:
            raise ApiError(404, "unknown_scan", f"unknown scan: {scan_id}")
        return ScanStatusResponse(
            scan_id=record.scan_id,
            status=record.status,
            stage=Stage.VERDICT
            if record.status in {ScanStatus.COMPLETED, ScanStatus.CACHED_HIT}
            else None,
            skill=record.skill_name,
            started_at=record.started_at,
            elapsed_ms=record.duration_ms,
            error=record.error,
        )

    async def get_verdicts(self, scan_id: UUID) -> VerdictsResponse:
        item = self._scans.get(scan_id)
        if item is not None:
            if item.status is ScanStatus.FAILED:
                raise ApiError(500, "scan_failed", item.error or "scan failed", scan_id=scan_id)
            if item.outcome is None:
                raise ApiError(
                    409,
                    "scan_in_progress",
                    "scan has not completed yet",
                    stage=item.current_stage or Stage.CACHE,
                    degraded=True,
                    scan_id=scan_id,
                )
            return VerdictsResponse(scan_id=scan_id, verdicts=[item.outcome.verdict])
        stored = await asyncio.to_thread(self.store.get_result, scan_id)
        if stored is None:
            raise ApiError(404, "unknown_scan", f"unknown scan: {scan_id}")
        verdict, _detail, _stages, _cached = stored
        return VerdictsResponse(scan_id=scan_id, verdicts=[verdict])

    async def list_scans(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        status: ScanStatus | None = None,
    ) -> ScanListResponse:
        rows = await asyncio.to_thread(
            self.store.list_scans, limit=limit, offset=offset, status=status
        )
        summaries: list[ScanSummary] = []
        for row in rows:
            if row["skill_id"] is None:
                continue
            summaries.append(
                ScanSummary(
                    scan_id=row["scan_id"],
                    skill_id=row["skill_id"],
                    skill=row["skill"],
                    verdict=row["verdict"],
                    risk_score=row["risk_score"],
                    cached=row["cached"],
                    status=row["status"],
                    started_at=row["started_at"],
                    duration_ms=row["duration_ms"],
                    key_finding=row["key_finding"],
                )
            )
        # Running scans come from the store: the engine records each scan (with its
        # skill id) before it starts the stages, so a running scan is listed with
        # status "running" from then on.  The in-memory pass only adds finished
        # outcomes whose row is missing.  A scan still before that row has no
        # skill id yet, and ScanSummary requires one, so it is not listed.  The store
        # has already applied pagination, so only page zero may add rows here, and the
        # final list must not be sliced a second time.
        if offset == 0:
            seen = {summary.scan_id for summary in summaries}
            live: list[ScanSummary] = []
            for item in self._scans.values():
                if item.scan_id in seen or (status is not None and item.status is not status):
                    continue
                if item.outcome is not None:
                    outcome = item.outcome
                    live.append(
                        ScanSummary(
                            scan_id=item.scan_id,
                            skill_id=outcome.skill_id,
                            skill=outcome.skill_name,
                            verdict=outcome.verdict.verdict,
                            risk_score=outcome.verdict.risk_score,
                            cached=outcome.cached,
                            status=outcome.status,
                            started_at=item.started_at,
                            duration_ms=outcome.duration_ms,
                            key_finding=_key_finding(outcome.verdict),
                        )
                    )
            summaries = live + summaries
        return ScanListResponse(scans=summaries[:limit])

    async def get_skill(self, skill_id: UUID) -> SkillDetail:
        scan_id = self._by_skill.get(skill_id)
        item = self._scans.get(scan_id) if scan_id else None
        if item is not None and item.outcome is not None and item.outcome.skill_id == skill_id:
            return item.outcome.detail
        stored = await asyncio.to_thread(self.store.get_result_for_skill, skill_id)
        if stored is None:
            raise ApiError(404, "unknown_scan", f"unknown skill: {skill_id}")
        _verdict, detail, _stages, _cached = stored
        return detail

    # -- streaming ---------------------------------------------------------
    async def stream(self, scan_id: UUID) -> AsyncGenerator[WSMessage, None]:
        item = self._scans.get(scan_id)
        if item is None:
            stored = await asyncio.to_thread(self.store.get_result, scan_id)
            if stored is None:
                raise ApiError(404, "unknown_scan", f"unknown scan: {scan_id}")
            verdict, _detail, _stages, _cached = stored
            yield WSMessage(
                stage=Stage.VERDICT,
                skill=verdict.skill,
                event=WSEventType.COMPLETED,
                ts=utc_now(),
                detail={"verdict": verdict.model_dump(by_alias=True, mode="json")},
            )
            return
        index = 0
        while True:
            while index < len(item.events):
                yield item.events[index]
                index += 1
            if item.done.is_set() and index >= len(item.events):
                break
            item.changed.clear()
            if index < len(item.events) or item.done.is_set():
                continue
            try:
                await asyncio.wait_for(item.changed.wait(), timeout=_STREAM_HEARTBEAT_S)
            except TimeoutError:
                yield WSMessage(
                    stage=item.current_stage or Stage.CACHE,
                    skill=item.outcome.skill_name if item.outcome else item.path.name,
                    event=WSEventType.PROGRESS,
                    ts=utc_now(),
                    detail={"heartbeat": True, "message": "scan still running"},
                )

    async def cancel(self, scan_id: UUID) -> None:
        item = self._scans.get(scan_id)
        if item is None:
            raise ApiError(404, "unknown_scan", f"unknown scan: {scan_id}")
        if item.done.is_set():
            return
        item.cancel_requested = True
        item.cancel_event.set()
        # The engine checks for cancellation between stages. Wait a short grace
        # period for that checkpoint; the worker's own outcome is kept if it arrives.
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(item.done.wait(), timeout=_CANCEL_GRACE_S)
        if item.done.is_set():
            return
        # The worker is stuck in a long call. Record the cancellation now so the
        # client is not left waiting. Its later writes are ignored by _finish, and
        # worker_running keeps a duplicate scan of the same path out until it exits.
        self._finish(item, ScanStatus.FAILED, stage=Stage.VERDICT)
        item.error = "cancelled by client"
        self._on_event(
            item,
            WSMessage(
                stage=Stage.VERDICT,
                skill=item.path.name,
                event=WSEventType.ERROR,
                ts=utc_now(),
                detail={"code": "cancelled", "message": "cancelled by client", "degraded": True},
            ),
        )
        item.done.set()
        item.changed.set()

    # -- meta / health -----------------------------------------------------
    async def health(self) -> HealthResponse:
        db_ok = False
        try:
            store = self.store
            db_ok = bool(await asyncio.to_thread(store.ping))
        except Exception:
            # Health is diagnostic: a broken database must produce "down", not
            # a 500 response that hides the rest of the system state.
            db_ok = False

        backend = await asyncio.to_thread(self._active_backend)
        ollama_ok = False
        if backend in {"mock", "demo"}:
            ollama_ok = True
        elif backend in {"ollama", "local"}:
            # Same readiness test as the model layer: the server answers and the
            # configured model is pulled.  "ready" is the only state reported as ok.
            with contextlib.suppress(Exception):
                ollama_ok = await asyncio.to_thread(_ollama_ready, self.config)
        elif backend == "cloud":
            with contextlib.suppress(Exception):
                from skill_sentry_cli.core.models.selector import select_model

                model = select_model(self.config, probe=False)
                ollama_ok = bool(await asyncio.to_thread(model.health))

        docker_ok = False
        with contextlib.suppress(Exception):
            from skill_sentry_cli.core.sandbox.runner import SandboxConfig, SandboxRunner

            runner = SandboxRunner(config=SandboxConfig(image=self.config.sandbox.base_image))
            try:
                docker_ok = await asyncio.to_thread(runner.available)
            finally:
                runner.close()
        return HealthResponse(
            ollama="ok" if ollama_ok else "down",
            docker="ok" if docker_ok else "down",
            db="ok" if db_ok else "down",
            demo_mode=False,
        )

    def _active_backend(self) -> str:
        """Report the model identity this backend will actually use.

        An injected engine may be running ``MockGemma`` even when the TOML says
        ``auto``; re-running selection here would lie about that.  Only fall
        back to configuration when there is no engine to inspect.
        """

        # Do not trigger a real health probe/selection from a status endpoint.
        # If a model has already been selected (including an injected one),
        # report it; otherwise fall back to configuration.
        if self._engine is not None and getattr(self._engine, "_model_selected", False):
            try:
                backend, _ = self._engine.model_identity()
                return backend
            except Exception:
                return "unavailable"
        try:
            from skill_sentry_cli.core.models.selector import select_model

            return str(select_model(self.config, probe=False).backend)
        except Exception:
            return "unavailable"

    async def meta(self) -> MetaResponse:
        backend = await asyncio.to_thread(self._active_backend)
        # Under ``auto`` with no model selected yet, the unprobed selection assumes
        # local but a scan may fall back to cloud.  Do not let the badge claim local
        # for that case; report it as unknown instead.
        selected = self._engine is not None and getattr(self._engine, "_model_selected", False)
        badge_source = backend if selected or self.config.model.backend != "auto" else "auto"
        return MetaResponse(
            version=__version__,
            backend_active=backend,
            gemma_badge=badge_for_backend(badge_source),
            demo_mode=False,
            contract_version=CONTRACT_VERSION,
        )

    async def cache_stats(self) -> CacheStatsResponse:
        entries, hit_rate = await asyncio.to_thread(self.store.cache_stats)
        size = await asyncio.to_thread(lambda: self.store.size_bytes)
        model_version = "unavailable"
        if self._engine is not None and getattr(self._engine, "_model_selected", False):
            with contextlib.suppress(Exception):
                _backend, model_version = self._engine.model_identity()
        else:
            with contextlib.suppress(Exception):
                from skill_sentry_cli.core.models.selector import select_model

                model = select_model(self.config, probe=False)
                model_version = model.model_version
        return CacheStatsResponse(
            entries=entries,
            hit_rate=hit_rate,
            db_size_bytes=size if isinstance(size, int) else 0,
            engine_version=engine_version(self.config.scoring.weights),
            model_version=model_version,
        )

    async def clear_cache(self, older_than: str | None = None) -> DeleteCacheResponse:
        try:
            deleted, retained = await asyncio.to_thread(self.store.clear_cache, older_than)
        except StoreError as exc:
            # The store raises StoreError only for an unreadable duration. Any other
            # failure is a server fault and must surface as a 500, not a client error.
            raise ApiError(422, "invalid_duration", str(exc), degraded=True) from exc
        return DeleteCacheResponse(deleted=deleted, retained=retained)

    def export(self, skill_id: UUID, fmt: ExportFormat) -> RenderedReport:
        stored = self.store.get_result_for_skill(skill_id)
        if stored is None:
            raise ApiError(404, "unknown_scan", f"unknown skill: {skill_id}")
        verdict, _detail, stages, _cached = stored
        try:
            return render_report(verdict, fmt, stage_results=stages)
        except NoIOCsError as exc:
            raise ApiError(
                409,
                "no_iocs",
                "STIX export requires an active-defense scan with confirmed IOCs",
                stage=Stage.POISONED_WELL,
            ) from exc


def _key_finding(verdict: Verdict) -> str | None:
    for finding in sorted(verdict.findings, key=lambda item: -item.severity.rank):
        if finding.severity.rank > 0:
            return finding.message
    return None


__all__ = ["LiveBackend"]
