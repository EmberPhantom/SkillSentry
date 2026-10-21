"""Live backend placeholder.

The route layer and contracts are ready; the analysis pipeline is delivered by
CL-D1-2..5.  Until then the live server reports dependencies honestly and
refuses scans instead of fabricating a verdict (fail-safe rule).
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from uuid import UUID

import httpx

from skillsentry.core.config import SkillsEntryConfig, load_config
from skillsentry.core.contracts import (
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
    SkillDetail,
    VerdictsResponse,
    WSMessage,
)
from skillsentry.core.models.mock import MockGemma
from skillsentry.core.reports import RenderedReport
from skillsentry.core.version import CONTRACT_VERSION, GEMMA_BADGE, __version__, engine_version
from skillsentry.server.errors import ApiError

_ENGINE_NOT_READY = (
    "The live analysis pipeline is not wired yet (CL-D1-2..5). "
    "Run `skillsentry serve --demo-mode` for the frozen demo store."
)


class LiveBackend:
    demo_mode = False

    def __init__(self, config: SkillsEntryConfig | None = None) -> None:
        self.config = config or load_config()

    async def start_scan(self, request: ScanRequest) -> ScanStartResponse:
        del request
        raise ApiError(503, "engine_not_ready", _ENGINE_NOT_READY, degraded=True)

    async def get_scan(self, scan_id: UUID) -> ScanStatusResponse:
        raise ApiError(404, "unknown_scan", f"unknown scan: {scan_id}")

    async def get_verdicts(self, scan_id: UUID) -> VerdictsResponse:
        raise ApiError(404, "unknown_scan", f"unknown scan: {scan_id}")

    async def list_scans(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        status: ScanStatus | None = None,
    ) -> ScanListResponse:
        del limit, offset, status
        return ScanListResponse(scans=[])

    async def get_skill(self, skill_id: UUID) -> SkillDetail:
        raise ApiError(404, "unknown_scan", f"unknown skill: {skill_id}")

    async def stream(self, scan_id: UUID) -> AsyncIterator[WSMessage]:
        raise ApiError(404, "unknown_scan", f"unknown scan: {scan_id}")
        # Unreachable yield marks this as an async generator so the route's
        # __anext__ call receives the structured error, not a coroutine.
        yield WSMessage.model_construct()  # pragma: no cover

    async def cancel(self, scan_id: UUID) -> None:
        raise ApiError(404, "unknown_scan", f"unknown scan: {scan_id}")

    async def health(self) -> HealthResponse:
        ollama = await self._ollama_health()
        docker = await asyncio.to_thread(self._docker_health)
        return HealthResponse(ollama=ollama, docker=docker, db="ok", demo_mode=False)

    async def meta(self) -> MetaResponse:
        return MetaResponse(
            version=__version__,
            backend_active=self.config.model.backend,
            gemma_badge=GEMMA_BADGE,
            demo_mode=False,
            contract_version=CONTRACT_VERSION,
        )

    async def cache_stats(self) -> CacheStatsResponse:
        return CacheStatsResponse(
            entries=0,
            hit_rate=0.0,
            db_size_bytes=0,
            engine_version=engine_version(self.config.scoring.weights),
            model_version=MockGemma.model_version,
        )

    async def clear_cache(self, older_than: str | None = None) -> DeleteCacheResponse:
        del older_than
        return DeleteCacheResponse(deleted=0, retained=0)

    def export(self, skill_id: UUID, fmt: ExportFormat) -> RenderedReport:
        del fmt
        raise ApiError(404, "unknown_scan", f"unknown skill: {skill_id}")

    # -- health probes ------------------------------------------------------
    async def _ollama_health(self) -> str:
        url = self.config.model.ollama_url.rstrip("/") + "/api/tags"
        try:
            async with httpx.AsyncClient(timeout=1.5) as client:
                response = await client.get(url)
            return "ok" if response.status_code == 200 else "down"
        except httpx.HTTPError:
            return "down"

    def _docker_health(self) -> str:
        try:
            import docker

            client = docker.from_env(timeout=2)
            client.ping()
            client.close()
            return "ok"
        except Exception:
            return "down"


__all__ = ["LiveBackend"]
