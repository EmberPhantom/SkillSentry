"""Server backend interface.

The route layer is shared by ``demo_mode`` and the live engine: both implement
this protocol, so the contract-parity tests exercise identical handlers.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from typing import Protocol, runtime_checkable
from uuid import UUID

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
    SkillDetail,
    VerdictsResponse,
    WSMessage,
)
from skill_sentry_cli.core.reports import RenderedReport


@runtime_checkable
class ScanBackend(Protocol):
    demo_mode: bool

    async def start_scan(self, request: ScanRequest) -> ScanStartResponse: ...

    async def get_scan(self, scan_id: UUID) -> ScanStatusResponse: ...

    async def get_verdicts(self, scan_id: UUID) -> VerdictsResponse: ...

    async def list_scans(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        status: ScanStatus | None = None,
    ) -> ScanListResponse: ...

    async def get_skill(self, skill_id: UUID) -> SkillDetail: ...

    def stream(self, scan_id: UUID) -> AsyncGenerator[WSMessage, None]: ...

    async def cancel(self, scan_id: UUID) -> None: ...

    async def health(self) -> HealthResponse: ...

    async def meta(self) -> MetaResponse: ...

    async def cache_stats(self) -> CacheStatsResponse: ...

    async def clear_cache(self, older_than: str | None = None) -> DeleteCacheResponse: ...

    def export(self, skill_id: UUID, fmt: ExportFormat) -> RenderedReport: ...
