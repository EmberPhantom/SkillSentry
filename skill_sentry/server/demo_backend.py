"""In-memory demo backend — serves the canned 7-skill store.

No Docker, no model, no database.  Responses are schema-identical to the live
server so Dev 3 can switch by base URL only.
"""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

from skill_sentry.core.contracts import (
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
    VerdictsResponse,
    WSEventType,
    WSMessage,
)
from skill_sentry.core.models.mock import MockGemma
from skill_sentry.core.reports import RenderedReport, render_report
from skill_sentry.core.verdict.stix_report import NoIOCsError
from skill_sentry.core.version import CONTRACT_VERSION, GEMMA_BADGE, __version__, engine_version
from skill_sentry.server.demo_data import DEMO_STARTED_AT, DemoSkill, build_demo_store
from skill_sentry.server.errors import ApiError


@dataclass
class _DemoScan:
    scan_id: UUID
    items: list[DemoSkill]
    started_at: datetime
    cached: bool
    status: ScanStatus = ScanStatus.QUEUED
    current_stage: Stage | None = None
    elapsed_ms: int = 0
    error: str | None = None
    events: list[WSMessage] = field(default_factory=list)


class DemoBackend:
    demo_mode = True

    def __init__(self, *, speed: float | None = None) -> None:
        self._store = build_demo_store()
        self._by_skill_id = {item.skill_id: item for item in self._store}
        self._by_scan_id = {item.scan_id: item for item in self._store}
        self._by_name = {item.name: item for item in self._store}
        self._scans: dict[UUID, _DemoScan] = {}
        self._completed: set[str] = set()
        if speed is None:
            speed = float(os.getenv("SKILLSENTRY_DEMO_SPEED", "1"))
        self._speed = max(0.0, speed)

    # -- lifecycle ----------------------------------------------------------
    async def start_scan(self, request: ScanRequest) -> ScanStartResponse:
        items = self._items_for(request.path)
        no_cache = request.options.no_cache
        cached = not no_cache and all(item.name in self._completed for item in items)

        scan_id = uuid4()
        started_at = datetime.now(UTC)
        scan = _DemoScan(
            scan_id=scan_id,
            items=items,
            started_at=started_at,
            cached=cached,
        )
        scan.events = self._build_events(scan)
        self._scans[scan_id] = scan
        return ScanStartResponse(
            scan_id=scan_id,
            status=ScanStatus.QUEUED,
            stream=f"/scan/{scan_id}/stream",
        )

    def _items_for(self, path: str | None) -> list[DemoSkill]:
        if not path:
            return list(self._store)
        name = Path(path).name.lower()
        if name in self._by_name:
            return [self._by_name[name]]
        lowered = path.lower()
        matches = [item for item in self._store if item.name in lowered]
        if len(matches) == 1:
            return matches
        raise ApiError(
            404,
            "no_skill_manifest",
            f"demo store has no skill matching path: {path}",
            stage=Stage.SPEC,
        )

    async def get_scan(self, scan_id: UUID) -> ScanStatusResponse:
        scan = self._scans.get(scan_id)
        if scan is not None:
            elapsed = scan.elapsed_ms
            if scan.status is ScanStatus.RUNNING:
                elapsed = int((datetime.now(UTC) - scan.started_at).total_seconds() * 1000)
            return ScanStatusResponse(
                scan_id=scan.scan_id,
                status=scan.status,
                stage=scan.current_stage,
                skill=scan.items[0].name if len(scan.items) == 1 else None,
                started_at=scan.started_at,
                elapsed_ms=elapsed,
                error=scan.error,
            )

        item = self._by_scan_id.get(scan_id)
        if item is not None:
            return ScanStatusResponse(
                scan_id=item.scan_id,
                status=ScanStatus.COMPLETED,
                stage=Stage.VERDICT,
                skill=item.name,
                started_at=DEMO_STARTED_AT,
                elapsed_ms=item.verdict.scan_duration_ms,
            )
        raise ApiError(404, "unknown_scan", f"unknown scan: {scan_id}")

    async def get_verdicts(self, scan_id: UUID) -> VerdictsResponse:
        scan = self._scans.get(scan_id)
        if scan is not None:
            return VerdictsResponse(
                scan_id=scan_id,
                verdicts=[
                    item.verdict_for_scan(scan_id, cached=scan.cached) for item in scan.items
                ],
            )
        item = self._by_scan_id.get(scan_id)
        if item is not None:
            return VerdictsResponse(scan_id=scan_id, verdicts=[item.verdict])
        raise ApiError(404, "unknown_scan", f"unknown scan: {scan_id}")

    async def list_scans(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        status: ScanStatus | None = None,
    ) -> ScanListResponse:
        summaries: list[ScanSummary] = []
        for index, item in enumerate(self._store):
            summaries.append(
                ScanSummary(
                    scan_id=item.scan_id,
                    skill_id=item.skill_id,
                    skill=item.name,
                    verdict=item.verdict.verdict,
                    risk_score=item.verdict.risk_score,
                    cached=False,
                    status=ScanStatus.COMPLETED,
                    started_at=DEMO_STARTED_AT + timedelta(seconds=index * 4),
                    duration_ms=item.verdict.scan_duration_ms,
                    key_finding=item.key_finding,
                )
            )
        # New demo runs are appended (a batch contributes one row per skill).
        for scan in self._scans.values():
            for item in scan.items:
                summaries.append(
                    ScanSummary(
                        scan_id=scan.scan_id,
                        skill_id=item.skill_id,
                        skill=item.name,
                        verdict=item.verdict.verdict,
                        risk_score=item.verdict.risk_score,
                        cached=scan.cached,
                        status=scan.status,
                        started_at=scan.started_at,
                        duration_ms=item.verdict.scan_duration_ms,
                        key_finding=item.key_finding,
                    )
                )
        if status is not None:
            summaries = [row for row in summaries if row.status is status]
        return ScanListResponse(scans=summaries[offset : offset + limit])

    async def get_skill(self, skill_id: UUID) -> SkillDetail:
        item = self._by_skill_id.get(skill_id) or self._by_scan_id.get(skill_id)
        if item is None:
            scan = self._scans.get(skill_id)
            if scan is not None and len(scan.items) == 1:
                item = scan.items[0]
        if item is None:
            raise ApiError(404, "unknown_scan", f"unknown skill: {skill_id}")
        return item.detail()

    # -- streaming ----------------------------------------------------------
    async def stream(self, scan_id: UUID):
        scan = self._scans.get(scan_id)
        if scan is None:
            raise ApiError(404, "unknown_scan", f"unknown scan: {scan_id}")
        scan.status = ScanStatus.RUNNING
        for message in scan.events:
            heartbeat = bool(message.detail and message.detail.get("heartbeat"))
            delay = (1.2 if heartbeat else 0.12) * self._speed
            if delay:
                await asyncio.sleep(delay)
            scan.current_stage = message.stage
            offset_ms = int((message.ts - scan.started_at).total_seconds() * 1000)
            scan.elapsed_ms = max(scan.elapsed_ms, offset_ms)
            yield message
        scan.status = ScanStatus.CACHED_HIT if scan.cached else ScanStatus.COMPLETED
        scan.current_stage = Stage.VERDICT
        for item in scan.items:
            self._completed.add(item.name)

    async def cancel(self, scan_id: UUID) -> None:
        scan = self._scans.get(scan_id)
        if scan is None:
            raise ApiError(404, "unknown_scan", f"unknown scan: {scan_id}")
        scan.status = ScanStatus.FAILED
        scan.error = "cancelled by client"

    # -- meta / health ------------------------------------------------------
    async def health(self) -> HealthResponse:
        return HealthResponse(ollama="ok", docker="ok", db="ok", demo_mode=True)

    async def meta(self) -> MetaResponse:
        return MetaResponse(
            version=__version__,
            backend_active="demo",
            gemma_badge=GEMMA_BADGE,
            demo_mode=True,
            contract_version=CONTRACT_VERSION,
        )

    async def cache_stats(self) -> CacheStatsResponse:
        entries = len(self._store)
        hit_rate = len(self._completed) / entries if entries else 0.0
        return CacheStatsResponse(
            entries=entries,
            hit_rate=round(hit_rate, 3),
            db_size_bytes=245_760,
            engine_version=engine_version(),
            model_version=MockGemma.model_version,
        )

    async def clear_cache(self, older_than: str | None = None) -> DeleteCacheResponse:
        del older_than
        deleted = len(self._completed)
        self._completed.clear()
        return DeleteCacheResponse(deleted=deleted, retained=0)

    def export(self, skill_id: UUID, fmt: ExportFormat) -> RenderedReport:
        item = self._by_skill_id.get(skill_id) or self._by_scan_id.get(skill_id)
        if item is None:
            raise ApiError(404, "unknown_scan", f"unknown skill: {skill_id}")
        try:
            return render_report(item.verdict, fmt)
        except NoIOCsError as exc:
            raise ApiError(
                409,
                "no_iocs",
                "STIX export requires an active-defense scan with confirmed IOCs",
                stage=Stage.POISONED_WELL,
            ) from exc

    # -- event generation ---------------------------------------------------
    def _build_events(self, scan: _DemoScan) -> list[WSMessage]:
        events: list[WSMessage] = []
        offset = 0

        def add(
            stage: Stage,
            event: WSEventType,
            detail: dict | None = None,
            *,
            delta: int = 120,
            skill: str | None = None,
        ) -> None:
            nonlocal offset
            offset += delta
            events.append(
                WSMessage(
                    stage=stage,
                    skill=skill or scan.items[0].name,
                    event=event,
                    ts=scan.started_at + timedelta(milliseconds=offset),
                    detail=detail,
                )
            )

        if scan.cached:
            for item in scan.items:
                add(
                    Stage.CACHE,
                    WSEventType.CACHED,
                    {
                        "message": "cached verdict",
                        "durationMs": 1180,
                        "hash": f"{item.skill_id.hex[:12]}…",
                    },
                    delta=60,
                    skill=item.name,
                )
                add(
                    Stage.VERDICT,
                    WSEventType.COMPLETED,
                    {
                        "verdict": item.verdict_for_scan(scan.scan_id, cached=True).model_dump(
                            by_alias=True, mode="json"
                        )
                    },
                    delta=80,
                    skill=item.name,
                )
            return events

        for item in scan.items:
            verdict = item.verdict_for_scan(scan.scan_id, cached=False)
            active = verdict.active_defense
            add(
                Stage.CACHE,
                WSEventType.PROGRESS,
                {"message": "cache miss", "hash": f"{item.skill_id.hex[:12]}…"},
                skill=item.name,
            )
            add(
                Stage.SPEC,
                WSEventType.PROGRESS,
                {"message": "frontmatter valid · typosquat check: clean"},
                skill=item.name,
            )

            for finding in verdict.findings:
                if finding.stage is Stage.DETERMINISTIC_ANCHOR:
                    add(
                        Stage.DETERMINISTIC_ANCHOR,
                        WSEventType.FINDING,
                        {"finding": finding.model_dump(by_alias=True, mode="json")},
                        delta=90,
                        skill=item.name,
                    )

            add(
                Stage.SEMANTIC,
                WSEventType.STARTED,
                {"message": "Gemma analyzing…"},
                skill=item.name,
            )
            add(
                Stage.SEMANTIC,
                WSEventType.PROGRESS,
                {"heartbeat": True, "message": "waiting on model…"},
                delta=1500,
                skill=item.name,
            )
            for finding in verdict.findings:
                if finding.stage is Stage.SEMANTIC:
                    add(
                        Stage.SEMANTIC,
                        WSEventType.FINDING,
                        {"finding": finding.model_dump(by_alias=True, mode="json")},
                        delta=120,
                        skill=item.name,
                    )
            add(
                Stage.SEMANTIC,
                WSEventType.COMPLETED,
                {"declaredIntent": (active.declared_intent if active else None) or "Not available"},
                delta=140,
                skill=item.name,
            )

            if item.vision_evidence:
                vision = item.vision_evidence[0]
                add(
                    Stage.VISION,
                    WSEventType.PROGRESS,
                    {"message": f"scanning {vision.image_name or 'image'}"},
                    skill=item.name,
                )
                for finding in verdict.findings:
                    if finding.stage is Stage.VISION:
                        add(
                            Stage.VISION,
                            WSEventType.FINDING,
                            {
                                "finding": finding.model_dump(by_alias=True, mode="json"),
                                "bbox": vision.bboxes[0] if vision.bboxes else None,
                                "ocr": vision.ocr,
                            },
                            delta=200,
                            skill=item.name,
                        )
            else:
                add(
                    Stage.VISION,
                    WSEventType.PROGRESS,
                    {"message": "no bundled images"},
                    delta=60,
                    skill=item.name,
                )

            add(
                Stage.SANDBOX,
                WSEventType.STARTED,
                {"message": "container up · 512 MB · 1 CPU · 60 s"},
                delta=180,
                skill=item.name,
            )
            for finding in verdict.findings:
                if finding.stage is Stage.SANDBOX:
                    add(
                        Stage.SANDBOX,
                        WSEventType.FINDING,
                        {"finding": finding.model_dump(by_alias=True, mode="json")},
                        delta=220,
                        skill=item.name,
                    )

            if active and active.triggered:
                add(
                    Stage.POISONED_WELL,
                    WSEventType.OVERRIDE,
                    {
                        "kind": "poisoned_well",
                        "message": "CANARY MARKER DECODED → CONFIRMED",
                        "marker": active.canary_marker,
                        "c2": active.c2_indicators,
                        "declaredIntent": active.declared_intent,
                        "contextAwareCanary": (
                            active.context_aware_canary.value
                            if active.context_aware_canary
                            else None
                        ),
                    },
                    delta=260,
                    skill=item.name,
                )

            if active and active.sandbox_evasion_detected:
                add(
                    Stage.EVASION,
                    WSEventType.OVERRIDE,
                    {
                        "kind": "evasion",
                        "message": "SANDBOX EVASION DETECTED",
                        "probes": ["/.dockerenv"],
                    },
                    delta=140,
                    skill=item.name,
                )

            add(
                Stage.VERDICT,
                WSEventType.COMPLETED,
                {
                    "verdict": verdict.model_dump(by_alias=True, mode="json"),
                    "durationMs": verdict.scan_duration_ms,
                },
                delta=160,
                skill=item.name,
            )
        return events


__all__ = ["DemoBackend"]
