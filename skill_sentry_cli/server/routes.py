"""Shared REST + WebSocket routes (used by demo and live backends)."""

from __future__ import annotations

import asyncio
from contextlib import suppress
from uuid import UUID

from fastapi import APIRouter, Query, Request, Response, WebSocket, WebSocketDisconnect

from skill_sentry_cli.core.contracts import (
    CacheStatsResponse,
    DeleteCacheResponse,
    ErrorResponse,
    ExportFormat,
    HealthResponse,
    MetaResponse,
    ScanListResponse,
    ScanRequest,
    ScanStartResponse,
    ScanStatus,
    ScanStatusResponse,
    SkillDetail,
    Stage,
    VerdictsResponse,
    WSEventType,
    WSMessage,
    utc_now,
)
from skill_sentry_cli.server.backend import ScanBackend
from skill_sentry_cli.server.errors import ApiError

router = APIRouter()

# After a client cancel, how long the socket keeps delivering events that were
# already produced (including the backend's "cancelled" ERROR) before it closes.
_CANCEL_DRAIN_S = 2.5


def _backend(request: Request) -> ScanBackend:
    return request.app.state.backend


@router.post("/scan", response_model=ScanStartResponse, status_code=202)
async def start_scan(payload: ScanRequest, request: Request) -> ScanStartResponse:
    return await _backend(request).start_scan(payload)


@router.get("/scans", response_model=ScanListResponse)
async def list_scans(
    request: Request,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    status: ScanStatus | None = Query(default=None),
) -> ScanListResponse:
    return await _backend(request).list_scans(limit=limit, offset=offset, status=status)


@router.get("/scan/{scan_id}", response_model=ScanStatusResponse)
async def get_scan(scan_id: UUID, request: Request) -> ScanStatusResponse:
    return await _backend(request).get_scan(scan_id)


@router.get("/scan/{scan_id}/verdicts", response_model=VerdictsResponse)
async def get_verdicts(scan_id: UUID, request: Request) -> VerdictsResponse:
    return await _backend(request).get_verdicts(scan_id)


@router.get("/skills/{skill_id}", response_model=SkillDetail)
async def get_skill(skill_id: UUID, request: Request) -> SkillDetail:
    return await _backend(request).get_skill(skill_id)


@router.get("/skills/{skill_id}/export")
async def export_skill(
    skill_id: UUID,
    request: Request,
    fmt: ExportFormat = Query(..., alias="format"),
) -> Response:
    # Rendering reads the store and can be slow; keep it off the event loop.
    report = await asyncio.to_thread(_backend(request).export, skill_id, fmt)
    return Response(
        content=report.content,
        media_type=report.media_type,
        headers={"Content-Disposition": f'attachment; filename="{report.filename}"'},
    )


@router.get("/cache/stats", response_model=CacheStatsResponse)
async def cache_stats(request: Request) -> CacheStatsResponse:
    return await _backend(request).cache_stats()


@router.delete("/cache", response_model=DeleteCacheResponse)
async def clear_cache(
    request: Request,
    older_than: str | None = Query(default=None),
) -> DeleteCacheResponse:
    return await _backend(request).clear_cache(older_than)


@router.get("/health", response_model=HealthResponse)
async def health(request: Request) -> HealthResponse:
    return await _backend(request).health()


@router.get("/meta", response_model=MetaResponse)
async def meta(request: Request) -> MetaResponse:
    return await _backend(request).meta()


@router.websocket("/scan/{scan_id}/stream")
async def scan_stream(websocket: WebSocket, scan_id: UUID) -> None:
    await websocket.accept()
    backend: ScanBackend = websocket.app.state.backend
    cancel = asyncio.Event()

    async def client_reader() -> None:
        try:
            while True:
                message = await websocket.receive_json()
                if isinstance(message, dict) and message.get("op") == "cancel":
                    cancel.set()
                    return
        except (WebSocketDisconnect, RuntimeError, ValueError):
            return

    reader = asyncio.create_task(client_reader())
    events = backend.stream(scan_id)
    queue: asyncio.Queue[WSMessage | None] = asyncio.Queue(maxsize=64)

    def error_message(exc: ApiError) -> WSMessage:
        error: ErrorResponse = exc.to_response()
        return WSMessage(
            stage=exc.stage or Stage.VERDICT,
            skill="",
            event=WSEventType.ERROR,
            ts=utc_now(),
            detail=error.model_dump(by_alias=True, mode="json")["error"],
        )

    async def pump() -> None:
        """Move backend events into a queue without cancelling the generator.

        ``asyncio.wait_for(agen.__anext__(), ...)`` closes async generators
        when it times out, which truncates slow stages.  The queue lets the
        route poll for client cancellation while the producer runs freely.
        """
        try:
            async for message in events:
                await queue.put(message)
        except ApiError as exc:
            await queue.put(error_message(exc))
        except Exception as exc:
            await queue.put(
                error_message(
                    ApiError(
                        500,
                        "internal_error",
                        f"stream failed: {exc}",
                        degraded=True,
                    )
                )
            )
        finally:
            await queue.put(None)

    async def _drain_after_cancel() -> None:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + _CANCEL_DRAIN_S
        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                return
            try:
                message = await asyncio.wait_for(queue.get(), timeout=remaining)
            except TimeoutError:
                return
            if message is None:
                return
            await websocket.send_json(message.model_dump(by_alias=True, mode="json"))

    producer = asyncio.create_task(pump())
    try:
        while not cancel.is_set():
            try:
                message = await asyncio.wait_for(queue.get(), timeout=0.25)
            except TimeoutError:
                continue
            if message is None:
                break
            await websocket.send_json(message.model_dump(by_alias=True, mode="json"))
        if cancel.is_set():
            with suppress(ApiError):
                await backend.cancel(scan_id)
            # Deliver what the backend recorded for the cancel (the "cancelled" ERROR)
            # before closing, instead of dropping the queue.
            await _drain_after_cancel()
    except WebSocketDisconnect:
        pass
    finally:
        reader.cancel()
        with suppress(asyncio.CancelledError):
            await reader
        producer.cancel()
        with suppress(asyncio.CancelledError):
            await producer
        with suppress(Exception):
            await events.aclose()
        with suppress(RuntimeError):
            await websocket.close()


__all__ = ["router"]
