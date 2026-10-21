"""Demo backend lifecycle, cache behaviour, and error paths."""

from __future__ import annotations

from uuid import uuid4

import pytest
from skillsentry.core.contracts import ExportFormat, ScanOptions, ScanRequest, ScanStatus
from skillsentry.server.demo_backend import DemoBackend
from skillsentry.server.demo_data import build_demo_store
from skillsentry.server.errors import ApiError
from skillsentry.server.live_backend import LiveBackend


@pytest.mark.asyncio
async def test_single_skill_lifecycle_and_cache():
    backend = DemoBackend(speed=0)
    started = await backend.start_scan(
        ScanRequest(path="cloud-sync-pro", options=ScanOptions(no_cache=True))
    )
    assert started.status is ScanStatus.QUEUED
    assert (await backend.get_scan(started.scan_id)).status is ScanStatus.QUEUED

    events = [event async for event in backend.stream(started.scan_id)]
    assert events[-1].stage.value == "verdict"
    assert events[-1].event.value == "completed"
    assert (await backend.get_scan(started.scan_id)).status is ScanStatus.COMPLETED

    verdicts = await backend.get_verdicts(started.scan_id)
    assert len(verdicts.verdicts) == 1
    assert verdicts.verdicts[0].skill == "cloud-sync-pro"
    assert verdicts.verdicts[0].scan_id == started.scan_id

    detail = await backend.get_skill(started.scan_id)  # scan id convenience lookup
    assert detail.verdict.risk_score == 97
    assert detail.poisoned_well.confirmed is True

    stats = await backend.cache_stats()
    assert stats.entries == 7
    assert 0.0 < stats.hit_rate <= 1.0

    cached = await backend.start_scan(ScanRequest(path="cloud-sync-pro"))
    cached_events = [event async for event in backend.stream(cached.scan_id)]
    assert cached_events[0].event.value == "cached"
    assert cached_events[-1].detail["verdict"]["cached"] is True
    assert cached_events[-1].detail["verdict"]["scanId"] == str(cached.scan_id)
    assert (await backend.get_scan(cached.scan_id)).status is ScanStatus.CACHED_HIT

    cleared = await backend.clear_cache()
    assert cleared.deleted >= 1
    assert (await backend.cache_stats()).hit_rate == 0.0


@pytest.mark.asyncio
async def test_batch_scan_and_pagination():
    backend = DemoBackend(speed=0)
    started = await backend.start_scan(ScanRequest(options=ScanOptions(no_cache=True)))
    await backend.cancel(started.scan_id)
    assert (await backend.get_scan(started.scan_id)).status is ScanStatus.FAILED

    listing = await backend.list_scans(limit=3, offset=0)
    assert len(listing.scans) == 3
    assert all(row.status is ScanStatus.COMPLETED for row in listing.scans)

    page_two = await backend.list_scans(limit=3, offset=3)
    assert {row.skill for row in page_two.scans}.isdisjoint({row.skill for row in listing.scans})


@pytest.mark.asyncio
async def test_unknown_path_and_scan_errors():
    backend = DemoBackend(speed=0)
    with pytest.raises(ApiError) as exc:
        await backend.start_scan(ScanRequest(path="not-a-skill"))
    assert exc.value.status_code == 404
    assert exc.value.code == "no_skill_manifest"

    with pytest.raises(ApiError) as exc:
        await backend.get_scan(uuid4())
    assert exc.value.code == "unknown_scan"

    with pytest.raises(ApiError) as exc:
        await backend.get_skill(uuid4())
    assert exc.value.code == "unknown_scan"


@pytest.mark.asyncio
async def test_cancel_marks_scan_failed():
    backend = DemoBackend(speed=0)
    started = await backend.start_scan(ScanRequest(path="pdf-summarizer"))
    await backend.cancel(started.scan_id)
    status = await backend.get_scan(started.scan_id)
    assert status.status is ScanStatus.FAILED
    assert status.error == "cancelled by client"


def test_stix_export_without_iocs_is_rejected():
    backend = DemoBackend(speed=0)
    benign = next(item for item in build_demo_store() if item.name == "pdf-summarizer")
    with pytest.raises(ApiError) as exc:
        backend.export(benign.skill_id, ExportFormat.STIX)
    assert exc.value.status_code == 409
    assert exc.value.code == "no_iocs"


@pytest.mark.asyncio
async def test_live_backend_refuses_scans_instead_of_fabricating_verdicts():
    backend = LiveBackend()
    with pytest.raises(ApiError) as exc:
        await backend.start_scan(ScanRequest(path="anything"))
    assert exc.value.status_code == 503
    assert exc.value.code == "engine_not_ready"
    assert exc.value.degraded is True
    assert (await backend.list_scans()).scans == []
    assert (await backend.meta()).demo_mode is False
