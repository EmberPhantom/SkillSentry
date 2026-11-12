"""The privacy badge must follow the analysis backend that actually runs."""

from __future__ import annotations

import asyncio

import pytest
from skill_sentry_cli.cli import _banner
from skill_sentry_cli.core.config import SkillsEntryConfig
from skill_sentry_cli.core.version import (
    CLOUD_BADGE,
    GEMMA_BADGE,
    UNKNOWN_BADGE,
    badge_for_backend,
)
from skill_sentry_cli.server.demo_backend import DemoBackend
from skill_sentry_cli.server.live_backend import LiveBackend


@pytest.mark.parametrize("backend", ["ollama", "local", "mock", "demo"])
def test_local_and_mock_backends_keep_the_local_badge(backend):
    assert badge_for_backend(backend) == GEMMA_BADGE


@pytest.mark.parametrize("backend", ["cloud", "gemini-api"])
def test_cloud_backend_discloses_code_leaving_the_machine(backend):
    badge = badge_for_backend(backend)
    assert badge == CLOUD_BADGE
    assert "Fully local" not in badge
    assert "Gemini API" in badge


@pytest.mark.parametrize("backend", ["auto", "unavailable", "", None, "something-new"])
def test_unknown_or_ambiguous_backends_never_claim_local(backend):
    assert badge_for_backend(backend) == UNKNOWN_BADGE


def test_cli_banner_follows_the_backend_flag():
    assert "Fully local" not in _banner("cloud")
    assert CLOUD_BADGE in _banner("cloud")
    assert GEMMA_BADGE in _banner("local")
    assert UNKNOWN_BADGE in _banner("auto")


def test_demo_meta_keeps_local_badge():
    meta = asyncio.run(DemoBackend().meta())
    assert meta.gemma_badge == GEMMA_BADGE


def test_live_meta_reports_cloud_badge_when_cloud_is_active(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    config = SkillsEntryConfig()
    config.model.backend = "cloud"
    meta = asyncio.run(LiveBackend(config=config).meta())
    assert meta.backend_active == "gemini-api"
    assert meta.gemma_badge == CLOUD_BADGE


def test_live_meta_does_not_claim_local_for_unselected_auto_backend():
    # Under auto, an unprobed selection assumes local but a scan may fall back to cloud.
    config = SkillsEntryConfig()
    config.model.backend = "auto"
    meta = asyncio.run(LiveBackend(config=config).meta())
    assert meta.gemma_badge == UNKNOWN_BADGE
