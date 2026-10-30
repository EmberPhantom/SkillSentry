"""Backend selection for model clients (I2).

Selection order is local -> cloud (only when ``GEMINI_API_KEY`` is configured)
-> demo.  Explicit ``local``/``cloud`` requests fail closed when their health
probe fails; no path silently substitutes a mock model for a real one.
"""

from __future__ import annotations

from typing import Any

from skillsentry.core.config import ModelSettings, SkillsEntryConfig
from skillsentry.core.contracts import Backend
from skillsentry.core.models.base import ModelClient, ModelUnavailable
from skillsentry.core.models.gemma_cloud import GemmaCloud
from skillsentry.core.models.gemma_local import GemmaLocal
from skillsentry.core.models.mock import MockGemma


def select_model(
    config: SkillsEntryConfig | ModelSettings | None = None,
    *,
    backend: str | Backend | None = None,
    probe: bool = True,
    local_client: ModelClient | None = None,
    cloud_client: ModelClient | None = None,
) -> ModelClient:
    """Return a ready model client or raise :class:`ModelUnavailable`.

    ``local_client`` / ``cloud_client`` are injection points for tests and for
    callers that already own a long-lived client.  ``probe=False`` skips the
    health call and is only appropriate when the caller performs its own
    readiness check before starting a scan.
    """

    settings = _model_settings(config)
    choice = _backend_value(backend if backend is not None else settings.backend)

    if choice == Backend.DEMO.value:
        return MockGemma()
    if choice == Backend.LOCAL.value:
        client = local_client or _local_client(settings)
        if probe and not _healthy(client):
            raise ModelUnavailable(f"local model is not reachable at {settings.ollama_url}")
        return client
    if choice == Backend.CLOUD.value:
        client = cloud_client or _cloud_client(settings)
        if not _configured(client):
            raise ModelUnavailable("GEMINI_API_KEY is not set")
        if probe and not _healthy(client):
            raise ModelUnavailable("cloud model is not reachable")
        return client
    if choice != Backend.AUTO.value:
        raise ValueError(f"unsupported model backend: {choice!r}")

    local = local_client or _local_client(settings)
    if not probe or _healthy(local):
        return local

    cloud = cloud_client or _cloud_client(settings)
    if _configured(cloud) and (not probe or _healthy(cloud)):
        return cloud
    raise ModelUnavailable(
        f"no model backend reachable (local: {settings.ollama_url}; "
        "cloud: GEMINI_API_KEY not configured or unreachable)"
    )


def _model_settings(
    config: SkillsEntryConfig | ModelSettings | None,
) -> ModelSettings:
    if config is None:
        return ModelSettings()
    if isinstance(config, ModelSettings):
        return config
    return config.model


def _backend_value(value: str | Backend) -> str:
    if isinstance(value, Backend):
        return value.value
    normalised = str(value).strip().lower()
    return {
        "gemini": Backend.CLOUD.value,
        "gemini-api": Backend.CLOUD.value,
        "ollama": Backend.LOCAL.value,
        "mock": Backend.DEMO.value,
    }.get(normalised, normalised)


def _local_client(settings: ModelSettings) -> ModelClient:
    return GemmaLocal(
        base_url=settings.ollama_url,
        model=settings.ollama_model,
        timeout_s=settings.request_timeout_s,
        max_px=settings.image_max_px,
        num_ctx=settings.ollama_num_ctx,
        num_predict=settings.ollama_num_predict,
        keep_alive=settings.ollama_keep_alive,
    )


def _cloud_client(settings: ModelSettings) -> ModelClient:
    return GemmaCloud(
        model=settings.gemini_model,
        timeout_s=settings.request_timeout_s,
        max_px=settings.image_max_px,
    )


def _healthy(client: Any) -> bool:
    try:
        return bool(client.health())
    except Exception:
        return False


def _configured(client: Any) -> bool:
    configured = getattr(client, "configured", True)
    return bool(configured)


__all__ = ["select_model"]
