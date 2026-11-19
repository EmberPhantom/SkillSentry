"""Backend selection for model clients (I2).

Selection order is local -> cloud (only when ``GEMINI_API_KEY`` is configured)
-> demo.  Explicit ``local``/``cloud`` requests fail closed when their health
probe fails; no path silently substitutes a mock model for a real one.
"""

from __future__ import annotations

from typing import Any

from skill_sentry_cli.core.config import ModelSettings, SkillsEntryConfig
from skill_sentry_cli.core.contracts import Backend
from skill_sentry_cli.core.models.base import ModelClient, ModelUnavailable
from skill_sentry_cli.core.models.gemma_cloud import GemmaCloud
from skill_sentry_cli.core.models.gemma_local import GemmaLocal
from skill_sentry_cli.core.models.mock import MockGemma
from skill_sentry_cli.core.models.openai_compat import OpenAICompat
from skill_sentry_cli.core.models.providers import PROVIDER_BACKENDS, resolve_provider


def select_model(
    config: SkillsEntryConfig | ModelSettings | None = None,
    *,
    backend: str | Backend | None = None,
    probe: bool = True,
    local_client: ModelClient | None = None,
    cloud_client: ModelClient | None = None,
    provider_client: ModelClient | None = None,
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
    if choice in PROVIDER_BACKENDS:
        # An OpenAI-compatible server, chosen on purpose: it is never a silent fallback,
        # because a remote one receives the skill's content.
        client = provider_client or _provider_client(settings, choice)
        if not _configured(client):
            variable = getattr(client, "key_variable", "") or settings.provider.api_key_env
            raise ModelUnavailable(
                f"{variable or 'the API key variable'} is not set "
                f"(it holds the key for the {choice} backend)"
            )
        if probe and not _healthy(client):
            raise ModelUnavailable(
                getattr(client, "last_health_error", None) or f"{choice} is not reachable"
            )
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
        "nvidia": "nim",
        "openai-compatible": "openai",
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


def _provider_client(settings: ModelSettings, choice: str) -> ModelClient:
    provider = resolve_provider(settings, choice)
    return OpenAICompat(
        provider,
        timeout_s=settings.request_timeout_s,
        max_px=settings.image_max_px,
        max_tokens=settings.provider.max_tokens,
        structured_output=settings.provider.structured_output,
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
