"""Provider presets and the settings that describe an OpenAI-compatible server.

A preset fills in the address and the name of the environment variable that holds the key.
It never holds a key. API keys are read from the environment, at request time, and are not
written to a configuration file, a log, an error message, a report or the cache.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
# Prefixes that real keys start with. A value that starts with one is a pasted key.
_KEY_PREFIXES = ("sk-", "sk_", "gsk_", "nvapi-", "aiza", "ghp_", "github_pat_", "hf_", "xai-")
_SECRET_HEADERS = frozenset(
    {"authorization", "proxy-authorization", "x-api-key", "api-key", "x-goog-api-key", "cookie"}
)
LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "0.0.0.0", "host.docker.internal"})


@dataclass(frozen=True)
class Preset:
    """A named provider: where it is and which environment variable holds its key."""

    name: str
    label: str
    base_url: str
    api_key_env: str
    headers: tuple[tuple[str, str], ...] = ()


PRESETS: dict[str, Preset] = {
    "openrouter": Preset(
        "openrouter",
        "OpenRouter",
        "https://openrouter.ai/api/v1",
        "OPENROUTER_API_KEY",
        (("X-Title", "SkillSentry"),),
    ),
    "nim": Preset("nim", "NVIDIA NIM", "https://integrate.api.nvidia.com/v1", "NVIDIA_API_KEY"),
    "groq": Preset("groq", "Groq", "https://api.groq.com/openai/v1", "GROQ_API_KEY"),
}
# Backend names that select an OpenAI-compatible server; "openai" has no preset and needs a base_url.
PROVIDER_BACKENDS = frozenset({"openai", *PRESETS})
STRUCTURED_MODES = ("auto", "json_schema", "json_object", "prompt")


def check_env_name(value: str) -> str:
    """``api_key_env`` is the NAME of an environment variable. Refuse anything that looks like a key."""

    value = value.strip()
    if not value:
        return value
    lowered = value.lower()
    if not _ENV_NAME.match(value) or lowered.startswith(_KEY_PREFIXES) or len(value) > 48:
        raise ValueError(
            "api_key_env must be the name of an environment variable (for example "
            "OPENROUTER_API_KEY), not the key itself. Keys are never stored in the configuration file"
        )
    return value


def check_headers(headers: dict[str, str]) -> dict[str, str]:
    """Extra headers are for non-secret values such as OpenRouter's referer and title."""

    for name, value in headers.items():
        if name.strip().lower() in _SECRET_HEADERS:
            raise ValueError(
                f"header {name!r} may not be set in the configuration file; keys come from the "
                "environment variable named by api_key_env"
            )
        if any(value.lower().startswith(prefix) for prefix in _KEY_PREFIXES):
            raise ValueError(
                f"header {name!r} looks like it holds a key; keys are never stored here"
            )
    return headers


def is_local_url(base_url: str) -> bool:
    """True for a server on this machine, where no key is needed and no content leaves it."""

    host = (urlsplit(base_url).hostname or "").lower()
    return host in LOCAL_HOSTS or host.endswith(".localhost")


@dataclass
class ResolvedProvider:
    """The settings of one provider after the preset is applied."""

    backend: (
        str  # the name the rest of the program sees: openrouter, nim, groq, openai, openai-local
    )
    label: str
    base_url: str
    model: str
    api_key_env: str
    headers: dict[str, str] = field(default_factory=dict)
    local: bool = False

    @property
    def api_key(self) -> str:
        """The key, read from the environment now. Empty when none is set."""

        return os.environ.get(self.api_key_env, "").strip() if self.api_key_env else ""

    @property
    def needs_key(self) -> bool:
        return not self.local and bool(self.api_key_env)


def resolve_provider(settings: Any, backend: str) -> ResolvedProvider:
    """Apply a preset (if ``backend`` names one) to ``settings.provider``.

    Raises ``ValueError`` with a message that says which setting is missing.
    """

    provider = settings.provider
    preset = PRESETS.get(backend)
    base_url = (provider.base_url or (preset.base_url if preset else "")).strip()
    if not base_url:
        raise ValueError(
            "the openai backend needs a server address: set [model.provider] base_url "
            "(or use a preset: openrouter, nim, groq)"
        )
    model = provider.model.strip()
    if not model:
        raise ValueError(f"set [model.provider] model to the id of the model {backend} should use")
    local = is_local_url(base_url)
    host = urlsplit(base_url).hostname or base_url
    if local:
        name, label = "openai-local", host
    elif preset:
        name, label = preset.name, preset.label
    else:
        name, label = "openai", host
    headers = {**dict(preset.headers if preset else ()), **provider.headers}
    return ResolvedProvider(
        backend=name,
        label=label,
        base_url=base_url,
        model=model,
        api_key_env=provider.api_key_env or (preset.api_key_env if preset else ""),
        headers=headers,
        local=local,
    )
