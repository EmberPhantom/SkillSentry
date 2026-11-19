"""Model profiles: the class of a model id, overrides, and what the client takes from them."""

from __future__ import annotations

import itertools

import pytest
from skill_sentry_cli.core.config import ModelSettings
from skill_sentry_cli.core.models.openai_compat import OpenAICompat
from skill_sentry_cli.core.models.profiles import (
    CLASSES,
    DEFAULT_PROFILE,
    PROFILES,
    classify,
    parameter_billions,
    resolve_profile,
)
from skill_sentry_cli.core.models.selector import profile_for, select_model

EXPECTED = {
    # tiny: under 5B
    "gemma3:1b": "tiny",
    "qwen2.5-coder:1.5b": "tiny",
    "llama3.2:3b": "tiny",
    "gemma4:e4b-it-qat": "tiny",
    # small: 5B to 13B
    "meta-llama/llama-3.1-8b-instruct": "small",
    "llama-3.1-8b-instant": "small",
    "mistralai/mistral-7b-instruct": "small",
    # mid: 14B to 40B
    "google/gemma-4-31b-it:free": "mid",
    "meta-llama/llama-4-scout-17b-16e-instruct": "mid",
    # large: 41B and up, and hosted frontier models
    "llama-3.3-70b-versatile": "large",
    "meta/llama-3.1-405b-instruct": "large",
    "gpt-4o": "large",
    "claude-3-5-sonnet": "large",
    "gemini-1.5-pro": "large",
    # reasoning
    "openai/gpt-oss-20b": "reasoning",
    "openai/gpt-oss-120b": "reasoning",
    "qwen3-32b": "reasoning",
    "qwen/qwen3-30b-a3b": "reasoning",
    "deepseek/deepseek-r1": "reasoning",
    "deepseek-r1:7b": "reasoning",
    "o3-mini": "reasoning",
    "gemini-2.5-flash": "reasoning",
    "nvidia/nemotron-3-ultra": "reasoning",
    # small by name, and the conservative default
    "gemini-2.5-flash-lite": "small",
    "gpt-4o-mini": "small",
    "unknown-model-x": "small",
    "": "small",
}


@pytest.mark.parametrize(("model_id", "expected"), list(EXPECTED.items()))
def test_a_model_id_maps_to_its_class(model_id: str, expected: str):
    assert classify(model_id) == expected, model_id


def test_the_default_for_an_unknown_model_is_the_conservative_one():
    assert DEFAULT_PROFILE == "small"
    assert classify("totally-new-model-2027") == "small"


@pytest.mark.parametrize(
    ("model_id", "size"),
    [
        ("gemma3:1b", 1.0),
        ("qwen2.5-coder:1.5b", 1.5),
        ("llama-3.3-70b-versatile", 70.0),
        ("qwen/qwen3-30b-a3b", 30.0),
        ("gemma4:e4b-it-qat", 4.0),
        ("gpt-4o", None),
    ],
)
def test_parameter_counts_are_read_from_the_name(model_id: str, size: float | None):
    assert parameter_billions(model_id) == size


def test_every_class_has_a_profile_and_sizes_grow_with_the_class():
    assert set(CLASSES) == set(PROFILES)
    order = ["tiny", "small", "mid", "large"]
    for lower, higher in itertools.pairwise(order):
        assert PROFILES[lower].context_tokens <= PROFILES[higher].context_tokens
        assert PROFILES[lower].chunk_chars <= PROFILES[higher].chunk_chars
        assert PROFILES[lower].max_output_tokens <= PROFILES[higher].max_output_tokens
    # A reasoning model needs the biggest output budget, and gets no automatic retry.
    assert PROFILES["reasoning"].max_output_tokens == max(
        p.max_output_tokens for p in PROFILES.values()
    )
    assert PROFILES["reasoning"].retries == 0
    assert PROFILES["tiny"].few_shot and not PROFILES["large"].few_shot


def test_a_named_class_wins_over_the_id():
    assert resolve_profile("gemma3:1b", name="large").name == "large"
    assert resolve_profile("gemma3:1b", name="auto").name == "tiny"


def test_an_unknown_class_name_is_refused():
    with pytest.raises(ValueError, match="unknown model profile"):
        resolve_profile("x", name="huge")


def test_overrides_replace_only_what_is_set():
    profile = resolve_profile("gemma3:1b", overrides={"max_chunks": 9, "chunk_chars": None})

    assert profile.max_chunks == 9
    assert profile.chunk_chars == PROFILES["tiny"].chunk_chars
    assert profile.name == "tiny"


# -- configuration and the client -----------------------------------------------------------------
def test_the_profile_settings_validate():
    assert ModelSettings().profile.name == "auto"
    with pytest.raises(ValueError, match="name must be"):
        ModelSettings(profile={"name": "huge"})  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        ModelSettings(profile={"max_chunks": 0})  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="structured_output"):
        ModelSettings(profile={"structured_output": "xml"})  # type: ignore[arg-type]


def test_profile_for_applies_the_configured_overrides():
    settings = ModelSettings(profile={"name": "mid", "max_chunks": 7})  # type: ignore[arg-type]

    profile = profile_for(settings, "gemma3:1b")

    assert (profile.name, profile.max_chunks, profile.chunk_chars) == (
        "mid",
        7,
        PROFILES["mid"].chunk_chars,
    )


def _client(monkeypatch, model: str, **extra) -> OpenAICompat:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("GROQ_API_KEY", "key-for-the-test-123456")
    settings = ModelSettings(
        backend="groq", provider={"model": model, **extra.pop("provider", {})}, **extra
    )  # type: ignore[arg-type]
    client = select_model(settings, probe=False)
    assert isinstance(client, OpenAICompat)
    return client


def test_the_client_takes_its_output_limit_from_the_profile(monkeypatch):
    assert (
        _client(monkeypatch, "llama-3.1-8b-instant").max_tokens
        == PROFILES["small"].max_output_tokens
    )
    assert (
        _client(monkeypatch, "openai/gpt-oss-120b").max_tokens
        == PROFILES["reasoning"].max_output_tokens
    )
    assert _client(monkeypatch, "llama-3.3-70b-versatile").profile.name == "large"


def test_a_configured_max_tokens_wins_over_the_profile(monkeypatch):
    client = _client(monkeypatch, "llama-3.1-8b-instant", provider={"max_tokens": 300})

    assert client.max_tokens == 300


def test_a_profile_override_changes_the_client(monkeypatch):
    client = _client(monkeypatch, "llama-3.1-8b-instant", profile={"max_output_tokens": 777})

    assert client.max_tokens == 777


def test_the_context_window_comes_from_the_profile(monkeypatch):
    assert (
        _client(monkeypatch, "gemma3:1b").profile.context_tokens == PROFILES["tiny"].context_tokens
    )
    assert (
        _client(monkeypatch, "gemma3:1b", profile={"context_tokens": 2048}).profile.context_tokens
        == 2048
    )


def test_the_cache_identity_names_the_profile(monkeypatch):
    version = _client(monkeypatch, "llama-3.1-8b-instant").model_version

    assert "profile=small" in version and "groq:llama-3.1-8b-instant" in version
    assert (
        version
        != _client(monkeypatch, "llama-3.1-8b-instant", profile={"name": "large"}).model_version
    )


def test_a_structured_output_set_in_the_provider_wins_over_the_profile(monkeypatch):
    client = _client(
        monkeypatch, "llama-3.1-8b-instant", provider={"structured_output": "json_object"}
    )

    assert client.structured_mode == "json_object"


def test_the_existing_ollama_settings_are_unchanged():
    settings = ModelSettings()

    assert (settings.ollama_num_ctx, settings.ollama_num_predict) == (8192, 2048)


# Ids a hosted provider lists (Groq, 2026-11): the class each gets, and the limits it is given.
@pytest.mark.parametrize(
    ("model_id", "name"),
    [
        ("allam-2-7b", "small"),
        ("gpt-oss-20b", "reasoning"),
        ("gpt-oss-120b", "reasoning"),
        ("openai/gpt-oss-20b", "reasoning"),
        ("qwen3.8-27b", "reasoning"),
        ("qwen/qwen3-32b", "reasoning"),
        ("llama-3.1-8b-instant", "small"),
        ("llama-3.3-70b-versatile", "large"),
    ],
)
def test_the_ids_a_hosted_provider_lists_get_sensible_classes(model_id, name):
    assert classify(model_id) == name


def test_a_model_with_a_known_small_window_is_given_it():
    profile = resolve_profile("allam-2-7b")

    assert profile.name == "small"
    assert profile.context_tokens == 4096 and profile.max_output_tokens == 1024
    # An explicit setting still wins over what is known.
    assert resolve_profile("allam-2-7b", overrides={"context_tokens": 8192}).context_tokens == 8192
    # Other models of the class are unchanged.
    assert resolve_profile("llama-3.1-8b-instant").context_tokens == 8192


def test_a_request_for_the_4k_window_model_fits_its_window():
    from skill_sentry_cli.core.semantic.plan import CHARS_PER_TOKEN, plan_from_profile

    plan = plan_from_profile(resolve_profile("allam-2-7b"))

    assert plan.unusable_reason is None
    # chunk + the fixed part of the prompt + the reply stay inside 4,096 tokens
    assert plan.chunk_chars / CHARS_PER_TOKEN + 1024 < 4096


def test_the_reasoning_profile_keeps_the_reply_room_and_does_not_retry():
    profile = resolve_profile("gpt-oss-20b")

    assert profile.name == "reasoning" and profile.max_output_tokens >= 4096
    assert profile.retries == 0 and not profile.few_shot
