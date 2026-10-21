"""Intent-aware fake canaries and context-honeypot planning."""

from __future__ import annotations

import re
from uuid import UUID

import pytest
from skillsentry.core.contracts import ContextCanary
from skillsentry.core.poisoned_well.canary_gen import (
    CANARY_ROOT,
    CanaryFile,
    extract_markers,
    generate_canary_set,
    new_marker,
    normalize_intent,
    validate_marker,
)
from skillsentry.core.sandbox.context_honeypot import build_honeypot, plan, runtime_environment

SCAN_ID = UUID("11111111-1111-4111-8111-111111111111")
MARKER = "SKS-7f3a9c21"
SECONDARY = "SKS-8b2c4d19"


def _canaries(intent: str = "cloud sync"):
    return generate_canary_set(SCAN_ID, intent, marker=MARKER, secondary_marker=SECONDARY)


def test_marker_format_and_fake_material():
    canaries = _canaries()
    assert canaries.intent is ContextCanary.AWS
    assert validate_marker(canaries.marker) == MARKER
    assert canaries.secondary_marker == SECONDARY
    assert canaries.files
    assert canaries.env

    for canary in canaries.files:
        assert canary.content
        assert MARKER in canary.content
        assert canary.container_path.startswith(f"{CANARY_ROOT}/")
        assert not canary.relative_path.startswith("/")
        assert ".." not in canary.relative_path.split("/")
    for value in canaries.env.values():
        assert any(token in value for token in canaries.search_tokens)

    credentials = next(item for item in canaries.files if item.relative_path == ".aws/credentials")
    access_key = re.search(r"aws_access_key_id = (\S+)", credentials.content)
    assert access_key is not None
    assert access_key.group(1).startswith("AKIA")
    assert len(access_key.group(1)) == 20
    assert "REAL" not in credentials.content.upper()


def test_new_marker_is_random_and_valid():
    first = new_marker()
    second = new_marker()
    assert validate_marker(first)
    assert validate_marker(second)
    assert first != second


@pytest.mark.parametrize(
    ("intent", "expected"),
    [
        ("GitHub repository helper", ContextCanary.GITHUB),
        ("Slack notifier for a workspace", ContextCanary.SLACK),
        ("SSH deployment helper", ContextCanary.SSH),
        ("AWS cloud credential sync", ContextCanary.AWS),
        ("PDF summarizer", ContextCanary.GENERIC),
        ("image resizer", ContextCanary.GENERIC),
    ],
)
def test_intent_mapping(intent, expected):
    assert normalize_intent(intent) is expected


def test_generic_intent_seeds_all_provider_files():
    canaries = _canaries("unclassified local utility")
    paths = {item.relative_path for item in canaries.files}
    assert ".aws/credentials" in paths
    assert ".config/gh/hosts.yml" in paths
    assert ".config/slack/token" in paths
    assert ".ssh/id_rsa" in paths
    assert ".env" in paths
    assert canaries.intent is ContextCanary.GENERIC


def test_specific_intent_still_has_common_context_files():
    canaries = _canaries("Slack notification bot")
    paths = {item.relative_path for item in canaries.files}
    assert ".config/slack/token" in paths
    assert ".aws/credentials" in paths
    assert ".ssh/id_rsa" in paths
    assert ".env" in paths
    # It should not seed every unrelated provider config.
    assert ".config/gh/hosts.yml" not in paths


def test_env_is_intent_matched_and_generic_is_broad():
    slack = _canaries("Slack bot")
    assert "SLACK_BOT_TOKEN" in slack.env
    assert "OPENAI_API_KEY" in slack.env
    assert "AWS_ACCESS_KEY_ID" not in slack.env

    generic = _canaries("sort csv files")
    assert "AWS_ACCESS_KEY_ID" in generic.env
    assert "GITHUB_TOKEN" in generic.env
    assert "SLACK_BOT_TOKEN" in generic.env


def test_search_tokens_accept_both_documented_spellings():
    canaries = _canaries()
    assert MARKER in canaries.search_tokens
    assert "SKS7f3a9c21" in canaries.search_tokens
    assert extract_markers("x SKS-7f3a9c21 ghp_SKS7f3a9c21 y") == {MARKER}
    assert extract_markers("AKIASKS7F3A9C21FAKEF") == {MARKER}


def test_invalid_marker_and_duplicate_secondary_are_rejected():
    with pytest.raises(ValueError):
        validate_marker("SKS-NOPE")
    with pytest.raises(ValueError):
        generate_canary_set(SCAN_ID, "x", marker=MARKER, secondary_marker=MARKER)


def test_honeypot_preview_and_runtime_environment():
    canaries = build_honeypot(SCAN_ID, "Slack workspace", marker=MARKER, secondary_marker=SECONDARY)
    preview = plan("Slack workspace")
    assert preview.intent is ContextCanary.SLACK
    assert "~/.config/slack/token" in preview.paths
    assert "SLACK_BOT_TOKEN" in preview.env_keys

    env = runtime_environment(canaries)
    assert env["HOME"] == CANARY_ROOT
    assert env["SLACK_BOT_TOKEN"] == canaries.env["SLACK_BOT_TOKEN"]
    assert env["USER"] == "nobody"


def test_canary_file_tar_path_is_relative():
    item = CanaryFile(".ssh/id_rsa", "~/.ssh/id_rsa", "x", 0o600, "ssh", MARKER)
    assert item.tar_path == "./.ssh/id_rsa"
    assert item.container_path == "/home/sandbox/.ssh/id_rsa"
