"""Live Ollama end-to-end tests.

Ported from feature/developer-2 (chauhanaman41), adapted to the v1 client
(GemmaLocal) and CLI.

Readiness means a real generation succeeds, not just that the server answers.
When generation fails (for example an HTTP 500 from a runner that cannot load
the model), the tests skip with that reason.  A scan whose semantic stage is
degraded fails, because a live run that never reached the model proves nothing.

Run on the test machine:

    pytest -m live_ollama
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from skill_sentry_cli.cli import app
from skill_sentry_cli.core.config import load_config
from skill_sentry_cli.core.models.base import ModelUnavailable
from skill_sentry_cli.core.models.gemma_local import GemmaLocal
from typer.testing import CliRunner

runner = CliRunner()
ROOT = Path(__file__).resolve().parents[2]


def _generation_error() -> str | None:
    """None when the configured model answers a real prompt, otherwise the reason."""

    cfg = load_config()
    client = GemmaLocal(base_url=cfg.model.ollama_url, model=cfg.model.ollama_model)
    try:
        if not client.preflight():
            return f"{cfg.model.ollama_model} is not pulled"
        client._generate(prompt='Reply with the JSON {"ok": true}.', system="", schema={})
        return None
    except (ModelUnavailable, OSError) as exc:
        return f"generation failed: {exc}"
    finally:
        client.close()


_ERROR = _generation_error()

pytestmark = [
    pytest.mark.live_ollama,
    pytest.mark.skipif(_ERROR is not None, reason=_ERROR or ""),
]


def _scan_json(skill: str) -> dict[str, object]:
    result = runner.invoke(
        app,
        ["scan", str(ROOT / skill), "--format", "json", "--no-cache", "--no-sandbox"],
    )
    assert result.exit_code in (0, 1), result.output
    payload: dict[str, object] = json.loads(result.stdout)
    degraded = [
        finding
        for finding in payload["findings"]  # type: ignore[index]
        if finding.get("stage") == "semantic" and finding.get("type") == "stage-degraded"  # type: ignore[union-attr]
    ]
    assert not degraded, f"semantic stage degraded for {skill}: {degraded}"
    return payload


def test_live_benign_skill_is_safe() -> None:
    payload = _scan_json("fixtures/benign/pdf-summarizer")

    assert payload["verdict"] == "SAFE"


def test_live_malicious_skill_is_malicious() -> None:
    payload = _scan_json("fixtures/malicious/cloud-sync-pro")

    assert payload["verdict"] == "MALICIOUS"
