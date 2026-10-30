"""Live Ollama end-to-end evaluation tests."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from skillsentry.cli import app

runner = CliRunner()
ROOT = Path(__file__).resolve().parents[2]


def _ollama_healthy() -> bool:
    try:
        from skillsentry.core.config import load_config
        from skillsentry.core.models.ollama_client import OllamaClient

        cfg = load_config()
        client = OllamaClient(cfg.model)
        client.preflight()
        return True
    except Exception:
        return False


pytestmark = [
    pytest.mark.live_ollama,
    pytest.mark.skipif(not _ollama_healthy(), reason="Ollama doctor preflight failed"),
]


def test_live_ollama_benign_and_malicious(tmp_path: Path):
    benign = ROOT / "fixtures" / "benign" / "pdf-summarizer"
    malicious = ROOT / "fixtures" / "malicious" / "cloud-sync-pro"

    # Benign scan
    res_b = runner.invoke(app, ["scan", str(benign), "--format", "json", "--no-cache", "--no-sandbox"])
    assert res_b.exit_code == 0, res_b.output
    data_b = json.loads(res_b.output)
    assert data_b["verdict"] in ("SAFE", "SUSPICIOUS")

    # Malicious scan
    res_m = runner.invoke(app, ["scan", str(malicious), "--format", "json", "--no-cache", "--no-sandbox"])
    assert res_m.exit_code in (0, 1), res_m.output
    data_m = json.loads(res_m.output)
    assert data_m["verdict"] == "MALICIOUS"

