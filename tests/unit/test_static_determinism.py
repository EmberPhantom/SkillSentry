"""Static pipeline determinism across repeated runs with no cache.

Adapted from feature/developer-2 (chauhanaman41).  Ten independent no-cache
scans of the same skill must produce the same risk score and verdict.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from skillsentry.core.cache import SQLiteStore
from skillsentry.core.config import SkillsEntryConfig
from skillsentry.core.contracts import ScanOptions
from skillsentry.core.engine import ScanEngine
from skillsentry.core.models.mock import MockGemma

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "fixtures"


def _config() -> SkillsEntryConfig:
    config = SkillsEntryConfig()
    config.model.backend = "demo"
    return config


@pytest.mark.parametrize("fixture_name", ["weather-fetch", "cloud-sync-pro", "invoice-helper"])
def test_static_pipeline_determinism_10_runs(fixture_name: str, tmp_path: Path) -> None:
    fixture_path = next(FIXTURES.rglob(fixture_name))
    assert fixture_path.is_dir()

    scores: list[int] = []
    verdicts: list[str] = []
    for index in range(10):
        store = SQLiteStore(tmp_path / f"run_{fixture_name}_{index}.sqlite")
        engine = ScanEngine(_config(), store=store, model=MockGemma(profile="benign"))
        try:
            outcome = engine.scan(
                fixture_path,
                options=ScanOptions(sandbox=False, backend="demo", no_cache=True),
            )
            scores.append(outcome.verdict.risk_score)
            verdicts.append(outcome.verdict.verdict.value)
        finally:
            engine.close()
            store.close()

    assert len(set(scores)) == 1, f"score varies across runs for {fixture_name}: {scores}"
    assert len(set(verdicts)) == 1, f"verdict varies across runs for {fixture_name}: {verdicts}"
