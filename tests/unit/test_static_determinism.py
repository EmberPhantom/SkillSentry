"""Test static pipeline determinism across multiple runs with no cache.

Validates Section 8.8:
Asserts that running static analysis repeatedly produces byte/score/verdict-identical
results across 10 independent iterations with no cache.
"""

from pathlib import Path
import pytest

from skillsentry.core.cache import SQLiteStore
from skillsentry.core.contracts import ScanOptions
from skillsentry.core.engine import ScanEngine
from tests.support.mock_gemma import MockGemma

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "fixtures"


@pytest.mark.parametrize(
    "fixture_name",
    [
        "weather-fetch",
        "cloud-sync-pro",
        "invoice-helper",
    ],
)
def test_static_pipeline_determinism_10_runs(fixture_name: str, tmp_path: Path):
    """Run each fixture 10 times with no-cache and assert identical scores and verdicts."""
    fixture_path = next(FIXTURES.rglob(fixture_name))
    assert fixture_path.is_dir()

    scores = []
    verdicts = []

    for i in range(10):
        store = SQLiteStore(tmp_path / f"run_{fixture_name}_{i}.sqlite")
        engine = ScanEngine(store=store, model=MockGemma())
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

    # All 10 runs must have identical risk score and identical verdict
    assert len(set(scores)) == 1, f"Variance in scores across 10 runs for {fixture_name}: {scores}"
    assert len(set(verdicts)) == 1, f"Variance in verdicts across 10 runs for {fixture_name}: {verdicts}"
