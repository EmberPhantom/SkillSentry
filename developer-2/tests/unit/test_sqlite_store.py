"""
Unit tests for sqlite_store.py (Stage 0 — SQLite Cache Store).

Covers: put/get round-trip, cache invalidation matrix, prune, stats,
schema versioning, context manager usage.
"""

import json
import tempfile
from pathlib import Path

import pytest

from skillsentry_dev2.core.cache.sqlite_store import CacheStore, CacheStats


@pytest.fixture
def cache_store(tmp_path):
    """Create a temporary CacheStore."""
    db_path = tmp_path / "test_cache.db"
    store = CacheStore(db_path=db_path)
    yield store
    store.close()


def _put_sample(store: CacheStore, content_hash: str = "abc123",
                engine_version: str = "1.0.0",
                model_version: str = "gemma4:e4b-q4",
                model_backend: str = "ollama") -> None:
    """Insert a sample cache entry."""
    store.put(
        content_hash=content_hash,
        skill_name="test-skill",
        verdict="SAFE",
        risk_score=15,
        confidence=0.92,
        verdict_json=json.dumps({"verdict": "SAFE", "risk_score": 15}),
        sarif_json=json.dumps({"runs": []}),
        engine_version=engine_version,
        model_backend=model_backend,
        model_version=model_version,
        scan_duration_ms=250,
    )


class TestCacheStore:
    def test_put_and_get_roundtrip(self, cache_store):
        _put_sample(cache_store)
        result = cache_store.get_cached("abc123", "1.0.0", "gemma4:e4b-q4")
        assert result is not None
        verdict_json, sarif_json = result
        assert '"SAFE"' in verdict_json

    def test_cache_miss(self, cache_store):
        result = cache_store.get_cached("nonexistent", "1.0.0", "gemma4:e4b-q4")
        assert result is None

    def test_engine_version_invalidation(self, cache_store):
        """Changing engine version should invalidate the cache entry."""
        _put_sample(cache_store, engine_version="1.0.0")
        # Same hash but different engine version = miss
        result = cache_store.get_cached("abc123", "2.0.0", "gemma4:e4b-q4")
        assert result is None

    def test_model_version_invalidation(self, cache_store):
        """Changing model version should invalidate the cache entry."""
        _put_sample(cache_store, model_version="gemma4:e4b-q4")
        result = cache_store.get_cached("abc123", "1.0.0", "gemma4:e4b-q8")
        assert result is None

    def test_backend_strict_invalidation(self, cache_store):
        """When backend_strict=True, model_backend must also match."""
        _put_sample(cache_store, model_backend="ollama")
        # Without strict: hit
        result = cache_store.get_cached("abc123", "1.0.0", "gemma4:e4b-q4")
        assert result is not None
        # With strict, wrong backend: miss
        result = cache_store.get_cached(
            "abc123", "1.0.0", "gemma4:e4b-q4",
            backend_strict=True, model_backend="gemini-api",
        )
        assert result is None
        # With strict, correct backend: hit
        result = cache_store.get_cached(
            "abc123", "1.0.0", "gemma4:e4b-q4",
            backend_strict=True, model_backend="ollama",
        )
        assert result is not None

    def test_upsert_overwrites(self, cache_store):
        """Second put with same hash should update the entry."""
        _put_sample(cache_store, content_hash="abc123")
        cache_store.put(
            content_hash="abc123",
            skill_name="updated-skill",
            verdict="MALICIOUS",
            risk_score=90,
            confidence=0.95,
            verdict_json=json.dumps({"verdict": "MALICIOUS"}),
            sarif_json=json.dumps({"runs": []}),
            engine_version="1.0.0",
            model_backend="ollama",
            model_version="gemma4:e4b-q4",
            scan_duration_ms=500,
        )
        result = cache_store.get_cached("abc123", "1.0.0", "gemma4:e4b-q4")
        assert result is not None
        assert '"MALICIOUS"' in result[0]

    def test_stats_empty(self, cache_store):
        stats = cache_store.stats()
        assert isinstance(stats, CacheStats)
        assert stats.total_entries == 0

    def test_stats_with_entries(self, cache_store):
        _put_sample(cache_store, content_hash="h1")
        _put_sample(cache_store, content_hash="h2")
        stats = cache_store.stats()
        assert stats.total_entries == 2
        assert stats.db_size_bytes > 0
        assert stats.engine_version == "1.0.0"

    def test_clear(self, cache_store):
        _put_sample(cache_store, content_hash="h1")
        _put_sample(cache_store, content_hash="h2")
        deleted = cache_store.clear()
        assert deleted == 2
        assert cache_store.stats().total_entries == 0

    def test_verify_returns_valid(self, cache_store):
        _put_sample(cache_store)
        results = cache_store.verify(sample_size=5)
        assert len(results) == 1
        assert results[0]["valid"] is True

    def test_context_manager(self, tmp_path):
        db_path = tmp_path / "ctx_test.db"
        with CacheStore(db_path=db_path) as store:
            _put_sample(store)
            result = store.get_cached("abc123", "1.0.0", "gemma4:e4b-q4")
            assert result is not None
        # After exit, connection should be closed

    def test_invalid_verdict_rejected(self, cache_store):
        """SQLite CHECK constraint should reject invalid verdict values."""
        with pytest.raises(Exception):
            cache_store.put(
                content_hash="bad",
                skill_name="bad-skill",
                verdict="INVALID_VERDICT",
                risk_score=50,
                confidence=0.5,
                verdict_json="{}",
                sarif_json="{}",
                engine_version="1.0.0",
                model_backend="ollama",
                model_version="v1",
                scan_duration_ms=100,
            )

    def test_risk_score_bounds_rejected(self, cache_store):
        """SQLite CHECK constraint should reject out-of-range risk scores."""
        with pytest.raises(Exception):
            cache_store.put(
                content_hash="bad2",
                skill_name="bad-skill",
                verdict="SAFE",
                risk_score=150,  # > 100
                confidence=0.5,
                verdict_json="{}",
                sarif_json="{}",
                engine_version="1.0.0",
                model_backend="ollama",
                model_version="v1",
                scan_duration_ms=100,
            )

