"""
Benchmark tests for performance-critical operations.

Target budgets (per docs/06-testing-and-evaluation.md):
  - hash + cache lookup: < 50ms
  - AST anchor scan: < 100ms per file

Uses time.perf_counter for portable measurement (pytest-benchmark has
compatibility issues with pytest 9.x).
"""

import json
import time
from pathlib import Path

import pytest

from skillsentry_dev2.contracts import ScriptFile
from skillsentry_dev2.core.cache.hash_utils import compute_directory_hash
from skillsentry_dev2.core.cache.sqlite_store import CacheStore
from skillsentry_dev2.core.semantic.ast_anchor import scan_anchors


@pytest.fixture
def sample_skill(tmp_path):
    """Create a realistic skill package for benchmarking."""
    (tmp_path / "SKILL.md").write_text(
        "---\nname: bench-test\ndescription: Benchmark fixture\n---\n"
    )
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    # Create a non-trivial Python script (~100 lines)
    code = 'import sys\nimport json\nimport os\n\n'
    for i in range(50):
        code += f'def func_{i}(x):\n    return x + {i}\n\n'
    code += 'if __name__ == "__main__":\n    print("done")\n'
    (scripts / "main.py").write_text(code)
    return tmp_path


@pytest.fixture
def cache_store(tmp_path):
    db_path = tmp_path / "bench.db"
    store = CacheStore(db_path=db_path)
    yield store
    store.close()


def _measure(func, *args, iterations: int = 20) -> float:
    """Run func N times and return median duration in ms."""
    times = []
    for _ in range(iterations):
        start = time.perf_counter()
        func(*args)
        elapsed = (time.perf_counter() - start) * 1000.0
        times.append(elapsed)
    times.sort()
    return times[len(times) // 2]  # median


class TestHashBenchmark:
    def test_hash_under_50ms(self, sample_skill):
        """Hashing a small skill package should complete in < 50ms."""
        median_ms = _measure(compute_directory_hash, sample_skill)
        assert median_ms < 50.0, f"Hash took {median_ms:.1f}ms (budget: 50ms)"

    def test_hash_plus_cache_lookup(self, sample_skill, cache_store):
        """Combined hash + cache lookup should be fast."""
        def hash_and_lookup():
            h = compute_directory_hash(sample_skill)
            return cache_store.get_cached(h, "1.0.0", "test-v1")

        median_ms = _measure(hash_and_lookup)
        assert median_ms < 50.0, f"Hash+lookup took {median_ms:.1f}ms (budget: 50ms)"


class TestAnchorScanBenchmark:
    def test_scan_under_100ms(self):
        """AST scanning a moderate Python file should complete in < 100ms."""
        code = 'import os\nimport subprocess\nimport base64\n\n'
        for i in range(30):
            code += f'def process_{i}(data):\n    return str(data)\n\n'
        code += 'result = os.path.join("/tmp", "output.txt")\n'

        lines = code.splitlines(keepends=True)
        script = ScriptFile(
            relative_path="scripts/bench.py",
            lines=lines,
            size_bytes=len(code.encode()),
            content_hash="bench_hash",
        )
        scripts = {"scripts/bench.py": script}

        median_ms = _measure(scan_anchors, scripts)
        assert median_ms < 100.0, f"AST scan took {median_ms:.1f}ms (budget: 100ms)"
