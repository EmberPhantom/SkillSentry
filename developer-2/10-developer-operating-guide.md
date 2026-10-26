# 10 · Developer Onboarding & Operating Guide

> **Subsystem:** Backend — Skill Analysis  
> **Author:** Developer 2 (Backend Engineer & Security Architect)  
> **Source-of-Truth References:** [docs/10-developer-guide.md](file:///d:/Skillsentry/SkillSentry/docs/10-developer-guide.md) §10.1 · [CONTRIBUTING.md](file:///d:/Skillsentry/SkillSentry/CONTRIBUTING.md) · [docs/checklists/dev2-skill-analysis.md](file:///d:/Skillsentry/SkillSentry/docs/checklists/dev2-skill-analysis.md)

---

## 1. Developer Onboarding & Local Environment Setup

This guide enables any engineer joining Developer 2's workstream to set up an environment, run tests, and begin implementing components immediately without requiring live GPU clusters, Docker daemons, or internet connections.

### 1.1 Prerequisites
- **Python**: Version `3.11+` (`python --version`).
- **Package Manager**: `pip` and standard `venv`.
- **Git**: Installed and configured.
- **Ollama (Optional for initial development, required for M2+)**: [ollama.com](https://ollama.com) with model pulled:
  ```bash
  ollama pull gemma4:e4b-q4
  ```

### 1.2 Quickstart Setup
```bash
# 1. Clone repository and navigate to root
cd d:/Skillsentry/SkillSentry

# 2. Create and activate Python virtual environment
python -m venv .venv
# On Windows PowerShell:
.venv\Scripts\Activate.ps1
# On Linux/macOS:
source .venv/bin/activate

# 3. Install development dependencies
pip install --upgrade pip
pip install -e ".[dev]"

# 4. Verify installation
python -c "import skillsentry; print('SkillSentry initialized successfully')"
```

---

## 2. Common Developer Workflows & Commands

### 2.1 Running the Analysis Unit Test Suite
Execute the fast, local, dependency-free unit tests covering the parser, typosquat detector, AST anchor scanner, and directory hasher:

```bash
# Run all Developer 2 unit tests
pytest tests/unit/test_analysis/ -v

# Run parser hardening and traversal defense tests
pytest tests/unit/test_analysis/test_skill_parser.py -k "test_traversal or test_size_caps"

# Run AST anchor pattern recognition tests
pytest tests/unit/test_analysis/test_ast_anchor.py -v
```

### 2.2 Running Contract Tests (Zero-Model Mode)
Verify that Developer 2’s analyzers serialize valid `StageResult` dataclasses and conform to the I2 Model Client protocol using `MockGemma`:

```bash
# Run contract verification against MockGemma
pytest tests/contract/test_stage_results.py -v
```

### 2.3 Running the Citation Accuracy Harness
Evaluate reported `file:line` citations against hand-annotated ground-truth:

```bash
python tests/check_citation_accuracy.py --ground-truth tests/ground_truth.json
```

### 2.4 Running Cache Performance Benchmark
Assert that directory hashing and SQLite retrieval complete well under the 2-second budget:

```bash
pytest tests/unit/test_cache_perf.py --benchmark
```

---

## 3. Step-by-Step Extension Guides

### 3.1 Adding a New AST Anchor Pattern
To add a new dangerous pattern to `skillsentry/core/semantic/ast_anchor.py`:
1. **Define Pattern**: Add pattern string, language applicability (`py`, `sh`, `js`), description, and severity (`critical`, `high`, `medium`, `low`) to `DANGEROUS_PATTERNS`.
2. **Add AST Visitor / Regex**:
   - For Python: Extend `ASTCallVisitor` in `ast_anchor.py` to match the target AST Call/Import node.
   - For Shell/JS: Add the regex pattern to the line-scan engine.
3. **Add Test Fixture**: Add a snippet containing the pattern to `tests/fixtures/test_patterns/` and assert exact `file:line` citation.
4. **Update Expected Findings**: If the pattern appears in an existing malicious fixture, update `tests/expected_verdicts.json`.

### 3.2 Adding a New Benign or Malicious Fixture
1. **Directory Creation**: Place new skill under `fixtures/benign/<name>` or `fixtures/malicious/<name>`.
2. **Author `SKILL.md`**: Ensure valid YAML frontmatter (`name`, `description` with trigger keywords).
3. **Enforce Safety Rules**:
   - Use fictional C2 domains (`evil-collector.net`).
   - Use fake canary credentials (`AKIA...SKS-...`).
   - Include a clear warning `README.md` inside any malicious folder.
4. **Annotate Ground Truth**: Add exact suspicious line numbers to `tests/ground_truth.json`.
5. **Update Expected Verdicts**: Add target verdict, risk band, and required findings to `tests/expected_verdicts.json`.

---

## 4. Diagnostics & Debugging Runbook

| Symptom | Probable Cause | Diagnostic & Remediation Steps |
|:---|:---|:---|
| **Semantic analysis yields empty or malformed JSON** | LLM output failed schema validation. | 1. Check if Ollama is running (`curl http://localhost:11434/api/tags`).<br>2. Inspect debug logs for the anchored prompt text.<br>3. Verify that the automatic single-retry logic fired.<br>4. Confirm that failure yields `semantic-unavailable` finding (never a silent `SAFE`). |
| **AST Anchor misses dangerous call in multi-line script** | Expression spans multiple lines or uses aliased import. | 1. Check Python AST node line mapping (`node.lineno`).<br>2. Run `python -m ast <script.py>` to inspect AST structure.<br>3. Verify alias resolution in `ast_anchor.py`. |
| **Directory hash changes across identical runs** | File ordering or exclusion rules non-deterministic. | 1. Check if un-ignored files (`.DS_Store`, `*.pyc`) were included.<br>2. Verify POSIX path byte-sorting in `hash_utils.py`.<br>3. Inspect permissions bits normalization. |
| **Gemma Vision fails to detect white-on-white text** | Contrast ratio too subtle or downscaling blurred text. | 1. Check output of contrast pre-filter (`sigma^2_L`).<br>2. Inspect downscaled image at 1024 px.<br>3. Tune test fixture font size from 4 px to 6 px per plan risk mitigation rule. |
