# 10 · Developer Onboarding & Operating Guide

> **Subsystem:** Backend — Skill Analysis  
> **Author:** Developer 2 (Backend Engineer & Security Architect)  
> **Source-of-Truth References:** [docs/10-developer-guide.md](docs/10-developer-guide.md) §10.1 · [CONTRIBUTING.md](CONTRIBUTING.md) · [docs/checklists/dev2-skill-analysis.md](docs/checklists/dev2-skill-analysis.md)

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

### 1.2 Quickstart Setup (Windows PowerShell)
```powershell
# 1. Open Windows PowerShell and navigate to repository root
cd 

# 2. Allow local script execution if restricted
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned

# 3. Create and activate Python virtual environment
python -m venv .venv
.venv\Scripts\Activate.ps1

# 4. Set UTF-8 encoding for clean Unicode/ANSI console output
$env:PYTHONUTF8 = "1"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# 5. Install development dependencies
pip install --upgrade pip
pip install -e ".[dev]"

# 6. Verify installation
python -c "import skillsentry; print('SkillSentry initialized successfully on Windows')"
```

---

## 2. Common Developer Workflows & Commands

### 2.1 Initiating Scans from Windows PowerShell
Test the full pipeline invocation using the documented PowerShell CLI syntax:

```powershell
# Scan malicious fixture in text format
skillsentry scan .\fixtures\malicious\cloud-sync-pro --format text

# Scan with SARIF report output
skillsentry scan .\fixtures\malicious\invoice-helper --sarif-out invoice-report.sarif

# Python module invocation fallback
python -m skillsentry.cli scan .\fixtures\benign\pdf-summarizer

# Check exit code (0 = Safe, 1 = Threshold exceeded/Malicious)
Write-Host "Scan completed with exit code: $LASTEXITCODE"
```

### 2.2 Running the Fast Unit Test Suite (<5s Loop)
Execute local, offline unit tests covering the parser, typosquat detector, AST anchor scanner, sandbox instruction generator, and directory hasher:

```powershell
# Run all Developer 2 fast unit tests
pytest tests/unit/test_analysis/ -v

# Run parser hardening, path normalization & traversal defense tests
pytest tests/unit/test_analysis/test_skill_parser.py -k "test_traversal or test_powershell_paths"

# Run AST anchor pattern recognition tests
pytest tests/unit/test_analysis/test_ast_anchor.py -v

# Run dynamic sandbox action instruction tests
pytest tests/unit/test_analysis/test_sandbox_instructions.py -v
```

### 2.3 Running Contract Tests (Zero-Model & Sandbox Handoff Mode)
Verify that Developer 2’s analyzers serialize valid `StageResult` dataclasses, conform to the I2 Model Client protocol via `MockGemma`, and generate valid `SandboxActionInstruction` objects:

```powershell
# Run contract verification against MockGemma and INT-4 sandbox handoff
pytest tests/contract/test_stage_results.py -v
pytest tests/contract/test_sandbox_handoff.py -v
```

### 2.4 Running Cache & Scanner Performance Benchmarks
Assert that directory hashing, AST walking, and SQLite operations meet latency SLAs:

```powershell
# Run dedicated performance benchmark suite
pytest tests/benchmark/ --benchmark-only

# Verify cache round-trip completes in <50ms (<2s budget)
pytest tests/unit/test_cache_perf.py --benchmark
```

### 2.5 Running the Citation Accuracy Harness
Evaluate reported `file:line` citations against hand-annotated ground-truth:

```powershell
python tests/check_citation_accuracy.py --ground-truth tests/ground_truth.json
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
| **PowerShell CLI output displays garbled characters / emojis** | Windows console encoding defaulted to legacy OEM code page. | 1. Run `$env:PYTHONUTF8 = "1"` in PowerShell session.<br>2. Set console output: `[Console]::OutputEncoding = [System.Text.Encoding]::UTF8`.<br>3. Ensure terminal font supports UTF-8 (e.g. Cascadia Code, Consolas). |
| **Sandbox instruction reports status 'blocked' or 'unsupported'** | Path traversal violation detected, or Docker daemon offline. | 1. If 'blocked', inspect Stage 1 findings for `critical` traversal attempts (`../`, `C:..`).<br>2. If 'unsupported', check Docker status (`docker info`).<br>3. Verify that verdict records `sandbox-unavailable` degraded finding. |
