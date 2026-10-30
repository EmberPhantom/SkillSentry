# SkillSentry Test Suite & Verification Guide

This document provides a comprehensive reference for executing, verifying, and maintaining the test suites across the SkillSentry repository.

---

## 1. Executive Summary & Test Status

As of **SkillSentry 2.0 (Remediated Architecture)**, all hardcoded heuristics, path cheating, and runtime mock engines have been eliminated. The system features:
- **Zero mocks in runtime code** (`git grep -n "Mock" skillsentry/` returns 0).
- **All automated tests passing with 0 failures** across both root `tests/` (370 succeeded, 8 skipped) and `developer-2/tests/` (228 succeeded).
- **Full CI regression gate passing** across all 20 test fixtures (12 benign confirmed `SAFE`, 8 malicious flagged `SUSPICIOUS` or `MALICIOUS`).
- **Transparent Inference Status:** Unit tests use `httpx.MockTransport` for client-level protocol verification; live model inference requires an active Ollama instance with `gemma4:e4b` and fails closed (`degraded=True`, risk 30) when offline.

### Test Metrics Summary

| Test Suite | Location | Tests Collected | Passed | Skipped | Failed | Notes |
|---|---|:---:|:---:|:---:|:---:|---|
| **Root Tests** | `tests/` | 378 | **370** | 8 | **0** | Skips: 2 symlink (Windows permissions), 1 Docker, 4 Laya extra, 1 Live Ollama |
| **Developer-2 Tests** | `developer-2/tests/` | 228 | **228** | 0 | **0** | Subsystem unit, contract, security, benchmarks |
| **Combined Passing** | Entire Workspace | 606 | **598** | 8 | **0** | 100% pass rate among executed tests |

---

## 2. Test Execution Commands

### Running All Root Tests
```powershell
python -m pytest tests
```
*Expected: 370 succeeded, 8 skipped, 0 failures.*

### Running Developer-2 Subsystem Tests
```powershell
cd developer-2
python -m pytest
cd ..
```
*Expected: 228 succeeded, 0 failures in ~3.2s.*

---

## 3. Key Test Categories & Critical CI Guards

### A. Zero Mocks in Runtime CI Guard (`tests/unit/test_no_mocks_in_runtime.py`)
Enforces that no mock classes (`MockGemma`, `MockMode`, `MockDecisionClient`, `FakeModel`) or hardcoded fixture cheat names appear in Developer 2 production analyzers.
```powershell
python -m pytest tests/unit/test_no_mocks_in_runtime.py
```

### B. Taint Analysis & Credential Flow (`tests/unit/test_credential_flow.py`)
Validates that AST taint analysis traces data flow from credential sources to network/DNS sinks without name-based false positives:
```powershell
python -m pytest tests/unit/test_credential_flow.py
```
- `test_benign_code_no_credential_flow`: Benign code reading config has 0 findings.
- `test_exfiltration_taint_detected`: Code passing `os.environ["API_KEY"]` to `requests.post()` raises a `credential-exfiltration` finding.
- `test_declared_hosts_suppressed`: Requests to declared hosts (e.g., `api.weather.gov` declared in `SKILL.md`) are suppressed.
- `test_dns_tunneling_credential_flow`: Chained calls (`token.encode().decode()`) sent via `socket.gethostbyname()` are tracked and flagged.

### C. File Chunking, Coverage & Grounding (`tests/unit/test_chunker_coverage.py`)
Validates large file ingestion without silent truncation:
```powershell
python -m pytest tests/unit/test_chunker_coverage.py
```
- `test_coverage_ledger_tracking`: Tracks analyzed vs. unanalyzed line ranges and computes coverage percentage.
- `test_file_chunker_markdown`: Splits markdown files respecting header hierarchy and token budgets.
- `test_file_chunker_python_ast`: Splits python source code cleanly along function/class boundaries without breaking syntax.
- `test_ground_quote_locates_lines`: Normalizes quotes and punctuation to verify LLM findings point to authentic file source lines.

### D. Fusion Floors & Monotonicity (`tests/unit/test_fusion_monotonic.py`)
Validates fail-closed behavior and hard/soft score floor mathematics:
```powershell
python -m pytest tests/unit/test_fusion_monotonic.py
```
- `test_hard_deterministic_floor_cannot_be_lowered_by_model`: A hard malicious anchor (risk 95) cannot be suppressed by a model returning risk 0.
- `test_degraded_stage_floors_at_suspicious`: When a stage is marked `degraded` (e.g. timeout, service offline), risk score is floored at 30 (`SUSPICIOUS`).
- `test_score_monotonicity`: Incremental findings can only increase the overall risk score, never decrease it.

---

## 4. CI Regression Gates & Expected Fixtures

### A. Root Static Regression Gate
```powershell
python tests/check_expected_verdicts.py --static-only
```
**Output:**
```text
PASS static pdf-summarizer (SAFE risk=0)
PASS static git-helper (SAFE risk=0)
PASS static image-resizer (SAFE risk=0)
PASS static weather-fetch (SAFE risk=0)
PASS static cloud-sync-pro (MALICIOUS risk=97)
PASS static invoice-helper (MALICIOUS risk=95)
PASS static slack-notif-mal (MALICIOUS risk=97)
PASS static g1t-translate (SUSPICIOUS risk=30)
```

### B. Developer-2 20-Fixture Regression Gate
```powershell
python developer-2/tests/check_expected_verdicts.py
```
**Output:**
```text
============================================================
SkillSentry Expected Verdicts Regression Gate
============================================================
[PASS] fixtures/malicious/invoice-helper   -> MALICIOUS  (Risk:  80)
[PASS] fixtures/malicious/g1t-translate    -> SUSPICIOUS (Risk:  19)
[PASS] fixtures/malicious/obfuscation-only -> SUSPICIOUS (Risk:  62)
[PASS] fixtures/malicious/instruction-poisoning -> SUSPICIOUS (Risk:  35)
[PASS] fixtures/malicious/svg-borne        -> MALICIOUS  (Risk:  71)
[PASS] fixtures/malicious/dns-tunneler     -> MALICIOUS  (Risk:  75)
[PASS] fixtures/malicious/sl4ck-bot        -> MALICIOUS  (Risk:  77)
[PASS] fixtures/malicious/credential-multi -> MALICIOUS  (Risk:  75)
[PASS] fixtures/benign/pdf-summarizer      -> SAFE       (Risk:   4)
[PASS] fixtures/benign/git-helper          -> SAFE       (Risk:   4)
[PASS] fixtures/benign/image-resizer       -> SAFE       (Risk:   4)
[PASS] fixtures/benign/weather-fetch       -> SAFE       (Risk:   6)
[PASS] fixtures/benign/csv-analyzer        -> SAFE       (Risk:   4)
[PASS] fixtures/benign/markdown-formatter  -> SAFE       (Risk:   4)
[PASS] fixtures/benign/docker-compose-helper -> SAFE       (Risk:   4)
[PASS] fixtures/benign/slack-notifier      -> SAFE       (Risk:   6)
[PASS] fixtures/benign/ssh-keygen-helper   -> SAFE       (Risk:   4)
[PASS] fixtures/benign/multi-lang-tool     -> SAFE       (Risk:   4)
[PASS] fixtures/benign/json-formatter      -> SAFE       (Risk:   4)
[PASS] fixtures/benign/backup-tool         -> SAFE       (Risk:   4)
============================================================
RESULT: ALL FIXTURES PASSED REGRESSION GATE
```

---

## 5. Frontend & Web Dashboard Alignment (Developer 3)

As defined in `docs/checklists/dev3-frontend.md`:
- The Web Dashboard is the assigned responsibility of **Developer 3**.
- Developer 2's backend provides the REST endpoints (`GET /meta`, `POST /scan`, `GET /scans`, `GET /scan/{id}/verdicts`) and WebSocket event stream (`/scan/{id}/stream`).
- Serving of dashboard assets is verified through backend tests (`tests/unit/test_live_api.py` and `tests/unit/test_backend.py`), while UI layout, components, and visuals are owned by Developer 3.
