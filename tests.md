# SkillSentry Test Suite & Verification Guide

This document provides a comprehensive reference for executing, verifying, and maintaining the test suites across the SkillSentry repository.

---

## 1. Executive Summary & Test Status

As of **SkillSentry 2.0 (Remediated Architecture)**, all hardcoded heuristics, path cheating, and runtime mock engines have been eliminated. The system features:
- **Zero mocks in runtime code** (`git grep -n "Mock" skillsentry/` returns 0).
- **566 automated tests passing with 0 failures** across both root `tests/` and `developer-2/tests/`.
- **Full CI regression gate passing** across all 20 test fixtures (12 benign confirmed `SAFE`, 8 malicious flagged `SUSPICIOUS` or `MALICIOUS`).
- **Complete Single-Page Application (SPA) Web Dashboard** served at `/` and `/assets/*` with real-time WebSocket telemetry and SARIF/STIX export.

### Test Metrics Summary

| Test Suite | Location | Tests Collected | Passed | Skipped | Failed | Execution Time |
|---|---|---|---|---|---|---|
| **Root Tests** | `tests/` | 345 | **338** | 7 (env/docker) | **0** | ~10.6s |
| **Developer-2 Tests** | `developer-2/tests/` | 228 | **228** | 0 | **0** | ~3.2s |
| **Total Automated** | Entire Workspace | 573 | **566** | 7 | **0** | ~13.8s |

---

## 2. Test Execution Environment Setup

All tests run using the dedicated Python 3.11 virtual environment configured with dependencies:

```powershell
# Set shortcut to virtual environment Python
$PY = "developer-2\.venv\Scripts\python.exe"
```

### Running All Root Tests
```powershell
developer-2\.venv\Scripts\python.exe -m pytest tests
```
*Expected: 338 passed, 7 skipped (Docker/Laya optional extras), 0 failures.*

### Running Developer-2 Subsystem Tests
```powershell
cd developer-2
..\developer-2\.venv\Scripts\python.exe -m pytest
cd ..
```
*Expected: 228 passed, 0 failures in ~3.2s.*

---

## 3. Key Test Categories & Critical CI Guards

### A. Zero Mocks in Runtime CI Guard (`tests/unit/test_no_mocks_in_runtime.py`)
Enforces that no mock classes (`MockGemma`, `MockMode`, `MockDecisionClient`, `FakeModel`) or hardcoded fixture cheat names appear anywhere in `skillsentry/`.
```powershell
developer-2\.venv\Scripts\python.exe -m pytest tests/unit/test_no_mocks_in_runtime.py
```
*Asserts:*
1. `test_runtime_has_no_mocks`: Scans all `.py` files in `skillsentry/` against banned patterns.
2. `test_runtime_has_no_fixture_cheats`: Confirms core engine and rule evaluators never reference fixture names to predetermine outcomes.

### B. Taint Analysis & Credential Flow (`tests/unit/test_credential_flow.py`)
Validates that AST taint analysis traces data flow from credential sources to network/DNS sinks without name-based false positives:
```powershell
developer-2\.venv\Scripts\python.exe -m pytest tests/unit/test_credential_flow.py
```
- `test_benign_code_no_credential_flow`: Benign code reading config has 0 findings.
- `test_exfiltration_taint_detected`: Code passing `os.environ["API_KEY"]` to `requests.post()` raises a `credential-exfiltration` finding.
- `test_declared_hosts_suppressed`: Requests to declared hosts (e.g., `api.weather.gov` declared in `SKILL.md`) are suppressed.
- `test_dns_tunneling_credential_flow`: Chained calls (`token.encode().decode()`) sent via `socket.gethostbyname()` are tracked and flagged.

### C. File Chunking, Coverage & Grounding (`tests/unit/test_chunker_coverage.py`)
Validates large file ingestion without silent truncation:
```powershell
developer-2\.venv\Scripts\python.exe -m pytest tests/unit/test_chunker_coverage.py
```
- `test_coverage_ledger_tracking`: Tracks analyzed vs. unanalyzed line ranges and computes coverage percentage.
- `test_file_chunker_markdown`: Splits markdown files respecting header hierarchy and token budgets.
- `test_file_chunker_python_ast`: Splits python source code cleanly along function/class boundaries without breaking syntax.
- `test_ground_quote_locates_lines`: Normalizes quotes and punctuation to verify LLM findings point to authentic file source lines.

### D. Fusion Floors & Monotonicity (`tests/unit/test_fusion_monotonic.py`)
Validates fail-closed behavior and hard/soft score floor mathematics:
```powershell
developer-2\.venv\Scripts\python.exe -m pytest tests/unit/test_fusion_monotonic.py
```
- `test_hard_deterministic_floor_cannot_be_lowered_by_model`: A hard malicious anchor (risk 95) cannot be suppressed by a model returning risk 0.
- `test_degraded_stage_floors_at_suspicious`: When a stage is marked `degraded` (e.g. timeout, service offline), risk score is floored at 30 (`SUSPICIOUS`).
- `test_score_monotonicity`: Incremental findings can only increase the overall risk score, never decrease it.

### E. CLI Smoke & Doctor Commands (`tests/unit/test_cli.py`)
```powershell
developer-2\.venv\Scripts\python.exe -m pytest tests/unit/test_cli.py
```
Validates:
- `skillsentry --version`: Emits version 2.0.0 and `Powered by Gemma 4`.
- `skillsentry doctor`: Verifies Ollama connectivity, model preflight, context length, and Docker availability.
- `skillsentry scan <path> --format json`: Verifies JSON output integrity, exit codes, and threshold enforcement.
- `skillsentry init`: Creates documented `skillsentry.toml`.

---

## 4. CI Regression Gates & Expected Fixtures

### A. Root Static Regression Gate
```powershell
developer-2\.venv\Scripts\python.exe tests/check_expected_verdicts.py --static-only
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
developer-2\.venv\Scripts\python.exe developer-2/tests/check_expected_verdicts.py
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

## 5. Web Dashboard Single-Page Application Verification

The web dashboard is served directly by `skillsentry serve` (or `skillsentry serve --demo-mode`):

```powershell
developer-2\.venv\Scripts\python.exe -c "
from fastapi.testclient import TestClient
from skillsentry.server.app import create_app
from skillsentry.server.demo_backend import DemoBackend

app = create_app(DemoBackend())
client = TestClient(app)

assert client.get('/').status_code == 200
assert client.get('/assets/style.css').status_code == 200
assert client.get('/assets/app.js').status_code == 200
assert client.get('/dashboard').status_code == 200
print('Web dashboard serving verified 100%!')
"
```
*Output: `Web dashboard serving verified 100%!`, with no 404s on SPA routing.*

