# 06 · Testing, Fixtures & Evaluation Specification

> **Subsystem:** Backend — Skill Analysis  
> **Author:** Developer 2 (Backend Engineer & Security Architect)  
> **Source-of-Truth References:** [docs/08-testing-and-evaluation.md](file:///d:/Skillsentry/SkillSentry/docs/08-testing-and-evaluation.md) · [docs/checklists/dev2-skill-analysis.md](file:///d:/Skillsentry/SkillSentry/docs/checklists/dev2-skill-analysis.md) CL-D2-6, CL-D2-7

---

## 1. Testing Philosophy & Multi-Tier Verification Strategy

> *"Professionals measure; students demo vibes."*

Developer 2’s testing suite guarantees that static, semantic, and visual analysis performs with mathematical determinism, zero false positives on legitimate skills, line-accurate citations, and complete resilience against corrupted or adversarial inputs.

```
                           VERIFICATION PYRAMID
                               ┌───────────┐
                               │ Chaos Run │
                               │  Drills   │
                           ┌───┴───────────┴───┐
                           │ Full Corpus E2E   │
                           │  Regression Gate  │
                       ┌───┴───────────────────┴───┐
                       │ Citation Accuracy Harness │
                       │    (±1 Source Line)       │
                   ┌───┴───────────────────────────┴───┐
                   │ Contract Tests (I1, I2 Mock, I3)  │
               ┌───┴───────────────────────────────────┴───┐
               │ Unit Tests (Parser, Typosquat, Hash, AST) │
               └───────────────────────────────────────────┘
```

---

## 2. Test Tiers & Execution Scopes

| Test Level | Scope & Components Under Test | Dependencies | Execution Command | Target SLA |
|:---|:---|:---|:---|:---:|
| **Unit** | `skill_parser.py`, `typosquat.py`, `ast_anchor.py`, `hash_utils.py`, `sqlite_store.py` | Local Python runtime (no model, no network) | `pytest tests/unit/test_analysis/` | $< 2$ s |
| **Contract** | I1 constants, I2 `MockGemma`, I3 `StageResult`, INT-4 `SandboxActionInstruction` | `MockGemma` stub | `pytest tests/contract/` | $< 1$ s |
| **Security** | Traversal, YAML bombs, Windows device names (`CON`, `PRN`), alternate data streams | Local Python runtime | `pytest tests/security/` | $< 2$ s |
| **Windows CLI** | PowerShell CLI path parsing, argument quoting, exit codes (0/1/2/3), UTF-8 console output | Windows PowerShell 5.1/7.x | `pytest tests/integration/test_powershell_cli.py` | $< 5$ s |
| **Benchmark** | Cache hashing, AST walk latency, PIL downscaling, SQLite WAL queries | `pytest-benchmark` | `pytest tests/benchmark/ --benchmark-only` | $< 5$ s |
| **Integration** | `analyzer.py` & `vision_scanner.py` with real local Ollama (Gemma 4 E4B Q4) | Ollama on `localhost:11434` | `pytest tests/integration/test_models/` | $< 60$ s |
| **Corpus E2E** | All 8 fixtures evaluated through Stages 0–3 against expected verdicts | Local pipeline | `python tests/check_expected_verdicts.py` | $< 90$ s |
| **Citation** | Accuracy harness evaluating reported `file:line` against ground truth | Annotated corpus | `python tests/check_citation_accuracy.py` | $\ge 80\%$ |

---

## 3. Developer 2 Fixture Corpus & Ground Truth

Developer 2 authors and maintains 6 of the 8 fixtures in the core evaluation suite, guaranteeing realistic structures and strict safety compliance:

### 3.1 Owned Fixtures Catalog

```
fixtures/
├── benign/
│   ├── pdf-summarizer/      # Pure text processing (PyPDF2 script, standard description)
│   ├── git-helper/          # Safe local git automation (git status, commit helpers)
│   ├── image-resizer/       # Local PIL/Pillow thumbnail creator (validates asset handling)
│   └── weather-fetch/       # DECLARED network call to api.open-meteo.com (Zero FP test)
└── malicious/
    ├── invoice-helper/      # logo.png containing white-on-white 4-6px injection text
    └── g1t-translate/       # Typosquat candidate impersonating 'git-translate'
```

### 3.2 Fixture Safety Rules (Strict Enforcement)
1. **No Live Infrastructure**: Fixtures must never contact real servers or real C2 domains. All URLs are fictional (`evil-collector.net`, `evil-c2.com`).
2. **Fake Secrets**: Credentials follow fake canary templates (`AKIA...SKS-...`, `ghp_SKS...`).
3. **Pillow Generator Scripts**: `invoice-helper/make_logo.py` is checked in to allow deterministic re-generation of the white-on-white payload image.

### 3.3 Ground-Truth Line Annotations (`tests/ground_truth.json`)
Developer 2 maintains hand-annotated suspicious line numbers for all malicious fixtures:

```json
{
  "fixtures/malicious/cloud-sync-pro": [
    {
      "file": "scripts/sync.sh",
      "lines": [5, 6],
      "pattern": "base64 credential read and nslookup DNS tunnel"
    }
  ],
  "fixtures/malicious/slack-notif-mal": [
    {
      "file": "scripts/notify.sh",
      "lines": [3, 4],
      "pattern": "Docker environment evasion probe"
    },
    {
      "file": "scripts/notify.sh",
      "lines": [10, 11, 12],
      "pattern": "Slack token theft and HTTP POST exfil"
    }
  ],
  "fixtures/malicious/invoice-helper": [
    {
      "file": "assets/logo.png",
      "lines": null,
      "pattern": "White-on-white prompt injection payload in bottom-right corner"
    }
  ]
}
```

---

## 4. Citation Accuracy Harness Specification

### 4.1 The $\pm 1$ Line Accuracy Rule
In static analysis, comments or multi-line commands can shift line numbers slightly across parsers. Developer 2 implements the official citation accuracy metric per [docs/08-testing-and-evaluation.md](file:///d:/Skillsentry/SkillSentry/docs/08-testing-and-evaluation.md) §8.4:

- **Matching Criteria**: A reported finding $F$ is classified as an **Accurate Citation** if:
  1. $F.\text{file} == G.\text{file}$ (Exact relative path match).
  2. $\min_{L \in G.\text{lines}} |F.\text{line} - L| \le 1$ (Reported line is within $\pm 1$ of any ground truth line).
- **Metric Formula**:
  $$\text{Citation Accuracy} = \frac{\text{Count of Accurate Citations}}{\text{Count of Total Ground Truth Incidents}} \times 100\%$$
- **Target Threshold**: **$\ge 80\%$** citation accuracy.

---

## 5. Automated CI Regression Gate (`tests/check_expected_verdicts.py`)

Developer 2 authors and maintains the CI regression script that blocks PR merges on regression:

```python
# Conceptual Verification Logic in tests/check_expected_verdicts.py
def verify_verdicts(results_file: Path, expected_file: Path):
    results = json.loads(results_file.read_text())
    expected = json.loads(expected_file.read_text())
    
    for fixture_name, target in expected.items():
        actual = results.get(fixture_name)
        assert actual is not None, f"Missing result for {fixture_name}"
        assert actual["verdict"] == target["verdict"], (
            f"Verdict regression on {fixture_name}: expected {target['verdict']}, got {actual['verdict']}"
        )
        assert target["risk_min"] <= actual["riskScore"] <= target["risk_max"], (
            f"Risk score out of bounds for {fixture_name}: {actual['riskScore']} not in [{target['risk_min']}, {target['risk_max']}]"
        )
        for req_finding in target["required_findings"]:
            assert any(f["stage"] == req_finding["stage"] and req_finding["pattern"] in f["message"] 
                       for f in actual["findings"]), f"Missing required finding {req_finding} on {fixture_name}"
```

---

## 6. Performance Benchmarking & SLA Enforcement

Developer 2’s automated test suite includes dedicated performance assertions via `pytest-benchmark`:
- **`test_cache_performance`**: Asserts that hashing a 50-file package and querying SQLite takes **$< 50\text{ ms}$** (target budget: $< 2$ s).
- **`test_ast_anchor_performance`**: Asserts that walking 1,000 lines of Python AST takes **$< 100\text{ ms}$** (cheap deterministic pre-filter gate).
- **`test_contrast_prefilter_performance`**: Asserts that pixel luminance contrast calculation takes **$< 50\text{ ms}$** per image.
- **`test_image_downscale_performance`**: Asserts that downscaling a $4096 \times 4096\text{ px}$ image to $1024\text{ px}$ takes **$< 200\text{ ms}$**.
- **`test_unit_suite_runtime`**: Asserts that Developer 2's pure unit test suite runs in **$< 5\text{ s}$** total to preserve a lightning-fast developer feedback loop.

---

## 7. Sandbox Action Instruction Verification Suite

Developer 2 maintains automated contract tests asserting correct emission of `SandboxActionInstruction` objects:
1. **Fixture `cloud-sync-pro` Test**: Verifies generation of:
   - `check_category="CREDENTIAL_CANARY_MONITOR"` with `contextual_intent=["aws"]`.
   - `check_category="DNS_SINKHOLE_WATCH"` with citation `scripts/sync.sh:6` and `check_status="required"`.
2. **Fixture `slack-notif-mal` Test**: Verifies generation of:
   - `check_category="EVASION_PROBE_WATCH"` with target `/.dockerenv`.
   - `check_category="CREDENTIAL_CANARY_MONITOR"` with `contextual_intent=["slack"]`.
3. **Traversal Package Test**: Verifies that malicious packages attempting path traversal outside the root boundary yield `check_status="blocked"` with safety notes, preventing untrusted execution.

---

## 8. Chaos Run & Windows Robustness Drills (Milestone M4)

During the Milestone M4 all-hands **Chaos Run**, Developer 2 is directly responsible for executing the **corrupted-fixture and Windows robustness drills**:
1. **Truncated YAML Test**: Introduce truncated frontmatter (`name: [unclosed bracket`) $\rightarrow$ verify scanner recovers with a `spec-invalid` finding without crashing.
2. **Zero-Byte Image Test**: Introduce a 0-byte `logo.png` $\rightarrow$ verify image extractor skips gracefully with `note` severity.
3. **Symlink Loop Test**: Introduce recursive directory symlinks $\rightarrow$ verify directory walker detects recursion depth and terminates cleanly.
4. **Offline Resilience**: Disconnect host network $\rightarrow$ verify all unit tests and local Ollama analyses complete normally without attempting network calls.
5. **Windows PowerShell Interrupt (Ctrl+C)**: Send `SIGINT` during directory hashing or AST scanning $\rightarrow$ verify database lock is released cleanly and temporary files are unlinked.
6. **Windows Path Anomalies Drill**: Submit paths with Windows drive letters (`C:\`), backslashes, mixed slashes, spaces, and trailing slashes $\rightarrow$ verify deterministic hashing and identical SARIF generation.
