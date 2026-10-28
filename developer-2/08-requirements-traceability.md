# 08 · Requirements Traceability Matrix

> **Subsystem:** Backend — Skill Analysis  
> **Author:** Developer 2 (Backend Engineer & Security Architect)  
> **Source-of-Truth References:** [docs/01-project-overview.md](file:///d:/Skillsentry/SkillSentry/docs/01-project-overview.md) · [docs/02-architecture.md](file:///d:/Skillsentry/SkillSentry/docs/02-architecture.md) · [docs/checklists/dev2-skill-analysis.md](file:///d:/Skillsentry/SkillSentry/docs/checklists/dev2-skill-analysis.md)

---

## 1. Traceability Architecture

This matrix establishes rigorous bidirectional traceability from high-level project goals and architectural specifications down to Developer 2's functional modules, test cases, and verification evidence.

```
PRD & Architecture Requirements (docs/01, docs/02, docs/04)
                     │
                     ▼
Developer 2 Work Checklists (CL-D2-0 through CL-D2-8)
                     │
                     ▼
Target Modules & Components (skillsentry/core/)
                     │
                     ▼
Test Harnesses & Automated CI Assertions (tests/)
                     │
                     ▼
Verifiable Acceptance Evidence ("Done means")
```

---

## 2. Requirements Traceability Matrix

| Req ID | Source Specification | Requirement Summary | Assigned Work Package / Checklist | Target Module(s) | Verification Test(s) | Acceptance Criteria ("Done means") | Status |
|:---|:---|:---|:---|:---|:---|:---|:---:|
| **REQ-CACHE-01** | `02-arch` §2.3<br>`03-db` §3.2 | Deterministic POSIX directory SHA-256 calculation | **W2.5**<br>CL-D2-4 | `core/cache/hash_utils.py` | `tests/unit/test_hash_utils.py` | Stable hash across runs; changes on file edit, rename, permission bit change. | Planned (M1) |
| **REQ-CACHE-02** | `02-arch` §2.3<br>`03-db` §3.4-3.5 | SQLite WAL `scan_cache` repository with invalidation logic | **W2.5**<br>CL-D2-4 | `core/cache/sqlite_store.py` | `tests/unit/test_sqlite_store.py` | Re-scan hash + lookup completes in $< 2\text{ s}$; invalidates on engine/model bump. | Planned (M1) |
| **REQ-SPEC-01** | `02-arch` §2.3<br>`04-sec` §4.6 | YAML frontmatter validation against Agent Skill spec | **W2.1**<br>CL-D2-1 | `core/parser/skill_parser.py` | `tests/unit/test_skill_parser.py` | Parses name, description 1–1024 chars, trigger keywords; rejects malformed YAML. | Planned (M1) |
| **REQ-SPEC-02** | `04-sec` §4.6 (#1) | Hardened parsing: size caps, bomb guards, traversal rejection | **W2.1**<br>CL-D2-1 | `core/parser/skill_parser.py` | `tests/security/test_parser_hardening.py` | Rejects `../../` traversal; caps files at 10 MB and package at 50 MB with findings. | Planned (M1) |
| **REQ-TYPO-01** | `02-arch` §2.3<br>`01-over` §1.2 | Deceptive naming detection (homoglyphs + Levenshtein $\le 2$) | **W2.1**<br>CL-D2-1 | `core/parser/typosquat.py` | `tests/unit/test_typosquat.py` | Flags `g1t-translate` vs `git-translate`; no false positive on `git-helper`; +15 bonus signal. | Planned (M1) |
| **REQ-ANCH-01** | `02-arch` §2.3<br>`04-sec` §4.8 | Deterministic code analysis (`ast` walk + regex line-scan) | **W2.2**<br>CL-D2-2 | `core/semantic/ast_anchor.py` | `tests/unit/test_ast_anchor.py` | Catches full `DANGEROUS_PATTERNS` catalog with exact `file:line` citations. | Planned (M1) |
| **REQ-ANCH-02** | `02-arch` §2.4 | Normalization of anchor findings to 0–100 sub-score | **W2.2**<br>CL-D2-2 | `core/semantic/ast_anchor.py` | `tests/unit/test_anchor_scoring.py` | Mathematical formula maps severity points to $s_{\text{anchor}} \in [0, 100]$. | Planned (M1) |
| **REQ-SEM-01** | `02-arch` §2.3 (prompt)<br>`05-api` §5.5 | Frozen prompt execution via I2 with anchors as ground truth | **W2.3**<br>CL-D2-3 | `core/semantic/analyzer.py`<br>`core/semantic/prompts.py` | `tests/unit/test_semantic_analyzer.py` | Output conforms to strict JSON; model cannot contradict anchors; 1 retry on malformed JSON. | Planned (M1) |
| **REQ-SEM-02** | `02-arch` §2.3<br>`11-team` §11.3 | Declared-intent keyword extraction for Stage 4 honeypots | **W2.3**<br>CL-D2-3 | `core/semantic/analyzer.py` | `tests/contract/test_intent_keywords.py` | Emits subset of `{aws, cloud, github, slack, ssh, devops, generic}`. | Planned (M1) |
| **REQ-VIS-01** | `02-arch` §2.3<br>`06-ui` §6.3 | Image asset inventory, downscaling to 1024 px & contrast pre-filter | **W2.4**<br>CL-D2-5 | `core/vision/image_extractor.py` | `tests/unit/test_image_extractor.py` | Enforces 10 MB / 4096 px caps; flags low-contrast text regions deterministically. | Planned (M2) |
| **REQ-VIS-02** | `02-arch` §2.3<br>`06-ui` §6.3 | Vision OCR, injection classification & bounding-box extraction | **W2.4**<br>CL-D2-5 | `core/vision/vision_scanner.py` | `tests/unit/test_vision_scanner.py` | Emits normalized `bbox: [x,y,w,h]` and OCR transcript for Gemma's Eye View. | Planned (M2) |
| **REQ-VIS-03** | `02-arch` §2.3 | SVG dual-scan (static XML parsing + rasterized scan) | **W2.4**<br>CL-D2-5 | `core/vision/vision_scanner.py` | `tests/unit/test_svg_dual_scan.py` | Detects `<script>`, `onload=`, hidden CSS, and visually rendered text payloads. | Planned (M2) |
| **REQ-FIX-01** | `08-test` §8.2<br>`11-team` §11.2 | Author 4 benign fixtures with honest scripts | **W2.6**<br>CL-D2-6 | `fixtures/benign/*` | `tests/e2e/test_benign_fixtures.py` | All 4 benign fixtures pass with verdict `SAFE` (risk $< 30$); 0/4 false positives. | Planned (M2) |
| **REQ-FIX-02** | `08-test` §8.2<br>`08-test` §8.4 | Author `invoice-helper` and `g1t-translate` fixtures | **W2.6**<br>CL-D2-6 | `fixtures/malicious/*` | `tests/e2e/test_malicious_fixtures.py` | `invoice-helper` flagged by vision ($> 85$); `g1t-translate` flagged `SUSPICIOUS`. | Planned (M2) |
| **REQ-EVAL-01** | `08-test` §8.4 | Citation accuracy verification harness ($\pm 1$ line rule) | **W2.6**<br>CL-D2-6 | `tests/check_citation_accuracy.py` | `tests/test_citation_harness.py` | Measured citation accuracy $\ge 80\%$ against `tests/ground_truth.json`. | Planned (M3) |
| **REQ-EVAL-02** | `08-test` §8.8 | Automated CI expected-verdicts regression gate | **W2.7**<br>CL-D2-7 | `tests/check_expected_verdicts.py` | GitHub Actions CI Run | Fails build if any fixture drifts in verdict, risk band, or required findings. | Planned (M3) |
| **REQ-CHAOS-01**| `08-test` §8.6 | Corrupted-fixture resilience during M4 Chaos Run | **W2.7**<br>CL-D2-7 | `core/parser/skill_parser.py` | `tests/chaos/test_corrupted_fixtures.py` | Truncated YAML, 0-byte images, symlink loops handled cleanly with findings. | Planned (M4) |
| **REQ-STAB-01** | `11-team` §11.8<br>`08-test` §8.2 | Expand evaluation corpus to 20 skills & publish metrics | **W2.8**<br>CL-D2-8 | `fixtures/corpus_20/` | `tests/e2e/test_corpus_20.py` | 20-skill suite green in CI; precision, recall, and F1 documented in README. | Planned (M5) |
| **REQ-D2-PS-01**| Plan Update §5 | Windows PowerShell path normalization & device name rejection | **W2.1**<br>CL-D2-1 | `core/parser/skill_parser.py` | `tests/unit/test_powershell_paths.py` | Normalizes drive letters (`C:\`), backslashes, spaces, quotes; rejects `CON`, `NUL`, `PRN`. | Planned (M1) |
| **REQ-D2-PS-02**| Plan Update §5<br>`07-cli` §7.5 | Windows PowerShell CLI options & exit code contract (0/1/2/3/4) | **W2.1**<br>CL-D2-7 | `cli.py` / `skill_parser.py` | `tests/integration/test_powershell_cli.py` | Correct exit codes on safe (0) vs malicious (1) vs usage (2) vs op error (3) vs model (4); clean ANSI text. | Planned (M1) |
| **REQ-D2-SBX-01**| Plan Update §6 | Dynamic SandboxActionInstruction generation from AST anchors | **W2.2**<br>CL-D2-2 | `core/semantic/sandbox_instructions.py` | `tests/unit/test_sandbox_instructions.py` | Emits structured INT-4 checks (`CREDENTIAL_CANARY_MONITOR`, `DNS_SINKHOLE_WATCH`). | Planned (M1) |
| **REQ-D2-SBX-02**| Plan Update §6 | Intent-adaptive parameter & canary handoff to Stage 4 | **W2.3**<br>CL-D2-3 | `core/semantic/sandbox_instructions.py` | `tests/contract/test_sandbox_handoff.py` | Maps `contextual_intent` keywords to canary tokens and container constraints. | Planned (M1) |
| **REQ-D2-SBX-03**| Plan Update §6 | Strict 5-phase sandbox execution boundary (no host execution) | **W2.2**<br>CL-D2-2 | Subsystem architectural invariant | `tests/security/test_no_host_execution.py` | Untrusted skills never executed in PowerShell process or on host OS. | Planned (M1) |
| **REQ-D2-PERF-01**| Plan Update §7 | Cheap deterministic pre-filtering (<100ms AST, <50ms contrast) | **W2.2**<br>CL-D2-2, CL-D2-5 | `core/semantic/ast_anchor.py`<br>`core/vision/image_extractor.py` | `tests/benchmark/test_prefilter_perf.py` | AST/regex and contrast filters run before expensive Gemma inference. | Planned (M1) |
| **REQ-D2-PERF-02**| Plan Update §7 | Bounded concurrency & persistent local model session reuse | **W2.3**<br>CL-D2-3 | `core/semantic/analyzer.py` | `tests/benchmark/test_concurrency.py` | Worker thread bounds prevent CPU exhaustion; keep-alive connection to Ollama. | Planned (M1) |
| **REQ-D2-PERF-03**| Plan Update §7 | Thoroughness preservation: timeouts & partial scans flagged | **W2.3**<br>CL-D2-3 | `core/semantic/analyzer.py` | `tests/unit/test_fail_safe_timeouts.py` | Timeouts yield `degraded: true` with `note` findings; never a silent `SAFE`. | Planned (M1) |
| **REQ-D2-PERF-04**| Plan Update §7 | Multi-tier test suite separation (fast unit loop vs benchmark) | **W2.7**<br>CL-D2-7 | `tests/` directory structure | `pytest -m "not benchmark"` | Unit suite runs in $< 2$s; full benchmarks separated in dedicated suite. | Planned (M1) |

---

## 3. Checklist-to-Artifact Mapping Index

| Work Checklist | Description | Primary Target Artifact(s) | Primary Test Harness | Milestone |
|:---|:---|:---|:---|:---:|
| **CL-D2-0** | Onboarding & Environment | `developer-2/` documentation suite | Manual check of constants | M0 |
| **CL-D2-1** | Parser, Spec & Typosquat | `skillsentry/core/parser/skill_parser.py`<br>`skillsentry/core/parser/typosquat.py` | `tests/unit/test_parser.py`<br>`tests/unit/test_typosquat.py` | M0–M1 |
| **CL-D2-2** | AST Anchor Scanner & Sbx Handoff | `skillsentry/core/semantic/ast_anchor.py`<br>`skillsentry/core/semantic/sandbox_instructions.py` | `tests/unit/test_ast_anchor.py`<br>`tests/unit/test_sandbox_instructions.py` | M1 |
| **CL-D2-3** | Semantic Analyzer & Prompts | `skillsentry/core/semantic/analyzer.py`<br>`skillsentry/core/semantic/prompts.py` | `tests/unit/test_analyzer.py` | M1 |
| **CL-D2-4** | Cache Store & Hashing | `skillsentry/core/cache/hash_utils.py`<br>`skillsentry/core/cache/sqlite_store.py` | `tests/unit/test_cache.py` | M1 |
| **CL-D2-5** | Vision Scanner Pipeline | `skillsentry/core/vision/image_extractor.py`<br>`skillsentry/core/vision/vision_scanner.py` | `tests/unit/test_vision.py` | M2 |
| **CL-D2-6** | Fixtures & Ground Truth | `fixtures/benign/*`<br>`fixtures/malicious/invoice-helper`<br>`fixtures/malicious/g1t-translate`<br>`tests/ground_truth.json` | `tests/check_citation_accuracy.py` | M2–M3 |
| **CL-D2-7** | Evaluation, Benchmarks & CI Gate | `tests/check_expected_verdicts.py`<br>`tests/expected_verdicts.json` | Full CI Run (`pytest tests/`) | M3–M4 |
| **CL-D2-8** | Stabilization & Swing Tasks | Expanded 20-skill corpus<br>Swing modules (if reassigned) | `tests/e2e/test_corpus_20.py` | M5 |
