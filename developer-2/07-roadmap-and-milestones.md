# 07 · Development Roadmap & Milestones (M0–M5)

> **Subsystem:** Backend — Skill Analysis  
> **Author:** Developer 2 (Backend Engineer & Security Architect)  
> **Source-of-Truth References:** [docs/11-team-and-workload.md](file:///d:/Skillsentry/SkillSentry/docs/11-team-and-workload.md) §11.4 · [docs/checklists/README.md](file:///d:/Skillsentry/SkillSentry/docs/checklists/README.md) · [docs/checklists/dev2-skill-analysis.md](file:///d:/Skillsentry/SkillSentry/docs/checklists/dev2-skill-analysis.md)

---

## 1. Roadmap Architecture & Scheduling Philosophy

SkillSentry follows a **milestone-based engineering schedule (M0 through M5)** with strict entry and exit criteria. Work is not bound to arbitrary hour slots, but to **verifiable capabilities and automated gates**.

Developer 2’s development track is deliberately designed for **high independence**:
- Stages 0, 1, 2, and 3 are developed against typed protocols and mock implementations (**I2** `MockGemma`).
- Unit and fixture tests run offline without waiting for Developer 1’s sandbox or Developer 3’s React UI.
- All handoffs (Interface **I3** `StageResult`, normalized intent keywords, and cache store) follow frozen schemas established in Milestone M0.

```
DEVELOPER 2 MILESTONE PROGRESSION TIMELINE
┌──────────────────────────────────────────────────────────────────────────────────┐
│ M0: Contracts & Scaffold                                                         │
│ └── Agree on I1 constants, I3 StageResult shape, draft benign fixture concepts    │
├──────────────────────────────────────────────────────────────────────────────────┤
│ M1: Deterministic Analysis & Cache Core                                          │
│ ├── W2.1: Spec Parser & Typosquat Engine (CL-D2-1)                               │
│ ├── W2.2: AST & Regex Anchor Scanner (CL-D2-2)                                   │
│ ├── W2.3: Semantic Analyzer against MockGemma (CL-D2-3)                          │
│ └── W2.5: Directory Hashing & SQLite Cache Store (CL-D2-4)                       │
├──────────────────────────────────────────────────────────────────────────────────┤
│ M2: Multimodal Vision & Fixture Completion                                       │
│ ├── W2.4: Vision Pipeline, Downscale & Bounding-Box Extractor (CL-D2-5)           │
│ └── W2.6: Author 6 Fixtures + Ground-Truth Annotations (CL-D2-6)                 │
├──────────────────────────────────────────────────────────────────────────────────┤
│ M3: Verdict Integration & Evaluation Harness                                     │
│ ├── W2.6: Export Canned Demo Payloads (I4) to Dev 1 demo_mode                    │
│ └── W2.7: Automated Regression Gate (check_expected_verdicts.py) (CL-D2-7)      │
├──────────────────────────────────────────────────────────────────────────────────┤
│ M4: Hardening & Chaos Run                                                        │
│ ├── Lead Corrupted-Fixture Chaos Run drill                                       │
│ └── Fill README Summary Metrics table from green benchmark run                   │
├──────────────────────────────────────────────────────────────────────────────────┤
│ M5: Stabilization & Phase 1 Expansion                                            │
│ ├── Grow Corpus to 20 Skills & Publish Precision/Recall (CL-D2-8)                │
│ └── Absorb Swing Tasks if triggered (STIX writer / Markdown renderer)            │
└──────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Milestone Breakdown & Work Package Allocation

### Milestone M0: Contracts & Scaffold (Entry Gate)
- **Work Package**: Pre-W2.1 setup (CL-D2-0).
- **Primary Tasks**:
  1. Review and freeze Interface **I1** (shared constants, stage names, severities, verdicts).
  2. Formalize Interface **I3** (`StageResult` dataclass) with Developer 1.
  3. Define the 4 benign fixture concepts (`pdf-summarizer`, `git-helper`, `image-resizer`, `weather-fetch`).
  4. Establish local development environment and pre-commit hooks (`ruff check`, `ruff format`).
- **Entry Criteria**: None (starts immediately).
- **Exit Gate ("Done means")**: Developer 2 can state all `StageResult` fields and legal enums; contract schemas signed off.

---

### Milestone M1: Deterministic Analysis & Cache Core
- **Work Packages**: W2.1 (Parser & Typosquat), W2.2 (AST Anchors), W2.3 (Semantic Analysis), W2.5 (Cache Store).
- **Primary Tasks**:
  1. **CL-D2-1**: Implement `parser/skill_parser.py` (YAML validation, size caps, traversal defense) and `parser/typosquat.py` (homoglyph fold + Levenshtein $\le 2$).
  2. **CL-D2-2**: Implement `semantic/ast_anchor.py` (Python `ast` walk, regex scanner, line citation generator, anchor block serializer).
  3. **CL-D2-3**: Implement `semantic/prompts.py` (frozen structured prompt) and `semantic/analyzer.py` (I2 caller, JSON retry logic, intent keyword extraction).
  4. **CL-D2-4**: Implement `cache/hash_utils.py` (deterministic POSIX directory hasher) and `cache/sqlite_store.py` (SQLite WAL repository, invalidation logic, migrations).
- **Entry Criteria**: Developer 1 delivers frozen contracts (**I1**) and `MockGemma` stub (**I2**).
- **Parallel Track**: Developer 2 builds against `MockGemma` without waiting for real Ollama or Docker.
- **Exit Gate ("Done means")**:
  - All drafted fixtures parse without crashes.
  - AST anchors catch dangerous patterns on test files with line accuracy.
  - Semantic analysis emits valid JSON on `MockGemma`.
  - Cache store performs hash + lookup in $< 50\text{ ms}$ ($< 2\text{ s}$ SLA).

---

### Milestone M2: Multimodal Vision & Fixture Completion
- **Work Packages**: W2.4 (Vision Pipeline), W2.6 (Fixture Finalization).
- **Primary Tasks**:
  1. **CL-D2-5**: Implement `vision/image_extractor.py` (asset inventory, 1024 px downscaler, luminance contrast pre-filter) and `vision/vision_scanner.py` (I2 `analyze_image`, bounding-box extraction, dual SVG scan).
  2. **CL-D2-5**: Author fixture `fixtures/malicious/invoice-helper` with checked-in Pillow script generating white-on-white `logo.png`.
  3. **CL-D2-5**: Author stretch fixture `fixtures/malicious/g1t-translate` (typosquat test).
  4. **CL-D2-6**: Finalize 4 benign fixtures with honest scripts and realistic metadata.
  5. **CL-D2-6**: Hand-annotate ground-truth lines in `tests/ground_truth.json`.
- **Entry Criteria**: Developer 1 delivers real Ollama model client (**I2**) for vision OCR; Developer 2 asset extractor operational.
- **Exit Gate ("Done means")**:
  - `invoice-helper` yields a vision finding with normalized bounding box and OCR transcript.
  - Benign fixture images yield zero findings.
  - Ground-truth lines hand-annotated for all malicious fixtures.

---

### Milestone M3: Verdict Integration & Evaluation Harness
- **Work Packages**: W2.6 (Demo Payloads), W2.7 (Evaluation Harness).
- **Primary Tasks**:
  1. **CL-D2-6**: Generate fixture-derived canned payloads (`tests/fixtures_canned_payloads.json`) and deliver Interface **I4** to Developer 1 for `demo_mode.py`.
  2. **CL-D2-7**: Implement `tests/check_expected_verdicts.py` CI regression harness.
  3. **CL-D2-7**: Implement `tests/check_citation_accuracy.py` harness ($\pm 1$ line rule).
  4. Coordinate with Developer 1's orchestrator to execute the full 8-fixture evaluation sheet.
- **Entry Criteria**: Developer 1 delivers full pipeline orchestrator and verdict fusion engine.
- **Exit Gate ("Done means")**:
  - Evaluation sheet passes targets: 3/3 malicious caught, 0/4 benign false positives, citation accuracy $\ge 80\%$, cached re-scan $< 2\text{ s}$.
  - Canned demo payloads merged into Developer 1's mock server.

---

### Milestone M4: Hardening & Chaos Run
- **Work Package**: W2.7 (Chaos Run & Benchmarks).
- **Primary Tasks**:
  1. **CL-D2-7**: Lead the **corrupted-fixture drill** during all-hands Chaos Run (truncated YAML, 0-byte images, symlink loops).
  2. Run flakiness watch: execute malicious fixtures $10\times$ each to guarantee deterministic outputs.
  3. Populate the official README Summary Metrics table with actual measured data from a clean benchmark run.
- **Entry Criteria**: Milestone M3 fully green.
- **Exit Gate ("Done means")**:
  - Corrupted fixtures handled gracefully with `note` findings without engine crashes.
  - CI expected-verdicts regression gate passing reliably on master.

---

### Milestone M5: Stabilization & Phase 1 Expansion
- **Work Package**: W2.8 (Stabilization & Swing Tasks).
- **Primary Tasks**:
  1. **CL-D2-8**: Scale test corpus to **20 skills** (multi-language scripts, varied injection vectors).
  2. Publish comprehensive precision, recall, and F1 methodology in docs.
  3. Curate and expand typosquatting dictionary to 150+ popular packages.
  4. Tag prompt templates with semantic version identifiers.
  5. Absorb any reassigned swing tasks per the workload balancing protocol.
- **Entry Criteria**: Successful Milestone M4 completion.
- **Exit Gate ("Done means")**: 20-skill benchmark green in CI; precision/recall documented; zero unowned swing tasks.

---

## 3. Critical Path & Dependency Management

```
CRITICAL PATH ANALYSIS
[CL-D1-1: Frozen I1/I3 Contracts] ──▶ [CL-D2-1: Spec Parser] ──▶ [CL-D2-2: AST Anchors]
                                                                        │
[CL-D1-3: MockGemma Stub (I2)] ─────────────────────────────────────────┼──▶ [CL-D2-3: Semantic Analyzer]
                                                                        │
[CL-D2-4: Cache Engine] ────────────────────────────────────────────────┴──▶ [CL-D1-5: Orchestrator E2E]
                                                                                    │
[CL-D2-5: Vision Pipeline] ──▶ [CL-D2-6: Fixtures] ──▶ [CL-D2-7: Eval Gate] ────────┘
```

### 3.1 Primary Bottlenecks & Mitigations
1. **Bottleneck: Model Client I2 Delivery**: If Developer 1 is delayed delivering the Ollama client, Developer 2 immediately proceeds using an internal `MockGemma` implementation matching the agreed protocol. Stage 2 and Stage 3 logic can be 100% verified prior to real model availability.
2. **Bottleneck: Orchestrator Integration**: Developer 2 provides standalone test runners for individual stages, allowing verification of AST anchors, spec validation, and hashing in complete isolation from `cli.py` or FastAPI.
