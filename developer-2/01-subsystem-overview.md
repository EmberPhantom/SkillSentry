# 01 · Subsystem Overview & Responsibility Boundaries

> **Subsystem:** Backend — Skill Analysis  
> **Author:** Developer 2 (Backend Engineer & Security Architect)  
> **Source-of-Truth References:** [docs/01-project-overview.md](file:///d:/Skillsentry/SkillSentry/docs/01-project-overview.md) · [docs/02-architecture.md](file:///d:/Skillsentry/SkillSentry/docs/02-architecture.md) · [docs/11-team-and-workload.md](file:///d:/Skillsentry/SkillSentry/docs/11-team-and-workload.md)

---

## 1. Context & Problem Statement

Modern AI Agent Skills (compliant with open standards such as [agentskills.io](https://agentskills.io/specification)) represent a dual-execution supply chain paradigm:
1. **Natural Language Instructions (`SKILL.md`)**: Prompt text, behavioral guidelines, and trigger rules injected directly into the LLM system prompt.
2. **Deterministic Code (`scripts/`, `assets/`)**: Arbitrary executable scripts (Bash, Python, Node.js) and bundled binary assets invoked by the agent to fulfill user requests.

This duality introduces novel supply-chain vulnerabilities. Snyk’s February 2026 *ToxicSkills* audit discovered that **36% of analyzed ClawHub skills contained prompt injection payloads**, and the *ClawHavoc* campaign weaponized **1,184+ malicious skills** over a six-week window. The OWASP Top 10 for Agentic Applications designates this category as **AST01 — Malicious Skills**.

Existing defenses fail because:
- Text-only scanners are completely blind to instructions hidden in image assets (white-on-white text, steganography).
- Post-install network monitors (e.g., Pipelock) act only after malicious code has already executed on the host.
- Enterprise firewalls (e.g., AIR Security) require sending proprietary skill IP to closed, third-party cloud environments.

**SkillSentry** provides an open-source, local-first pre-installation firewall combining multimodal reasoning (Gemma 4 text + vision), deterministic AST anchors, an intent-adaptive honeypot sandbox, sandbox evasion detection, and the **☠️ Poisoned Well** active defense.

---

## 2. Developer 2's Mandate & Boundaries

Developer 2 is responsible for **detecting malicious instructions and suspicious patterns across all static, semantic, and multimodal modalities** of the skill package, as well as managing high-speed incremental caching.

### 2.1 The Core Mission
> *"Find malicious instructions in skills — every static, semantic, visual, and typosquat detection stage — while providing fast, deterministic, and verifiable evidence."*

Developer 2 provides the **eyes, parsers, and static intelligence** of SkillSentry. Developer 1 provides the execution sandbox, active deception, and pipeline orchestration. Developer 3 provides the user experience and visualization.

```
                    SKILLSENTRY THREE-DEVELOPER WORKLOAD SPLIT
┌───────────────────────────────────────────────────────────────────────────────────┐
│ DEVELOPER 1: Backend + AI Integration                                             │
│ - Pipeline Orchestration & CLI (`cli.py`, `server/app.py`, `routes.py`)           │
│ - Model Client Plumbing (`core/models/gemma_local.py`, `gemma_cloud.py`) [I2]     │
│ - Docker Execution Sandbox & Masquerade (`core/sandbox/runner.py`, `masquerade.py`)│
│ - Intent-Adaptive Canaries & Inotify Monitor (`canary_fs.py`, `monitor.py`)       │
│ - Poisoned Well Active Defense & C2 Profiling (`canary_gen.py`, `exfil_tracker.py`)│
│ - Sandbox Evasion Detector (`core/evasion/detector.py`)                           │
│ - Verdict Engine, Risk Fusion & SARIF Exporter (`verdict/fusion.py`, `sarif.py`)   │
└────────────────────────────────────────┬──────────────────────────────────────────┘
                                         │ Consumes I3 (StageResult) & Cache Store
                                         │ Provides I2 (Model Client)
┌────────────────────────────────────────▼──────────────────────────────────────────┐
│ DEVELOPER 2: Backend — Skill Analysis (OUR SUBSYSTEM)                             │
│ - Package Parsing & Spec Validation (`core/parser/skill_parser.py`)              │
│ - Typosquatting Detection Engine (`core/parser/typosquat.py`)                     │
│ - Deterministic AST & Regex Anchor Scanner (`core/semantic/ast_anchor.py`)        │
│ - Semantic Analysis Orchestrator & Prompt Templates (`analyzer.py`, `prompts.py`) │
│ - Multimodal Vision OCR & Hidden-Text Scanner (`image_extractor.py`, `vision.py`) │
│ - Incremental Cache Engine & Content Hasher (`hash_utils.py`, `sqlite_store.py`)  │
│ - Ground Truth Corpus & Benchmark Harness (4 Benign + 2 Malicious Fixtures)       │
│ - Evaluation Run Sheet & CI Regression Gate (`tests/check_expected_verdicts.py`)   │
└────────────────────────────────────────┬──────────────────────────────────────────┘
                                         │ Provides I4 (Canned Demo Payloads)
                                         │ Bounding Box Evidence for Gemma's Eye View
┌────────────────────────────────────────▼──────────────────────────────────────────┐
│ DEVELOPER 3: Frontend (UI Only)                                                   │
│ - React 18 + Vite + Tailwind + shadcn/ui Console (`ui/`)                          │
│ - Triage Table with Risk Gauges & Cache Indicator ⚡                               │
│ - Live Scan Console (WebSocket stream consumer)                                   │
│ - Evidence Tabs: Static Code Viewer (file:line highlights) & Gemma's Eye View     │
│ - Poisoned Well Attack Timeline & React Flow IOC Graph                            │
│ - Demo Assets (README 30s GIF, unlisted YouTube backup demo video)                │
└───────────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Module Ownership Breakdown

Per [docs/11-team-and-workload.md](file:///d:/Skillsentry/SkillSentry/docs/11-team-and-workload.md) §11.2, Developer 2 owns the following exact paths and responsibilities:

| Module / Component | File Path | Scope & Primary Function |
|:---|:---|:---|
| **Directory Hasher** | `skillsentry/core/cache/hash_utils.py` | Computes deterministic, normalized SHA-256 directory digest (POSIX sorted, permission bits, exclusion rules). |
| **SQLite Cache Store** | `skillsentry/core/cache/sqlite_store.py` | Repository pattern for `scan_cache` & `schema_meta`; handles hit/miss, invalidation matrix, WAL mode, pruning (<2s budget). |
| **Package & Spec Parser** | `skillsentry/core/parser/skill_parser.py` | Parses YAML frontmatter via `python-frontmatter`, validates against Agent Skill Spec, enforces size caps, prevents path traversal, normalizes Windows PowerShell paths. |
| **Typosquat Detector** | `skillsentry/core/parser/typosquat.py` | Identifies deceptive naming via homoglyph folding + Levenshtein distance $\le 2$ against curated top-skill dictionary (+15 risk bonus). |
| **AST Anchor Scanner** | `skillsentry/core/semantic/ast_anchor.py` | Fast deterministic code scan (`ast` walk for Python, regex for Shell/JS) extracting dangerous calls with line citations (<100ms budget). |
| **Sandbox Instruction Gen** | `skillsentry/core/semantic/sandbox_instructions.py` | Derives structured `SandboxActionInstruction` records from AST/semantic/vision findings to drive Stage 4 sandbox execution. |
| **Semantic Analyzer** | `skillsentry/core/semantic/analyzer.py` | Coordinates Gemma 4 E4B text analysis over anchored prompts via I2; handles JSON retries, schema enforcement, fallback, embedding/intent extraction. |
| **Analyzer Prompts** | `skillsentry/core/semantic/prompts.py` | Frozen structured prompt templates framing skill code as untrusted data with anchored facts injected as ground truth. |
| **Asset Extractor** | `skillsentry/core/vision/image_extractor.py` | Inventories raster images and SVGs, enforces size/count caps, applies 1024 px downscale, executes contrast pre-filter. |
| **Vision Scanner** | `skillsentry/core/vision/vision_scanner.py` | Coordinates Gemma 4 Vision OCR via I2, extracts bounding boxes for Gemma's Eye View, performs dual SVG scan (XML + rendered). |
| **Benign Fixtures** | `fixtures/benign/` (4 skills) | `pdf-summarizer`, `git-helper`, `image-resizer`, `weather-fetch` (validates declared network use without false positives). |
| **Malicious Fixtures** | `fixtures/malicious/` (2 skills) | `invoice-helper` (white-on-white image payload), `g1t-translate` (typosquat of `git-translate`). |
| **Ground Truth & Harness** | `tests/ground_truth.json`, `expected_verdicts.json` | Hand-annotated suspicious line numbers for citation validation ($\pm 1$ line rule); automated regression test runner. |

---

## 4. Pipeline Stage RACI Matrix

The table below defines the exact RACI assignments (Responsible, Accountable, Consulted, Informed) across the entire 8-stage pipeline:

| Stage Identifier | Stage Name | Dev 1 | Dev 2 | Dev 3 | Dev 2 Role Details |
|:---|:---|:---:|:---:|:---:|:---|
| `cache` | **Stage 0: Incremental Cache** | A | **R / A** | C | Dev 2 builds hashing & SQLite repository; Dev 1 orchestrates query & write. Sub-2s SLA. |
| `spec` | **Stage 1: Spec Validation** | C | **R / A** | I | Dev 2 parses package, validates frontmatter, inventories files, normalizes Windows paths. |
| `typosquat` | **Stage 1: Typosquatting** | C | **R / A** | I | Dev 2 computes distance against dictionary; emits +15 risk bonus signal. |
| `deterministicAnchor` | **Stage 2: AST Anchors** | C | **R / A** | I | Dev 2 scans Python AST & scripts; extracts exact `file:line` anchors; emits sandbox instructions. |
| `semantic` | **Stage 2: Semantic Analysis** | C (Client) | **R / A** | I | Dev 2 formats prompts, calls I2 model client, extracts intent keywords (`aws`, `slack`, etc.). |
| `vision` | **Stage 3: Multimodal Vision** | C (Client) | **R / A** | C (BBox) | Dev 2 extracts images, scans via I2, outputs bounding boxes for UI, maps visual payloads to sandbox checks. |
| `sandbox` | **Stage 4: Sandbox Execution** | **R / A** | C | I | Dev 1 runs Docker container; Dev 2 provides normalized intent keywords and `SandboxActionInstruction` records. |
| `poisonedWell` | **Stage 4.5: Poisoned Well** | **R / A** | I | C | Dev 1 generates canaries, correlates exfil; Dev 2 provides demo data. |
| `evasion` | **Stage 5: Evasion Detection** | **R / A** | I | I | Dev 1 detects inotify probes on Docker artifacts. |
| `verdict` | **Stage 6: Verdict Engine** | **R / A** | C | C | Dev 1 fuses signals and outputs SARIF; Dev 2 provides normalized signals and evidence. |
| `eval` | **Evaluation & Benchmarking** | C | **R / A** | C | Dev 2 maintains ground-truth annotations and verifies evaluation sheet and benchmark gates. |

---

## 5. Architectural Decision Records (ADRs) Affecting Developer 2

The team workload agreement established eight core architectural decisions that dictate Developer 2’s interfaces:

- **ADR-D1 (Model Client Separation)**: Dev 2 owns analysis logic (`ast_anchor`, `analyzer`, `prompts`, `vision_scanner`); Dev 1 owns model plumbing (`gemma_local`, `gemma_cloud`). Dev 1 exposes the typed protocol **I2**; Dev 2 consumes it as a library. Dev 2 uses `MockGemma` for zero-blocker parallel development.
- **ADR-D2 (Pipeline Orchestration)**: Dev 1 owns `cli.py`, FastAPI `app.py`, WebSocket streaming, and `demo_mode.py`. Dev 2 does not write HTTP endpoints; Dev 2 returns standard `StageResult` dataclasses (Interface **I3**) to the orchestrator.
- **ADR-D3 (Milestone Gates M0–M5)**: Progress is measured against verifiable exit criteria (e.g., "cache lookup < 2 s", "benign FP rate = 0/4") rather than arbitrary work-hour estimates.
- **ADR-D4 (Dev 1 Sequence Priority)**: Dev 1 builds Sandbox $\rightarrow$ Deception $\rightarrow$ Model Plumbing $\rightarrow$ Report Generation. Dev 2 can develop Stages 0, 1, 2, and 3 completely in parallel using mock backends.
- **ADR-D5 (Cache Store Ownership)**: The `core/cache/` implementation is transferred to Dev 2 to balance workload. Dev 2 implements `hash_utils.py`, `sqlite_store.py`, and database migration scripts; Dev 1 consumes them in Stage 0 and Stage 6.
- **ADR-D6 (Dynamic Sandbox Instruction Contract & 5-Phase Boundary)**: Developer 2 analysis stages emit structured `SandboxActionInstruction` objects defining required check categories, target scripts, reasons, intent keywords, and constraints. Developer 2 **never** executes untrusted skills on the host machine or in the CLI process. All execution is strictly delegated to Developer 1's isolated Docker sandbox container.
- **ADR-D7 (Performance Optimization & Fail-Safe Invariance)**: Scan and test performance is maximized via content hashing, sub-2s SQLite cache hits, cheap deterministic AST/regex pre-filtering (<100ms) before model calls, image contrast pre-filtering, and bounded concurrency. However, optimizations must never skip required security stages or omit sandbox checks under time pressure. Model or sandbox timeouts never default to `SAFE`; they yield explicit degraded findings (`degraded: true`).
- **ADR-D8 (Windows PowerShell CLI Support)**: The scanning pipeline fully supports Windows PowerShell invocation (`skillsentry scan <path>` / `python -m skillsentry.cli scan <path>`). Developer 2's parsers and path utilities strictly normalize Windows path formats (`C:\`, backslashes, long paths, spaces) and handle console character encoding (UTF-8) cleanly.

---

## 6. Swing Task Protocol

If Dev 1 encounters delivery delays on the critical path, the following tasks are pre-agreed to transfer to Developer 2 per [docs/11-team-and-workload.md](file:///d:/Skillsentry/SkillSentry/docs/11-team-and-workload.md) §11.8:

1. **STIX 2.1 Bundle Serialization**: Writing `attacker_profile.py` STIX JSON serialization based on established schemas.
2. **Markdown Report Renderer**: Rendering human-readable Markdown summaries from SARIF results.
3. **Gemini API Cloud Fallback Client (`gemma_cloud.py`)**: Implementing the I2 protocol against the Google GenAI SDK.
4. **CLI Progress Bars & Initial Setup Wizard (`skillsentry init`)**: User experience enhancements for Phase 1.
5. **PowerShell CLI Windows Wrapper & Formatter**: PowerShell-specific output formatting and tab completion scripts.
