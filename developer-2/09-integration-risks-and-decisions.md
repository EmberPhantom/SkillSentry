# 09 · Integration Risks & Technical Decisions

> **Subsystem:** Backend — Skill Analysis  
> **Author:** Developer 2 (Backend Engineer & Security Architect)  
> **Source-of-Truth References:** [docs/10-developer-guide.md](docs/10-developer-guide.md) §10.9 · [docs/11-team-and-workload.md](docs/11-team-and-workload.md) §11.6, §11.8

---

## 1. Technical & Integration Risk Register

The table below catalogs all architectural, operational, and cross-workstream risks affecting Developer 2's components, with concrete mitigation strategies:

| Risk ID | Risk Description | Prob. | Impact | Mitigation Strategy | Owner |
|:---|:---|:---:|:---:|:---|:---:|
| **RSK-D2-01** | **Model Client (I2) Delivery Delay**: Developer 1's local Ollama client is delayed due to sandbox work. | Med | High | **Decoupled Mock Architecture**: Developer 2 implements and codes against `MockGemma` implementing the frozen I2 Protocol. Semantic and vision analysis logic are 100% testable in CI without a live model. | Dev 2 / Dev 1 |
| **RSK-D2-02** | **Adversarial Typography / OCR Evasion**: 4 px white-on-white text in `invoice-helper` fails recognition in Gemma 4 Vision due to quantization artifacts. | Med | Med | **Dual Mitigation**: (1) Deterministic luminance/contrast pre-filter flags suspicious low-contrast text regions prior to inference; (2) If rehearsed inference misses, tune fixture font size from 4 px to 6 px per plan risk mitigation rule (never weaken the detector). | Dev 2 |
| **RSK-D2-03** | **LLM Semantic Non-Determinism**: Semantic analysis produces varying JSON or missed intent contradictions across re-runs. | Med | High | **Deterministic Anchoring Invariance**: Hard AST/regex anchors are injected into the prompt as immutable facts. If model output contradicts an anchor, the engine overrides the model and enforces the anchor's severity. | Dev 2 |
| **RSK-D2-04** | **Citation Line Drift ($\pm 1$ line)**: Source code comments or multi-line statement differences cause reported finding lines to miss ground truth. | Med | Med | **$\pm 1$ Line Evaluation Metric**: The citation evaluation harness explicitly incorporates the $\pm 1$ line tolerance window per [docs/08-testing-and-evaluation.md](docs/08-testing-and-evaluation.md) §8.4. AST visitor maps Call nodes to `lineno` attribute. | Dev 2 |
| **RSK-D2-05** | **Cache Invalidation Failure**: Skill is altered post-audit but returns cached SAFE verdict. | Low | Crit | **Canonical Directory SHA-256**: Key incorporates relative POSIX path, file mode bits, and content digest. Any byte change, rename, or permission modification forces a cache miss. | Dev 2 |
| **RSK-D2-06** | **Parser Denial of Service**: Hostile package contains nested YAML bombs or recursive symlink loops. | Low | High | **Hardened Parsing Boundaries**: Safe YAML loader with max recursion depth of 10; 10 MB per-file cap; 50 MB package cap; strict root-boundary containment checks. | Dev 2 |
| **RSK-D2-07** | **Workload Imbalance & Dev 1 Bottleneck**: Dev 1’s surface area (~20 modules) slips behind milestone exit gates. | Med | High | **Swing Task Execution**: Pre-agreed tasks (STIX bundle writer, Markdown renderer, Gemini cloud fallback client, CLI setup) immediately transfer to Dev 2 per [docs/11-team-and-workload.md](docs/11-team-and-workload.md) §11.8. | Dev 2 / Dev 1 |
| **RSK-D2-08** | **Windows Path & Encoding Anomalies**: PowerShell passes backslashes, drive letters, spaces, or Unicode with BOM; scripts use CRLF. | Med | Med | **Path & Line Normalizer**: Safe path resolution with `pathlib.Path`, conversion to POSIX `/`, UTF-8 BOM handling (`utf-8-sig`), and universal newline normalization. | Dev 2 |
| **RSK-D2-09** | **Sandbox Instruction Schema Drift**: Dev 1 sandbox runner expects different arguments or fails to map canary tokens. | Low | High | **Frozen Interface INT-4 & Contract Tests**: Dataclass schema frozen in M0; automated contract tests (`test_sandbox_handoff.py`) block merges on drift. | Dev 2 / Dev 1 |
| **RSK-D2-10** | **Optimization vs. Thoroughness Conflict**: Aggressive latency optimization risks skipping required stages or treating timeouts as safe. | Med | Crit | **Architectural Axiom ADR-D7**: Optimize redundant parsing and caching only; never omit required detection stages; timeouts flagged `degraded: true`, never `SAFE`. | Dev 2 / Dev 1 |

---

## 2. Unresolved Technical Questions & Clarification Proposals

The following specifications are currently provisional and require formal cross-developer agreement during Milestone M0/M1:

### 2.1 Decision Item 1: Bounding Box Coordinate Normalization
- **Issue**: [docs/checklists/dev3-frontend.md](docs/checklists/dev3-frontend.md) §98 states *"bbox normalized to displayed image size"*, while [docs/checklists/dev2-skill-analysis.md](docs/checklists/dev2-skill-analysis.md) §95 states `[x, y, w, h]`.
- **Proposed Resolution**: Developer 2 standardizes on **normalized floats in range $[0.0, 1.0]$** formatted as:
  $$\text{bbox} = [x_{\text{min\_norm}}, y_{\text{min\_norm}}, \text{width}_{\text{norm}}, \text{height}_{\text{norm}}]$$
  Developer 3’s canvas/SVG overlay calculates rendered pixel coordinates by multiplying normalized coordinates with the rendered DOM image dimensions. This maintains complete resolution independence across client viewport sizes.
- **Action**: Confirmed in Interface INT-3; Developer 3 to review.

### 2.2 Decision Item 2: Database Initialization & Migration Coordination
- **Issue**: Developer 2 owns `scan_cache` and `schema_meta` tables, while Developer 1 owns `scans`, `findings`, `active_defense`, and `iocs`. Both reside in `~/.skillsentry/skillsentry.db`.
- **Proposed Resolution**:
  1. The initial DDL script `migrations/0001_init.sql` will contain the complete schema with `CREATE TABLE IF NOT EXISTS` for all tables.
  2. Developer 2 owns the migration runner utility (`core/cache/sqlite_store.py`) that applies sequential SQL migrations inside a single transaction and checks `schema_version`.
  3. Neither developer drops or alters tables destructively; version bumps apply forward-only.
- **Action**: Signed off between Dev 1 and Dev 2 in Milestone M1.

### 2.3 Decision Item 3: Exact Signal Normalization Mapping
- **Issue**: Developer 1's fusion formula requires sub-scores $s_i \in [0, 100]$. How does Developer 2 compute $s_{\text{anchor}}$ and $s_{\text{semantic}}$?
- **Proposed Resolution**: Formally document the deterministic mapping formula:
  - **AST Anchors ($s_{\text{anchor}}$)**:
    $$s_{\text{anchor}} = \min\left(100, 40 \times N_{\text{crit}} + 25 \times N_{\text{high}} + 15 \times N_{\text{med}} + 5 \times N_{\text{low}}\right)$$
  - **Semantic Sub-Score ($s_{\text{semantic}}$)**:
    - If `is_deceptive == True`: $s_{\text{semantic}} = \max(75.0, \text{confidence} \times 100.0)$.
    - If `is_deceptive == False`: $s_{\text{semantic}} = \min(20.0, (1.0 - \text{confidence}) \times 100.0)$.
- **Action**: Confirmed in Interface I3 and `03-functional-specifications.md`.

### 2.4 Decision Item 4: PowerShell CLI Exit Codes vs. Operational Failures
- **Issue**: When a scan fails due to an environmental failure (e.g. Docker daemon stopped or Ollama model not pulled), what exit code should PowerShell return?
- **Proposed Resolution**: Strictly separate security verdicts from operational failures:
  - Verdict `MALICIOUS` returns exit code `1` (blocks PR merge).
  - Usage / syntax error returns exit code `2`.
  - Operational error (Docker down, SQLite locked) returns exit code `3` and emits an operational alert, never a verdict.
  - Model unavailable without configured fallback returns exit code `4`.
- **Action**: Confirmed in Interface INT-5.

### 2.5 Decision Item 5: Host Traversal Threat & Blocked Sandbox Execution
- **Issue**: If a skill package contains path traversal (`../../.ssh`), should the Docker sandbox still attempt execution?
- **Proposed Resolution**: No. If Stage 1 spec validation flags path traversal or reserved DOS devices, sandbox check status is set to `blocked`. Untrusted code with host-traversal intent must never be mounted or executed.
- **Action**: Confirmed in Interface INT-4.

### 2.6 Decision Item 6: In-Memory PackageManifest Sharing across Stages
- **Issue**: Each pipeline stage independently reading files from disk induces redundant I/O, slowing down Windows scan turnaround.
- **Proposed Resolution**: Stage 1 constructs an immutable, in-memory `PackageManifest` (scripts, AST nodes, normalized paths, metadata). Downstream stages (AST anchor scan, semantic prompt fencing, image extraction, and Docker bind mounts) consume this shared in-memory object, cutting filesystem I/O to a single traversal pass.
- **Action**: Confirmed in `03-functional-specifications.md` Capability K.

---

## 3. Cross-Developer Coordination & Sync Cadence

1. **Daily Standup against Milestone Criteria**: Focus on blockers on Interfaces I1, I2, I3, INT-4, and INT-5.
2. **Contract Freeze Windows**:
   - Interface I1 (Verdict schema & constants) frozen at M0 exit.
   - Interface INT-4 (`SandboxActionInstruction`) frozen at M1 entry.
   - Analyzer prompts frozen at M2 exit (modifications require full corpus re-run).
3. **Escalation Protocol for Swing Tasks**: If any milestone exit criterion for Developer 1 is at risk within 24 hours of gate review, the affected swing task (e.g., STIX writer) is formally transferred to Developer 2.

---

## 4. Project-Wide Planning Document Change Proposals (For Project Owner & Dev 1)

Developer 2 proposes the following formal updates to shared documentation files outside `developer-2/`:

### Proposal 1: Update `docs/07-cli-reference.md`
- Add Windows PowerShell documentation section describing invocation (`skillsentry scan <path>`), path normalization (`C:/...`), and execution in PowerShell 5.1 and 7.x.
- Document exit codes: 0 = Safe, 1 = Threshold exceeded (Gate fail), 2 = Usage error, 3 = Operational error, 4 = Model unavailable.
- Document supported flags: `--sarif-out`, `--format text|json|sarif|markdown`, `--no-cache`, `--no-sandbox`, `--backend auto|local|cloud|demo`, `--demo-mode`, `--timeout`, `--fail-on`, `--quiet`.

### Proposal 2: Update `docs/05-api-reference.md`
- Extend `GET /skills/{id}` endpoint schema to include `sandboxInstructions` field listing generated `SandboxActionInstruction` objects.

### Proposal 3: Update `docs/02-architecture.md`
- Include the **5-Phase Sandbox Execution Boundary** in §2.3 to formally distinguish Analysis Output (Dev 2) from Execution Request (Orchestrator) and Sandbox Enforcement (Dev 1).
- Codify the **Thoroughness Preservation Axioms** in §2.6: never silently drop required stages; record timeouts as `degraded: true` with findings (never default to `SAFE`); explicitly disclose fast profiles.

### Proposal 4: Update `docs/08-testing-and-evaluation.md`
- Formally document the multi-tier test suite separation (Tier 1 Unit <2s, Tier 2 Contract <1s, Tier 3 Security <2s, Tier 4 Windows CLI <5s, Tier 5 Benchmarks <5s, Tier 6 Full Regression <90s) to keep local developer loops fast while preserving full CI regression gates.
