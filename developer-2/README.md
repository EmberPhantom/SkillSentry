# Developer 2 Documentation Package: Skill Analysis Subsystem

> **SkillSentry — A Context-Aware Firewall for the Agent Skill Supply Chain with Poisoned Well Active Defense**  
> **Subsystem:** Backend — Skill Analysis  
> **Owner:** Developer 2 (Senior Software Architect & Backend Engineer)  
> **Repository Root:** `.` (SkillSentry Repository Root)  
> **Workspace Location:** `developer-2/`

---

## 1. Executive Summary & Mission

SkillSentry sits as a pre-installation security gate and runtime active defense between public/third-party AI agent skill repositories (such as OpenClaw's ClawHub) and developer runtime environments. Agent skills represent a novel and dual-natured attack surface: they combine executable program code (Bash, Python, JavaScript) with natural language instructions that are dynamically ingested into AI agents' system contexts.

Within the 3-developer architecture of SkillSentry, **Developer 2** is exclusively accountable for the **Skill Analysis Subsystem**: detecting, cataloging, and evidencing **all malicious instructions, suspicious code patterns, visual injection payloads, and typosquatting attempts** across static, semantic, and multimodal modalities, while managing the high-performance content-addressable cache store.

In addition, Developer 2 generates **dynamic sandbox action instructions** (`SandboxActionInstruction`, Interface INT-4) to drive Developer 1's Stage 4 behavioral sandbox, supports the **Windows PowerShell CLI scan workflow** through safe path normalization and console compatibility, and enforces a **performance optimization architecture** that minimizes scan and test latency without sacrificing detection thoroughness or security controls.

```
+---------------------------------------------------------------------------------------------------+
|                                      SKILLSENTRY SYSTEM                                           |
|                                                                                                   |
|   Developer 1                        DEVELOPER 2 (Our Scope)                      Developer 3     |
|   (Backend + AI Integration)         (Backend - Skill Analysis)                   (Frontend UI)   |
|  +--------------------------+       +------------------------------------+       +---------------+|
|  | - Pipeline Orchestrator  |  I3   | [Stage 0] Incremental Cache Store  |  I4   | - React 18    ||
|  | - PowerShell CLI Runner  |<------| [Stage 1] Spec & Typosquat Detector|------>|   Dashboard   ||
|  | - Docker Sandbox Core    | INT-4 | [Stage 2] AST Anchors & Semantic   | INT-3 | - Live Console||
|  | - Context Honeypots      |<======| [Stage 3] Multimodal Vision OCR    |======>| - Triage Table||
|  | - Poisoned Well Engine   | (Sbx) | [Perf]    Pre-filter & Concurrency |(BBox) | - Gemma's Eye ||
|  | - Evasion Detection      |  I2   | [Handoff] Dynamic Sbx Instructions |       | - PW Timeline ||
|  | - Verdict Engine & SARIF |<------| [Eval]    Fixtures & Ground Truth  |       |               ||
|  +--------------------------+(Model)| [Quality] Regression Gate & Harness|       +---------------+|
|                             |Client +------------------------------------+                        |
+---------------------------------------------------------------------------------------------------+
```

---

## 2. Subsystem Documentation Sitemap

This documentation package constitutes the complete architectural, functional, security, interface, and operational reference for Developer 2's responsibilities across all project milestones (**M0 through M5** and Phase 1/Phase 2).

| Document | Title & Focus | Primary Cross-References |
|:---|:---|:---|
| [**01-subsystem-overview.md**](01-subsystem-overview.md) | **Subsystem Overview & Responsibility Boundaries**<br>Mandate, module ownership, RACI matrix, team integration, core principles, PowerShell & sandbox handoff scope. | `docs/01-project-overview.md`<br>`docs/11-team-and-workload.md` |
| [**02-architecture-and-dataflow.md**](02-architecture-and-dataflow.md) | **Module Architecture & Interaction Diagrams**<br>System context, data flows, trust boundaries, pipeline sequencing, Mermaid models, 5-phase sandbox boundary. | `docs/02-architecture.md`<br>`docs/04-security.md` |
| [**03-functional-specifications.md**](03-functional-specifications.md) | **Detailed Functional Specifications (Stages 0–3 & Handoffs)**<br>Specs for Parser, Typosquat, AST Anchors, Semantic, Vision, Cache, Dynamic Sandbox Instructions & Performance Optimization. | `docs/02-architecture.md` §2.3<br>`docs/03-database.md` §3.2<br>`docs/checklists/dev2-skill-analysis.md` |
| [**04-interfaces-and-contracts.md**](04-interfaces-and-contracts.md) | **Interface & Data-Contract Reference**<br>I1 (Constants), I2 (Model Client), I3 (`StageResult`), I4 (Demo Payloads), INT-1 to INT-5 (Cache, BBox, Sbx Instructions, PowerShell CLI). | `docs/05-api-reference.md`<br>`docs/11-team-and-workload.md` §11.6 |
| [**05-security-and-threat-model.md**](05-security-and-threat-model.md) | **Security Architecture & Threat Handling**<br>Hostile input defense, parser hardening, prompt injection resilience, fail-safe rules, Windows path & PowerShell defense, sandbox safety boundary. | `docs/04-security.md`<br>`docs/10-developer-guide.md` |
| [**06-testing-and-evaluation-spec.md**](06-testing-and-evaluation-spec.md) | **Testing, Fixtures & Evaluation Specification**<br>Test pyramid (unit, contract, benchmark, E2E), corpus design, ground-truth annotations, citation accuracy ($\pm 1$ line), CI gate. | `docs/08-testing-and-evaluation.md`<br>`docs/checklists/dev2-skill-analysis.md` |
| [**07-roadmap-and-milestones.md**](07-roadmap-and-milestones.md) | **Development Roadmap & Milestones (M0–M5)**<br>Dependency-aware execution plan, critical path, parallel tasks, sandbox handoff milestones, swing task protocol. | `docs/11-team-and-workload.md` §11.4<br>`docs/checklists/README.md` |
| [**08-requirements-traceability.md**](08-requirements-traceability.md) | **Requirements Traceability Matrix**<br>End-to-end mapping from PRD and checklists (CL-D2-0..8) to specs, code, tests, PowerShell workflow, and sandbox instructions. | `docs/checklists/dev2-skill-analysis.md`<br>`docs/01-project-overview.md` |
| [**09-integration-risks-and-decisions.md**](09-integration-risks-and-decisions.md) | **Integration Risks, Decisions & External Proposals**<br>Risk register, unresolved specs, cross-developer coordination protocols, project-wide doc change proposals for Dev 1 / Dev 3. | `docs/10-developer-guide.md` §10.9<br>`docs/11-team-and-workload.md` §11.8 |
| [**10-developer-operating-guide.md**](10-developer-operating-guide.md) | **Developer Operating & Onboarding Guide**<br>Environment setup, verification commands, PowerShell CLI local run workflows, Windows test commands, debugging runbook. | `docs/10-developer-guide.md` §10.1<br>`CONTRIBUTING.md` |
| [**test.md**](test.md) | **Comprehensive Build, Test, and Verification Guide**<br>Full testing procedures, commands, build verification, failure diagnostic runbooks, and PR CI guidance. | `developer-2/pyproject.toml` |

---

## 3. Strict Development Rules & Boundaries

As Developer 2, the following engineering boundaries are strictly enforced:

1. **Workspace Boundary**: Developer 2's standalone skill analysis reference implementation and test suite reside in `developer-2/` and are ported into `skillsentry/core/` and `tests/` on `main`.
2. **Read-Only Shared Assets**: Existing shared project files (`docs/`, `ui/`, `skillsentry/skill/`, `pyproject.toml`) are read-only on feature branches until merged or ported.
3. **Implementation Status**: Full implementation and security hardening complete across all 7 pipeline stages, with 228 passing tests, 0 skips, and 0 failures.
4. **Local-First & Privacy Guarantee**: All analysis algorithms run locally using local or demo backends and local SQLite. No unauthorized telemetry or external data leakage.
5. **Fail-Safe Principle**: No error path, malformed input, model timeout, or parser failure may ever result in a `SAFE` verdict. Unhandled errors must yield explicit degraded findings (`note` severity with `*-unavailable` codes) and propagate to the orchestrator.
6. **Deterministic Ground Truth Principle**: AST/regex anchor findings are immutable ground truth. The LLM may never override, soften, or contradict confirmed deterministic code findings.
7. **Sandbox Execution Separation**: Developer 2 detects and communicates sandbox-related actions (`SandboxActionInstruction`) but **never executes untrusted skills on the host machine or in the CLI process**. All execution is isolated to Developer 1's Docker sandbox subsystem.
8. **Performance Optimization Invariance**: Performance optimizations (caching, AST pre-filters, bounded concurrency) must never sacrifice detection thoroughness, bypass required stages, or report timeouts as clean results.
