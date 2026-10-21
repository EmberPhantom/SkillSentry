# 🛡️ SkillSentry — Project Documentation

> **SkillSentry** — A Context-Aware Firewall for the Agent Skill Supply Chain with "Poisoned Well" Active Defense.
>
> *"Your proprietary skills never leave your machine for auditing. We don't just block attackers; we follow them home."*

This directory contains the complete documentation set for **SkillSentry v2.0**, an open-source, fully-local gatekeeper that audits AI Agent Skills before installation — fusing Gemma 4 multimodal reasoning (text + vision) with deterministic sandbox telemetry, context-aware honeypots, sandbox-evasion detection, and active deception (Poisoned Well).

> 📌 **Provenance:** This documentation set is generated from *SkillSentry — Complete Implementation Plan v2.0* (MLH Hacktoberfest Hack Day). Where a document extends the plan with concrete engineering detail (e.g., full database DDL, CLI exit codes), the additions are marked as **Spec (proposed)** and are consistent with the plan's contracts.

---

## 📚 Document Index

| # | Document | Contents |
|:--|:---------|:---------|
| 1 | [Project Overview](01-project-overview.md) | Problem statement, market validation, solution summary, feature matrix, competitive positioning, success metrics, glossary |
| 2 | [Architecture](02-architecture.md) | System context, the 8-stage inspection pipeline, risk scoring model, data flow, module map, tech stack, integration contracts, Phase-2 MCP proxy |
| 3 | [Database](03-database.md) | SQLite schema (cache, scans, findings, canary events, IOCs, attacker profiles), directory hashing spec, cache invalidation, ERD, migrations, Postgres team-server variant |
| 4 | [Security](04-security.md) | Supply-chain threat model, SkillSentry's own attack surface, sandbox hardening, Poisoned Well ethics & safety, prompt-injection defense, privacy, vulnerability disclosure policy, known limitations |
| 5 | [API Reference](05-api-reference.md) | FastAPI REST endpoints, WebSocket live-scan stream, frozen Verdict JSON Contract v1, SARIF 2.1.0 extension schema, STIX export mapping, error model, mock-server contract |
| 6 | [UI/UX Design](06-ui-ux.md) | Design language & tokens, screen architecture, wireframes (Triage Table, Poisoned Well IOC view, Gemma's Eye View), component tree, UX rules, accessibility |
| 7 | [CLI Reference](07-cli-reference.md) | `skillsentry` command reference, configuration file, environment variables, exit codes for CI, examples |
| 8 | [Testing & Evaluation](08-testing-and-evaluation.md) | Test strategy, the 7+1 fixture corpus, evaluation plan & metrics, Chaos Run procedure, rehearsed demo script, CI pipeline |
| 9 | [Deployment & Production](09-deployment-and-production.md) | Distribution surfaces (pip / Docker / GitHub Action), self-hosted team-server topology, MCP runtime interception (Phase 2), production hardening, observability, operations |
| 10 | [Developer Guide](10-developer-guide.md) | Environment setup, repo structure, dev workflow, coding standards, extension guides (new stage / fixture / canary intent), roadmap |
| 11 | [Team & Workload](11-team-and-workload.md) | **Authoritative** 3-developer role split, module ownership map, work packages, milestones M0–M5, RACI, interface contracts, swing tasks |
| ✓ | [Work Checklists](checklists/README.md) | Task-level checklists per developer (CL-D1/D2/D3 series) with dependencies, acceptance criteria, and a milestone → checklist matrix |
| — | [Changelog](CHANGELOG.md) | Version history following Keep a Changelog |

## 🗂 Repository-Root Artifacts

The following live at the **repo root** (one level above `docs/` in the assembled `skillsentry/` skeleton), not inside this folder:

| File | Purpose |
|:-----|:--------|
| `README.md` | Public repo readme in the judge-compliance order: GIF → threat model → architecture → how-to-run → eval table |
| `LICENSE` | MIT |
| `SECURITY.md` | Vulnerability disclosure policy (mirrors docs/04-security.md §4.12) |
| `CONTRIBUTING.md` | Contributor workflow, contract-freeze rules, PR checklist |
| `skillsentry/skill/SKILL.md` | SkillSentry's **own** spec-compliant Agent Skill (compliance requirement) |
| `skillsentry/skill/scripts/audit.sh` | Bundled audit entrypoint for that skill |

## 🧭 Reading Paths

- **New contributor** → 1 → 2 → 10 → 8
- **Team lead / project planning** → 11 → 2 → 8
- **Security reviewer / judge** → 1 → 4 → 2 → 8
- **Frontend developer (Dev 3)** → 11 → 6 → 5 → 2 (§Integration Contracts)
- **Backend developer (Dev 1 / Dev 2)** → 11 → 2 → 3 → 5 → 4
- **Ops / platform team** → 9 → 7 → 3

## 🔑 Key Facts at a Glance

| Attribute | Value |
|:---|:---|
| License | MIT (open source) |
| Core language | Python 3.11+ |
| Frontend | React 18 + Vite + TypeScript + Tailwind + shadcn/ui |
| Local model | Gemma 4 E4B via Ollama (Q4 quantized) — **100% local by default** |
| Cloud fallback | Gemini API (opt-in, wired from M1) |
| Sandbox | Docker (`python:3.11-slim`), 60 s timeout, 512 MB RAM, 1 CPU |
| Report formats | SARIF 2.1.0 JSON · Markdown · STIX 2.1 |
| Cache | SHA-256 content hash → SQLite (re-scan < 2 s) |
| Verdicts | `SAFE` (< 30) · `SUSPICIOUS` (30–70) · `MALICIOUS` (> 70 or hard-evidence override) |

*Powered by Gemma 4 · open weights*
