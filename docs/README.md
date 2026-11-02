# 🛡️ SkillSentry — Project Documentation

> **SkillSentry** — A Context-Aware Firewall for the Agent Skill Supply Chain with "Poisoned Well" Active Defense.
>
> *"Your proprietary skills never leave your machine for auditing. We don't just block attackers; we follow them home."*

This directory contains the documentation for **SkillSentry v2.0**, an open-source, fully-local gatekeeper that audits AI Agent Skills before installation. It combines local multimodal model reasoning (text and vision) with deterministic sandbox telemetry, context-aware honeypots, sandbox-evasion detection, and active deception (Poisoned Well).

> 📌 **Provenance:** The design documents were first written as a plan for the MLH Hacktoberfest Hack Day. Where a document extends the plan with concrete engineering detail, the additions are marked **Spec (proposed)**. Parts of the plan changed during the build; the code and the [user guide](16-user-guide.md) are the current reference.

---

## 📚 Document Index

Start with the [User Guide](16-user-guide.md) if you use SkillSentry, or the [Developer Guide](10-developer-guide.md) if you contribute.

| # | Document | Contents |
|:--|:---------|:---------|
| 1 | [Project Overview](01-project-overview.md) | Problem statement, market validation, solution summary, feature matrix, competitive positioning, success metrics, glossary |
| 2 | [Architecture](02-architecture.md) | System context, the 8-stage inspection pipeline, risk scoring model, data flow, module map, tech stack, integration contracts, Phase-2 MCP proxy |
| 3 | [Database](03-database.md) | SQLite schema (cache, scans, findings, canary events, IOCs, attacker profiles), directory hashing spec, cache invalidation, migrations, Postgres team-server variant |
| 4 | [Security](04-security.md) | Supply-chain threat model, SkillSentry's own attack surface, sandbox hardening, Poisoned Well ethics and safety, prompt-injection defense, privacy, known limitations |
| 5 | [API Reference](05-api-reference.md) | REST endpoints, WebSocket live-scan stream, frozen Verdict JSON Contract v1, SARIF 2.1.0 extension schema, STIX export mapping, error model |
| 6 | [UI/UX Design](06-ui-ux.md) | Design language and tokens, screen architecture, wireframes (Triage Table, Poisoned Well IOC view, Eye View), component tree, UX rules, accessibility |
| 7 | [CLI Reference](07-cli-reference.md) | `skill-sentry-cli` command reference, configuration file, environment variables, exit codes for CI, examples |
| 8 | [Testing & Evaluation](08-testing-and-evaluation.md) | Test strategy, the fixture corpus, evaluation plan and metrics, Chaos Run procedure, demo script, CI pipeline |
| 9 | [Deployment & Production](09-deployment-and-production.md) | Distribution (pip, Docker, GitHub Action), self-hosted team-server topology, MCP runtime interception (Phase 2), hardening, observability |
| 10 | [Developer Guide](10-developer-guide.md) | Environment setup, repository layout, development workflow, coding standards, extension guides (new stage, fixture, canary intent), roadmap |
| 12 | [Contract Additions](12-contract-additions.md) | Additive contract fields, API clarifications, batch semantics |
| 15 | [v1 Test Results](15-v1-test-results.md) | Recorded results of the v1 test run |
| 16 | [User Guide](16-user-guide.md) | Install, check readiness, scan skills, read verdicts, reports, dashboard, CI use, troubleshooting |
| 17 | [Release Process](17-release-process.md) | Tag-driven release runbook: TestPyPI and PyPI publishing, sandbox and server images, provenance |
| 18 | [Registry Accounts](18-registry-accounts.md) | Creating PyPI and TestPyPI accounts with two-factor authentication, trusted-publisher setup, recovery |
| 19 | [Landing-Page Brief](19-landing-page-brief.md) | Product and command reference: positioning, pipeline, install, every CLI command and flag, verdicts, configuration, outputs, CI, open-source readiness |
| — | [Changelog](CHANGELOG.md) | Version history following Keep a Changelog |

### Archived planning material

These documents record how the 2.0 build was organised. They are history, not user documentation, and they no longer assign ownership. See the [archive note](internal/README.md).

| Document | Contents |
|:---|:---|
| [Team & Workload](internal/11-team-and-workload.md) | The three-role split, milestones M0–M5, and the interface contracts used during the build |
| [Laya Integration Plan](internal/13-laya-integration-plan.md) | Plan for an optional alternative decision layer |
| [Developer Handoff](internal/14-developer2-handoff.md) | An integration log from one contributor's branch |
| [Work Checklists](internal/checklists/README.md) | Per-task checklists for the build |

## 🗂 Repository-Root Artifacts

The following files live at the **repository root**, not inside this folder:

| File | Purpose |
|:-----|:--------|
| `README.md` | Public repository readme: pitch, threat model, architecture, how to run, evaluation |
| `LICENSE` | MIT |
| `SECURITY.md` | Vulnerability disclosure policy (mirrors [04-security.md](04-security.md) §4.12) |
| `CONTRIBUTING.md` | Contributor workflow, contract rules, and where to find the pull request checklist |
| `.github/CODE_OF_CONDUCT.md`, `.github/SUPPORT.md` | Community standards and where to get help |
| `skill_sentry_cli/skill/SKILL.md` | SkillSentry's **own** Agent Skill, which it can audit with `self-audit` |
| `skill_sentry_cli/skill/scripts/audit.sh` | Bundled audit entrypoint for that skill |

## 🧭 Reading Paths

- **New user** → 16 → 7
- **New contributor** → 1 → 2 → 10 → 8
- **Security reviewer** → 1 → 4 → 2 → 8
- **Frontend developer** → 6 → 5 → 2 (§Integration Contracts)
- **Backend developer** → 2 → 3 → 5 → 4
- **Release or ops** → 17 → 18 → 9 → 7 → 3

## 🔑 Key Facts at a Glance

| Attribute | Value |
|:---|:---|
| License | MIT (open source) |
| Core language | Python 3.11 to 3.13 |
| Frontend | React 18 + Vite + TypeScript |
| Local model | A quantized local model served by Ollama. The model is set in `[model]` in `skillsentry.toml`. **100% local by default.** |
| Cloud fallback | Gemini API (opt-in) |
| Sandbox | Docker (`skillsentry-sandbox:local`), 60 s timeout, 512 MB RAM, 1 CPU |
| Report formats | SARIF 2.1.0 JSON · Markdown · STIX 2.1 |
| Cache | SHA-256 content hash → SQLite (re-scan < 2 s, target) |
| Verdicts | `SAFE` (< 30) · `SUSPICIOUS` (30–70) · `MALICIOUS` (> 70 or hard-evidence override) |

*Fully local analysis · open weights.*
