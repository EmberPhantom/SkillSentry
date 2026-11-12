---
name: skillsentry-audit
description: >-
  Audit AI Agent Skills for malware before installation with SkillSentry, a
  fully-local open-source scanner that runs a local model. Use when the user asks to
  audit a skill, scan a skill, check if a skill is safe, detect malicious
  skills, review a SKILL.md package, or verify a skill from a registry such as
  ClawHub before installing it. Runs an 8-stage inspection: SHA-256 incremental
  cache, spec validation with typosquat detection, AST anchors fused with local-model
  semantic analysis, vision scanning for image-hidden prompt injection,
  sandboxed execution with context-aware honeypots, Poisoned Well active
  defense (fake credentials, exfil tracked to C2), sandbox-evasion detection,
  weighted verdict fusion. Returns a SAFE, SUSPICIOUS, or MALICIOUS verdict
  with a 0-100 risk score, line-accurate citations, and SARIF/STIX reports.
  Trigger keywords: audit skill, scan skill, skill security, malicious skill,
  pre-install check, SKILL.md review, supply-chain audit, typosquat check.
---

# SkillSentry Audit

Pre-install security gate for Agent Skills. Everything runs **locally** (Ollama + Docker + SQLite) — audited skill content never leaves the machine unless the user explicitly enabled the Gemini API fallback.

## When to use

- Before installing any skill from a registry (ClawHub, marketplaces) or a third-party repo.
- When re-auditing installed skills after upstream updates (supply-chain poisoning check).
- When the user asks: *"is this skill safe?"*, *"scan this skill"*, *"audit SKILL.md"*, *"check for typosquats"*.

## How to run

Use the bundled script (preferred):

```bash
scripts/audit.sh <path-to-skill-directory> [extra skill-sentry-cli flags]
```

Equivalent direct CLI:

```bash
skill-sentry-cli scan <path-to-skill-directory> --fail-on suspicious
```

`scripts/audit.sh` exits `1` on any SUSPICIOUS or MALICIOUS verdict. It also exits `1` on a degraded scan, because a degraded scan is never SAFE: its verdict is at least SUSPICIOUS. Pass `--fail-on malicious` only after the user has reviewed a SUSPICIOUS result and decided to accept it.

Useful flags: `--demo-mode` (offline canned demo), `--no-cache` (force full re-scan), `--sarif-out report.sarif`, `--format json`, `--backend local|cloud`.

## Interpreting results

| Verdict | Risk score | Recommended action |
|:---|:---|:---|
| ✅ `SAFE` | < 30 | Install normally |
| ⚠️ `SUSPICIOUS` | 30–70 | Review the cited `file:line` findings with the user before deciding |
| 🚫 `MALICIOUS` | > 70, or hard-evidence override (confidence 1.0) | **Do not install.** Report the SARIF/STIX exports; note any C2 indicators |

Always surface to the user: the verdict, risk score, top findings with `file:line` citations, whether the result was ⚡ cached (< 2 s), and — if triggered — the Poisoned Well summary (targeted assets, exfil channel, C2 indicators). Never suppress a `MALICIOUS` verdict, and never present a degraded scan (e.g., `sandbox-unavailable`) as a clean pass.

## Requirements

- `skill-sentry-cli` CLI installed (`pip install skill-sentry-cli`)
- Ollama running with the local model pulled (`skill-sentry-cli doctor` names it) — or `--backend cloud` with `GEMINI_API_KEY`, or `--demo-mode`
- Docker daemon available for sandbox stages (Stage 4/4.5/5); without it the scan degrades to static-only analysis and says so explicitly

## Safety notes

- SkillSentry never connects to attacker infrastructure; C2 indicators are harvested passively from the sinkhole.
- All canary credentials served during analysis are fake by construction (marker `SKS-<8hex>`).
- Audited packages are executed **only** inside the hardened sandbox (60 s, 512 MB, 1 CPU, sinkhole-only egress).

*Local analysis by default · open weights. Cloud analysis is opt-in and is labelled as such.*
