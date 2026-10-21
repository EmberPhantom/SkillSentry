# 1 · Project Overview

> **SkillSentry v2.0** — A Context-Aware Firewall for the Agent Skill Supply Chain with "Poisoned Well" Active Defense.

**One-liner:** An open-source, fully-local gatekeeper that audits Agent Skills *before* installation — fusing Gemma 4 multimodal reasoning (text + vision) with deterministic sandbox telemetry, dynamically adapting honeypots to the skill's declared intent, detecting sandbox evasion, and actively deceiving malicious skills by feeding them fake credentials to track exfiltration back to attacker infrastructure.

**Tagline:** *"Your proprietary skills never leave your machine for auditing. We don't just block attackers; we follow them home."*

---

## 1.1 Why Now — Market Validation

Agent Skills execute code **and** inject instructions into AI agents. They are the newest supply-chain attack surface, and the ecosystem is currently building skills far faster than it is defending them:

- **Snyk's Feb 2026 "ToxicSkills" audit** found **~1,467 malicious skills**, with prompt injection present in **36%** of ClawHub skills examined. ([snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub](https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/))
- The related **"ClawHavoc"** campaign pushed **1,184+ malicious skills** into OpenClaw's ClawHub registry in six weeks.
- The **OWASP Agentic Skills Top 10** now lists **AST01 — Malicious Skills** as a formal risk category.
- Capital is flowing into the space: AI-agent-firewall startup **AIR Security raised $50M** (Sept 2026) — but its product is enterprise/cloud/closed.

**Conclusion:** the threat is real and documented, the market is validated, and the open-source/local-first niche is unoccupied.

## 1.2 The Problem

Attack vectors SkillSentry targets:

| Vector | Example |
|:---|:---|
| **Credential theft** | Scripts reading `~/.aws/credentials`, `~/.ssh/id_rsa`, environment variables |
| **Image-hidden prompt injection** | Payloads in white-on-white text inside bundled images (documented real-world vector) |
| **Typosquatting** | `g1t-translate` impersonating `git-translate` |
| **Tool poisoning** | Malicious instructions hidden in skill descriptions/frontmatter |
| **Obfuscation** | base64-encoded payloads, `eval()` bombs |
| **Sandbox evasion** | Malware probing for Docker artifacts (`/.dockerenv`) and going dormant |
| **Supply-chain poisoning** | A benign skill updated with a malicious payload post-install |

## 1.3 The Solution

Before any skill installs, SkillSentry runs an **8-stage inspection pipeline**:

0. **Incremental Cache** — SHA-256 directory hash → cached SARIF verdict in < 2 s
1. **Spec Validation + Typosquat Detection** — frontmatter rules, Levenshtein distance ≤ 2 against known skill names
2. **Deterministic Anchor + Semantic Analysis** — AST/regex pre-scan produces *hard facts* ("anchors") fed to Gemma 4 E4B as ground truth
3. **Multimodal Vision Scan** — Gemma 4 vision OCRs bundled images (white-on-white text, stego-style instructions; SVG scanned as text *and* rendered)
4. **Context-Aware Behavioral Sandbox** — Docker execution with masquerade layer, intent-matched canary filesystem, DNS sinkhole, fake HTTP responder
4.5. **☠️ Poisoned Well** — on canary credential read: serve intent-matched *fake* secrets, harvest exfil into the sinkhole, profile the C2
5. **Sandbox Evasion Detection** — probing for Docker/VM artifacts ⇒ auto-`MALICIOUS`
6. **Verdict Engine** — weighted signal fusion → risk score 0–100 → SARIF 2.1.0 JSON with line-accurate citations → cached to SQLite

Clean skills install with **zero friction**; malicious skills are blocked with **hard evidence**, and their C2 infrastructure is mapped and exportable as STIX IOCs.

Full pipeline detail: [02-architecture.md](02-architecture.md).

## 1.4 Key Differentiators (Competitive Positioning)

| Feature | Pipelock (OSS) | AIR Security | Text-only Scanners | **SkillSentry v2.0** |
|:---|:---|:---|:---|:---|
| **When it acts** | Runtime (post-install) | Cloud policy | Pre-scan | **Pre-install + Runtime (MCP)** |
| **Detection method** | Network heuristics | Enterprise rules | Regex / LLM text | **LLM + Vision + Sandbox + Active Defense** |
| **Image-hidden payloads** | ✗ | ✗ | ✗ | **✓ (Gemma 4 Vision)** |
| **Context-Aware Honeypots** | ✗ | ✗ | ✗ | **✓ (Dynamic Intent Matching)** |
| **Sandbox Evasion Detection** | ✗ | ✗ | ✗ | **✓ (Anti-Anti-Sandbox)** |
| **Deterministic Anchoring** | ✗ | ✗ | ✗ | **✓ (AST pre-scan → LLM ground truth)** |
| **Incremental Scanning** | ✗ | ✗ | ✗ | **✓ (SHA-256 SQLite Cache)** |
| **Privacy** | Local | Cloud | Varies | **100% local (Ollama)** |
| **Fights back** | ✗ | ✗ | ✗ | **✓ Poisoned Well + C2 Tracking** |
| **Cost** | Free | Enterprise $$$ | Free/cheap | **Free & open-source** |

**The wedge:** Pipelock watches the network *after* install. Text scanners are blind to image payloads. AIR is cloud-only. **SkillSentry catches threats pre-install, sees hidden image payloads, never sends your skills off-machine, dynamically adapts its deception to the attacker's intent, detects sandbox-evasion attempts, and actively counter-attacks.**

## 1.5 Success Metrics

| Metric | Target |
|:---|:---|
| Malicious fixture detection | 2/2 (+ optional typosquat = 3/3) |
| Benign false-positive rate | 0/4 |
| Image-hidden payload catch | ✓ |
| Context-Aware Poisoned Well | ✓ (matches skill's declared intent) |
| Sandbox Evasion Detection | ✓ (probing triggers auto-fail) |
| Scan latency (cached) | < 2 s (SHA-256 SQLite cache) |
| Poisoned Well activation on credential thief | ✓ with C2 domain captured |
| Citation accuracy (right source line) | ≥ 80% |
| Local scan time per skill (E4B, Q4, uncached) | < 90 s |

Evaluation procedure and fixture corpus: [08-testing-and-evaluation.md](08-testing-and-evaluation.md).

## 1.6 Design Principles

1. **Local-first, private by default.** Auditing runs entirely on the user's machine via Ollama. The Gemini API fallback is opt-in. No telemetry, ever.
2. **Credible, not vibes.** Every LLM judgment is anchored to deterministic evidence (AST/regex findings the model may not contradict) and every `MALICIOUS` verdict ships with `file:line` citations.
3. **Hard evidence overrides uncertainty.** A confirmed Poisoned Well correlation (canary marker observed in outbound traffic) or a sandbox-evasion probe forces `MALICIOUS` with `confidence: 1.0`, regardless of what the LLM thinks.
4. **Defense without friction.** Benign skills pass with zero added steps and instant cached re-scans.
5. **Contract-first.** The Verdict JSON schema is frozen early (milestone M0) so frontend, backend, and AI workstreams integrate without drift.
6. **Fail safe, demo safe.** `--demo-mode` canned responses guarantee the product story survives network/Docker/model outages (Chaos Run doctrine).

## 1.7 Distribution Surfaces

- `pip install skillsentry` — CLI + library
- Published Docker image — server/CI usage
- `skillsentry/scan@v1` GitHub Action — PR gates, SARIF upload to GitHub Code Scanning, scheduled registry re-scans
- Phase 2: **MCP runtime proxy** for post-install behavioral enforcement

See [09-deployment-and-production.md](09-deployment-and-production.md).

## 1.8 Glossary

| Term | Definition |
|:---|:---|
| **Agent Skill** | A package (`SKILL.md` + scripts + assets) that extends an AI agent with instructions and executable code; the unit SkillSentry audits. |
| **Deterministic Anchor** | A hard, reproducible static finding (regex/AST) injected into the LLM prompt as ground truth the model must not contradict. |
| **Canary** | A fake-but-plausible credential (or file) seeded in the sandbox, embedded with a unique marker `SKS-<8hex>`. |
| **Context-Aware Honeypot** | Canary seeding adapted to the skill's *declared intent* (e.g., fake Slack tokens for a "Slack integration"). |
| **Poisoned Well** | The active-defense subsystem: serves fake credentials to a detected thief, sinkholes the exfiltration, correlates the canary marker, and profiles the attacker's C2. |
| **Masquerade** | The layer that hides sandbox artifacts (`/.dockerenv`, `/proc/1/cgroup`, …) so evasion-probing malware behaves normally and reveals itself. |
| **Sandbox Evasion Probe** | A skill's attempt to detect the analysis environment; treated as hard proof of malice (auto-`MALICIOUS`). |
| **IOC** | Indicator of Compromise (C2 domain, IP, exfil channel, encoding) harvested during a Poisoned Well engagement; exportable as STIX 2.1. |
| **Gemma's Eye View** | UI mode showing what Gemma 4 vision actually saw in an image: OCR text + bounding-box overlay + contrast enhancement. |
| **Verdict** | One of `SAFE` / `SUSPICIOUS` / `MALICIOUS`, with risk score 0–100 and confidence. |
| **SARIF** | Static Analysis Results Interchange Format 2.1.0 — the standard machine-readable report SkillSentry emits. |

## 1.9 Key Links

| Resource | URL |
|:---|:---|
| Gemma 4 docs | https://ai.google.dev/gemma/docs/core |
| Gemini API | https://ai.google.dev/gemini-api/docs |
| Agent Skill Open Standard | https://agentskills.io/specification |
| Snyk ToxicSkills audit | https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/ |
| Ollama (local serving) | https://ollama.com |

---

**Prior art (honest citations):** Snyk ToxicSkills audit · Pipelock · AIR Security · MCP prompt-injection research.
