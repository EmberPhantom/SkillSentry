# Security Policy

SkillSentry is a security tool that **executes untrusted code by design** (inside a hardened, sinkhole-only Docker sandbox). We take its own security seriously and welcome responsible disclosure.

> Full security architecture — threat model, sandbox hardening, Poisoned Well ethics, prompt-injection defenses, and known limitations: **[docs/04-security.md](docs/04-security.md)**.

## Supported Versions

| Version | Supported | Notes |
|:---|:---|:---|
| 2.0.x | ✅ | Current; receives security fixes |
| < 2.0 | ❌ | Pre-release concepts; do not use |

## Reporting a Vulnerability

**Please report privately — do NOT open a public issue.**

- **Channel:** GitHub Security Advisories → *"Report a vulnerability"* on this repository.
- **Include:** reproduction steps, affected version/commit, impact, and (for sandbox issues) whether the escape requires special host configuration.
- **SLA (target):** acknowledge ≤ 72 h · triage ≤ 7 days · coordinated disclosure with a **90-day default embargo** · reporters credited in release notes.

## Scope

**High-priority (in scope):**

- Sandbox escape from the analysis container (host filesystem write/read, host network access, process breakout)
- Leakage of **real** (non-canary) host credentials or data to a scanned skill
- Cache poisoning that yields false `SAFE` verdicts (e.g., forged `scan_cache` rows surviving version checks)
- Remote code execution in parsers via crafted skill packages (YAML bombs, path traversal, image/SVG handlers)
- Signature-verification bypass: signed verdicts (sigstore/cosign), community IOC feed, or release artifacts
- Sinkhole/egress failure that lets sandbox traffic reach the real internet
- Verdict downgrade attacks: any input that makes the engine emit `SAFE` when hard evidence (Poisoned Well correlation, evasion probe) says `MALICIOUS`

**Out of scope:**

- Demo fixtures being detected (that is the product working)
- `--demo-mode` canned responses
- Cloud-fallback (Gemini API) latency or availability
- Findings that require the user to have disabled documented hardening (e.g., mounting the Docker socket into untrusted containers against our guidance)
- Social engineering of maintainers

## Design Guarantees You Can Hold Us To

1. **Fail-safe verdicts:** no error path may produce `SAFE`; degraded scans carry explicit `*-unavailable` findings.
2. **Sinkhole-only egress:** analysis containers have no route to the internet — DNS and HTTP are answered locally.
3. **Fake-by-construction credentials:** Poisoned Well canaries are generated fake (`SKS-<8hex>` markers); no real secret material is ever created, served, or stored.
4. **No hack-back:** SkillSentry never connects to attacker infrastructure; C2 indicators are harvested from logs only.
5. **Local-first privacy:** no telemetry, no phone-home; skill content leaves the machine only if you explicitly enable the Gemini API fallback (the UI always shows the active backend).

## Safe Harbor & Fixture Warning

Good-faith research against **your own** installations and the `fixtures/` corpus is welcome and covered by safe harbor. Never point SkillSentry's deception outputs at third-party infrastructure.

⚠️ `fixtures/malicious/` contains intentionally malicious skill code for testing. It must only ever be executed **through `skill-sentry scan`** (which sandboxes it) — never run fixture scripts directly on a host.

## Secure Distribution

- Phase 2: signed release tags and **sigstore keyless-signed verdicts** (`cosign verify-blob`); until then, prefer installing from source at a reviewed commit or the published Docker image digest.
- Verify Ollama model digests (`model_version` is recorded with every verdict — see [docs/03-database.md](docs/03-database.md)).
