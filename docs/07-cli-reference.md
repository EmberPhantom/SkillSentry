# 7 · CLI Reference

> `skillsentry` — audit Agent Skills from the terminal, wire scans into CI, and manage the local cache.
>
> Items defined by the v2.0 plan are marked as such; additional commands/flags needed for a complete CLI surface are marked **Spec (proposed)**.

---

## 7.1 Installation

```bash
# PyPI (Phase 1)
pip install skillsentry

# Docker image
docker pull skillsentry/skillsentry:2.0
docker run --rm -v "$PWD/skills:/skills:ro" skillsentry/skillsentry:2.0 scan /skills/pdf-summarizer

# From source (hackathon / dev)
git clone https://github.com/<org>/skillsentry && cd skillsentry
pip install -e ".[dev]"
```

**Prerequisites:**

| Dependency | Required for | Check |
|:---|:---|:---|
| Python 3.11+ | everything | `python --version` |
| Ollama + Gemma 4 E4B (Q4) | local semantic/vision analysis | `ollama list` → pull: `ollama pull gemma4:e4b-q4` |
| Docker daemon | sandbox, Poisoned Well, evasion detection | `docker info` |
| Gemini API key (**opt-in**) | cloud fallback | `export GEMINI_API_KEY=…` |

Without Ollama/Docker the CLI still runs in **degraded static mode** (explicitly flagged — never a silent `SAFE`; see fail-safe rule in [05-api-reference.md](05-api-reference.md) §5.8) or in `--demo-mode`.

## 7.2 Commands

### `skillsentry scan <path>` — the core command

Audits a skill directory (or a folder of skills) through the full 8-stage pipeline.

```bash
skillsentry scan ./fixtures/malicious/cloud-sync-pro
```

```text
🛡 SkillSentry v2.0 · Powered by Gemma 4 · open weights · backend: local (ollama)
[0/7] cache      ✓ miss (hash 9f2c…)
[1/7] spec       ✓ frontmatter valid · typosquat check: clean
[2/7] anchors    ⚑ 3 deterministic findings (eval, nslookup, credential read)
[2/7] semantic   ✓ Gemma: declared "cloud sync" ≠ actual "credential exfil" (deceptive)
[3/7] vision     ✓ 0 images
[4/7] sandbox    🚨 CANARY READ ~/.aws/credentials (T+1.2s)
[4.5] ☠ well     🔍 marker SKS-7f3a9c21 decoded from DNS query → CONFIRMED
[5/7] evasion    ✓ no probes
[6/7] verdict    🚫 MALICIOUS · risk 99 · confidence 1.0 (hard evidence)

C2 indicators: evil-collector.net (DNS_TUNNELING, base64)
Report: ~/.skillsentry/reports/3f9c…/report.sarif
```

| Flag | Default | Description |
|:---|:---|:---|
| `--format text\|json\|sarif\|markdown` | `text` | Console/report format. Folders emit a JSON array (or concatenated SARIF runs). |
| `--fail-on safe\|suspicious\|malicious` | `malicious` | CI gate: exit `1` when any verdict meets or exceeds this tier. `safe` therefore always passes. |
| `--output <file>` | — | Write the rendered report to a file instead of stdout (text reports are also echoed). |
| `--sarif-out <file>` | — | Write a SARIF 2.1.0 sidecar in addition to the selected `--format`. |
| `--no-cache` | off | Bypass Stage 0 read **and** write for this scan. |
| `--sandbox / --no-sandbox` | sandbox on | `--no-sandbox` is an explicitly labelled static-only scan; it never reads or writes the reusable verdict cache. |
| `--backend auto\|local\|cloud\|demo` | `auto` | Model backend selection. `demo` runs the real engine with the deterministic `MockGemma`; it is not the canned `--demo-mode` store. |
| `--timeout <s>` | `60` | Sandbox execution window, 5–600 seconds. Non-default timeouts bypass the cache. |
| `-q, --quiet` | off | Verdict line only (suppresses the banner and progress chatter). |
| `--demo-mode` | off | Serve the canned 7-skill demo verdict. Kept separate from live scans; no fabricated live evidence. |

`scan` accepts either one skill directory or a folder. Discovery recurses deterministically, skips symlinked/ignored directories, and refuses more than 500 skills rather than silently truncating. `--watch`, `--upload-sarif`, and managed `cache`/`export` commands remain roadmap items, not M1 CLI flags.

### `skillsentry init` (plan, Phase 1 DX)

Creates `./skillsentry.toml` with documented defaults; `--force` overwrites; detects Ollama/Docker and pre-fills backend advice. Also offers `ollama pull` helper for the model (plan: "model auto-download helper").

### `skillsentry cache …` (proposed, backed by plan's SQLite cache)

| Command | Description |
|:---|:---|
| `cache stats` | Entries, hit rate, DB size, engine/model versions |
| `cache list [--verdict malicious]` | Inspect cached hashes |
| `cache clear [--older-than 90d]` | Prune |
| `cache verify [--sample N]` | Re-hash N random entries, recompute verdicts with `--no-cache`, diff results |

### `skillsentry export <scan_id> --format sarif|markdown|stix` (proposed)

Re-emit stored reports from `~/.skillsentry/reports/<scan_id>/` (STIX requires a triggered Poisoned Well).

### `skillsentry serve [--port 8000] [--demo-mode]` (proposed)

Runs the FastAPI server + React dashboard ([05-api-reference.md](05-api-reference.md), [06-ui-ux.md](06-ui-ux.md)).

### `skillsentry self-audit` (plan: SkillSentry ships its own `SKILL.md`)

Scans SkillSentry's own Agent Skill package (`skillsentry/skill/SKILL.md` + `scripts/audit.sh`) — the product audits itself, on stage.

## 7.3 Configuration — `skillsentry.toml`

Created by `skillsentry init`; precedence: **CLI flags > env vars > config file > defaults**.

```toml
[model]
backend = "auto"                 # auto | local | cloud
ollama_url = "http://localhost:11434"
ollama_model = "gemma4:e4b-q4"
gemini_model = "gemma-4-e4b"     # used only when backend = cloud/auto-fallback
image_max_px = 1024              # vision downscale (plan §4)

[sandbox]
enabled = true
base_image = "skillsentry-sandbox:local"   # built from assets/Dockerfile.sandbox
timeout_s = 60
memory_mb = 512
cpus = 1
masquerade = true                # hide Docker artifacts (plan §6.4)

[poisoned_well]
enabled = true                   # false ⇒ passive canary logging only
correlation_window_s = 10        # "within N seconds" rule (plan §6.5)
secondary_canary = true          # keep multi-stage malware talking

[scoring]
weights = { anchors = 0.15, semantic = 0.20, vision = 0.20, sandbox = 0.25 }
typosquat_bonus = 15
tiers = { safe_max = 30, malicious_min = 70 }

[cache]
db_path = "~/.skillsentry/skillsentry.db"
backend_strict = false           # true ⇒ cache hits must match backend identity

[ci]
fail_on = "malicious"            # exit-code gate
upload_sarif = false
```

## 7.4 Environment Variables (proposed)

| Variable | Effect |
|:---|:---|
| `SKILLSENTRY_BACKEND` | Overrides `model.backend` |
| `SKILLSENTRY_NO_SANDBOX` | `1` ⇒ static-only mode |
| `SKILLSENTRY_DEMO` | `1` ⇒ demo mode |
| `SKILLSENTRY_DB` | Override SQLite path |
| `GEMINI_API_KEY` | Required for cloud backend; never logged, never embedded in reports |
| `OLLAMA_HOST` | Passed through to the Ollama client |

## 7.5 Exit Codes (CI contract)

| Code | Meaning | CI usage |
|:--|:---|:---|
| `0` | All scanned skills are below the `--fail-on` threshold | Merge allowed |
| `1` | At least one verdict meets/exceeds `--fail-on` (default: MALICIOUS) | **Blocks PR merge** |
| `2` | Usage error (unsupported `--format`, `--fail-on`, `--backend`, or invalid option) | Pipeline config bug |
| `3` | Operational error (missing/invalid skill path, Docker/DB failure, no scan completed) — *never* a fabricated verdict | Retry/alert |
| `4` | Reserved for a future hard model-unavailable abort. Current live scans degrade model-dependent stages honestly, emit an explicit degradation finding, and still return a verdict. | Fix backend config |

A parent folder containing a valid skill and an invalid/unscannable child returns the completed reports and exits `3`; partial success is never reported as a clean CI pass. Usage errors are checked before any scan starts.

GitHub Action `skillsentry/scan@v1` maps `fail-on: malicious` to this contract (see [09-deployment-and-production.md](09-deployment-and-production.md)).

## 7.6 GitHub Action Quick Reference (plan §12.3)

```yaml
# consumer's .github/workflows/skill-audit.yml
- uses: skillsentry/scan@v1
  with:
    path: ./skills/
    fail-on: malicious        # blocks PR merge
    upload-sarif: true        # appears in GitHub Security tab
    model: gemma-4-e4b-local  # or gemini-api
    cache: true               # enable incremental scanning
```

---

*Next: [08-testing-and-evaluation.md](08-testing-and-evaluation.md).*
