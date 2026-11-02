# 7 · CLI Reference

> `skill-sentry-cli` — audit Agent Skills from the terminal, wire scans into CI, and manage the local cache.
>
> Items defined by the v2.0 plan are marked as such; additional commands/flags needed for a complete CLI surface are marked **Spec (proposed)**.

---

## 7.1 Installation

```bash
# From a source checkout (works today)
git clone https://github.com/EmberPhantom/SkillSentry.git && cd SkillSentry
python3.12 -m venv .venv && . .venv/bin/activate
python -m pip install -e ".[dev]"

# Install script from the latest release (Linux, macOS, WSL), checksum-verified
sh install.sh

# PyPI, once the release is published
pipx install skill-sentry-cli
```

**Prerequisites:**

| Dependency | Required for | Check |
|:---|:---|:---|
| Python 3.11+ | everything | `python --version` |
| Ollama with the configured local model | local semantic and vision analysis | `ollama list`; `skill-sentry-cli doctor` names the model to pull |
| Docker daemon | sandbox, Poisoned Well, evasion detection | `docker info` |
| Gemini API key (**opt-in**) | cloud fallback | `export GEMINI_API_KEY=…` |

Without Ollama/Docker the CLI still runs in **degraded static mode** (explicitly flagged — never a silent `SAFE`; see fail-safe rule in [05-api-reference.md](05-api-reference.md) §5.8) or in `--demo-mode`.

## 7.2 Commands

### `skill-sentry-cli scan <path>` — the core command

Audits a skill directory (or a folder of skills) through the full 8-stage pipeline.

```bash
skill-sentry-cli scan cloud-sync-pro --demo-mode
```

```text
SkillSentry <version> - Fully local analysis · open weights - backend: demo/mock
[X] cloud-sync-pro - MALICIOUS - risk 97 - confidence 1.00
   Canary marker exfiltrated via DNS tunnel to evil-collector.net (scripts/sync.sh:7)
   Poisoned Well: DNS_TUNNELING -> evil-collector.net (marker SKS-7f3a9c21)
```

This is the offline demo output, captured from a real run. A sandboxed scan prints the same shape, with the evidence from each stage. The per-stage progress lines in earlier drafts of this page were never printed by the CLI; see the [user guide](16-user-guide.md) §7 for real sandboxed output.

| Flag | Default | Description |
|:---|:---|:---|
| `--format text\|json\|sarif\|markdown` | `text` | Console/report format. Folders emit a JSON array (or concatenated SARIF runs). |
| `--fail-on safe\|suspicious\|malicious` | `suspicious` | CI gate: exit `1` when any verdict meets or exceeds this tier. `safe` therefore always passes. |
| `--output <file>` | — | Write the rendered report to a file instead of stdout (text reports are also echoed). |
| `--sarif-out <file>` | — | Write a SARIF 2.1.0 sidecar in addition to the selected `--format`. |
| `--no-cache` | off | Bypass Stage 0 read **and** write for this scan. |
| `--sandbox / --no-sandbox` | sandbox on | `--no-sandbox` is an explicitly labelled static-only scan; it never reads or writes the reusable verdict cache. |
| `--backend auto\|local\|cloud` | `auto` | Model backend selection. `--backend demo` (the deterministic mock model) is refused for real scans; it is only for development, with `SKILLSENTRY_DEV=1`. The canned store is `--demo-mode`. |
| `--timeout <s>` | `60` | Sandbox execution window, 5–600 seconds. Non-default timeouts bypass the cache. |
| `-q, --quiet` | off | Verdict line only (suppresses the banner and progress chatter). |
| `--demo-mode` | off | Serve the canned 7-skill demo verdict. Kept separate from live scans; no fabricated live evidence. |

`scan` accepts either one skill directory or a folder. Discovery recurses deterministically, skips symlinked/ignored directories, and refuses more than 500 skills rather than silently truncating. `--watch` and `--upload-sarif` are planned and not implemented.

### `skill-sentry-cli init`

Writes a documented `skillsentry.toml`. `--path` chooses the file (default `./skillsentry.toml`); `--force` overwrites an existing file. It does not probe Ollama or Docker; use `skill-sentry-cli doctor` for that.

### `skill-sentry-cli cache …`

| Command | Description |
|:---|:---|
| `cache stats` | Number of cached verdicts and the database size |
| `cache list [--limit N]` | Most recent scans and their verdicts (1–500, default 20) |
| `cache clear [--older-than 7d]` | Remove cached verdicts; `--older-than` accepts a number of days or hours (`7d`, `12h`) |

### `skill-sentry-cli export <scan_id> [--format sarif|markdown|stix] [-o FILE]`

Re-render the report of a stored scan without re-running it. `--format` defaults to `markdown`; `-o`/`--output` writes to a file instead of stdout. STIX output needs a triggered Poisoned Well.

**Verdict status.** A result is `UNSCANNED` when a stage did not complete (for example the model was unreachable, a file was not read, or the sandbox could not run). The verdict is still shown, with the reason. `UNSCANNED` is never shown for a `MALICIOUS` verdict, and it is never a clean result. In JSON, the verdict is unchanged; exit codes follow the verdict.

**Skills without an entrypoint.** A skill that ships scripts but does not declare `entrypoint:` in its frontmatter cannot be run in the sandbox, so its scripts are read but not executed. The result is `UNSCANNED` until the author declares the entrypoint.

### `skill-sentry-cli serve [--host 127.0.0.1] [--port 8000] [--demo-mode] [--speed 1.0]`

Runs the FastAPI server and dashboard ([05-api-reference.md](05-api-reference.md), [06-ui-ux.md](06-ui-ux.md)). `--demo-mode` serves the canned store; `--speed` sets the demo replay speed (0 is instant). The bind address defaults to loopback.

### `skill-sentry-cli self-audit`

Scans SkillSentry's own Agent Skill package (`skill_sentry_cli/skill/SKILL.md` + `scripts/audit.sh`) — the product audits itself. It takes the same `--format`, `--fail-on`, `-q`, `--no-cache`, `--sandbox/--no-sandbox`, `--backend` and `--timeout` options as `scan`, and `--fail-on` defaults to `suspicious`.

## 7.3 Configuration — `skillsentry.toml`

Created by `skill-sentry-cli init`; precedence: **CLI flags > env vars > config file > defaults**.

```toml
[model]
backend = "auto"                 # auto | local | cloud
ollama_url = "http://localhost:11434"
ollama_model = "gemma4:e4b-it-qat"
gemini_model = "gemma-4-e4b"     # used only when backend = cloud/auto-fallback
image_max_px = 768               # vision downscale; at most 3 images per scan

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
fail_on = "malicious"            # not read in v1; the CLI gate is --fail-on (default suspicious)
upload_sarif = false             # not read in v1; roadmap with the GitHub Action
```

## 7.4 Environment Variables

| Variable | Effect |
|:---|:---|
| `SKILLSENTRY_BACKEND` | Overrides `model.backend` |
| `SKILLSENTRY_NO_SANDBOX` | `1` ⇒ static-only mode |
| `SKILLSENTRY_CONFIG` | Path to the config file, instead of `./skillsentry.toml` |
| `SKILLSENTRY_DB` | Override SQLite path |
| `GEMINI_API_KEY` | Required for cloud backend; never logged, never embedded in reports |
| `OLLAMA_HOST` | Passed through to the Ollama client |

## 7.4a Commands added for version 1

| Command | Purpose |
|:---|:---|
| `skill-sentry-cli doctor` | Check the model, dashboard and database (required), and Docker and the sandbox image (optional). Exits 3 when a required check fails. |
| `skill-sentry-cli cache stats` | Show the number of cached verdicts and the database size. |
| `skill-sentry-cli cache list [--limit N]` | List the most recent scans and their verdicts. |
| `skill-sentry-cli cache clear [--older-than 7d]` | Remove cached verdicts, optionally only the older ones. |
| `skill-sentry-cli export <scan_id> [--format sarif\|markdown\|stix] [-o FILE]` | Re-render the report of a stored scan without re-running it. |
| `skill-sentry-cli sandbox build` | Build the sandbox image from the sources packaged with SkillSentry. |

`--fail-on` defaults to `suspicious` for `scan` and `self-audit`.

## 7.5 Exit Codes (CI contract)

| Code | Meaning | CI usage |
|:--|:---|:---|
| `0` | All scanned skills are below the `--fail-on` threshold | Merge allowed |
| `1` | At least one verdict meets/exceeds `--fail-on` (default: SUSPICIOUS) | **Blocks PR merge** |
| `2` | Usage error (unsupported `--format`, `--fail-on`, `--backend`, or invalid option) | Pipeline config bug |
| `3` | Operational error (missing/invalid skill path, Docker/DB failure, no scan completed) — *never* a fabricated verdict | Retry/alert |
| `4` | Defined in the source but never returned. A scan that cannot reach the model degrades to `UNSCANNED` and exits with its verdict code. | Fix the model setup (`skill-sentry-cli doctor`) |

A parent folder containing a valid skill and an invalid/unscannable child returns the completed reports and exits `3`; partial success is never reported as a clean CI pass. Usage errors are checked before any scan starts.

A planned GitHub Action, `skillsentry/scan@v1`, would map to this contract (see [09-deployment-and-production.md](09-deployment-and-production.md)). **It is not published.** Until it is, call the CLI directly in your workflow, as shown in the [user guide](16-user-guide.md) §11.

## 7.6 GitHub Action (planned)

```yaml
# Planned interface; not available yet
- uses: skillsentry/scan@v1
  with:
    path: ./skills/
    fail-on: malicious        # blocks PR merge
    upload-sarif: true        # appears in GitHub Security tab
    backend: auto             # auto | local | cloud
    cache: true               # enable incremental scanning
```

---

*Next: [08-testing-and-evaluation.md](08-testing-and-evaluation.md).*
