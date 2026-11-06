# CLI reference

Every command, option, default, and exit code of `skill-sentry-cli`, as the program prints them with `--help`. For a walkthrough, see the [user guide](../user/guide.md).

```text
skill-sentry-cli [--version] [--help] COMMAND [ARGS]
```

Running the command with no arguments prints its help. Shell completion is not installed.

## Global options

| Option | Effect |
|:---|:---|
| `--version` | Prints `SkillSentry <version> - Fully local analysis · open weights` and exits 0. |
| `--help` | Lists the commands. |

## Exit codes

Scripts and CI should branch on these.

| Code | Meaning |
|:---|:---|
| `0` | Every verdict is below the `--fail-on` gate, or the command succeeded. |
| `1` | At least one verdict meets the `--fail-on` gate. |
| `2` | Usage error: a bad option or value, a missing configuration file, or an unknown scan ID. |
| `3` | Operational error: a bad path, Docker or database failure, or nothing could be scanned. |

Code `4` is defined in the source but is never returned. A scan that cannot reach the local model completes with an `UNSCANNED` verdict and exits with the code for its verdict.

## `scan`

Audits one skill folder, or a folder that contains skills.

```text
skill-sentry-cli scan PATH [OPTIONS]
```

`PATH` is either a skill folder (one that contains `SKILL.md`) or a folder whose child folders are skills. A run covers at most 500 skills.

| Option | Default | Meaning |
|:---|:---|:---|
| `--format` | `text` | Output format: `text`, `json`, `sarif`, or `markdown`. |
| `--fail-on` | `suspicious` | Exit `1` when a verdict is at or above this level: `safe` (any verdict other than SAFE), `suspicious`, or `malicious`. |
| `-q`, `--quiet` | off | Print only the verdict line. |
| `--no-cache` | off | Ignore saved results and scan again. |
| `--sandbox` / `--no-sandbox` | sandbox on | With `--no-sandbox`, the entrypoint never runs and the verdict is weaker. |
| `--backend` | `auto` | Model backend: `auto`, `local`, `cloud`, or `demo`. `demo` is refused unless `SKILLSENTRY_DEV=1` is set. |
| `--timeout` | `60` | Sandbox time limit in seconds, from 5 to 600. |
| `--output FILE` | none | Write the rendered report to a file. |
| `--sarif-out FILE` | none | Also write a SARIF 2.1.0 file. |
| `--report-dir DIR` | none | Write one Markdown report per skill, and a `summary.md` for a folder. |
| `--recursive` | off | Also scan skills nested inside a skill folder. |
| `--demo-mode` | off | `PATH` is then the name of a canned skill: `pdf-summarizer`, `git-helper`, `image-resizer`, `weather-fetch`, `cloud-sync-pro`, `invoice-helper`, or `slack-notif-mal`. Other names exit `2`. |

Examples:

```bash
skill-sentry-cli scan fixtures/malicious/cloud-sync-pro
skill-sentry-cli scan skills/ --report-dir reports
skill-sentry-cli scan skills/ --format sarif --sarif-out results.sarif
skill-sentry-cli scan my-skill --no-sandbox -q
skill-sentry-cli scan cloud-sync-pro --demo-mode
```

A folder scan ends with a summary line. `INVALID` appears only when at least one skill has a malformed `SKILL.md`, and `failed` appears only when a skill could not be scanned.

```text
Summary: 4 scanned - 4 SAFE, 0 SUSPICIOUS, 0 MALICIOUS, 0 UNSCANNED
```

Each text result starts with one of these markers:

| Marker | Status |
|:---|:---|
| `[OK]` | SAFE |
| `[!]` | SUSPICIOUS |
| `[X]` | MALICIOUS |
| `[?]` | UNSCANNED, or INVALID SKILL |

## `self-audit`

Audits the skill that ships with SkillSentry. It takes `--format`, `--fail-on`, `-q`, `--no-cache`, `--sandbox` / `--no-sandbox`, `--backend`, and `--timeout`, with the same defaults as `scan`. It has no `--output` option; redirect standard output instead.

## `init`

Writes a configuration file with comments.

| Option | Default | Meaning |
|:---|:---|:---|
| `--path PATH` | `skillsentry.toml` | Where to write the file. |
| `--force` | off | Overwrite an existing file. |

An existing file without `--force` exits `2`. A write failure exits `3`.

## `serve`

Runs the API and the dashboard.

| Option | Default | Meaning |
|:---|:---|:---|
| `--host` | `127.0.0.1` | Address to bind. Keep the default. The API has no authentication; see the [security model](../developer/security.md). |
| `--port` | `8000` | Port, from 1 to 65535. |
| `--demo-mode` | off | Serve the canned seven-skill store instead of live scans. |
| `--speed` | `1.0` | Replay speed for demo mode. `0` is instant. |

The dashboard is served at `/`, and the API endpoints (for example `/scans`) are on the same port. Press `Ctrl+C` to stop.

## `doctor`

Checks what a full scan needs on this machine.

```text
PASS  model: <configured model> is pulled
PASS  dashboard: built
PASS  database: writable at <path>
WARN  docker: engine not reachable; sandbox scans are unavailable (use --no-sandbox)
PASS  platform: Linux
ready for a full scan
```

| Check | Required | What it means |
|:---|:---|:---|
| `model` | yes | The local model server is reachable and the configured model is pulled. |
| `dashboard` | yes | The dashboard has been built. |
| `database` | yes | The scan history can be written. |
| `docker` | no | The Docker engine is reachable. |
| `sandbox image` | no | The sandbox image is present. |
| `platform` | no | Advice for your platform. It never fails. |

Each line is `PASS`, `FAIL` (a required check failed), or `WARN` (an optional check). The command exits `3` when a required check fails.

## `setup`

Guided first-time setup. It asks before each download or build.

| Option | Effect |
|:---|:---|
| `--yes` | Answer yes to every prompt. |
| `--skip-model` | Do not check or pull the model. |
| `--skip-sandbox` | Do not check or install the sandbox image. |

`setup` writes the default configuration if none exists, installs the sandbox image (the published copy when this release has one, otherwise a local build), offers to run `ollama pull` for the configured model, and ends with the same checks as `doctor`. It never installs Docker or Ollama.

## `export`

Re-renders a stored scan without running it again.

```text
skill-sentry-cli export SCAN_ID [--format markdown|sarif|stix] [-o FILE]
```

| Option | Default | Meaning |
|:---|:---|:---|
| `--format` | `markdown` | `markdown`, `sarif`, or `stix`. |
| `-o`, `--output` | standard output | Write to a file. |

Get the scan ID from `scan` output or from `cache list`. An ID that is not a UUID, or that is not stored, exits `2`. STIX output carries Poisoned Well indicators, so it is only useful for scans in which that stage triggered.

## `cache`

Inspects and clears the verdict cache and the scan history.

| Subcommand | Options | Output |
|:---|:---|:---|
| `cache stats` | none | `entries`, `size_bytes`, and `hit_rate`. |
| `cache list` | `--limit N` (1–500, default 20) | One line per scan: `scan_id  skill  status  verdict`. |
| `cache clear` | `--older-than 7d` or `12h` | `deleted: N  retained: M`. A malformed age exits `2`. |

## `sandbox build`

Builds the sandbox image from the sources packaged with SkillSentry, tagged with the configured base image (`skillsentry-sandbox:local` by default). A Docker failure exits `3`.

## Configuration file

`skill-sentry-cli` reads `./skillsentry.toml`, or the file named by `SKILLSENTRY_CONFIG`. A named file that does not exist is an error. Precedence, highest first: command-line options, environment variables, the file, built-in defaults. Unknown keys are rejected.

The keys below use the defaults in the code. `init` writes a commented file with the same keys.

| Section | Key | Default | Meaning |
|:---|:---|:---|:---|
| `[model]` | `backend` | `auto` | `auto`, `local`, `cloud`, or `demo`. |
| `[model]` | `ollama_url` | `http://localhost:11434` | Where the local model server listens. |
| `[model]` | `ollama_model` | the model named in the file | The model to pull and use. `doctor` names it. |
| `[model]` | `gemini_model` | the model named in the file | Used only by the cloud backend. |
| `[model]` | `image_max_px` | `768` | Longest side of images sent to the model, from 256 to 4096. |
| `[model]` | `request_timeout_s` | `180` | Time limit for one model request. |
| `[sandbox]` | `enabled` | `true` | Run entrypoints in the sandbox. |
| `[sandbox]` | `base_image` | `skillsentry-sandbox:local` | Sandbox image name. |
| `[sandbox]` | `timeout_s` | `60` | Time limit for one entrypoint run, from 5 to 600. |
| `[sandbox]` | `memory_mb` | `512` | Memory limit for the sandbox container. |
| `[sandbox]` | `cpus` | `1.0` | CPU limit for the sandbox container. |
| `[poisoned_well]` | `enabled` | `true` | Plant decoy credentials and track their use. |
| `[poisoned_well]` | `correlation_window_s` | `10.0` | Time window for matching a decoy to an outbound request. |
| `[scoring]` | `weights` | anchors 0.15, semantic 0.20, vision 0.20, sandbox 0.25 | Weight of each signal in the risk score. |
| `[scoring]` | `typosquat_bonus` | `15` | Points added for a likely typosquat. |
| `[scoring]` | `tiers` | `safe_max = 30`, `malicious_min = 70` | Score boundaries for the verdicts. |
| `[cache]` | `db_path` | `~/.skillsentry/skillsentry.db` | Scan history and cache database. |

Two sections deserve a warning:

- **`[ci]`** is written by `init` but **not read** by the CLI. Its `fail_on` value has no effect; the gate is set by `--fail-on`, which defaults to `suspicious`. Do not rely on this section.
- **`[decision]`** selects an optional alternative decision layer. It is off by default (`backend = "legacy"`). Leave it alone unless you know you need it.

## Environment variables

| Variable | Effect |
|:---|:---|
| `SKILLSENTRY_CONFIG` | Path to the configuration file. |
| `SKILLSENTRY_DB` | Path to the scan history database. |
| `SKILLSENTRY_BACKEND` | Default model backend. |
| `SKILLSENTRY_NO_SANDBOX` | Set to `1` to turn the sandbox off. |
| `OLLAMA_HOST` | Address of the local model server. |
| `GEMINI_API_KEY` | API key for the cloud backend. Used only when the cloud backend is selected. |
| `SKILLSENTRY_DEV` | Set to `1` to allow `--backend demo` for development. |
| `SKILLSENTRY_DECISION_BACKEND` | Overrides `[decision] backend`. |
| `SKILLSENTRY_LAYA_CHECKPOINT`, `SKILLSENTRY_LAYA_DEVICE`, `SKILLSENTRY_LAYA_MODEL_PATH`, `SKILLSENTRY_LAYA_REQUIRED` | Options for the optional decision layer. |

The installer also reads `SKILL_SENTRY_HOME` (install location) and `SKILL_SENTRY_RELEASE_URL` (a mirror for release files).

## Planned, not available

These are not implemented. Do not build on them yet.

- `scan --watch`
- `scan --upload-sarif`
- A GitHub Action (`skillsentry/scan`)
