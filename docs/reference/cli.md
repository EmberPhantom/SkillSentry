# CLI reference

Every command, option, default, and exit code of `skill-sentry-cli`, as the program prints them with `--help`. For a walkthrough, see the [user guide](../user/guide.md).

```text
skill-sentry-cli [--version] [--help] COMMAND [ARGS]
```

Running the command with no arguments prints its help. Shell completion is not installed.

## Global options

| Option | Effect |
|:---|:---|
| `--version` | Prints `SkillSentry <version>` and exits 0. It makes no claim about the analysis backend. |
| `--help` | Lists the commands. |

## Exit codes

Scripts and CI should branch on these.

| Code | Meaning |
|:---|:---|
| `0` | Every verdict is below the `--fail-on` gate, or the command succeeded. |
| `1` | At least one verdict meets the `--fail-on` gate. |
| `2` | Usage error: a bad option or value, a missing configuration file, or an unknown scan ID. |
| `3` | Operational error: a bad path, a missing `--project` or `extra_paths` folder (see [Scan with no path](#scan-with-no-path)), Docker or database failure, or nothing could be scanned. |

Code `4` is defined in the source but is never returned. A scan that cannot reach the local model completes with an `UNSCANNED` verdict and exits with the code for its verdict.

## `scan`

Audits one skill folder, or a folder that contains skills. With no `PATH`, it audits every installed skill; see [Scan with no path](#scan-with-no-path).

```text
skill-sentry-cli scan [PATH] [OPTIONS]
```

`PATH` is either a skill folder (one that contains `SKILL.md`) or a folder whose child folders are skills. A folder search finds at most 500 skills. With more than 500 under `PATH`, or more than 100,000 directories, the command stops with an error (exit `3`) and scans nothing. Scan a smaller folder, or the skill folders one at a time.

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
| `--demo-mode` | off | `PATH` is then the name of a canned skill: `pdf-summarizer`, `git-helper`, `image-resizer`, `weather-fetch`, `cloud-sync-pro`, `invoice-helper`, or `slack-notif-mal`. Other names exit `2`. A warning on standard error says that the path was not read and the verdict is canned. Needs a `PATH`; without one it exits `2`. |
| `--project DIR` | current directory | Project folder whose project-level skills are included. Without `PATH` only. |
| `--agent NAME` | all | Scan only this agent's skills. Repeatable. Without `PATH` only. Names: `claude`, `codex`, `agents`, `gemini`, `cursor`, `opencode`, `copilot`, `custom`. `custom` selects only the `[discovery] extra_paths` and `SKILLSENTRY_EXTRA_SKILL_PATHS` folders. |
| `--include-experimental` | off | Also look in the experimental agent locations. Without `PATH` only. |
| `--save-report FORMAT` | none | Save a combined report of this run to `~/.skillsentry/reports/scan-<timestamp>/`: `markdown`, `sarif`, or `none`. Skips the question. Works with or without `PATH`. |
| `--no-prompt` | off | Never ask whether to save a report. Without `PATH` only. |

`--output`, `--sarif-out`, `--report-dir` and `--recursive` need a `PATH`. Without one they exit with code 2; use `--save-report` to keep a report from a no-path scan.

Examples:

```bash
skill-sentry-cli scan
skill-sentry-cli scan --project ~/work/app --save-report markdown --no-prompt
skill-sentry-cli scan --agent claude --agent codex --format json
skill-sentry-cli scan fixtures/malicious/cloud-sync-pro
skill-sentry-cli scan skills/ --report-dir reports
skill-sentry-cli scan skills/ --format sarif --sarif-out results.sarif
skill-sentry-cli scan my-skill --no-sandbox -q
skill-sentry-cli scan cloud-sync-pro --demo-mode
```

**Usage errors (exit `2`).** `--project`, `--agent` and `--include-experimental` with a `PATH`. `--demo-mode` without a `PATH`. An unknown `--agent` name. A `--project` that is not a folder (both `scan` with no path and `discover`). A `--save-report` value other than `markdown`, `sarif` or `none`. A `[discovery]` section that does not validate, or a configuration file that cannot be read.

A folder scan ends with a summary line. `INVALID` appears only when at least one skill has a malformed `SKILL.md`, and `failed` appears only when a skill could not be scanned. A text path scan on a terminal also prints a one-line tip about `scan` with no path on standard error. Redirected or piped runs get no tip.

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

### Scan with no path

`skill-sentry-cli scan` finds the installed skills (the same list that [`discover`](#discover) prints), scans each one, and prints a verdict for each. The skills scanned are the ones `discover` lists. The search covers verified locations by default and experimental ones only with `--include-experimental`; see [`discover`](#discover).

- Each skill is scanned at its real folder. A symlinked install is resolved first. The text output adds `installed at <link>` under a verdict when the link differs from the real folder.
- A folder reached by more than one path is scanned once. A skill counts toward `duplicates merged` only when it is reached under a different path. When the project folder is the home folder, user skills stay user-scope: the project sources that point at the same folders are dropped.
- Enabled Claude Code plugins are read from `enabledPlugins` in `~/.claude/settings.json`, `<project>/.claude/settings.json` and `<project>/.claude/settings.local.json`. The most specific file that mentions a plugin decides (local, then project, then user). `true` enables the plugin and `false` disables it.
- Hidden (dot) folders inside the built-in locations are skipped at every depth. For example, Codex's bundled `.system` skills are not listed, because they were not installed by the user. A folder named with `--project` or `extra_paths` is scanned even when its own name starts with a dot.
- The text output starts with `Found N skills (...)`. Skipped entries (broken links, folders without `SKILL.md`, unreadable folders, plugin problems) are printed as `note:` lines on standard error, unless `--quiet` is set.
- With more than one skill, each scan prints `[i/n] <folder name> ...` on standard error. This happens in every format, whether or not standard error is a terminal, so standard output stays clean JSON or SARIF. The run ends with `Scanned X, failed Y, skipped Z.` on standard error: X skills were scanned, Y could not be scanned, and Z entries were set aside by discovery (broken links, folders without `SKILL.md`, entries that could not be read). Plugin notes and the cap note are not counted in Z. `--quiet` suppresses both lines.
- If the 500-skill cap stops discovery, a note says how many more skills were not scanned, or `at least N more` when the count itself stopped early. The note appears in the JSON `notes` and on standard error (unless `--quiet`).
- `--format json` always prints one envelope with the keys `skills`, `notes` and `summary`, whether one skill, several or none were scanned. Each entry in `skills` is the verdict object a path scan prints, plus an `install` object (`agent`, `scope`, `declared_path`, `real_path`, `is_symlink`, `aliases`, all as full paths). `notes` lists the discovery notes once. `summary` has `scanned`, `failed` and `skipped`, the same numbers as the `Scanned X, failed Y, skipped Z.` line. A path scan's JSON keeps its own shape (one object for one skill, an array for several) and has none of these keys. Example:

```json
{
  "skills": [
    {
      "skill": "notes-summarizer",
      "verdict": "SAFE",
      "riskScore": 0,
      "...": "the same fields as a path scan's verdict",
      "install": {
        "agent": "claude",
        "scope": "user",
        "declared_path": "/home/you/.claude/skills/notes-summarizer",
        "real_path": "/srv/shared/notes-summarizer",
        "is_symlink": true,
        "aliases": ["/home/you/.agents/skills/notes-summarizer"]
      }
    }
  ],
  "notes": ["/home/you/.claude/skills/broken-link: broken symlink"],
  "summary": {"scanned": 1, "failed": 0, "skipped": 1}
}
```

   SARIF runs and results carry `declaredPath`, `agent` and `scope` properties, and each result's artifact URI is a `file:` URI under the real path of the skill folder. With more than one skill, the Markdown summary table has `Agent`, `Scope` and `Path` columns.
- When no skill is found, the command lists the locations it checked on standard error and exits `0`, as `discover` does. `--format json` prints the envelope with an empty `skills` array, and `--format sarif` prints an empty SARIF log. One case exits `3` instead: an `extra_paths` or `SKILLSENTRY_EXTRA_SKILL_PATHS` folder that does not exist when nothing was found. A `--project` folder that does not exist is a usage error (exit `2`), as it is for `discover`.

**Exit codes for a scan with no path:**

| Code | Meaning |
|:---|:---|
| `0` | Every verdict is below the `--fail-on` gate, or no installed skill was found. |
| `1` | At least one verdict meets the `--fail-on` gate, and every skill was scanned. |
| `2` | Usage error (see above). |
| `3` | An `extra_paths` folder does not exist and no skill was found; or no skill could be scanned; or at least one skill could not be scanned. A scan failure takes precedence over exit `1`. |

**Markdown report layout.** `--format markdown`, `--save-report markdown` and `--report-dir` share one layout. A run of more than one skill, and every no-path run, starts with a summary: a table of scanned, failed and skipped counts, the verdict totals, and a table of skills ordered with the most serious verdict first (MALICIOUS, SUSPICIOUS, UNSCANNED, INVALID SKILL, SAFE) and the highest risk first within a verdict. Skills that failed are listed under `Failed` and discovery notes under `Notes`. A no-path scan with nothing to scan still prints the summary, with a line saying that no skills were scanned. For a no-path scan the table adds Agent, Scope and Path columns, and each per-skill report adds Agent, Scope and Install path rows. Every finding, citation and verdict is kept. A single skill scanned by path prints only its own report.

**Saving a report.** In a text run on an interactive terminal (standard input and output are both terminals), the command asks after the verdicts:

```text
Save a report? [m]arkdown / [s]arif / [n]o (default n)
```

Pressing Enter, answering `n`, pressing Ctrl+C, reaching end of input, or giving three unrecognised answers means no. `--save-report` decides without asking, and `--no-prompt` skips the question. The question is never asked for `--format json`, `sarif` or `markdown`, or with `--quiet`.

When standard input or output is not a terminal, nothing is asked. A text run prints `Tip: add --save-report markdown to keep a report.` on standard error instead.

Saved reports go into a new private folder, `~/.skillsentry/reports/scan-<timestamp>/`. The timestamp is the UTC date, time and microseconds, written as `scan-YYYYMMDD-HHMMSS-ffffff`. If that name is taken, a numeric suffix (`-1`, `-2`, and so on) is added. An existing folder is never reused or overwritten. Markdown writes one file per skill and a `summary.md`. SARIF writes one file, `skills.sarif`. The text output names the folder.

## `discover`

Lists the installed skills that `scan` with no path would check. It scans nothing. It checks that each skill folder has a `SKILL.md`, but does not read the skill.

```text
skill-sentry-cli discover [OPTIONS]
```

| Option | Default | Meaning |
|:---|:---|:---|
| `--project DIR` | current directory | Project folder whose project-level skills are included. |
| `--agent NAME` | all | List only this agent's skills. Repeatable. Same names as [`scan`](#scan). |
| `--include-experimental` | off | Also look in the experimental agent locations. |
| `--format` | `text` | `text` or `json`. |

The command exits `0` whenever it prints the listing, including when nothing is found. It exits `2` for a bad `--format`, an unknown `--agent`, a `--project` that is not a folder, or a configuration that does not load.

The text output is a table with the columns `AGENT`, `SCOPE`, `SKILL` and `PATH`. For a symlinked install, `PATH` reads `<link> -> <real folder>`. Below the table, `notes:` lists skipped entries, and a `1 duplicate merged` or `N duplicates merged` line follows when any path was merged. When nothing is found, the table is replaced by the list of locations checked.

`--format json` prints one object:

| Field | Meaning |
|:---|:---|
| `skills` | One object per skill: `name`, `agent`, `scope` (`user`, `project`, `plugin` or `custom`), `declared_path` (where it was found), `real_path` (the folder that is scanned), `is_symlink`, and `aliases` (other paths that resolve to the same folder). |
| `checked` | Every location that was looked at, including locations that do not exist. |
| `notes` | Strings that say what was skipped and why, including a note when the 500-skill cap stopped the search, with how many more skills were not scanned. |
| `duplicates_merged` | How many paths were merged into a skill that was already listed. |

```bash
skill-sentry-cli discover
skill-sentry-cli discover --project ~/work/app --format json
```

## `self-audit`

Audits the skill that ships with SkillSentry. It takes `--format`, `--fail-on`, `-q`, `--no-cache`, `--sandbox` / `--no-sandbox`, `--backend`, and `--timeout`, with the same defaults as `scan`. It has no `--output` option; redirect standard output instead.

The bundled Agent Skill's `scripts/audit.sh DIR` runs `scan DIR --fail-on suspicious` and passes extra flags through. A SUSPICIOUS verdict exits `1`. Pass `--fail-on malicious` explicitly to accept SUSPICIOUS after review.

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
| `--host` | `127.0.0.1` | Address to bind. Keep the default. The API has no authentication, so any other address prints a warning; see the [security model](../developer/security.md). |
| `--port` | `8000` | Port, from 1 to 65535. |
| `--demo-mode` | off | Serve the canned seven-skill store instead of live scans. |
| `--speed` | `1.0` | Replay speed for demo mode. `0` is instant. |

The dashboard is served at `/`, and the API endpoints (for example `/scans`) are on the same port. Requests whose `Host` header is not loopback or the bind address are refused with `400 untrusted_host`. To accept another name, such as a LAN name, set `SKILLSENTRY_ALLOWED_HOSTS` (see the environment variables). Press `Ctrl+C` to stop.

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
| `[server]` | `allowed_scan_roots` | `[]` (any folder) | Absolute folders the API may scan. A scan path must resolve, with symlinks followed, to one of them or to a folder inside one. Read by `serve`; the CLI `scan` command is not limited. See [§5.2 of the API reference](api.md). |
| `[discovery]` | `extra_paths` | `[]` | Extra folders for `scan` and `discover` with no path. Each is a skill folder (one with `SKILL.md`) or a folder of skills. Each must be absolute after `~` expansion; otherwise the configuration is refused (exit `2`). A folder that does not exist is listed as a note, not an error. If no other skill is found, `scan` exits `3`; `discover` still exits `0`. |
| `[discovery]` | `agents` | `[]` (all agents) | Limits discovery to these agents. Names as for `scan --agent`. `--agent` on the command line replaces this list. |
| `[discovery]` | `include_experimental` | `false` | Also look in the experimental agent locations. `--include-experimental` turns them on for one run. |

Two sections deserve a warning:

- **`[ci]`** is accepted so that older files still load, but the CLI **does not read** it, and `init` no longer writes it. The gate is set with `--fail-on`, which defaults to `suspicious`. Do not rely on this section.
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
| `SKILLSENTRY_ALLOWED_SCAN_ROOTS` | Folders the API may scan, separated by the platform path separator (`:` on Linux and macOS, `;` on Windows). Overrides `[server] allowed_scan_roots`. Each must be an absolute path. Read by `serve`. |
| `SKILLSENTRY_EXTRA_SKILL_PATHS` | Extra folders for `scan` and `discover` with no path, separated by the platform path separator (`:` on Linux and macOS, `;` on Windows). Replaces `[discovery] extra_paths`. Each must be an absolute path after `~` expansion. |
| `SKILLSENTRY_ALLOWED_HOSTS` | Comma-separated host names the server accepts in the `Host` and `Origin` headers, in addition to `localhost`, `127.0.0.1`, `::1`, and the bind address. Read by `serve`. |
| `SKILLSENTRY_VERIFY_PROVENANCE` | Installer. Set to `1` to require the `gh attestation verify` check on the wheel: the install stops if `gh` is missing or the check fails. Without it, the check runs when `gh` is installed and a failure is only a warning. |
| `SKILLSENTRY_CONTAINER` | Set to `1` by the official server image. It silences the warning that `serve` prints when bound beyond loopback. Do not set it elsewhere. |
| `SKILLSENTRY_DECISION_BACKEND` | Overrides `[decision] backend`. |
| `SKILLSENTRY_LAYA_CHECKPOINT`, `SKILLSENTRY_LAYA_DEVICE`, `SKILLSENTRY_LAYA_MODEL_PATH`, `SKILLSENTRY_LAYA_REQUIRED` | Options for the optional decision layer. |

The installer also reads `SKILL_SENTRY_HOME` (install location), `SKILL_SENTRY_RELEASE_URL` (a mirror for release files), and `SKILLSENTRY_VERIFY_PROVENANCE` (above).

## Planned, not available

These are not implemented. Do not build on them yet.

- `scan --watch`
- `scan --upload-sarif`
- A GitHub Action (`skillsentry/scan`)
