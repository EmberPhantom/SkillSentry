# 16 · User Guide: set up and use SkillSentry

> Written for someone who wants to audit agent skills on their own machine. You do not need to contribute code. Follow the steps in order; each one says what you should see.

**Verified on:** Linux (Python 3.12 venv, Docker, Ollama). The commands below were run start to finish on a fresh clone. macOS and Windows notes are marked **not verified here**.

---

## 1. What SkillSentry does

SkillSentry reads an agent skill (a folder with a `SKILL.md` file and any scripts it ships), checks it statically, runs its entrypoint inside a locked-down Docker sandbox, asks a local language model to judge whether the text matches what the code does, and returns one verdict: `SAFE`, `SUSPICIOUS`, or `MALICIOUS`, with the evidence it found.

**What stays on your machine:** the skill, the scan, the model, and the reports. Nothing is uploaded unless you turn on the optional cloud backend (section 15).

---

## 2. Requirements

| Needed for | What | Check |
|:---|:---|:---|
| Everything | Python 3.11, 3.12 or 3.13 | `python3.12 --version` |
| Everything | git | `git --version` |
| Full scans | Docker, and permission to use it without sudo | `docker ps` works |
| Full scans | Ollama, running, with the model that `skill-sentry-cli doctor` names | `ollama list` |
| Dashboard only | Node.js 24 | `node --version` |
| Model | About 8 GB of free RAM while a scan runs | Close heavy apps first |

> **Python version:** use `python3.11`, `python3.12` or `python3.13` explicitly. Python 3.14 is not supported yet. CI runs the unit tests on it as a non-blocking check, so its status is visible before support is announced.

---

## 3. Install

Pick the option for your system. Each puts the `skill-sentry-cli` command on your PATH.

**A. The install script** (Linux, macOS, and WSL; the release files are checksum-verified):

```bash
curl -fsSLO https://github.com/EmberPhantom/SkillSentry/releases/latest/download/install.sh
sh install.sh                 # installs, then runs `skill-sentry-cli setup`
```

Read `install.sh` before running it, as you would any script you download. Useful options:

| Option | What it does |
|:---|:---|
| `--no-setup` | Install only; run `skill-sentry-cli setup` yourself later |
| `--dry-run` | Print the download URL and steps; change nothing |
| `--version 2.1.0` | Install a specific published version |
| `--upgrade` | Reinstall over an existing install |
| `--uninstall` | Remove the command; your scan history is kept |

If the GitHub CLI (`gh`) is installed, the script also runs `gh attestation verify` on the wheel. Success prints that the build provenance is verified. A failed check is a warning, and the checksum result stands. Set `SKILLSENTRY_VERIFY_PROVENANCE=1` to make the check required: the install then stops if `gh` is missing or the check cannot pass.

The script never uses sudo and installs only under your home folder. If the command is not found afterwards, the script prints the exact line to add to your shell's startup file (for example `~/.bashrc` or `~/.zshrc`).

**D. Windows (PowerShell)** (native Windows; no administrator rights needed):

```powershell
Invoke-WebRequest -Uri https://github.com/EmberPhantom/SkillSentry/releases/latest/download/install.ps1 -OutFile install.ps1
powershell -ExecutionPolicy Bypass -File install.ps1
```

It needs Python 3.11 to 3.13 (`winget install Python.Python.3.12`). It checks the download against `SHA256SUMS`. If the GitHub CLI (`gh`) is installed, it also runs `gh attestation verify`; set `$env:SKILLSENTRY_VERIFY_PROVENANCE = "1"` first to make that check required. It installs under `%LOCALAPPDATA%\skill-sentry-cli`, adds that folder to your user PATH, and runs setup. Add `-DryRun`, `-NoSetup`, or `-Uninstall` as needed. Open a new PowerShell window after installing.

**Windows and WSL:** the sandbox needs Docker Desktop. On WSL, turn on WSL integration for your distribution in Docker Desktop settings. Keep your skills inside the Linux filesystem (for example `~/skills`), not under `/mnt/c/...`: scans of Windows-drive folders are much slower. `doctor` warns when the working folder is on a Windows drive.

**B. pipx** (any platform with Python 3.11 to 3.13):

```bash
pipx install skill-sentry-cli
```

**C. From a checkout** (for contributors):

```bash
git clone https://github.com/EmberPhantom/SkillSentry.git
cd SkillSentry
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

Check the install with `skill-sentry-cli --version`. Expected: `SkillSentry 2.1.0` (the version number matches the release you installed).

**Build the dashboard** only when you install from a checkout (B and A ship it built):

```bash
cd ui
npm ci
npm run build
cd ..
```

> **Windows and macOS status:** the installers and Windows support are new in 2.1 and are being verified on real machines. Until then, treat a failed sandbox step on these systems as expected and run `skill-sentry-cli doctor` to see what is missing.

**Upgrade:** `pipx upgrade skill-sentry-cli`, or run the install script again. **Uninstall:** `sh install.sh --uninstall`, or `pipx uninstall skill-sentry-cli`. Both keep your scan history and any `skillsentry.toml` you wrote.

**Verify a download.** The install script checks the wheel against `SHA256SUMS` before installing. To check a release's image or wheel yourself, see [Verify a release](../operations/release-process.md#verify-a-release).

---

## 4. Docker access and the sandbox image

The sandbox runs each skill's entrypoint in a container on an internal Docker network with no route to the internet, plus a memory limit and a time limit. Its DNS and HTTP requests go to a local sinkhole that answers with fake responses and records what was asked for.

**Give your user access to Docker** (Linux, once):

```bash
sudo usermod -aG docker "$USER"
```

Then **log out and back in** (or reboot). A shell started before the change does not have the new group, and Docker will still say `permission denied`. Check it:

```bash
id -nG | tr ' ' '\n' | grep -x docker   # should print: docker
docker ps                                # should print a table, even if empty
```

**Build the sandbox image** (once; it takes a few minutes the first time):

```bash
skill-sentry-cli sandbox build
```

Expected: `built skillsentry-sandbox:local`.

---

## 5. The local model

SkillSentry uses a language model that runs on your machine through Ollama.

1. Install Ollama from <https://ollama.com>, then start it (on Linux it usually runs as a service; otherwise run `ollama serve` in a terminal and leave it open).
2. Ask SkillSentry which model it needs and what to run:

```bash
skill-sentry-cli doctor
```

If the last line says `FAIL model: … is not pulled; run: ollama pull …`, run the command it prints. Pulling a model downloads several gigabytes; do this once.

If you want a different model, set `ollama_model` in the `[model]` section of `skillsentry.toml` to the name you pulled (section 14).

---

## 6. Check that you are ready

`skill-sentry-cli setup` walks through the same checks. It asks before every download or build, and it never installs Docker or Ollama for you. Use `--yes` to accept every prompt, or `--skip-model` / `--skip-sandbox` to skip a step.

```bash
skill-sentry-cli setup
```


```bash
skill-sentry-cli doctor
```

Each line is one check:

| Line | Meaning | What to do |
|:---|:---|:---|
| `PASS model: … is pulled` | The local model is ready | Nothing |
| `FAIL model: cannot reach the model server at …` | Ollama is not running, or the address is wrong | Start Ollama, or fix `ollama_url` (section 14) |
| `FAIL model: … is not pulled; run: ollama pull …` | The configured model is missing | Run the command it prints |
| `PASS dashboard: built` | The dashboard is built | Nothing; otherwise run the dashboard build (section 3) |
| `PASS database: writable at …` | Scan history can be saved | Nothing |
| `WARN docker: engine not reachable …` | Full sandbox scans are not possible | Section 4 |
| `PASS sandbox image: … is present` | The sandbox image is built | Nothing |
| `WARN stale images: N older or test SkillSentry image(s) …` | Old SkillSentry images are using disk space | Run the `docker rmi …` command it prints, if you do not need them. `doctor` removes nothing itself |
| `ready for a full scan` | Every required check passed | You can run full scans |

`doctor` exits `0` when it is ready and `3` when a required check fails.

> If `doctor` says Docker is unreachable but you already ran `docker ps` successfully, your terminal session started before you joined the `docker` group. Open a new terminal.

---

## 7. Your first scans

The repository includes two sample skills under `fixtures/`. One is harmless. The other is a deliberately malicious test skill that steals credentials through DNS. Both are safe to scan because they only run inside the sandbox.

**Scan the harmless sample:**

```bash
skill-sentry-cli scan fixtures/benign/pdf-summarizer
```

Expected (the first time; a repeat is marked `(cached)`):

```text
SkillSentry 2.1.1 - Fully local analysis · open weights - backend: local (ollama)
[OK] pdf-summarizer - SAFE - risk 0 - confidence 0.95
```

**Scan the malicious sample:**

```bash
skill-sentry-cli scan fixtures/malicious/cloud-sync-pro
```

Expected:

```text
[X] cloud-sync-pro - MALICIOUS - risk 95 - confidence 1.00
   AWS credential file or environment variable referenced (scripts/sync.sh:4)
   Poisoned Well: DNS_TUNNELING -> evil-collector.net (marker SKS-…)
```

The `(scripts/sync.sh:4)` is the file and line of the evidence. The `SKS-…` marker is a fake credential that SkillSentry planted in the sandbox; seeing it leave the sandbox proves the skill tried to steal it.

**Reading the result**

| Line | Meaning |
|:---|:---|
| `[OK]` / `[!]` / `[X]` | `SAFE`, `SUSPICIOUS`, `MALICIOUS` |
| `[?] … UNSCANNED` | The verdict is shown, but the scan did not finish every check. See section 15 |
| `risk N` | 0 to 100; higher is worse |
| `confidence X` | How certain the verdict is, from 0 to 1. See "Risk, confidence, coverage and tiers" below |
| `(cached)` | The same skill, unchanged, was scanned before |

**What a verdict means**

- `SAFE` means these checks found nothing. It is not a guarantee that the skill is safe, and it is not a substitute for reading a skill that asks for credentials, network access or a shell.
- A verdict mostly comes from deterministic patterns (the anchors), which are auditable and run on every file. The model adds intent that no pattern names, but a claim only the model makes cannot raise a verdict above `SUSPICIOUS`, and on its own it does not raise it at all. The sandbox shows what the entrypoint does when it runs, and only the declared entrypoint is run.
- Patterns can be written around. Obfuscation that builds a command at run time, lookalike letters, and a download in one file with the run in another are examples; some are caught and two are known gaps. The list, with the reasons, is in [Evasion limits](../security/evasion-limits.md).
- `coverage` and `confidence` say how much weight a result deserves: a `SAFE` with full coverage and a sandbox run is the strongest result; one with the sandbox or the model off is weaker.

**Risk, confidence, coverage and tiers**

- **Risk** (0 to 100) is the score. The **tier** comes from it: `SAFE` below 30, `SUSPICIOUS` from 30 to 70, `MALICIOUS` above 70. A score of exactly 30 is the lowest `SUSPICIOUS` score, and exactly 70 is the highest. Change the boundaries with `tiers = { safe_max = 30, malicious_min = 70 }` under `[scoring]` in `skillsentry.toml`: a score below `safe_max` is SAFE, and one above `malicious_min` is MALICIOUS. A single hit on a name that looks like a known skill (a typosquat) scores a quarter of the way up the SUSPICIOUS band (40 with the defaults), so it stays SUSPICIOUS and does not sit on the boundary.
- **Confidence** (0 to 1) is how certain the verdict is. It is not the share of checks that ran. A canary leaving the sandbox or an evasion probe is direct observation: `1.00`. A `MALICIOUS` verdict backed by a deterministic finding is `0.85`, and `0.95` when the model agrees. A `SUSPICIOUS` verdict is `0.65` with independent evidence, `0.75` when the model agrees, `0.40` when only the model flags it, and `0.30` when the only reason is a failed check. A `SAFE` verdict is `0.50 + 0.45 x coverage` (so `0.95` for a fully analysed skill), times `0.6` when the model flagged something nothing else supported. A failed check caps anything below `MALICIOUS` at `0.50`.
- **Coverage** (0 to 1, `coverage` in the JSON) is the share of the checks that apply to this skill that actually ran, weighted like the score. A check that does not apply (vision with no images, the sandbox for a skill with nothing to run) is not counted. Turning the sandbox off, or a check failing, lowers it.

Read them together: `SAFE` with confidence `0.95` and coverage `1.00` is a skill that was fully analysed and found clean. `SAFE` with coverage `0.58` is clean as far as the checks that ran can tell, with the sandbox off. Neither is a guarantee. Verdicts cached by an older version are scanned again.

**What to do with each verdict**

| Verdict | Meaning | Action |
|:---|:---|:---|
| `SAFE` | Nothing suspicious was found | Install after a quick look at the report |
| `SUSPICIOUS` | Something needs a human look | Read every cited finding; ask the author if unclear |
| `MALICIOUS` | Hard evidence of hostile behaviour | Do not install |
| `UNSCANNED` | The scan is incomplete (model, sandbox, or a file was not read) | Fix the reason shown, then scan again; do not install meanwhile |
| `INVALID SKILL` | The SKILL.md is malformed (for example a missing `name:`). No behaviour was judged; the verdict is about the package format | Fix the frontmatter named in the line, then scan again. It still fails the CI gate |

Exit codes for scripts: `0` below the gate, `1` at or above it, `2` a usage error, `3` an operational error, `5` a malformed skill (`INVALID SKILL`). See section 12.

---

## 8. Scan everything installed

With no path, `scan` finds the skills that agents on this machine have installed, and scans each one:

```bash
skill-sentry-cli scan
```

To see the list without scanning anything, run `skill-sentry-cli discover`. It prints a table, or JSON with `--format json`.

**What it searches.** The verified locations are on by default:

| Where | Notes |
|:---|:---|
| `~/.claude/skills` | Claude Code user skills. Skills synced to your account are stored in group folders here, such as `~/.claude/skills/synced/<id>/<skill>`, and are found. |
| Enabled Claude Code plugins | The `skills` folder of each plugin that is enabled in `~/.claude/settings.json`, or in the project's `.claude/settings.json` or `.claude/settings.local.json`. The most specific file that mentions a plugin decides. A plugin that is only present in a marketplace checkout is not searched. |
| `~/.codex/skills` | Codex skills. |
| `~/.agents/skills` | Shared agent skills. |
| `.claude/skills` and `.agents/skills` in the project folder | Project skills. The project folder is the current directory, or the folder named by `--project`. |
| `[discovery] extra_paths` and `SKILLSENTRY_EXTRA_SKILL_PATHS` | Your own folders. See **Custom locations** below. |

The experimental locations are searched only with `--include-experimental`, or with `include_experimental = true` in `[discovery]`. They have not yet been checked against each tool's documentation:

- Cursor: `~/.cursor/skills`
- OpenCode: `~/.config/opencode/skills` and `~/.config/opencode/skill`
- Copilot: `.github/skills` in the project folder
- One more agent, whose folders are under its home directory. Its name is listed with the other `--agent` names in the [CLI reference](../reference/cli.md).

**How the search works.**

- Symlinks are followed. A skill that is installed as a link is scanned in the folder the link points to. The text output shows `installed at <link>` under its verdict.
- A folder reached by more than one path is scanned once. When the project folder is your home folder, your user skills stay user skills.
- A folder without a `SKILL.md` is searched for skills up to two levels down, so `<group>/<group>/<skill>` is found.
- Hidden (dot) folders inside the built-in locations are skipped. Codex's bundled `.system` skills are not listed, because you did not install them. A folder you name with `--project` or `extra_paths` is scanned even when its name starts with a dot.
- At most 500 skills are scanned. A note says when the search stopped at that limit, and how many more skills were not scanned.
- Anything skipped (a broken link, a folder without `SKILL.md`, an unreadable folder) is printed as a `note:` line on standard error.
- With several skills, the command prints `[i/n] name ...` progress on standard error and ends with `Scanned X, failed Y, skipped Z.`. These lines appear even when the output is piped. `--quiet` hides them.

**Machine-readable output.** `--format json` gives each verdict an `install` object (the agent, scope, declared path, real path, whether it is a symbolic link, and any aliases, all as full paths) one `notes` list and a `summary` of how many skills were scanned, failed and set aside, in one envelope (`skills`, `notes`, `summary`) that has the same shape for one skill, several or none. SARIF records the declared path, agent and scope on each run and result, and points each result at the real folder. With no skills found, `--format json` prints the envelope with an empty `skills` array.

**Scope.** Use `--agent` to scan only some agents. The names are listed in the [CLI reference](../reference/cli.md); `custom` selects only your own folders. Use `--project DIR` to check another project. A `--project` folder that does not exist is a usage error (exit `2`), as it is for `discover`. Without `--project`, the project is the folder you run the command from.

**Time.** Each skill gets a full scan, with the sandbox and the local model, so scanning many skills can be slow. Verdicts for unchanged skills are reused from the cache unless you pass `--no-cache`. The cost can be changed in two ways:

- `--no-sandbox` skips Docker and the sandbox run. The verdicts are weaker; see the table in section 9.
- `--backend local|cloud` chooses the model. `cloud` sends code excerpts to a hosted model service and needs the API key set in the environment (see the [CLI reference](../reference/cli.md)). The default, `auto`, tries the local model first, and uses the hosted model only when its key is set and the local model cannot be reached.

**Saving a report.** In a text run on an interactive terminal, the command asks after the verdicts:

```text
Save a report? [m]arkdown / [s]arif / [n]o (default n)
```

Answer `m` for Markdown or `s` for SARIF. Enter, `n`, or Ctrl+C means no. To decide in advance, pass `--save-report markdown`, `--save-report sarif`, or `--save-report none`. Pass `--no-prompt` to skip the question. Reports are saved in a new private folder, `~/.skillsentry/reports/scan-<timestamp>/`, where the timestamp holds the UTC date, time and microseconds. A numeric suffix is added if that name is taken, and an existing folder is never reused. Markdown writes one file per skill and a `summary.md`. SARIF writes `skills.sarif`.

**CI.** The question is never asked when standard input or output is not a terminal, so a CI job does not hang. Use `--save-report` to keep files, or `--format sarif > results.sarif` to send SARIF to a file. The exit codes are the same as for a path scan, with two differences. Finding no skills exits `0`, with a message on standard error. A configured `extra_paths` folder that does not exist exits `3` when no other skill is found. A `--project` folder that does not exist exits `2`. See section 12.

**Custom locations.** To scan a project outside the current directory, use `--project DIR`. To add folders, set them in `skillsentry.toml`:

```toml
[discovery]
extra_paths = ["/srv/team-skills", "~/work/skills"]   # absolute after ~ expansion
agents = []                                            # empty means all agents
include_experimental = false
```

On Windows, write the path as a single-quoted TOML string, which keeps backslashes as they are, for example `extra_paths = ['~\work\skills']`. A double-quoted string treats the backslash as an escape and fails to load; forward slashes (`"~/work/skills"`) also work. Each extra path is either one skill folder or a folder of skills. A missing extra folder is listed as a note; if no skill is found at all, `scan` exits `3`. The `skillsentry.toml` file is read from the current directory, or from the file named by `SKILLSENTRY_CONFIG`. Run the command from a folder that has the file, or set that variable, for the `[discovery]` settings to apply. `SKILLSENTRY_EXTRA_SKILL_PATHS` replaces `extra_paths` and separates entries with the path separator (`:` on Linux and macOS).

---

## 9. Scan your own skills

**One skill:**

```bash
skill-sentry-cli scan path/to/my-skill
```

A skill folder must contain a `SKILL.md`. If it has scripts, its `SKILL.md` must declare the entrypoint:

```yaml
---
name: my-skill
description: One sentence that says what the skill does.
entrypoint: python scripts/run.py
---
```

Without an `entrypoint:`, SkillSentry reads the scripts but does not run them, and it never guesses a command. The scan still finishes: the verdict comes from the static and model stages, the report carries a `sandbox-no-entrypoint` note, and the command prints a warning on stderr. Declare an `entrypoint:` to have the scripts tested. In a pipeline that must not accept untested scripts, add `--strict-sandbox`: the skill is then `UNSCANNED` and the exit code is 1.

**A folder of skills** (each child folder that has a `SKILL.md` is scanned):

```bash
skill-sentry-cli scan path/to/skills-folder
```

The last line is a summary:

```text
Summary: 4 scanned - 4 SAFE, 0 SUSPICIOUS, 0 MALICIOUS, 0 UNSCANNED
```

**Useful options**

| Option | What it does |
|:---|:---|
| `--fail-on suspicious` (default) | Exit `1` for `SUSPICIOUS` and `MALICIOUS` |
| `--fail-on safe` | Exit `1` for any verdict other than `SAFE` |
| `--fail-on malicious` | Exit `1` only for `MALICIOUS` (not recommended in CI; see section 12) |
| `--no-cache` | Ignore saved results and scan again |
| `--timeout 120` | Sandbox time limit in seconds (5 to 600; default 60) |
| `--max-time 600` | Cap for scanning one skill, in seconds (default 300). The model and the sandbox stop at it and the stage is reported as degraded |
| `--timings` | Print how long each stage took, to find the slow one |
| `--no-sandbox` | Static analysis and the model only; the entrypoint is never run. Verdicts are weaker. |
| `-q` / `--quiet` | Print only the verdict line |

**Skills that are never run:** a skill with scripts and no `entrypoint:` is scanned statically and reported with a warning (`UNSCANNED` with `--strict-sandbox`). A skill whose SKILL.md or files cannot be read as text is reported with the reason; see the troubleshooting table.

---

## 10. Reports and stored scans

**Where the report is.** Every text scan ends with the command that writes its report. A plain `scan` prints the verdict in the terminal and stores the scan; it does not write a file. To write files in one run:

```bash
skill-sentry-cli scan path/to/skills --report-dir reports   # one .md per skill, plus summary.md
skill-sentry-cli scan path/to/skills --recursive            # also scan skills nested in a skill folder
```

**Which output option to use**

| You want | Use |
|:---|:---|
| The result in the terminal | `scan` (text, the default) |
| JSON for a script | `scan --format json` (add `-q` for a verdict line only) |
| One report as a file | `scan PATH --format markdown\|json\|sarif --output FILE` |
| A SARIF file for code scanning, and the normal text output as well | `scan PATH --sarif-out FILE` |
| One Markdown report per skill, plus `summary.md`, for a folder | `scan PATH --report-dir DIR` |
| A report from a run with no path (every installed skill) | `scan --save-report markdown\|sarif` |
| The report of a scan you already ran, without scanning again | `export SCAN_ID --format markdown\|sarif\|json\|stix --output FILE` |

`--format` and `export --format` share `markdown`, `sarif` and `json`. `export` also has `stix`, which needs a Poisoned Well hit, and `scan` also has `text`, which is for a terminal. `--output`, `--sarif-out` and `--report-dir` need a `PATH`.

Choose a format with `--format` (`text`, `json`, `markdown`, `sarif`), and save it with `--output`:

```bash
skill-sentry-cli scan fixtures/malicious/cloud-sync-pro --format markdown --output reports/cloud-sync-pro.md
skill-sentry-cli scan fixtures/malicious/cloud-sync-pro --format json --output reports/cloud-sync-pro.json
skill-sentry-cli scan fixtures/malicious/cloud-sync-pro --format sarif --output reports/cloud-sync-pro.sarif
```

SARIF 2.1.0 files open in editors and in code-scanning tools.

**Find a stored scan and export it again without re-running it:**

```bash
skill-sentry-cli cache list                  # newest first: scan ID, skill, status, verdict
skill-sentry-cli export <scan-id> --format markdown -o reports/again.md
```

Each `cache list` line starts with the scan ID. Copy it into `export`.

**Cache and history:**

```bash
skill-sentry-cli cache stats                 # entries, database size, hit rate
skill-sentry-cli cache clear --older-than 7d # remove old saved results
```

**Where the history lives:** `~/.skillsentry/skillsentry.db`. Change it with the `SKILLSENTRY_DB` environment variable, for example `SKILLSENTRY_DB=/tmp/test.db skill-sentry-cli scan …`.

---

## 11. The dashboard

```bash
skill-sentry-cli serve
```

Open <http://127.0.0.1:8000> in a browser. The server listens only on your own machine.

The dashboard has no login. Anyone who can reach the port can see your scans and start new ones, so keep the server on `127.0.0.1`. `serve` refuses any other `--host` unless you set `SKILLSENTRY_TOKEN`, which makes the API require a bearer token (the dashboard does not send one yet).

The server only scans inside the folder you started it in (it prints that folder). To scan elsewhere, start it there, or set `[server] allowed_scan_roots`.

- `/` serves the dashboard page.
- `/health` reports whether Ollama, Docker and the database are ready (`"ok"` or `"down"`).
- `/scans` lists stored scans as JSON.

Use another port with `skill-sentry-cli serve --port 8080`. Stop the server with `Ctrl+C`.

If the port is taken, you see `address already in use`. Pick another port.

---

## 12. Use SkillSentry in CI

A CI runner needs Docker and a local model server to produce full verdicts. Hosted runners usually have neither, so a hosted run will report `UNSCANNED` unless you provide a model server. Plan for that before you rely on the gate.

A degraded scan is never `SAFE`: its verdict is at least `SUSPICIOUS`, and the report shows `UNSCANNED` with the reason. Keep the default `--fail-on suspicious`, which fails such a scan. `--fail-on malicious` lets it pass, so do not use it for this reason.

The bundled Agent Skill ships `scripts/audit.sh`, which runs `scan` with `--fail-on suspicious` and passes extra flags through. Pass `--fail-on malicious` to it only after you have reviewed a SUSPICIOUS result and accepted it.

Example workflow (**the commands were run locally; this file was not run on GitHub**):

```yaml
name: skill audit
on: [pull_request]
jobs:
  audit:
    runs-on: self-hosted        # a runner with Docker, Ollama, and the model pulled
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: python -m pip install -e .
      - run: skill-sentry-cli sandbox build
      - run: skill-sentry-cli scan skills/ --format sarif --sarif-out results.sarif
      - uses: github/codeql-action/upload-sarif@v3   # not verified here
        if: always()
        with:
          sarif_file: results.sarif
```

**Exit codes**

| Code | Meaning | CI |
|:---|:---|:---|
| `0` | Every skill is below the gate | Pass |
| `1` | At least one skill meets the gate | Fail the merge |
| `2` | Bad command-line options | Fix the workflow |
| `3` | Operational error: bad path, Docker or database failure, nothing completed | Investigate |
| `5` | A skill is malformed (`INVALID SKILL`): bad frontmatter, a symlink, a non-UTF-8 `SKILL.md`, or a package over 64 MiB. Not a verdict; `--fail-on` does not apply | Fix the skill. The message says what to change |

With several skills the most serious result wins: `3`, then `1`, then `5`, then `0`.

---

## 13. The offline demo

To see the output without Docker or a model:

```bash
skill-sentry-cli scan cloud-sync-pro --demo-mode
```

`--demo-mode` takes a skill **name** from the built-in demo set (`pdf-summarizer`, `git-helper`, `image-resizer`, `weather-fetch`, `cloud-sync-pro`, `invoice-helper`, `slack-notif-mal`). It does not scan a folder, and its results are canned, not real analysis. The banner says `demo`, and a warning on standard error says that the path was not read.

---

## 13a. A light setup: no Docker, no Ollama

Docker and a local model are the full setup. When you have neither, a light scan still runs the deterministic checks, which find the common cases:

```toml
# skillsentry.toml
[model]
backend = "local"        # nothing is called; the model stage is off below

[decision]
backend = "none"         # switch the semantic stage off on purpose
```

```bash
skill-sentry-cli scan path/to/skill --no-sandbox
```

This runs the patterns and the syntax-tree checks only. The result is a normal verdict, not `UNSCANNED`, because you switched the stages off on purpose; the report carries `semantic-disabled` and `sandbox-disabled` notes, and `coverage` is about `0.58` and `confidence` lower than a full scan, so it reads as the weaker result it is. Without the `[decision]` setting, a missing model makes the scan `UNSCANNED`. `--backend cloud` is the other way to get a model without installing one, but it sends code excerpts to a cloud API.

Treat a light `SAFE` as "none of the patterns matched", and see [Evasion limits](../security/evasion-limits.md).

---

## 14. Configuration

```bash
skill-sentry-cli init            # writes skillsentry.toml in the current folder
skill-sentry-cli init --force    # overwrite it
```

The file has sections for the model, the sandbox, the Poisoned Well deception, scoring, and the decision layer. The keys you are most likely to change:

```toml
[model]
ollama_url = "http://localhost:11434"   # where Ollama listens
ollama_model = "…"                      # the model you pulled (doctor names it)
```

**Precedence:** command-line flags, then environment variables, then `skillsentry.toml`, then built-in defaults.

**Choosing the file:** SkillSentry reads `./skillsentry.toml`, or the file named by `SKILLSENTRY_CONFIG`. A path that does not exist is an error, not a silent fallback:

```bash
SKILLSENTRY_CONFIG=/path/to/other.toml skill-sentry-cli doctor
```

Useful environment variables:

| Variable | Use |
|:---|:---|
| `SKILLSENTRY_CONFIG` | Path to the configuration file |
| `SKILLSENTRY_DB` | Path to the history database |
| `OLLAMA_HOST` | Address of the Ollama server (overrides the file) |

---

## 15. Troubleshooting

Each message below was produced on purpose and quoted exactly. The first line of a scan's reason names the first stage that did not finish; the report lists every stage.

| What you see | Cause | Fix |
|:---|:---|:---|
| `INVALID SKILL - frontmatter is missing required field: name (SKILL.md:1)` | The SKILL.md has no `name:` (or `description:`) in its frontmatter | Add the field between the `---` lines at the top of SKILL.md, then scan again |
| `Warning: … is a skill itself; its N nested skill(s) were not scanned` | The folder has its own SKILL.md, so only that skill was scanned | Pass `--recursive` to scan the nested skills too, or point at a subfolder |
| `UNSCANNED … sandbox degraded: Docker unavailable … Permission denied` | Your shell is not in the `docker` group | Section 4: join the group and open a new terminal |
| `FAIL model: cannot reach the model server at …` | Ollama is not running, or `ollama_url` is wrong | Start Ollama; check `ollama_url` |
| `UNSCANNED … semantic degraded: model unavailable: local model is not reachable at …` | The model server could not be reached | Start Ollama; run `doctor` |
| `FAIL model: … is not pulled; run: ollama pull …` | The configured model is not downloaded | Run the command it prints |
| `error: config file not found: …` (exit 2) | `SKILLSENTRY_CONFIG` names a missing file | Fix the path |
| `error: no SKILL.md found under …` (exit 3) | The folder has no `SKILL.md` | Point at the skill folder, or add the file |
| `ERROR: … address already in use` | The port is taken | `skill-sentry-cli serve --port 8080` |
| `UNSCANNED … spec degraded: manifest validation failed`, then `symlink is not allowed in a skill package: …` | The skill contains a symbolic link | Replace it with a real file, or remove it |
| `UNSCANNED … SKILL.md is not valid UTF-8` | The file is not plain UTF-8 text | Re-save it as UTF-8 |
| `UNSCANNED … text file not analysed: scripts/x.py (larger than 1 MiB)` | A file is too large to read | Split or shrink the file; SkillSentry will not call it clean |
| `UNSCANNED … file not analysed: data/model.dat (binary or unrecognised content, …)` | The skill ships a file SkillSentry cannot read: a dataset, archive, PDF or other binary | Review it by hand or remove it. It is reported MEDIUM and the scan is never SAFE. A small image or font that matches its file name is only a NOTE |
| `opaque content: scripts/helper is an executable binary (ELF)` | The skill ships a compiled program (ELF, Windows PE or Mach-O), under any name, even one that looks like an image | Ship the source instead, or remove it. It is reported HIGH |
| `opaque content: … is 50.0 MiB, close to the 64 MiB package limit` | One file is 48 MiB or more | Remove it. It is reported HIGH |
| `error: … skill package is larger than 64 MiB` | The whole skill folder is over the size limit. Nothing is read and no model is called | Remove large or generated files (models, datasets, archives, build output) |
| `image not analysed: assets/x.png has content that is not a png image` | A file named like an image is not one | Replace it with a real image or remove it. It is reported MEDIUM
| `warning: <skill>: scripts were not executed because SKILL.md declares no 'entrypoint:'` | The skill has scripts but no `entrypoint:`. The scan finished without running them | Add `entrypoint:` to `SKILL.md`. With `--strict-sandbox` the same case is `UNSCANNED` with exit 1 |
| `[?] … UNSCANNED` with a reason you do not understand | Anything not listed here | Read the report: `--format markdown --output …` |
| `[OK] … SAFE` with `LOW sandbox-exit: Skill exited with status 2` | The skill ran and exited with an error (for example, it needs an argument) | Expected for some skills; the finding is low risk |
| `bad interpreter` or `No such file or directory` when you run `skill-sentry-cli`, after moving or copying a virtual environment | A console script starts with the absolute path of the Python that installed it, so it is not relocatable | Recreate the virtual environment where it will live and reinstall (`pip install skill-sentry-cli`), or run `python -m skill_sentry_cli` from the moved environment |
| A scan is very slow | The first scan of a large skill, or the model is short of memory | Run with `--timings` to see which stage is slow. A scan stops at `--max-time` (default 300 s), so it cannot run unbounded; use a smaller model or `--no-sandbox`. Cached rescans take under a second |
| `scan-time-limit` note, or a stage `degraded: ... time limit` | The model or sandbox was still running when `--max-time` passed | Raise `--max-time` (or `[scan] max_time_s`), or use a smaller model. A timed-out scan is not cached |
| A scan is killed with `sandbox timed out` | The entrypoint ran past `--timeout` | Raise `--timeout` (up to 600) if the skill is legitimately slow |

**Where to look when something is still wrong**

- The verdict's full reason: `skill-sentry-cli scan <path> --format json` (every stage and finding).
- Ollama: `curl http://localhost:11434/api/tags` should list the model.
- Docker: `docker ps` should print a table.
- The history database: `skill-sentry-cli cache list`.

---

## 16. Safety notes

- The malicious sample is test material. It only runs inside the sandbox through `skill-sentry-cli scan`. Do not copy its scripts out and run them.
- The sandbox has no route to the internet. A skill that tries to reach an outside host fails inside the sandbox and is reported as a finding.
- `--no-sandbox` never runs the entrypoint. Use it only when Docker is not available, and read the verdict as weaker evidence.
- Canary credentials planted in the sandbox are fake. They are never real secrets.
- Nothing leaves your machine unless you enable the cloud backend.

---

## 17. Command cheat sheet

```bash
skill-sentry-cli --version
skill-sentry-cli doctor
skill-sentry-cli init [--force]
skill-sentry-cli sandbox build
skill-sentry-cli scan <skill-or-folder> [--format text|json|markdown|sarif] [--output FILE] [--sarif-out FILE]
skill-sentry-cli scan <skill-or-folder> [--fail-on safe|suspicious|malicious] [--no-cache] [--timeout N] [--no-sandbox] [-q]
skill-sentry-cli scan <skill-name> --demo-mode
skill-sentry-cli scan [--project DIR] [--agent NAME]... [--include-experimental] [--save-report markdown|sarif|none] [--no-prompt]
skill-sentry-cli discover [--project DIR] [--agent NAME]... [--include-experimental] [--format text|json]
skill-sentry-cli self-audit
skill-sentry-cli cache list [--limit N]
skill-sentry-cli cache stats
skill-sentry-cli cache clear [--older-than 7d]
skill-sentry-cli export <scan-id> [--format markdown|sarif|stix] [-o FILE]
skill-sentry-cli serve [--host 127.0.0.1] [--port 8000]
```

Full reference: [07-cli-reference.md](../reference/cli.md).
