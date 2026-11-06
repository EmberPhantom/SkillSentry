# 16 · User Guide: set up and use SkillSentry

> Written for someone who wants to audit agent skills on their own machine. You do not need to contribute code. Follow the steps in order; each one says what you should see.

**Verified on:** Linux (Python 3.12 venv, Docker, Ollama). The commands below were run start to finish on a fresh clone. macOS and Windows notes are marked **not verified here**.

---

## 1. What SkillSentry does

SkillSentry reads an agent skill (a folder with a `SKILL.md` file and any scripts it ships), checks it statically, runs its entrypoint inside a locked-down Docker sandbox, asks a local language model to judge whether the text matches what the code does, and returns one verdict: `SAFE`, `SUSPICIOUS`, or `MALICIOUS`, with the evidence it found.

**What stays on your machine:** the skill, the scan, the model, and the reports. Nothing is uploaded unless you turn on the optional cloud backend (section 14).

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
| `--version 2.1.0rc1` | Install a specific published version |
| `--upgrade` | Reinstall over an existing install |
| `--uninstall` | Remove the command; your scan history is kept |

The script never uses sudo and installs only under your home folder. If the command is not found afterwards, the script prints the exact line to add to your shell's startup file (for example `~/.bashrc` or `~/.zshrc`).

**D. Windows (PowerShell)** (native Windows; no administrator rights needed):

```powershell
Invoke-WebRequest -Uri https://github.com/EmberPhantom/SkillSentry/releases/latest/download/install.ps1 -OutFile install.ps1
powershell -ExecutionPolicy Bypass -File install.ps1
```

It needs Python 3.11 to 3.13 (`winget install Python.Python.3.12`). It checks the download against `SHA256SUMS`, installs under `%LOCALAPPDATA%\skill-sentry-cli`, adds that folder to your user PATH, and runs setup. Add `-DryRun`, `-NoSetup`, or `-Uninstall` as needed. Open a new PowerShell window after installing.

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

Check the install with `skill-sentry-cli --version`. Expected: `SkillSentry 2.1.0rc1 - Fully local analysis · open weights` (the version number matches the release you installed).

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

The sandbox runs each skill's entrypoint in a container with no network access, a memory limit, and a time limit.

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

If you want a different model, set `ollama_model` in the `[model]` section of `skillsentry.toml` to the name you pulled (section 13).

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
| `FAIL model: cannot reach the model server at …` | Ollama is not running, or the address is wrong | Start Ollama, or fix `ollama_url` (section 13) |
| `FAIL model: … is not pulled; run: ollama pull …` | The configured model is missing | Run the command it prints |
| `PASS dashboard: built` | The dashboard is built | Nothing; otherwise run the dashboard build (section 3) |
| `PASS database: writable at …` | Scan history can be saved | Nothing |
| `WARN docker: engine not reachable …` | Full sandbox scans are not possible | Section 4 |
| `PASS sandbox image: … is present` | The sandbox image is built | Nothing |
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
SkillSentry 2.0.0 - Fully local analysis · open weights - backend: auto (local -> cloud -> unavailable)
[OK] pdf-summarizer - SAFE - risk 0 - confidence 0.75
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
| `[?] … UNSCANNED` | The verdict is shown, but the scan did not finish every check. See section 14 |
| `risk N` | 0 to 100; higher is worse |
| `confidence X` | How much of the pipeline contributed to the verdict |
| `(cached)` | The same skill, unchanged, was scanned before |

**What to do with each verdict**

| Verdict | Meaning | Action |
|:---|:---|:---|
| `SAFE` | Nothing suspicious was found | Install after a quick look at the report |
| `SUSPICIOUS` | Something needs a human look | Read every cited finding; ask the author if unclear |
| `MALICIOUS` | Hard evidence of hostile behaviour | Do not install |
| `UNSCANNED` | The scan is incomplete (model, sandbox, or a file was not read) | Fix the reason shown, then scan again; do not install meanwhile |
| `INVALID SKILL` | The SKILL.md is malformed (for example a missing `name:`). No behaviour was judged; the verdict is about the package format | Fix the frontmatter named in the line, then scan again. It still fails the CI gate |

Exit codes for scripts: `0` below the gate, `1` at or above it, `2` a usage error, `3` an operational error. See section 11.

---

## 8. Scan your own skills

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

Without an `entrypoint:`, SkillSentry reads the scripts but does not run them. The result is `UNSCANNED` until you declare one.

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
| `--fail-on malicious` | Exit `1` only for `MALICIOUS` (not recommended in CI; see section 11) |
| `--no-cache` | Ignore saved results and scan again |
| `--timeout 120` | Sandbox time limit in seconds (5 to 600; default 60) |
| `--no-sandbox` | Static analysis and the model only; the entrypoint is never run. Verdicts are weaker. |
| `-q` / `--quiet` | Print only the verdict line |

**Skills that are never run:** a skill with no `entrypoint:` is reported `UNSCANNED`. A skill whose SKILL.md or files cannot be read as text is reported with the reason; see the troubleshooting table.

---

## 9. Reports and stored scans

**Where the report is.** Every text scan ends with the command that writes its report. A plain `scan` prints the verdict in the terminal and stores the scan; it does not write a file. To write files in one run:

```bash
skill-sentry-cli scan path/to/skills --report-dir reports   # one .md per skill, plus summary.md
skill-sentry-cli scan path/to/skills --recursive            # also scan skills nested in a skill folder
```

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

## 10. The dashboard

```bash
skill-sentry-cli serve
```

Open <http://127.0.0.1:8000> in a browser. The server listens only on your own machine.

The dashboard has no login. Anyone who can reach the port can see your scans and start new ones, so keep the server on `127.0.0.1` and do not expose it to a network.

- `/` serves the dashboard page.
- `/health` reports whether Ollama, Docker and the database are ready (`"ok"` or `"down"`).
- `/scans` lists stored scans as JSON.

Use another port with `skill-sentry-cli serve --port 8080`. Stop the server with `Ctrl+C`.

If the port is taken, you see `address already in use`. Pick another port.

---

## 11. Use SkillSentry in CI

A CI runner needs Docker and a local model server to produce full verdicts. Hosted runners usually have neither, so a hosted run will report `UNSCANNED` unless you provide a model server. Plan for that before you rely on the gate.

The gate must fail when a skill is not fully scanned. Keep the default `--fail-on suspicious`: an `UNSCANNED` skill shows as `SUSPICIOUS`, which fails the gate. Do not use `--fail-on malicious` for this reason.

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

---

## 12. The offline demo

To see the output without Docker or a model:

```bash
skill-sentry-cli scan cloud-sync-pro --demo-mode
```

`--demo-mode` takes a skill **name** from the built-in demo set (`pdf-summarizer`, `git-helper`, `image-resizer`, `weather-fetch`, `cloud-sync-pro`, `invoice-helper`, `slack-notif-mal`). It does not scan a folder, and its results are canned, not real analysis. The banner says `demo`.

---

## 13. Configuration

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

## 14. Troubleshooting

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
| `UNSCANNED … sandbox … no declared entrypoint, so the scripts were not executed; declare 'entrypoint:' …` | The skill has scripts but no `entrypoint:` | Add `entrypoint:` to `SKILL.md` |
| `[?] … UNSCANNED` with a reason you do not understand | Anything not listed here | Read the report: `--format markdown --output …` |
| `[OK] … SAFE` with `LOW sandbox-exit: Skill exited with status 2` | The skill ran and exited with an error (for example, it needs an argument) | Expected for some skills; the finding is low risk |
| A scan is very slow | The first scan of a large skill, or the model is short of memory | Wait once; close other apps; cached rescans take under a second |
| A scan is killed with `sandbox timed out` | The entrypoint ran past `--timeout` | Raise `--timeout` (up to 600) if the skill is legitimately slow |

**Where to look when something is still wrong**

- The verdict's full reason: `skill-sentry-cli scan <path> --format json` (every stage and finding).
- Ollama: `curl http://localhost:11434/api/tags` should list the model.
- Docker: `docker ps` should print a table.
- The history database: `skill-sentry-cli cache list`.

---

## 15. Safety notes

- The malicious sample is test material. It only runs inside the sandbox through `skill-sentry-cli scan`. Do not copy its scripts out and run them.
- The sandbox has no route to the internet. A skill that tries to reach an outside host fails inside the sandbox and is reported as a finding.
- `--no-sandbox` never runs the entrypoint. Use it only when Docker is not available, and read the verdict as weaker evidence.
- Canary credentials planted in the sandbox are fake. They are never real secrets.
- Nothing leaves your machine unless you enable the cloud backend.

---

## 16. Command cheat sheet

```bash
skill-sentry-cli --version
skill-sentry-cli doctor
skill-sentry-cli init [--force]
skill-sentry-cli sandbox build
skill-sentry-cli scan <skill-or-folder> [--format text|json|markdown|sarif] [--output FILE] [--sarif-out FILE]
skill-sentry-cli scan <skill-or-folder> [--fail-on suspicious|malicious] [--no-cache] [--timeout N] [--no-sandbox] [-q]
skill-sentry-cli scan <skill-name> --demo-mode
skill-sentry-cli self-audit
skill-sentry-cli cache list [--limit N]
skill-sentry-cli cache stats
skill-sentry-cli cache clear [--older-than 7d]
skill-sentry-cli export <scan-id> [--format markdown|sarif|stix] [-o FILE]
skill-sentry-cli serve [--host 127.0.0.1] [--port 8000]
```

Full reference: [07-cli-reference.md](../reference/cli.md).
