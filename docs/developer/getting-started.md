# Developer setup and workflow

This page gets a contributor from a fresh clone to a passing local gate, and explains how the repository is organised. For the contribution rules, read [CONTRIBUTING.md](../../CONTRIBUTING.md).

## 1. Prerequisites

| Tool | Needed for | Check |
|:---|:---|:---|
| Python 3.11, 3.12, or 3.13 | Everything | `python3.12 --version` |
| Git | Everything | `git --version` |
| Node.js 24 | The dashboard (`ui/`) | `node --version` |
| Docker, usable without sudo | Full sandboxed scans, and the Docker-backed tests | `docker ps` |
| Ollama with the configured local model | Model-backed scans and `tests/live` | `ollama list` |

Python 3.14 is not supported yet. CI runs the unit tests on it as a non-blocking check.

## 2. Clone and install

```bash
git clone https://github.com/EmberPhantom/SkillSentry.git && cd SkillSentry
python3.12 -m venv .venv && . .venv/bin/activate
python -m pip install --require-hashes -r requirements-dev.txt
python -m pip install --no-deps --no-build-isolation -e .   # the lock file pins every dependency by hash
pre-commit install            # optional: lint hooks before each commit
```

The `dev` extra installs the test, lint, and type-check tools: pytest, ruff, mypy, and coverage.

Build the dashboard once, so the server can serve it:

```bash
cd ui && npm ci && npm run build && cd ..
```

Create a configuration file in your working copy. It is not committed:

```bash
skill-sentry-cli init
```

Check what your machine can do:

```bash
skill-sentry-cli doctor
```

## 3. The local gate

Run this before you push. It is the same gate CI runs.

```bash
scripts/check.sh
```

It runs, in order: ruff lint, ruff format check, mypy, the unit and contract tests with a coverage floor of 86%, the schema drift check, and the demo smoke test. It prints `ALL CHECKS PASSED` on success.

Individual steps:

```bash
ruff check skill_sentry_cli tests scripts
ruff format --check skill_sentry_cli tests scripts
mypy
pytest tests/unit tests/contract -q --cov=skill_sentry_cli
python scripts/export_schema.py && git diff --exit-code -- schemas/
```

The live tests need a running local model server. They are skipped unless you run them on purpose:

```bash
pytest tests/live
```

## 4. Repository layout

| Path | Contents |
|:---|:---|
| `skill_sentry_cli/` | The Python package. |
| `skill_sentry_cli/cli.py` | The `skill-sentry-cli` command. |
| `skill_sentry_cli/core/` | Analysis engine, parsers, anchors, semantic and vision analysis, sandbox, Poisoned Well, evasion detection, model clients, verdict fusion, reports, cache, configuration. |
| `skill_sentry_cli/server/` | FastAPI server, REST and WebSocket routes, and the demo backend. |
| `skill_sentry_cli/skill/` | The Agent Skill that ships with SkillSentry (`self-audit`). |
| `skill_sentry_cli/rules/` | Credential rules as data. |
| `skill_sentry_cli/data/` | Packaged data: the typosquat name list and the pinned sandbox image record. |
| `ui/` | The React and TypeScript dashboard. |
| `schemas/` | JSON Schemas of the public contracts. They are generated, and CI fails if they drift. |
| `tests/unit/` | Unit tests, one module per area. |
| `tests/contract/` | Tests that the API, CLI, and reports match the contracts. |
| `tests/live/` | Tests that need a live model server. |
| `tests/expected_verdicts.json` | The expected verdict for each fixture. |
| `fixtures/` | Sample skills: benign, malicious, and a stretch case. Read [fixtures/README.md](../../fixtures/README.md) before you touch them. |
| `scripts/` | Local gate, release build, schema export, demo smoke test, and evaluation helpers. |
| `packaging/` | The PyPI long description. |
| `docs/` | This documentation. See the [index](../README.md). |

## 5. How a change moves through the code

- **Analysis stages** live in `skill_sentry_cli/core/`. Each stage returns a result that the engine collects. A degraded stage must say so; it may not return a clean result.
- **Verdict fusion** is in `core/verdict/`. Changing a weight, a threshold, or the list of stages changes scores for every skill. Such a change needs a full fixture run and an update to `tests/expected_verdicts.json` in the same pull request.
- **Contracts** are the JSON shapes that other programs depend on: the verdict, the API, and the report formats. They are versioned, and the schemas in `schemas/` are generated from the code. Regenerate them with `python scripts/export_schema.py` and commit the result.
- **The CLI and the server** share the same engine. The CLI's help text and its exit codes are tested against [the CLI reference](../reference/cli.md).

## 6. Extending SkillSentry

### A new anchor (deterministic check)

Add the rule where the other anchors live in `skill_sentry_cli/core/anchors/`. Add a fixture that triggers it and a unit test that checks the finding and its line number. Run the fixture regression.

### A new canary intent

Decoy credentials are generated per scan in `skill_sentry_cli/core/poisoned_well/canary_gen.py`, and every value carries a `SKS-<8 hex>` marker. Add the new intent there, and add a test that the marker is planted and that the exfiltration tracker in `exfil_tracker.py` detects it.

### A new fixture

Put it under `fixtures/benign/` or `fixtures/malicious/`. Malicious fixtures use only fictional domains (`evil-collector.net`, `evil-c2.com`) and fake credentials. Record the expected verdict in `tests/expected_verdicts.json`.

### A new report format

Add a writer in `core/verdict/`, route it from `render_report` in `core/reports.py`, and validate its output against the official schema in a contract test, as the SARIF tests do.

## 7. Working with the dashboard

```bash
cd ui && npm run dev          # Vite development server
cd ui && npm run build        # type check and production build
skill-sentry-cli serve --demo-mode --port 8000
```

The demo mode serves seven canned skills, so you can work on the interface without Docker or a model.

## 8. Branches, commits, and pull requests

- Branch names: `feat/<topic>`, `fix/<topic>`, `docs/<topic>`, or `chore/<topic>`, from `main`.
- Commit messages: [Conventional Commits](https://www.conventionalcommits.org/).
- Pull requests: the checklist is in the [pull request template](../../.github/PULL_REQUEST_TEMPLATE.md). `main` requires the CI checks and a code-owner review. See [governance](../operations/governance.md) for who decides what.

## 9. Known gaps

- The sandbox does not trace system calls. A skill that does nothing observable within its time limit can pass. See [security](security.md) §4.11.
- The API has no authentication. It is meant for loopback use only.
- Strict type checking is not enforced in a few modules, which are listed in `pyproject.toml`.
