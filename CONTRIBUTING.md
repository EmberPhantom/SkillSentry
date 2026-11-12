# Contributing to SkillSentry

Thanks for helping defend the agent skill supply chain! 🛡️ SkillSentry is MIT-licensed; by contributing you agree your contributions are licensed under the same terms.

**Start here:** [Developer Guide](docs/developer/getting-started.md) for environment setup, the module layout, coding standards, and extension guides. Participation is governed by the [Code of Conduct](.github/CODE_OF_CONDUCT.md). Questions and help: [SUPPORT.md](.github/SUPPORT.md). How decisions and releases are handled: [Governance](docs/operations/governance.md).

---

## Ground Rules

1. **The Verdict JSON Contract v1 is frozen.** Backward-compatible additions (new optional fields) only. Breaking changes need a `v2` with a migration path and maintainer sign-off. See [docs/reference/api.md](docs/reference/api.md) §5.5.
2. **Shared identifiers stay shared.** Stage names, WebSocket event names, and severity enums live in one constants module. Do not duplicate them as strings in the UI or the backend.
3. **No error path may produce `SAFE`.** A degraded scan must carry an explicit `*-unavailable` finding (the fail-safe rule).
4. **Fixtures are hazardous material.** Malicious fixtures run *only* through `skill-sentry-cli scan` (sandboxed). They use fictional C2 domains (`evil-collector.net`, `evil-c2.com`) and never contain real credentials. See the fixture safety rules in [docs/developer/testing.md](docs/developer/testing.md) §8.2.
5. **Fusion-weight, prompt, anchor, and masquerade changes must re-run the full fixture corpus** and update `tests/expected_verdicts.json` in the same pull request.
6. **Docs ship with behavior.** A user-visible change updates the relevant file in `docs/` in the same pull request.

## Development Workflow

```bash
git clone https://github.com/EmberPhantom/SkillSentry.git && cd SkillSentry
python3.12 -m venv .venv && source .venv/bin/activate
python -m pip install --require-hashes -r requirements-dev.txt
python -m pip install --no-deps -e .   # the lock file pins every dependency by hash
pre-commit install                      # optional: runs the lint hooks before each commit
skill-sentry-cli init                   # writes skillsentry.toml (not committed)
scripts/check.sh                        # lint, format, tests, schema drift, demo smoke
```

To change a dependency, edit `pyproject.toml` or the `.in` input files, then regenerate the locks with uv on Python 3.11 so the hashes cover every platform:

```bash
uv pip compile --universal --generate-hashes --python-version 3.11 --extra dev pyproject.toml requirements-bootstrap.in -o requirements-dev.txt
uv pip compile --universal --generate-hashes --python-version 3.11 pyproject.toml requirements-bootstrap.in -o requirements-runtime.txt
uv pip compile --universal --generate-hashes --python-version 3.11 requirements-tools.in requirements-bootstrap.in -o requirements-tools.txt
uv pip compile --universal --generate-hashes --python-version 3.11 skill_sentry_cli/core/sandbox/assets/requirements-sandbox.in -o skill_sentry_cli/core/sandbox/assets/requirements-sandbox.txt
```

Commit the regenerated files with the change. Leave the project's own entry out of the locks; it is installed with `--no-deps`.

**Dashboard (frontend):**

```bash
cd ui && npm ci && npm run dev
```

**Work without a model or Docker:** serve the canned demo store.

```bash
skill-sentry-cli serve --demo-mode --port 8000
```

- **Branches:** `feat/<topic>`, `fix/<topic>`, `docs/<topic>`, or `chore/<topic>`, off `main`.
- **Commits:** [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `docs:`, `test:`, `chore:`).
- **Style:**
  - Python: `ruff check` and `ruff format` (configured in `pyproject.toml`), type hints, Python 3.11 or newer.
  - TypeScript: `strict: true` in `ui/tsconfig.json`. No linter or formatter is configured for `ui/` yet; contributions that add one are welcome.
- **Gates:** CI and `scripts/check.sh` run ruff, mypy (blocking, with a short list of lenient modules in `pyproject.toml`), the unit and contract tests with a coverage floor of 86%, the schema check, and the demo smoke test.
- **Pull requests:** the checklist is in [.github/PULL_REQUEST_TEMPLATE.md](.github/PULL_REQUEST_TEMPLATE.md). Fill it in; it is applied to every pull request.

## Good First Contributions

| Area | Ideas |
|:---|:---|
| **Detection** | New AST anchor patterns (PowerShell, Node skills); new evasion-probe indicators; typosquat dictionary expansion |
| **Fixtures** | Benign and malicious fixtures, with hand-annotated ground-truth lines |
| **Canary intents** | New context-aware canary sets (for example npm, PyPI, or OpenAI-style keys). Guide: [docs/developer/getting-started.md](docs/developer/getting-started.md) §10.7 |
| **UI** | Empty, loading, and error state polish; accessibility passes (WCAG rules in [docs/developer/ui-design.md](docs/developer/ui-design.md) §6.6) |
| **Docs** | Tutorials, troubleshooting recipes, translations |
| **Reports** | SARIF rule-metadata enrichment; Markdown report theming |

Look for the `good first issue` label on the issue tracker.

## Maintainers and Decisions

The repository owner is the current maintainer. Review requests are assigned automatically through [.github/CODEOWNERS](.github/CODEOWNERS).

Changes to these need a maintainer decision before they are merged, not only a passing build:

- the Verdict JSON contract and its schemas in `schemas/`
- the fusion weights, tier thresholds, and the list of stages
- the sandbox hardening (`core/sandbox/`) and the network sinkhole
- the Poisoned Well canary formats

Module areas, for orientation:

| Area | Modules |
|:---|:---|
| Sandbox and deception | `core/sandbox/`, `core/poisoned_well/`, `core/evasion/` |
| Models and verdict | `core/models/`, `core/verdict/`, `core/semantic/`, `core/vision/` |
| Analysis and cache | `core/parser/`, `core/anchors/`, `core/cache/` |
| Server, CLI, and UI | `server/`, `cli.py`, `ui/` |

The archived build plan, which assigned work to three roles, is in [docs/internal/](docs/internal/README.md). It is history and no longer assigns ownership.

## Security Issues

**Do not open public issues for vulnerabilities.** Follow [SECURITY.md](SECURITY.md). Reports go through a private GitHub Security Advisory.

## Community IOC Feed (planned)

Contributing indicators to the community blocklist is **opt-in**, strips all skill content and user identifiers, and is governed by a signed-feed and dispute process ([docs/developer/security.md](docs/developer/security.md) §4.10). It is not implemented yet.

---

*Local analysis by default · open weights. Cloud analysis is opt-in and is labelled as such.*
