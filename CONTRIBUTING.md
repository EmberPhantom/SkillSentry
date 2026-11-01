# Contributing to SkillSentry

Thanks for helping defend the agent skill supply chain! 🛡️ SkillSentry is MIT-licensed; by contributing you agree your contributions are licensed under the same terms.

**Start here:** [Developer Guide](docs/10-developer-guide.md) — environment setup, module ownership, coding standards, and extension guides.

---

## Ground Rules

1. **The Verdict JSON Contract v1 is frozen.** Backward-compatible additions (new optional fields) only; breaking changes require a `v2` + migration path and sign-off from all maintainers. See [docs/05-api-reference.md](docs/05-api-reference.md) §5.5.
2. **Shared identifiers stay shared.** Stage names, WS event names, and severity enums live in one constants module — no stringly-typed duplicates in UI or backend.
3. **No error path may produce `SAFE`.** Any degraded scan must carry explicit `*-unavailable` findings (fail-safe rule).
4. **Fixtures are hazardous material.** Malicious fixtures run *only* through `skill-sentry-cli scan` (sandboxed), use fictional C2 domains (`evil-collector.net`, `evil-c2.com`), and never reference real credentials. See fixture safety rules in [docs/08-testing-and-evaluation.md](docs/08-testing-and-evaluation.md) §8.2.
5. **Fusion-weight / prompt / anchor / masquerade changes must re-run the full fixture corpus** and update `tests/expected_verdicts.json` in the same PR.
6. **Docs ship with behavior.** Public-facing changes update the relevant `docs/` file in the same PR.

## Development Workflow

```bash
git clone https://github.com/<org>/skillsentry && cd skillsentry
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
skill-sentry-cli init
# frontend:
cd ui && npm install && npm run dev
# no backend yet? build against the mock server:
python -m skill_sentry_cli.server.demo_mode --port 8000
```

- **Branches:** `feat/<topic>`, `fix/<topic>`, `docs/<topic>` off `main`.
- **Commits:** [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `docs:`, `test:`, `chore:`).
- **Style:** Python — `ruff check` + `ruff format`, type hints, 3.11+ · TypeScript — `strict: true`, ESLint + Prettier.
- **PR checklist:**
  - [ ] Unit tests for new logic; contract tests pass against **both** real API and mock server
  - [ ] Fixture regression green (`pytest tests/` + `tests/check_expected_verdicts.py`)
  - [ ] No new dependencies without rationale (minimal-dep principle; pinned lockfile)
  - [ ] Docs updated (or `docs:` follow-up issue linked)
  - [ ] No secrets, no real credential formats in tests/fixtures

## Good First Contributions

| Area | Ideas |
|:---|:---|
| **Detection** | New AST anchor patterns (PowerShell, Node skills); new evasion-probe indicators; typosquat dictionary expansion |
| **Fixtures** | Add benign/malicious fixtures toward the 20-skill Phase-1 corpus (with hand-annotated ground-truth lines) |
| **Canary intents** | New context-aware canary sets (e.g., npm, PyPI, OpenAI keys) — guide: [docs/10-developer-guide.md](docs/10-developer-guide.md) §10.7 |
| **UI** | Empty/loading/error state polish; accessibility passes (WCAG rules in [docs/06-ui-ux.md](docs/06-ui-ux.md) §6.6) |
| **Docs** | Tutorials, troubleshooting recipes, translations |
| **Reports** | SARIF rule-metadata enrichment; Markdown report theming |

## Ownership Map (core team)

Authoritative assignment: **[docs/11-team-and-workload.md](docs/11-team-and-workload.md)**.

| Area | Owner | Modules |
|:---|:---|:---|
| Sandbox, deception, models, verdict/reports, server | Dev 1 · Backend + AI Integration | `core/sandbox/`, `core/poisoned_well/`, `core/evasion/`, `core/models/`, `core/verdict/`, `server/`, `cli.py` |
| Malicious-instruction analysis | Dev 2 · Backend (Skill Analysis) | `core/parser/`, `core/semantic/`, `core/vision/`, `core/cache/`, analysis + benign fixtures |
| UI + demo assets | Dev 3 · Frontend | `ui/`, README GIF, backup demo video |

Cross-cutting changes (schemas, weights, stage list) need sign-off from all three owners.

## Security Issues

**Do not open public issues for vulnerabilities.** Follow [SECURITY.md](SECURITY.md) (private GitHub Security Advisory, 90-day embargo, safe harbor for good-faith research).

## Community IOC Feed (Phase 2)

Contributing indicators to the community blocklist is **opt-in**, strips all skill content/user identifiers, and is governed by a signed-feed + dispute process ([docs/04-security.md](docs/04-security.md) §4.10).

---

*Powered by Gemma 4 · open weights.*
