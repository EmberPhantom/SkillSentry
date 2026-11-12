<div align="center">

# SkillSentry

**Audit agent skills before you install them. Locally, in a sandbox, with evidence.**

![License: MIT](https://img.shields.io/badge/license-MIT-emerald) ![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue) ![Docker](https://img.shields.io/badge/sandbox-Docker-2496ED?logo=docker&logoColor=white)

[![CI](https://github.com/EmberPhantom/SkillSentry/actions/workflows/ci.yml/badge.svg)](https://github.com/EmberPhantom/SkillSentry/actions/workflows/ci.yml) [![CodeQL](https://github.com/EmberPhantom/SkillSentry/actions/workflows/codeql.yml/badge.svg)](https://github.com/EmberPhantom/SkillSentry/actions/workflows/codeql.yml) [![Release](https://github.com/EmberPhantom/SkillSentry/actions/workflows/release.yml/badge.svg)](https://github.com/EmberPhantom/SkillSentry/actions/workflows/release.yml) [![PyPI](https://img.shields.io/pypi/v/skill-sentry-cli)](https://pypi.org/project/skill-sentry-cli/) [![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/EmberPhantom/SkillSentry/badge)](https://securityscorecards.dev/viewer/?uri=github.com/EmberPhantom/SkillSentry)

</div>

---

Agent skills are folders of instructions and scripts that an AI agent reads and runs. A skill can hide a credential stealer, or an instruction that overrides the agent. SkillSentry checks a skill before you install it:

- It validates `SKILL.md`, and flags names that look like typosquats of known skills.
- It runs the skill's entrypoint in a sandbox with a memory limit and a time limit. The sandbox has no route to the internet: its DNS and HTTP requests go to a local sinkhole that answers with fake responses and records them.
- It plants decoy credentials in the sandbox. If one shows up in outbound traffic, the skill has proven it tried to steal it, and the decoy's destination is recorded as an indicator.
- A local model reads the text and judges whether it matches what the code does. Deterministic checks are the ground truth, and the model cannot override them.
- It returns one verdict: `SAFE`, `SUSPICIOUS`, `MALICIOUS`, or `UNSCANNED` when a check could not run. Every finding cites a file and line.

Your skills stay on your machine. The cloud model backend is opt-in and off by default.

## Quick start

```bash
pipx install skill-sentry-cli     # or: sh install.sh from the latest release
skill-sentry-cli setup            # guided; asks before each download or build
skill-sentry-cli doctor           # what is ready, and what is missing
skill-sentry-cli scan path/to/skill
skill-sentry-cli serve            # dashboard at http://127.0.0.1:8000
```

No Docker or model? Try the offline demo:

```bash
skill-sentry-cli scan cloud-sync-pro --demo-mode
```

The [user guide](docs/user/guide.md) walks through installation, the first scans, reading verdicts, reports, and CI use. The [CLI reference](docs/reference/cli.md) lists every command and option.

## Install

| Method | Use |
|:---|:---|
| `pipx install skill-sentry-cli` | Developers. Published on PyPI. |
| Install script (`install.sh`, `install.ps1`) | Checksum-verified installs from a release. If `gh` is installed, the wheel's build provenance is checked too. `SKILLSENTRY_VERIFY_PROVENANCE=1` makes that check required. |
| Server image `ghcr.io/emberphantom/skill-sentry-server` | Running the dashboard and API in a container. Publish the port on `127.0.0.1` only. |
| Source checkout | Contributors. See the [developer setup](docs/developer/getting-started.md). |

Requirements: Python 3.11 to 3.13. Docker, for sandboxed scans. A local model server (Ollama), with the model that `doctor` names. macOS and native Windows are best-effort; see the [support policy](docs/operations/governance.md#204-support-policy).

## Verdicts

| Verdict | Meaning |
|:---|:---|
| `SAFE` | No suspicious behaviour was found. |
| `SUSPICIOUS` | Read each cited finding before you decide. |
| `MALICIOUS` | Hard evidence of hostile behaviour. Do not install. |
| `UNSCANNED` | A check could not finish, such as the sandbox or the model being unavailable. Fix the reason and scan again. |
| `INVALID SKILL` | `SKILL.md` is malformed. This is a packaging problem, not a malware finding. |

Exit codes: `0` below the gate, `1` at or above it, `2` a usage error, `3` an operational error. CI uses the exit code.

## Documentation

| For | Start here |
|:---|:---|
| Using SkillSentry | [User guide](docs/user/guide.md) · [Overview](docs/user/overview.md) |
| Commands, configuration, and exit codes | [CLI reference](docs/reference/cli.md) |
| The HTTP API and report formats | [API reference](docs/reference/api.md) |
| How it works inside | [Architecture](docs/developer/architecture.md) · [Security model](docs/developer/security.md) |
| Contributing | [Developer setup](docs/developer/getting-started.md) · [CONTRIBUTING.md](CONTRIBUTING.md) |
| Running it for a team | [Deployment](docs/operations/deployment.md) · [Governance](docs/operations/governance.md) |
| Releases | [Release process](docs/operations/release-process.md) · [Changelog](docs/CHANGELOG.md) |

Every published release can be checked with the commands in [verify a release](docs/operations/release-process.md#verify-a-release): the images are signed, and the wheel has a build attestation.

## Planned, not available

These are proposals. Do not build on them yet.

- A GitHub Action for pull request gates.
- A `--watch` mode for scans.
- Uploading SARIF from the CLI.
- An MCP proxy that enforces policy while an agent runs.
- Signed verdicts, and an opt-in community indicator feed.
- A team server with authentication.

## Security

The API has no authentication, so it is meant for loopback use only. Read the [security model](docs/developer/security.md), including its known limitations, before you run SkillSentry on anything that matters. To report a vulnerability, follow [SECURITY.md](SECURITY.md). Do not open a public issue.

## Contributing

Contributions are welcome. Start with [CONTRIBUTING.md](CONTRIBUTING.md). Participation is covered by the [Code of Conduct](.github/CODE_OF_CONDUCT.md), and questions go to the [support guide](.github/SUPPORT.md).

## License

MIT. See [LICENSE](LICENSE).
