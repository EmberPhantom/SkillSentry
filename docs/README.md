# Documentation

SkillSentry audits agent skills before you install them. This index groups the documentation by who it is for. The [README](../README.md) gives the short version.

## For users

| Document | What it covers |
|:---|:---|
| [Overview](user/overview.md) | What SkillSentry does, what ships today, and what is planned. |
| [User guide](user/guide.md) | Installing, the first scans, reading verdicts, reports, the dashboard, CI use, and troubleshooting (section 14). |

## For reference

| Document | What it covers |
|:---|:---|
| [CLI reference](reference/cli.md) | Every command and option, exit codes, the configuration file, and environment variables. |
| [API reference](reference/api.md) | The HTTP and WebSocket endpoints, the verdict format, and the report formats. |

## For developers

| Document | What it covers |
|:---|:---|
| [Developer setup](developer/getting-started.md) | Setting up a checkout, the local gate, the repository layout, and how to extend the code. |
| [Architecture](developer/architecture.md) | The pipeline, the components, the technology stack, and the model backends. |
| [Security model](developer/security.md) | The threat model, the sandbox, the trust boundaries, and known limitations. |
| [Database](developer/database.md) | The local SQLite schema, caching, and the planned team-server variant. |
| [Testing and evaluation](developer/testing.md) | The gates a change must pass, CI jobs, and the evaluation targets. |
| [Dashboard design](developer/ui-design.md) | The dashboard's screens, its design rules, and planned work. |

## For operators and maintainers

| Document | What it covers |
|:---|:---|
| [Deployment](operations/deployment.md) | Installing and running SkillSentry, container use, and a checklist before you rely on it. |
| [Release process](operations/release-process.md) | Cutting a release, the release workflow, and verifying a release. |
| [Registry accounts](operations/registry-accounts.md) | The PyPI and TestPyPI accounts and trusted publishing. |
| [Governance](operations/governance.md) | Roles, decisions, release authority, the support policy, and the repository settings checklist. |
| [Changelog](CHANGELOG.md) | Version history, and the policy for writing entries. |

## Archive

[docs/internal](internal/README.md) holds the planning material from the original build and the landing-page brief. These are records, not current documentation.

## Related files

| File | Purpose |
|:---|:---|
| [README](../README.md) | The short introduction and quick start. |
| [CONTRIBUTING](../CONTRIBUTING.md) | How to contribute. |
| [SECURITY](../SECURITY.md) | How to report a vulnerability. |
| [LICENSE](../LICENSE) | MIT. |

*Local analysis by default · open weights. Cloud analysis is opt-in and is labelled as such.*
