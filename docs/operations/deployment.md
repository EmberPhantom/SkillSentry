# Deployment

How to run SkillSentry today: on a developer machine, as a container, and what to check before running it anywhere people depend on it. Features that are planned rather than shipped are listed at the end and labelled as such.

## 1. Ways to install

| Method | For | Command | Status |
|:---|:---|:---|:---|
| pipx or pip | Developers, local use | `pipx install skill-sentry-cli` | Published on PyPI (2.1.0). |
| Install script | Linux, macOS, WSL | `sh install.sh` from the latest release | Checksum-verified against `SHA256SUMS`. Also runs `gh attestation verify` when `gh` is installed; `SKILLSENTRY_VERIFY_PROVENANCE=1` makes it required. |
| Windows installer | Windows | `powershell -ExecutionPolicy Bypass -File install.ps1` | Included with the release. Not yet verified on real machines. |
| Server image | Running the dashboard and API in a container | `ghcr.io/emberphantom/skill-sentry-server:<version>` | Published, signed, and public. |
| Source | Contributors | `python -m pip install -e ".[dev]"` | See [developer setup](../developer/getting-started.md). |

Check any installation with `skill-sentry-cli --version` and then `skill-sentry-cli doctor`.

## 2. Local machine

**Requirements**

- Python 3.11, 3.12, or 3.13.
- Docker, usable without sudo, for sandboxed scans.
- A local model server (Ollama) with the configured model pulled. Set-up is guided by `skill-sentry-cli setup`.
- About 8 GB of RAM while a scan runs, and disk space for the model.

**First run**

```bash
skill-sentry-cli setup           # guided; asks before each download or build
skill-sentry-cli doctor          # checks: model, dashboard, database, Docker, sandbox image
skill-sentry-cli scan ./my-skill
skill-sentry-cli serve           # dashboard at http://127.0.0.1:8000
```

The full walkthrough is in the [user guide](../user/guide.md).

**Performance**

- An uncached scan is a target of under 90 seconds per skill on a typical laptop. Measure your own machine; the number depends heavily on the model and the hardware.
- A cached re-scan of an unchanged skill is a target of under 2 seconds.
- Images sent to the model are downscaled. The default is 768 pixels on the longest side, set by `image_max_px`.

## 3. Container

The server image runs the dashboard and API. It does not include Docker, so sandboxed scans are unavailable inside it by default.

```bash
docker run -d --name skillsentry \
  -p 127.0.0.1:8000:8000 \
  -v skillsentry-data:/home/skillsentry/.skillsentry \
  ghcr.io/emberphantom/skill-sentry-server:<version>
```

- **Publish the port on loopback only.** The API has no authentication. The container listens on all interfaces inside its own network, so the `127.0.0.1:` prefix is what keeps it local.
- **Reaching it from another machine.** The server refuses requests whose `Host` is not loopback or its bind address (`400 untrusted_host`). If you publish the port on a LAN address and open the dashboard by that address or a LAN name, add it with `-e SKILLSENTRY_ALLOWED_HOSTS=<name or address>`. Publishing on a LAN address exposes the unauthenticated API to that network, so do it only on a network you trust.
- **The data volume keeps the scan history.** Without it, history is lost when the container is removed.
- **The Docker socket is not mounted by default.** Mounting `/var/run/docker.sock` lets the container control the host's Docker engine, which is root-equivalent on the host. Only do it deliberately, on a machine you control.
- **Health.** The image has a healthcheck on the `/meta` endpoint. Check it with `docker inspect --format '{{.State.Health.Status}}' skillsentry`.
- **The model server is separate.** The container cannot reach a model on your host unless you configure `ollama_url` (or `OLLAMA_HOST`) to an address it can reach. Without a model, scans return `UNSCANNED`.

## 4. Before you rely on it

Work through this list for any machine that people depend on.

- [ ] **Keep the API on loopback.** There is no authentication. If you need remote access, put it behind a reverse proxy that enforces authentication, and do not expose the port directly.
- [ ] **Pin the image to a version tag,** and verify its signature before you run it (see below).
- [ ] **Confirm the sandbox works.** `skill-sentry-cli doctor` should report the Docker engine and the sandbox image as present. Without them, scans degrade and say so.
- [ ] **Set resource limits.** The sandbox limits memory, CPU, and run time by default. Check that `[sandbox]` in the configuration matches your machine.
- [ ] **Back up the database.** It holds the scan history. Copy `~/.skillsentry/skillsentry.db` while the server is stopped, or use SQLite's backup command.
- [ ] **Re-scan after an upgrade.** A new version changes the scoring fingerprint, so old cached results are not reused, and skills are scanned again on demand.
- [ ] **Pin and test the model.** Verdicts depend on the model. Note the model you use, and re-run the fixture regression before you change it.
- [ ] **Know the limits.** Read the [security model](../developer/security.md), especially section 4.11.

### Verify what you installed

```bash
cosign verify ghcr.io/emberphantom/skill-sentry-server:<version> \
  --certificate-identity-regexp '^https://github.com/EmberPhantom/SkillSentry/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

The release page also lists an SBOM (`sbom.cdx.json`) of the wheel's dependencies. The full verification is in [release process](release-process.md#verify-a-release).

## 5. Operations

| Task | How |
|:---|:---|
| Upgrade | Install the new version, then run `skill-sentry-cli doctor`. The cache is keyed to the scoring version, so results from an older version are not reused. |
| Stuck sandbox run | The sandbox stops a run at its time limit. To find leftovers, use `docker ps -a`, and remove them with `docker rm -f <container>`. |
| Disputed verdict | Re-scan with `--no-cache`. Keep the report (`--format sarif --output`) and open an issue with it attached. Do not paste real credentials or private skill contents. |
| Suspected real command-and-control | Export the indicators with `skill-sentry-cli export <scan-id> --format stix -o indicators.json`, and pass them to your security team. |

If you use the cloud model backend, a scan sends the skill's content to the cloud provider. Do not use it for private skills unless that is acceptable to you.

## 6. Planned, not available

These are design proposals. Nothing in this section ships today.

- **GitHub Action** for pull request gates, SARIF upload to code scanning, and scheduled re-scans of a registry. Until it exists, call the CLI from your workflow. See the [user guide](../user/guide.md) section on CI.
- **Team server** with shared storage and authentication. See the proposal in the [database design](../developer/database.md).
- **Runtime interception** through an MCP proxy, which would enforce policy while an agent runs.
- **Signed verdicts** with `cosign verify-blob`.
- **Community indicator feed**, opt-in.
- **Structured logs and OpenTelemetry metrics.** The metric names are a proposal only.
