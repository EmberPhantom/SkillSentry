# 17 · Release process (maintainers)

This is the runbook for publishing a version of SkillSentry. It has two parts: the steps only a maintainer with the accounts can do, and what the release workflow does once a tag is pushed.

**Names.** The Python distribution is `skill-sentry-cli`, the module is `skill_sentry_cli`, and the command is `skill-sentry-cli`. The product is still called SkillSentry. The sandbox image is published as `skillsentry-sandbox` and the server image as `skill-sentry-server`, both under `ghcr.io/emberphantom`.

## 1. One-time setup (maintainer)

Create the accounts and register the trusted publishers as described in [18-registry-accounts.md](18-registry-accounts.md). That manual covers both indexes, two-factor setup, the pending publisher values, and recovery.

In the repository settings, the following is also needed:

- **Environments:** `testpypi` (no protection rules) and `pypi` (required reviewer, so no one can publish alone).
- **Packages:** after the first image push, set `skillsentry-sandbox` and `skill-sentry-server` to public, so anyone can pull them.
- **Branch protection on `main`:** pull request reviews required, and the `CI` and `checks` jobs required before merge.

## 2. Cutting a pre-release (dry run)

```bash
# On main, after the change set is merged:
#   1. set __version__ in skill_sentry_cli/core/version.py to e.g. 2.0.0rc1
#   2. move the matching notes into docs/CHANGELOG.md under a new version heading
git tag v2.0.0rc1
git push origin v2.0.0rc1
```

The workflow then publishes to TestPyPI and creates a GitHub pre-release. Install it in a clean environment to check it:

```bash
python3.12 -m venv /tmp/rc-check && . /tmp/rc-check/bin/activate
python -m pip install --index-url https://test.pypi.org/simple/ \
  --extra-index-url https://pypi.org/simple/ skill-sentry-cli==2.0.0rc1
skill-sentry-cli --version
```

## 3. Final release

Only after the release candidate checks out:

```bash
git tag v2.0.0
git push origin v2.0.0
```

The `checks` and `build` jobs run. The `publish-pypi` job then waits for a reviewer to approve the `pypi` environment. Approve it only after you have checked the build's artifacts and the release notes. Once published, a version can never be re-uploaded, so a broken release gets a new version number.

## 4. What the workflow produces

| Artifact | Where it goes |
|:---|:---|
| `skill_sentry-<v>-py3-none-any.whl`, `skill_sentry-<v>.tar.gz` | PyPI (or TestPyPI for rc), GitHub release |
| `install.sh` | GitHub release |
| `SHA256SUMS` | GitHub release; `install.sh` verifies the wheel against it |
| Build provenance attestations | Attached to the wheel and sdist |
| Sandbox image, both architectures | `ghcr.io/emberphantom/skillsentry-sandbox:<v>`; its digest is written into the wheel |
| Server image, both architectures | `ghcr.io/emberphantom/skill-sentry-server:<v>` |

The sandbox digest is written into `skill_sentry_cli/data/sandbox_image.json` before the wheel is built. `skill-sentry-cli setup` pulls that exact digest, so an installed version uses the image it shipped with. Source checkouts have no digest and build the image locally.

## 5. Checks before tagging

```bash
python -m pip install -e ".[dev]"
ruff check skill_sentry_cli tests scripts && ruff format --check skill_sentry_cli tests scripts
pytest tests -q
scripts/build_release.sh      # dashboard, wheel, fresh-venv install
python scripts/check_wheel.py dist/*.whl
```

## 6. Limits

- The workflow itself runs only on GitHub. A real tag is the only full test of it.
- Windows is not a supported install target yet; the install script covers Linux and macOS only, and macOS has not been verified.
- Hardware for the ARM image is built in CI and not exercised here.
