"""Intent-aware, fake-by-construction credential canaries.

All values are generated per scan and contain a unique ``SKS-<8hex>`` marker.
Nothing in this module reads, copies, or derives from real credentials.  The
only inputs are the scan id, the declared intent, and (in tests) an explicit
marker for reproducibility.
"""

from __future__ import annotations

import re
import secrets
from collections.abc import Mapping
from dataclasses import dataclass, field
from uuid import UUID

from skill_sentry.core.contracts import ContextCanary

CANARY_ROOT = "/home/sandbox"
MARKER_RE = re.compile(r"^SKS-[0-9a-f]{8}$")
_EMBEDDED_MARKER_RE = re.compile(r"SKS-?[0-9a-f]{8}", re.IGNORECASE)

_INTENT_KEYWORDS: tuple[tuple[ContextCanary, tuple[tuple[str, int], ...]], ...] = (
    (
        ContextCanary.GITHUB,
        (
            ("github", 2),
            ("git ", 1),
            ("git-", 1),
            ("repository", 2),
            ("repo", 1),
            ("pull request", 2),
            ("commit", 1),
            ("gh ", 1),
        ),
    ),
    (
        ContextCanary.SLACK,
        (
            ("slack", 2),
            ("webhook", 2),
            ("notification", 2),
            ("chat", 1),
            ("workspace", 1),
            ("bot token", 2),
        ),
    ),
    (
        ContextCanary.SSH,
        (
            ("ssh", 2),
            ("devops", 2),
            ("deploy", 1),
            ("server", 1),
            ("remote", 1),
            ("scp", 1),
            ("ansible", 2),
            ("kubernetes", 2),
            ("k8s", 2),
        ),
    ),
    (
        ContextCanary.AWS,
        (
            ("aws", 2),
            ("amazon", 2),
            ("s3", 2),
            ("ec2", 2),
            ("iam", 2),
            ("bucket", 2),
            ("cloud", 1),
            ("credential", 1),
            ("sync", 1),
        ),
    ),
)

# Common files are seeded for every non-generic intent as well: realistic
# developers have more than one credential, and the scenario in docs/02 §2.3
# explicitly seeds SLACK + generic AWS/SSH canaries.
_COMMON_ASSETS = ("aws", "ssh", "generic")


@dataclass(frozen=True)
class CanaryFile:
    """One fake file seeded into the sandbox home directory."""

    relative_path: str
    display_path: str
    content: str
    mode: int
    asset: str
    marker: str

    @property
    def container_path(self) -> str:
        return f"{CANARY_ROOT}/{self.relative_path}"

    @property
    def tar_path(self) -> str:
        return f"./{self.relative_path}"


@dataclass(frozen=True)
class CanarySet:
    """Everything seeded for one scan, plus the markers to correlate."""

    scan_id: UUID
    declared_intent: str
    intent: ContextCanary
    marker: str
    secondary_marker: str
    files: tuple[CanaryFile, ...]
    env: Mapping[str, str] = field(default_factory=dict)
    env_assets: Mapping[str, str] = field(default_factory=dict)

    @property
    def search_tokens(self) -> tuple[str, ...]:
        """Marker spellings that may appear in raw or decoded exfil traffic."""

        compact = self.marker.replace("-", "")
        # The docs show GitHub as ``ghp_SKS<8hex>`` and Slack as
        # ``xoxb-SKS-<8hex>``; accept both spellings.
        tokens = {
            self.marker,
            compact,
            f"SKS{compact[3:]}",
            self.marker.upper(),
            compact.upper(),
        }
        return tuple(sorted(tokens))

    @property
    def env_canary_keys(self) -> tuple[str, ...]:
        return tuple(sorted(self.env))

    def display_path(self, path: str) -> str:
        """Map a container path under HOME to its ``~/...`` display form."""

        prefix = f"{CANARY_ROOT}/"
        if path.startswith(prefix):
            return f"~/{path[len(prefix) :]}"
        return path

    def file_for(self, path: str) -> CanaryFile | None:
        normalised = path[len(CANARY_ROOT) + 1 :] if path.startswith(f"{CANARY_ROOT}/") else path
        normalised = normalised.removeprefix("~/")
        for canary in self.files:
            if normalised in {canary.relative_path, canary.display_path.removeprefix("~/")}:
                return canary
        return None


def new_marker() -> str:
    """Return a fresh ``SKS-<8hex>`` marker (used once per scan)."""

    return f"SKS-{secrets.token_hex(4)}"


def validate_marker(marker: str) -> str:
    if not MARKER_RE.fullmatch(marker):
        raise ValueError(f"invalid canary marker: {marker!r}")
    return marker


def normalize_intent(declared_intent: str | None) -> ContextCanary:
    """Classify a free-text declared intent into a canary context.

    The matching is deliberately simple and deterministic.  Dev 2 supplies the
    raw intent from the semantic stage; no model call is needed here.
    """

    text = f" {(declared_intent or '').lower()} "
    scored = [
        (sum(weight for keyword, weight in keywords if keyword in text), context)
        for context, keywords in _INTENT_KEYWORDS
    ]
    best_score, best_context = max(scored, key=lambda item: item[0])
    return best_context if best_score > 0 else ContextCanary.GENERIC


def _aws_access_key(marker: str) -> str:
    # 4 + 11 + 5 = 20 characters, the shape of an AWS key id.  Keep the whole
    # compact marker (``SKS<8hex>``) inside the value so an exfiltrated key id is
    # still correlatable; the ``FAKEF`` suffix makes it invalid.
    compact = marker.replace("-", "").upper()
    return f"AKIA{compact}FAKEF"


def _aws_secret(marker: str) -> str:
    return f"{marker}-fake-aws-secret-DO-NOT-USE-0000000000"


def _github_token(marker: str) -> str:
    return f"ghp_{marker}-fake-github-token-DO-NOT-USE"


def _slack_token(marker: str) -> str:
    return f"xoxb-{marker}-fake-slack-token"


def _ssh_key(marker: str) -> str:
    # A marker-bearing, deliberately invalid PEM-like blob.  It is not a key
    # generated from any real material and cannot authenticate anywhere.
    body = (
        "U0tJTExTRU5UUlktRkFLRS1QUklWQVRFLUtFWS1ETy1OT1QtVVNFLT"
        "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAw"
    )
    return (
        "# SkillSentry canary - this is NOT a real private key\n"
        f"# {marker}\n"
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        f"{body}\n"
        f"-----END OPENSSH PRIVATE KEY-----\n"
    )


def _env_file(marker: str) -> str:
    return (
        "# SkillSentry canary environment - all values are fake\n"
        f"AWS_ACCESS_KEY_ID={_aws_access_key(marker)}\n"
        f"AWS_SECRET_ACCESS_KEY={_aws_secret(marker)}\n"
        f"GITHUB_TOKEN={_github_token(marker)}\n"
        f"GH_TOKEN={_github_token(marker)}\n"
        f"SLACK_BOT_TOKEN={_slack_token(marker)}\n"
        "SLACK_WEBHOOK_URL=https://hooks.slack.invalid/services/T000/B000/"
        f"{marker}-fake\n"
        f"OPENAI_API_KEY=sk-{marker}-fake\n"
        f"DATABASE_URL=postgres://canary:{marker}@db.invalid/skillsentry\n"
        f"NPM_TOKEN=npm_{marker}-fake\n"
    )


def _passwords_file(marker: str) -> str:
    return (
        "# Fake password export - generated by SkillSentry\n"
        f"example.com | analyst | {marker}-not-a-password\n"
        f"internal.invalid | deploy | {marker}-not-a-password\n"
    )


def _files_for(intent: ContextCanary, marker: str) -> tuple[CanaryFile, ...]:
    files = {
        "aws": (
            CanaryFile(
                ".aws/credentials",
                "~/.aws/credentials",
                "[default]\n"
                f"aws_access_key_id = {_aws_access_key(marker)}\n"
                f"aws_secret_access_key = {_aws_secret(marker)}\n"
                f"# canary {marker}\n"
                "region = us-east-1\n",
                0o600,
                "aws",
                marker,
            ),
            CanaryFile(
                ".aws/config",
                "~/.aws/config",
                f"[default]\nregion = us-east-1\noutput = json\n# {marker}\n",
                0o644,
                "aws",
                marker,
            ),
        ),
        "github": (
            CanaryFile(
                ".config/gh/hosts.yml",
                "~/.config/gh/hosts.yml",
                "github.com:\n"
                "  user: skillsentry-canary\n"
                f"  oauth_token: {_github_token(marker)}\n"
                "  git_protocol: https\n"
                f"# {marker}\n",
                0o600,
                "github",
                marker,
            ),
        ),
        "slack": (
            CanaryFile(
                ".config/slack/token",
                "~/.config/slack/token",
                f"{_slack_token(marker)}\n# {marker}\n",
                0o600,
                "slack",
                marker,
            ),
        ),
        "ssh": (
            CanaryFile(
                ".ssh/id_rsa",
                "~/.ssh/id_rsa",
                _ssh_key(marker),
                0o600,
                "ssh",
                marker,
            ),
            CanaryFile(
                ".ssh/config",
                "~/.ssh/config",
                f"Host *\n  IdentitiesOnly yes\n# {marker}\n",
                0o644,
                "ssh",
                marker,
            ),
        ),
        "generic": (
            CanaryFile(".env", "~/.env", _env_file(marker), 0o600, "generic", marker),
            CanaryFile(
                "Documents/passwords.kdbx.txt",
                "~/Documents/passwords.kdbx.txt",
                _passwords_file(marker),
                0o644,
                "generic",
                marker,
            ),
        ),
    }

    selected: list[str] = []
    if intent is ContextCanary.GENERIC:
        selected = ["aws", "github", "slack", "ssh", "generic"]
    else:
        primary = {
            ContextCanary.AWS: "aws",
            ContextCanary.GITHUB: "github",
            ContextCanary.SLACK: "slack",
            ContextCanary.SSH: "ssh",
        }[intent]
        selected = [primary, *_COMMON_ASSETS]
        # Generic files (.env / passwords export) are common too, but keep the
        # list deterministic and deduplicated.
        selected = list(dict.fromkeys([*selected, "generic"]))

    result: list[CanaryFile] = []
    for key in selected:
        result.extend(files[key])
    # Stable order by display path makes tar output and tests deterministic.
    return tuple(sorted(result, key=lambda item: item.relative_path))


def _env_for(intent: ContextCanary, marker: str) -> tuple[dict[str, str], dict[str, str]]:
    values: dict[str, tuple[str, str]] = {
        "AWS_ACCESS_KEY_ID": (_aws_access_key(marker), "aws"),
        "AWS_SECRET_ACCESS_KEY": (_aws_secret(marker), "aws"),
        "AWS_SESSION_TOKEN": (f"{marker}-fake-session-token", "aws"),
        "GITHUB_TOKEN": (_github_token(marker), "github"),
        "GH_TOKEN": (_github_token(marker), "github"),
        "SLACK_BOT_TOKEN": (_slack_token(marker), "slack"),
        "SLACK_WEBHOOK_URL": (
            f"https://hooks.slack.invalid/services/T000/B000/{marker}-fake",
            "slack",
        ),
        "OPENAI_API_KEY": (f"sk-{marker}-fake", "generic"),
        "DATABASE_URL": (f"postgres://canary:{marker}@db.invalid/skillsentry", "generic"),
        "NPM_TOKEN": (f"npm_{marker}-fake", "generic"),
    }

    if intent is ContextCanary.GENERIC:
        selected = values
    else:
        primary_asset = {
            ContextCanary.AWS: "aws",
            ContextCanary.GITHUB: "github",
            ContextCanary.SLACK: "slack",
            ContextCanary.SSH: "ssh",
        }[intent]
        selected = {
            key: value for key, value in values.items() if value[1] in {primary_asset, "generic"}
        }

    env = {key: value for key, (value, _asset) in selected.items()}
    assets = {key: asset for key, (_value, asset) in selected.items()}
    return env, assets


def generate_canary_set(
    scan_id: UUID,
    declared_intent: str | None,
    *,
    marker: str | None = None,
    secondary_marker: str | None = None,
) -> CanarySet:
    """Build a complete, deterministic-by-input canary set for one scan."""

    primary = validate_marker(marker) if marker else new_marker()
    secondary = validate_marker(secondary_marker) if secondary_marker else new_marker()
    if secondary == primary:
        raise ValueError("primary and secondary canary markers must differ")

    intent = normalize_intent(declared_intent)
    env, env_assets = _env_for(intent, primary)
    return CanarySet(
        scan_id=scan_id,
        declared_intent=(declared_intent or "").strip()[:500],
        intent=intent,
        marker=primary,
        secondary_marker=secondary,
        files=_files_for(intent, primary),
        env=env,
        env_assets=env_assets,
    )


def extract_markers(text: str) -> set[str]:
    """Return every embedded ``SKS-<8hex>``/``SKS<8hex>`` marker in *text*."""

    markers: set[str] = set()
    for match in _EMBEDDED_MARKER_RE.findall(text):
        compact = match.replace("-", "").lower()
        markers.add(f"SKS-{compact[3:]}")
    return markers
