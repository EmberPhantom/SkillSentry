"""Configuration loading for SkillSentry.

Precedence (docs/reference/cli.md §7.3): CLI flags > environment > file >
defaults.  The file is ``skillsentry.toml`` in the working directory, or the
path supplied via ``--config`` / ``SKILLSENTRY_CONFIG``.
"""

from __future__ import annotations

import os
import tomllib
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from skill_sentry_cli.core.version import DEFAULT_WEIGHTS, engine_version

APP_DIR_NAME = ".skillsentry"
ALLOWED_SCAN_ROOTS_ENV = "SKILLSENTRY_ALLOWED_SCAN_ROOTS"
EXTRA_SKILL_PATHS_ENV = "SKILLSENTRY_EXTRA_SKILL_PATHS"
DISCOVERY_AGENTS = frozenset(
    {"claude", "codex", "agents", "gemini", "cursor", "opencode", "copilot", "custom"}
)


class ConfigError(RuntimeError):
    """Raised when the configuration file is invalid."""


class _ConfigModel(BaseModel):
    model_config = ConfigDict(extra="forbid", protected_namespaces=())


class ProviderSettings(_ConfigModel):
    """An OpenAI-compatible server: OpenRouter, NVIDIA NIM, Groq, a local server, or any other.

    Select it with ``[model] backend = "openrouter"`` (or ``nim``, ``groq``, ``openai``). A preset
    fills ``base_url`` and ``api_key_env``; ``openai`` needs a ``base_url``. The key itself is
    never in this file: ``api_key_env`` is the NAME of the environment variable that holds it.
    """

    base_url: str = ""
    model: str = ""
    api_key_env: str = ""
    headers: dict[str, str] = Field(default_factory=dict)
    structured_output: str = "auto"  # auto | json_schema | json_object | prompt
    # Output limit of one reply. Unset means the model profile's value.
    max_tokens: int | None = Field(default=None, ge=16, le=65536)
    # Limits the provider enforces, for this model. Unset takes the preset's starting value; 0
    # turns the limit off. The client paces its requests to them and stops cleanly when a daily
    # quota is used up.
    requests_per_minute: int | None = Field(default=None, ge=0, le=100_000)
    tokens_per_minute: int | None = Field(default=None, ge=0, le=100_000_000)
    requests_per_day: int | None = Field(default=None, ge=0, le=10_000_000)

    @field_validator("api_key_env")
    @classmethod
    def _env_name(cls, value: str) -> str:
        from skill_sentry_cli.core.models.providers import check_env_name

        return check_env_name(value)

    @field_validator("headers")
    @classmethod
    def _headers(cls, value: dict[str, str]) -> dict[str, str]:
        from skill_sentry_cli.core.models.providers import check_headers

        return check_headers(value)

    @field_validator("structured_output")
    @classmethod
    def _mode(cls, value: str) -> str:
        from skill_sentry_cli.core.models.providers import STRUCTURED_MODES

        normalised = value.strip().lower()
        if normalised not in STRUCTURED_MODES:
            raise ValueError(f"structured_output must be one of {list(STRUCTURED_MODES)}")
        return normalised


class ProfileSettings(_ConfigModel):
    """Override how requests are shaped for the model (``[model.profile]``).

    ``name`` picks a capability class (``tiny``, ``small``, ``mid``, ``large``, ``reasoning``);
    ``auto`` chooses one from the model id. Every other field left unset keeps the class's value.
    """

    name: str = "auto"
    context_tokens: int | None = Field(default=None, ge=512, le=2_000_000)
    max_output_tokens: int | None = Field(default=None, ge=16, le=65536)
    chunk_chars: int | None = Field(default=None, ge=200, le=200_000)
    max_chunks: int | None = Field(default=None, ge=1, le=50)
    retries: int | None = Field(default=None, ge=0, le=3)
    structured_output: str | None = None
    few_shot: bool | None = None
    max_anchors: int | None = Field(default=None, ge=1, le=200)
    compact_schema: bool | None = None

    @field_validator("name")
    @classmethod
    def _class_name(cls, value: str) -> str:
        from skill_sentry_cli.core.models.profiles import CLASSES

        normalised = value.strip().lower() or "auto"
        if normalised != "auto" and normalised not in CLASSES:
            raise ValueError(f"name must be 'auto' or one of {list(CLASSES)}")
        return normalised

    @field_validator("structured_output")
    @classmethod
    def _mode(cls, value: str | None) -> str | None:
        from skill_sentry_cli.core.models.providers import STRUCTURED_MODES

        if value is None:
            return None
        normalised = value.strip().lower()
        if normalised not in STRUCTURED_MODES:
            raise ValueError(f"structured_output must be one of {list(STRUCTURED_MODES)}")
        return normalised


class ModelSettings(_ConfigModel):
    backend: str = "auto"  # auto | local | cloud | demo | openai | openrouter | nim | groq
    ollama_url: str = "http://localhost:11434"
    ollama_model: str = "gemma4:e4b-it-qat"
    gemini_model: str = "gemma-4-e4b"
    image_max_px: int = Field(default=768, ge=256, le=4096)
    request_timeout_s: float = Field(default=180.0, gt=0)
    ollama_num_ctx: int = Field(default=8192, ge=512, le=32768)
    ollama_num_predict: int = Field(default=2048, ge=1, le=4096)
    ollama_keep_alive: str = "30m"
    provider: ProviderSettings = Field(default_factory=ProviderSettings)
    profile: ProfileSettings = Field(default_factory=ProfileSettings)


class DecisionSettings(_ConfigModel):
    """Typed semantic decision backend settings.

    ``model`` remains the legacy generation/vision client selection.  This
    section controls the Laya-style decision layer independently.
    """

    # Opt-in: Laya stays off until its calibration gates pass (docs/13 §13.20).
    backend: str = "legacy"  # auto | laya | legacy | none
    checkpoint: str = "auto"  # auto | english | multilingual | typed-decisions
    device: str = "auto"  # auto | cpu | cuda | mps
    model_path: str = ""
    timeout_s: float = Field(default=30.0, gt=0, le=600)
    max_len: int = Field(default=1024, ge=64, le=8192)
    head_max_len: int = Field(default=256, ge=16, le=4096)
    calibration_path: str = ""
    calibration_version: str = ""
    required: bool = False

    @field_validator("backend")
    @classmethod
    def _validate_backend(cls, value: str) -> str:
        normalised = value.strip().lower()
        allowed = {"auto", "laya", "legacy", "none"}
        if normalised not in allowed:
            raise ValueError(f"backend must be one of {sorted(allowed)}")
        return normalised

    @field_validator("checkpoint")
    @classmethod
    def _validate_checkpoint(cls, value: str) -> str:
        normalised = value.strip().lower()
        allowed = {"auto", "english", "multilingual", "typed-decisions"}
        if normalised not in allowed:
            raise ValueError(f"checkpoint must be one of {sorted(allowed)}")
        return normalised

    @field_validator("device")
    @classmethod
    def _validate_device(cls, value: str) -> str:
        normalised = value.strip().lower()
        allowed = {"auto", "cpu", "cuda", "mps"}
        if normalised not in allowed:
            raise ValueError(f"device must be one of {sorted(allowed)}")
        return normalised

    @model_validator(mode="after")
    def _validate_token_budgets(self) -> DecisionSettings:
        if self.head_max_len > self.max_len:
            raise ValueError("head_max_len must not exceed max_len")
        return self

    @property
    def cache_identity(self) -> str:
        """Stable identity for cache invalidation when the decision layer changes."""

        calibration = self.calibration_version.strip() or "uncalibrated"
        return f"{self.backend}:{self.checkpoint}:{calibration}:{self.max_len}:{self.head_max_len}"


class SandboxSettings(_ConfigModel):
    """Sandbox settings.

    ``max_parallel`` is accepted so existing files still load, but no code reads it:
    scans run one sandbox at a time. ``init`` no longer writes it.
    """

    enabled: bool = True
    base_image: str = "skillsentry-sandbox:local"
    timeout_s: int = Field(default=60, ge=5, le=600)
    memory_mb: int = Field(default=512, ge=128)
    cpus: float = Field(default=1.0, gt=0)
    masquerade: bool = True
    max_parallel: int = Field(default=1, ge=1, le=8)


class ScanSettings(_ConfigModel):
    """Limits that apply to one scan."""

    # Wall-clock cap for one skill. Model calls and the sandbox stop at it; the scan returns
    # what the finished stages found and says which stage ran out of time.
    max_time_s: int = Field(default=300, ge=5, le=86400)


class PoisonedWellSettings(_ConfigModel):
    enabled: bool = True
    correlation_window_s: float = Field(default=10.0, gt=0)
    secondary_canary: bool = True


class TierSettings(_ConfigModel):
    safe_max: int = Field(default=30, ge=0, le=100)
    malicious_min: int = Field(default=70, ge=0, le=100)


class ScoringSettings(_ConfigModel):
    weights: dict[str, float] = Field(default_factory=lambda: dict(DEFAULT_WEIGHTS))
    typosquat_bonus: int = Field(default=15, ge=0, le=100)
    tiers: TierSettings = Field(default_factory=TierSettings)

    def weight_fingerprint_input(self) -> dict[str, float]:
        return dict(self.weights)


class CacheSettings(_ConfigModel):
    db_path: str = "~/.skillsentry/skillsentry.db"
    backend_strict: bool = False


class ServerSettings(_ConfigModel):
    """Settings that apply only to the API server (``serve``).

    ``allowed_scan_roots`` limits which folders a ``POST /scan`` may read. The empty
    default allows any readable folder, as before. Each entry must be an absolute path;
    symlinks are resolved before the check.
    """

    allowed_scan_roots: list[str] = Field(default_factory=list)

    @field_validator("allowed_scan_roots")
    @classmethod
    def _validate_scan_roots(cls, value: list[str]) -> list[str]:
        cleaned: list[str] = []
        for entry in value:
            text = entry.strip()
            if not text:
                raise ValueError("allowed_scan_roots must not contain an empty path")
            if not Path(text).expanduser().is_absolute():
                raise ValueError(f"allowed_scan_roots must be absolute paths: {text!r}")
            cleaned.append(text)
        return cleaned


class DiscoverySettings(_ConfigModel):
    """Settings for ``scan`` with no path (installed-skill discovery).

    ``extra_paths`` are folders of skills, or single skill folders, checked in addition
    to the built-in locations. Each entry must be absolute after ``~`` expansion.
    ``agents`` restricts discovery to the named agents; empty means all of them.
    """

    extra_paths: list[str] = Field(default_factory=list)
    agents: list[str] = Field(default_factory=list)
    include_experimental: bool = False

    @field_validator("extra_paths")
    @classmethod
    def _validate_extra_paths(cls, value: list[str]) -> list[str]:
        cleaned: list[str] = []
        for entry in value:
            text = entry.strip()
            if not text:
                raise ValueError("discovery.extra_paths must not contain an empty path")
            if not Path(text).expanduser().is_absolute():
                raise ValueError(f"discovery.extra_paths must be absolute paths: {text!r}")
            cleaned.append(text)
        return cleaned

    @field_validator("agents")
    @classmethod
    def _validate_agents(cls, value: list[str]) -> list[str]:
        cleaned: list[str] = []
        for entry in value:
            name = entry.strip().lower()
            if name not in DISCOVERY_AGENTS:
                raise ValueError(
                    f"discovery.agents must be among {sorted(DISCOVERY_AGENTS)}: {entry!r}"
                )
            cleaned.append(name)
        return cleaned


class CISettings(_ConfigModel):
    """Accepted so that existing files with a ``[ci]`` section still load.

    The CLI does not read these values; the gate is set with ``--fail-on``.
    ``init`` does not write this section.
    """

    fail_on: str = "malicious"
    upload_sarif: bool = False


class SkillsEntryConfig(_ConfigModel):
    model: ModelSettings = Field(default_factory=ModelSettings)
    decision: DecisionSettings = Field(default_factory=DecisionSettings)
    sandbox: SandboxSettings = Field(default_factory=SandboxSettings)
    scan: ScanSettings = Field(default_factory=ScanSettings)
    poisoned_well: PoisonedWellSettings = Field(default_factory=PoisonedWellSettings)
    scoring: ScoringSettings = Field(default_factory=ScoringSettings)
    cache: CacheSettings = Field(default_factory=CacheSettings)
    server: ServerSettings = Field(default_factory=ServerSettings)
    discovery: DiscoverySettings = Field(default_factory=DiscoverySettings)
    ci: CISettings = Field(default_factory=CISettings)

    @property
    def db_path(self) -> Path:
        return Path(os.path.expandvars(os.path.expanduser(self.cache.db_path))).resolve()

    @property
    def engine_version(self) -> str:
        return engine_version(self.scoring.weights)


DEFAULT_CONFIG_TOML = """\
# SkillSentry configuration — generated by `skill-sentry-cli init`.
# Precedence: CLI flags > environment > this file > built-in defaults.

[model]
backend = "auto"                 # auto | local | cloud | demo
ollama_url = "http://localhost:11434"
ollama_model = "gemma4:e4b-it-qat"
gemini_model = "gemma-4-e4b"     # used only when backend = cloud/auto-fallback
image_max_px = 768
request_timeout_s = 180

[decision]
backend = "legacy"               # auto | laya | legacy | none (laya is opt-in until calibrated)
checkpoint = "auto"              # auto | english | multilingual | typed-decisions
device = "auto"                  # auto | cpu | cuda | mps
model_path = ""                  # optional offline checkpoint directory
timeout_s = 30
max_len = 1024
head_max_len = 256
calibration_path = ""
calibration_version = ""
required = false

[sandbox]
enabled = true
base_image = "skillsentry-sandbox:local"   # built from assets/Dockerfile.sandbox
timeout_s = 60
memory_mb = 512
cpus = 1.0
masquerade = true

[scan]
max_time_s = 300                 # wall-clock cap for one skill; --max-time overrides it

[poisoned_well]
enabled = true
correlation_window_s = 10
secondary_canary = true

[scoring]
weights = { anchors = 0.15, semantic = 0.20, vision = 0.20, sandbox = 0.25 }
typosquat_bonus = 15
tiers = { safe_max = 30, malicious_min = 70 }

# An OpenAI-compatible server instead of Ollama or Gemini (OpenRouter, NVIDIA NIM, Groq, LM Studio, ...).
# The key comes from an environment variable and is never written here. A remote provider receives
# the skill's content.
# [model]
# backend = "groq"                # openrouter | nim | groq | openai
# [model.provider]
# model = "openai/gpt-oss-20b"
# base_url = ""                   # only for backend = "openai", or to override a preset
# api_key_env = ""                # the NAME of the variable (a preset fills in GROQ_API_KEY and so on)

[cache]
db_path = "~/.skillsentry/skillsentry.db"
backend_strict = false

# [server]
# allowed_scan_roots = ["/srv/skills"]   # API scans only inside these folders; empty = any folder

# [discovery]
# extra_paths = ["~/work/skills"]        # extra skill folders, or folders of skills, for `scan` with no path
#                                        # Windows: use a single-quoted TOML string, which keeps backslashes:
#                                        #   extra_paths = ['~\\work\\skills']   (or forward slashes: "~/work/skills")
# agents = []                            # empty = all; claude | codex | agents | gemini | cursor | opencode | copilot | custom
# include_experimental = false           # also look in the experimental Gemini, Cursor, OpenCode and Copilot locations
"""


def settings_dir() -> Path:
    return Path.home() / APP_DIR_NAME


def ensure_private_dir(path: Path) -> None:
    """Create ``path`` for this user only (0700 on POSIX).

    ``mkdir``'s mode is masked by the umask, so a directory we create is chmodded
    explicitly. An existing directory is left as the user set it.
    """

    if os.name == "nt":
        path.mkdir(parents=True, exist_ok=True)
        return
    existed = path.exists()
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not existed:
        os.chmod(path, 0o700)


def ensure_private_file(path: Path) -> None:
    """Make sure ``path`` exists and is readable and writable by this user only (0600 on POSIX).

    The file is created with the restricted mode before SQLite opens it, so there is
    no window in which the database is world-readable.
    """

    if os.name == "nt":
        return
    if not path.exists():
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            pass
        else:
            os.close(fd)
    os.chmod(path, 0o600)


def reports_dir(scan_id: str | None = None) -> Path:
    base = settings_dir() / "reports"
    return base / scan_id if scan_id else base


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def _env_overrides() -> dict[str, Any]:
    overrides: dict[str, Any] = {}

    def set_value(section: str, key: str, value: Any) -> None:
        overrides.setdefault(section, {})[key] = value

    if backend := os.getenv("SKILLSENTRY_BACKEND"):
        set_value("model", "backend", backend)
    if decision_backend := os.getenv("SKILLSENTRY_DECISION_BACKEND"):
        set_value("decision", "backend", decision_backend)
    if checkpoint := os.getenv("SKILLSENTRY_LAYA_CHECKPOINT"):
        set_value("decision", "checkpoint", checkpoint)
    if device := os.getenv("SKILLSENTRY_LAYA_DEVICE"):
        set_value("decision", "device", device)
    if model_path := os.getenv("SKILLSENTRY_LAYA_MODEL_PATH"):
        set_value("decision", "model_path", model_path)
    if os.getenv("SKILLSENTRY_LAYA_REQUIRED") == "1":
        set_value("decision", "required", True)
    if os.getenv("SKILLSENTRY_NO_SANDBOX") == "1":
        set_value("sandbox", "enabled", False)
    if db_path := os.getenv("SKILLSENTRY_DB"):
        set_value("cache", "db_path", db_path)
    if ollama_host := os.getenv("OLLAMA_HOST"):
        set_value("model", "ollama_url", ollama_host)
    if scan_roots := os.getenv(ALLOWED_SCAN_ROOTS_ENV):
        # os.pathsep separates entries, as in PATH. Empty entries are dropped here and
        # refused by the validator if they are not absolute.
        roots = [part for part in scan_roots.split(os.pathsep) if part.strip()]
        if roots:
            set_value("server", "allowed_scan_roots", roots)
    if extra_paths := os.getenv(EXTRA_SKILL_PATHS_ENV):
        # Same convention as SKILLSENTRY_ALLOWED_SCAN_ROOTS: os.pathsep separated.
        paths = [part for part in extra_paths.split(os.pathsep) if part.strip()]
        if paths:
            set_value("discovery", "extra_paths", paths)
    return overrides


def default_config() -> SkillsEntryConfig:
    return SkillsEntryConfig()


def load_config(path: str | Path | None = None) -> SkillsEntryConfig:
    """Load config from TOML, then apply environment overrides.

    A missing file is not an error: defaults are used (except when the caller
    explicitly passes a path, in which case a missing file raises).
    """
    # A path named by the environment is as explicit as one passed in: a typo must not
    # silently fall back to defaults.
    env_path = os.getenv("SKILLSENTRY_CONFIG")
    explicit = path is not None or bool(env_path)
    if path is None:
        path = env_path or Path.cwd() / "skillsentry.toml"
    config_path = Path(path).expanduser()

    data: dict[str, Any] = {}
    if config_path.exists():
        try:
            data = tomllib.loads(config_path.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError) as exc:
            raise ConfigError(f"could not read {config_path}: {exc}") from exc
    elif explicit:
        raise ConfigError(f"config file not found: {config_path}")

    data = _deep_merge(data, _env_overrides())
    try:
        return SkillsEntryConfig.model_validate(data)
    except ValidationError as exc:
        # The text names the keys and the problems, never the values: a value that is
        # wrong may be a key that was pasted into the file, and it must not be echoed.
        raise ConfigError(
            f"invalid configuration in {config_path}: {_validation_summary(exc)}"
        ) from exc
    except Exception as exc:
        raise ConfigError(f"invalid configuration in {config_path}: {exc}") from exc


def _validation_summary(exc: ValidationError) -> str:
    lines = []
    for error in exc.errors(include_input=False, include_url=False, include_context=False):
        location = ".".join(str(part) for part in error.get("loc", ()))
        message = str(error.get("msg", "invalid value"))
        message = message.removeprefix("Value error, ")
        lines.append(f"{location}: {message}" if location else message)
    return "; ".join(lines) or "invalid value"


def write_default_config(path: str | Path, *, force: bool = False) -> Path:
    target = Path(path).expanduser()
    if target.exists() and not force:
        raise ConfigError(f"{target} already exists (use --force to overwrite)")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(DEFAULT_CONFIG_TOML, encoding="utf-8")
    return target
