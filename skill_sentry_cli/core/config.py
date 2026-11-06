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

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from skill_sentry_cli.core.version import DEFAULT_WEIGHTS, engine_version

APP_DIR_NAME = ".skillsentry"


class ConfigError(RuntimeError):
    """Raised when the configuration file is invalid."""


class _ConfigModel(BaseModel):
    model_config = ConfigDict(extra="forbid", protected_namespaces=())


class ModelSettings(_ConfigModel):
    backend: str = "auto"  # auto | local | cloud | demo
    ollama_url: str = "http://localhost:11434"
    ollama_model: str = "gemma4:e4b-it-qat"
    gemini_model: str = "gemma-4-e4b"
    image_max_px: int = Field(default=768, ge=256, le=4096)
    request_timeout_s: float = Field(default=180.0, gt=0)
    ollama_num_ctx: int = Field(default=4096, ge=512, le=32768)
    ollama_num_predict: int = Field(default=768, ge=1, le=4096)
    ollama_keep_alive: str = "30m"


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
    enabled: bool = True
    base_image: str = "skillsentry-sandbox:local"
    timeout_s: int = Field(default=60, ge=5, le=600)
    memory_mb: int = Field(default=512, ge=128)
    cpus: float = Field(default=1.0, gt=0)
    masquerade: bool = True
    max_parallel: int = Field(default=1, ge=1, le=8)


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


class CISettings(_ConfigModel):
    fail_on: str = "malicious"
    upload_sarif: bool = False


class SkillsEntryConfig(_ConfigModel):
    model: ModelSettings = Field(default_factory=ModelSettings)
    decision: DecisionSettings = Field(default_factory=DecisionSettings)
    sandbox: SandboxSettings = Field(default_factory=SandboxSettings)
    poisoned_well: PoisonedWellSettings = Field(default_factory=PoisonedWellSettings)
    scoring: ScoringSettings = Field(default_factory=ScoringSettings)
    cache: CacheSettings = Field(default_factory=CacheSettings)
    ci: CISettings = Field(default_factory=CISettings)

    @property
    def db_path(self) -> Path:
        return Path(os.path.expandvars(os.path.expanduser(self.cache.db_path))).resolve()

    @property
    def engine_version(self) -> str:
        return engine_version(self.scoring.weights)


DEFAULT_CONFIG_TOML = """\
# SkillSentry 2.0 configuration — generated by `skill-sentry-cli init`.
# Precedence: CLI flags > environment > this file > built-in defaults.

[model]
backend = "auto"                 # auto | local | cloud | demo
ollama_url = "http://localhost:11434"
ollama_model = "gemma4:e4b-it-qat"
gemini_model = "gemma-4-e4b"     # used only when backend = cloud/auto-fallback
image_max_px = 1024
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
max_parallel = 1

[poisoned_well]
enabled = true
correlation_window_s = 10
secondary_canary = true

[scoring]
weights = { anchors = 0.15, semantic = 0.20, vision = 0.20, sandbox = 0.25 }
typosquat_bonus = 15
tiers = { safe_max = 30, malicious_min = 70 }

[cache]
db_path = "~/.skillsentry/skillsentry.db"
backend_strict = false

[ci]
fail_on = "malicious"
upload_sarif = false
"""


def settings_dir() -> Path:
    return Path.home() / APP_DIR_NAME


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
    except Exception as exc:  # pydantic ValidationError
        raise ConfigError(f"invalid configuration in {config_path}: {exc}") from exc


def write_default_config(path: str | Path, *, force: bool = False) -> Path:
    target = Path(path).expanduser()
    if target.exists() and not force:
        raise ConfigError(f"{target} already exists (use --force to overwrite)")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(DEFAULT_CONFIG_TOML, encoding="utf-8")
    return target
