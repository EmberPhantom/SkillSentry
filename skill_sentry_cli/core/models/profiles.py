"""Model profiles: what a model of a given size and kind can be asked to do.

A 1B model and a frontier reasoning model need different requests: how much text goes in one
call, how many calls a skill may use, how large a reply to allow, whether to show worked
examples. A profile is one row of that table. It is chosen from the model id by pattern, can be
overridden in ``[model.profile]``, and falls back to a conservative default for an unknown model.

The numbers here are starting points, set from the size class. They are tuned from measurements
by the benchmark (``docs/operations/model-matrix/``), not guessed per model.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, replace
from typing import Any

CLASSES = ("tiny", "small", "mid", "large", "reasoning")


@dataclass(frozen=True)
class ModelProfile:
    """The request shape for one capability class."""

    name: str
    # Tokens the model can read and write in one call.
    context_tokens: int
    max_output_tokens: int
    # Where the structured-output ladder starts: json_schema, json_object or prompt.
    structured_output: str
    # How the skill is cut up for the model: characters per call and calls per skill.
    chunk_chars: int
    max_chunks: int
    # Extra attempts after a malformed reply (a timeout or a cut reply is never retried).
    retries: int
    temperature: float
    # Whether the prompt carries short worked examples (for models that need them).
    few_shot: bool
    # Findings listed in one call's prompt, and whether the reply schema is the short one.
    max_anchors: int
    compact_schema: bool

    @property
    def fingerprint(self) -> str:
        """A short hash of every value, for the cache identity: a changed profile is a new model."""

        payload = json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode()).hexdigest()[:8]

    @property
    def identity(self) -> str:
        return f"profile={self.name}#{self.fingerprint}"

    def with_overrides(self, overrides: dict[str, Any]) -> ModelProfile:
        """A copy with every non-``None`` override applied."""

        return replace(self, **{k: v for k, v in overrides.items() if v is not None})


PROFILES: dict[str, ModelProfile] = {
    # chunk_chars x max_chunks stays at the 12,000 characters the fixed legacy shape covered, so a
    # long skill that was fully read before is not a partial read (and so UNSCANNED) on a small
    # model. The split between size and count is a guess until the benchmark measures it: smaller
    # chunks cost more calls (about 40% more time on a 7,000-character script with a 1B model).
    "tiny": ModelProfile("tiny", 4096, 1024, "auto", 3000, 4, 1, 0.0, True, 8, True),
    "small": ModelProfile("small", 8192, 1536, "auto", 4000, 3, 1, 0.0, True, 12, True),
    "mid": ModelProfile("mid", 32768, 2048, "auto", 4000, 4, 1, 0.0, False, 20, False),
    "large": ModelProfile("large", 128000, 4096, "auto", 8000, 6, 1, 0.0, False, 40, False),
    # A reasoning model spends part of its output on thinking, so it needs a large budget, and a
    # call is slow and costly, so it gets few of them and no automatic retry.
    "reasoning": ModelProfile("reasoning", 128000, 8192, "auto", 8000, 6, 0, 0.0, False, 40, False),
}
DEFAULT_PROFILE = "small"

# Models that think before they answer, by name. Checked before size.
_REASONING = re.compile(
    r"(?:^|[/:_\-.\s])(?:o1|o3|o4)(?:[-_.:\s]|$)"
    r"|gpt-oss|deepseek[-_]?r1|\br1\b|qwq|qwen-?3(?!.*instruct)|thinking|reasoner|reasoning"
    r"|gemini-?(?:2\.5|3)|nemotron.*(?:ultra|super)|magistral|phi-?4-?reasoning|kimi-?k2.*thinking",
    re.IGNORECASE,
)
# Parameter counts in billions: "8b", "70b", "1.5b", "e4b" (effective), "a3b" is active, not total.
_SIZE = re.compile(r"(?<![a-z0-9])(?:e)?(\d+(?:\.\d+)?)\s*b(?![a-z0-9])", re.IGNORECASE)
_ACTIVE = re.compile(r"-?a\d+(?:\.\d+)?b", re.IGNORECASE)
# A mixture of experts named "8x7b" has 8 x 7 = 56B parameters in total (all must be loaded).
_EXPERTS = re.compile(r"(?<![a-z0-9])(\d+)x(\d+(?:\.\d+)?)b(?![a-z0-9])", re.IGNORECASE)
# Models whose name carries no count, with their size in billions.
_NAMED_SIZES: tuple[tuple[re.Pattern[str], float], ...] = (
    (re.compile(r"phi-?3(?:\.5)?[-:_]?mini", re.IGNORECASE), 3.8),
    (re.compile(r"phi-?4[-:_]?mini", re.IGNORECASE), 3.8),
    (re.compile(r"phi-?3[-:_]?small", re.IGNORECASE), 7.0),
    (re.compile(r"phi-?3[-:_]?medium", re.IGNORECASE), 14.0),
    (re.compile(r"phi-?4(?![-\w]*(?:mini|multimodal))", re.IGNORECASE), 14.0),
    (re.compile(r"mistral-small", re.IGNORECASE), 24.0),
    (re.compile(r"mistral-nemo", re.IGNORECASE), 12.0),
    (re.compile(r"mistral-large", re.IGNORECASE), 123.0),
    (re.compile(r"codestral(?!-mamba)", re.IGNORECASE), 22.0),
)
# Frontier hosted models with no size in their name.
_LARGE_NAMES = re.compile(
    r"gpt-4(?!o-mini)|gpt-5|claude|gemini.*(?:pro|flash)(?!-lite)|command-r-plus|grok|mistral-large|llama-?4",
    re.IGNORECASE,
)
_SMALL_NAMES = re.compile(
    r"flash-?lite|gpt-4o-mini|haiku|(?<![a-z])mini(?![a-z])|nano|tiny|smol", re.IGNORECASE
)


def parameter_billions(model_id: str) -> float | None:
    """The size in billions of parameters named in a model id, or ``None``.

    The largest number wins when a name carries two (``qwen3-30b-a3b`` is a 30B model with 3B
    active). A trailing ``:free``, ``:latest`` or quantisation tag is ignored.
    """

    cleaned = _ACTIVE.sub("", model_id)
    experts = [
        float(match.group(1)) * float(match.group(2)) for match in _EXPERTS.finditer(cleaned)
    ]
    if experts:
        return max(experts)
    sizes = [float(match.group(1)) for match in _SIZE.finditer(cleaned)]
    sizes = [size for size in sizes if 0.1 <= size <= 2000]
    if sizes:
        return max(sizes)
    for pattern, size in _NAMED_SIZES:
        if pattern.search(cleaned):
            return size
    return None


def classify(model_id: str) -> str:
    """The capability class of a model id: ``tiny``, ``small``, ``mid``, ``large`` or ``reasoning``.

    An unknown model is ``small``: the conservative choice, with short requests and a modest
    reply budget, so it is asked for less than it might manage rather than more than it can.
    """

    name = model_id.strip().lower()
    if re.search(r"flash-?lite", name):
        return "small"  # thinking is off by default on the lite models
    if _REASONING.search(name):
        return "reasoning"
    size = parameter_billions(name)
    if size is not None:
        if size < 5:
            return "tiny"
        if size < 14:
            return "small"
        if size < 41:
            return "mid"
        return "large"
    if _SMALL_NAMES.search(name):
        return "small"
    if _LARGE_NAMES.search(name):
        return "large"
    return DEFAULT_PROFILE


def resolve_profile(
    model_id: str, *, name: str = "auto", overrides: dict[str, Any] | None = None
) -> ModelProfile:
    """The profile for a model: the configured class (or the one its id suggests) with overrides."""

    chosen = name.strip().lower() if name else "auto"
    if chosen == "auto":
        chosen = classify(model_id)
    if chosen not in PROFILES:
        raise ValueError(f"unknown model profile {name!r}; use one of {list(CLASSES)} or 'auto'")
    profile = PROFILES[chosen]
    return profile.with_overrides(overrides or {})


__all__ = [
    "CLASSES",
    "DEFAULT_PROFILE",
    "PROFILES",
    "ModelProfile",
    "classify",
    "parameter_billions",
    "resolve_profile",
]
