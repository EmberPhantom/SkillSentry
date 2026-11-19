"""How one skill is cut up and asked about, for one model.

The semantic stage used to use one fixed shape: 4,000 characters a call, three calls, a long
reply schema. That fits a mid-size model and fits no other. A plan is the shape derived from a
model's profile: how much text goes in one call, how many calls a skill may use, how many
findings are listed, whether the reply schema is the short one, whether the prompt carries
examples, and how many times a malformed reply is retried.

The input of a call is bounded by the model's real context window: the window, minus the reply
budget, minus the fixed part of the prompt (the system text, the schema, the intent, the findings
list). A chunk is never cut to fit. A line that cannot fit becomes a recorded gap, and a model
whose window is too small for any chunk makes the stage degraded with that reason.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from skill_sentry_cli.core.models.profiles import ModelProfile
from skill_sentry_cli.core.semantic.prompts import (
    FEW_SHOT,
    SEMANTIC_SCHEMA,
    SEMANTIC_SCHEMA_COMPACT,
    SYSTEM_PROMPT,
)

# Bump when the prompt, the examples or the schemas change in a way that changes replies.
PLAN_REVISION = 1
# Source code and prose tokenise to about this many characters per token.
CHARS_PER_TOKEN = 3.2
# The intent line (up to 2,048 characters), the markers, and the instructions around a chunk.
PROMPT_SCAFFOLD_CHARS = 2_600
# One listed finding: its severity, type, location and up to 200 characters of code.
ANCHOR_ROW_CHARS = 280
# JSON tokenises worse than prose: braces, quotes and keys cost about this many characters a token.
JSON_CHARS_PER_TOKEN = 2.5
# A chunk smaller than this is not worth a call.
MIN_CHUNK_CHARS = 400


@dataclass(frozen=True)
class SemanticPlan:
    chunk_chars: int
    max_chunks: int
    max_anchors: int
    retries: int
    few_shot: bool
    compact_schema: bool
    # None for a model with no profile (a mock, an injected client): the fixed legacy shape.
    profile: str | None = None
    context_tokens: int | None = None
    # Set when the model's window cannot hold even a small chunk.
    unusable_reason: str | None = None

    @property
    def schema(self) -> dict[str, object]:
        return SEMANTIC_SCHEMA_COMPACT if self.compact_schema else SEMANTIC_SCHEMA

    @property
    def system(self) -> str:
        return SYSTEM_PROMPT + FEW_SHOT if self.few_shot else SYSTEM_PROMPT

    def describe(self) -> dict[str, object]:
        return {
            "profile": self.profile,
            "chunk_chars": self.chunk_chars,
            "max_chunks": self.max_chunks,
            "max_anchors": self.max_anchors,
            "retries": self.retries,
            "few_shot": self.few_shot,
            "compact_schema": self.compact_schema,
            "context_tokens": self.context_tokens,
        }


def max_reply_chars(schema: object) -> int:
    """The longest JSON reply a schema allows, in characters (keys, quotes and braces included)."""

    if not isinstance(schema, dict):
        return 8
    kind = schema.get("type")
    if kind == "object":
        properties = schema.get("properties", {})
        return 2 + sum(
            len(str(name)) + 4 + max_reply_chars(item) for name, item in properties.items()
        )
    if kind == "array":
        return 2 + int(schema.get("maxItems", 5)) * (max_reply_chars(schema.get("items")) + 1)
    if kind == "string":
        values = schema.get("enum")
        if isinstance(values, list) and values:
            return max(len(str(value)) for value in values) + 2
        return int(schema.get("maxLength", 200)) + 2
    return 8  # a boolean or a number


def plan_from_profile(profile: ModelProfile) -> SemanticPlan:
    """The plan a model's profile allows, with the chunk size bounded by its context window.

    The window must hold the request and the reply. The reply is reserved at the smaller of the
    profile's output limit and the longest reply the schema allows, so a model with a large output
    limit but a short reply schema is not charged for a reply it cannot write.
    """

    schema = SEMANTIC_SCHEMA_COMPACT if profile.compact_schema else SEMANTIC_SCHEMA
    system_chars = len(SYSTEM_PROMPT) + (len(FEW_SHOT) if profile.few_shot else 0)
    fixed_chars = (
        system_chars
        + len(json.dumps(schema, separators=(",", ":")))
        + PROMPT_SCAFFOLD_CHARS
        + profile.max_anchors * ANCHOR_ROW_CHARS
    )
    reply_tokens = min(
        profile.max_output_tokens, int(max_reply_chars(schema) / JSON_CHARS_PER_TOKEN) + 1
    )
    input_chars = int((profile.context_tokens - reply_tokens) * CHARS_PER_TOKEN)
    room = input_chars - fixed_chars
    chunk_chars = min(profile.chunk_chars, room)
    unusable = None
    if chunk_chars < MIN_CHUNK_CHARS:
        unusable = (
            f"the model's context window ({profile.context_tokens} tokens) is too small for the "
            f"semantic stage once {reply_tokens} tokens are kept for the reply; "
            "raise [model.profile] context_tokens, lower max_output_tokens, or use a larger model"
        )
        chunk_chars = max(chunk_chars, 0)
    return SemanticPlan(
        chunk_chars=chunk_chars,
        max_chunks=profile.max_chunks,
        max_anchors=profile.max_anchors,
        retries=profile.retries,
        few_shot=profile.few_shot,
        compact_schema=profile.compact_schema,
        profile=profile.name,
        context_tokens=profile.context_tokens,
        unusable_reason=unusable,
    )


def prompt_fingerprint() -> str:
    """A hash of everything about the prompts that changes replies: for the cache identity."""

    payload = json.dumps(
        {
            "revision": PLAN_REVISION,
            "system": SYSTEM_PROMPT,
            "few_shot": FEW_SHOT,
            "schema": SEMANTIC_SCHEMA,
            "compact": SEMANTIC_SCHEMA_COMPACT,
        },
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode()).hexdigest()[:8]


__all__ = [
    "MIN_CHUNK_CHARS",
    "PLAN_REVISION",
    "SemanticPlan",
    "max_reply_chars",
    "plan_from_profile",
    "prompt_fingerprint",
]
