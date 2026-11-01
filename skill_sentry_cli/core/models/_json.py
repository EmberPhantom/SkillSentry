"""Small, dependency-free JSON helpers shared by the model clients.

The real model backends must never hand malformed data to Dev 2's analyzers.
This module parses model text defensively and validates the common JSON Schema
features used by the I2 prompts.  It is deliberately not a full JSON Schema
implementation; unsupported keywords are ignored rather than rejecting a
useful response.
"""

from __future__ import annotations

import json
from typing import Any


def parse_json_object(text: str) -> dict[str, Any]:
    """Parse a model response into a JSON object.

    Models occasionally wrap JSON in Markdown fences or surround it with a
    sentence.  We first try the whole string, then the first ``{`` through the
    last ``}``.  Anything that is not an object is rejected: the I2 contract
    only permits objects.
    """

    candidate = _strip_fences(text).strip()
    for value in (candidate, _object_slice(candidate)):
        if not value:
            continue
        try:
            parsed = json.loads(value)
        except (TypeError, ValueError):
            continue
        if isinstance(parsed, dict):
            return parsed
    raise ValueError("model response is not a JSON object")


def validate_json(instance: Any, schema: dict[str, Any]) -> None:
    """Validate ``instance`` against the JSON Schema subset we emit.

    Raises ``ValueError`` with a path to the first mismatch.  ``$ref`` is
    intentionally not supported; the prompts use flat, self-contained schemas.
    """

    _validate(instance, schema, "$", schema)


def _validate(instance: Any, schema: Any, path: str, root: dict[str, Any]) -> None:
    if schema is True or schema == {}:
        return
    if schema is False:
        raise ValueError(f"{path}: schema forbids any value")
    if not isinstance(schema, dict):
        return

    if "const" in schema and instance != schema["const"]:
        raise ValueError(f"{path}: expected constant {schema['const']!r}")
    if "enum" in schema and instance not in schema["enum"]:
        raise ValueError(f"{path}: value is not in enum")

    expected = schema.get("type")
    if expected is not None and not _matches_type(instance, expected):
        raise ValueError(f"{path}: expected {expected}, got {type(instance).__name__}")

    if isinstance(instance, dict):
        _validate_object(instance, schema, path, root)
    elif isinstance(instance, list):
        item_schema = schema.get("items")
        if item_schema is not None:
            for index, item in enumerate(instance):
                _validate(item, item_schema, f"{path}[{index}]", root)

    if isinstance(instance, str):
        if "minLength" in schema and len(instance) < int(schema["minLength"]):
            raise ValueError(f"{path}: string is too short")
        if "maxLength" in schema and len(instance) > int(schema["maxLength"]):
            raise ValueError(f"{path}: string is too long")
    if isinstance(instance, (int, float)) and not isinstance(instance, bool):
        if "minimum" in schema and instance < schema["minimum"]:
            raise ValueError(f"{path}: number is below minimum")
        if "maximum" in schema and instance > schema["maximum"]:
            raise ValueError(f"{path}: number is above maximum")


def _validate_object(
    instance: dict[str, Any], schema: dict[str, Any], path: str, root: dict[str, Any]
) -> None:
    required = schema.get("required") or []
    for key in required:
        if key not in instance:
            raise ValueError(f"{path}: missing required property {key!r}")

    properties = schema.get("properties") or {}
    if not isinstance(properties, dict):
        properties = {}
    for key, value in instance.items():
        if key in properties:
            _validate(value, properties[key], f"{path}.{key}", root)
            continue
        additional = schema.get("additionalProperties", True)
        if additional is False:
            raise ValueError(f"{path}: unexpected property {key!r}")
        if isinstance(additional, dict):
            _validate(value, additional, f"{path}.{key}", root)


def _matches_type(value: Any, expected: Any) -> bool:
    choices = expected if isinstance(expected, list) else [expected]
    for choice in choices:
        if choice == "object" and isinstance(value, dict):
            return True
        if choice == "array" and isinstance(value, list):
            return True
        if choice == "string" and isinstance(value, str):
            return True
        if choice == "integer" and isinstance(value, int) and not isinstance(value, bool):
            return True
        if choice == "number" and isinstance(value, (int, float)) and not isinstance(value, bool):
            return True
        if choice == "boolean" and isinstance(value, bool):
            return True
        if choice == "null" and value is None:
            return True
    return False


def _strip_fences(text: str) -> str:
    stripped = text.strip()
    if not stripped.startswith("```"):
        return stripped
    lines = stripped.splitlines()
    if lines and lines[0].startswith("```"):
        lines = lines[1:]
    if lines and lines[-1].strip() == "```":
        lines = lines[:-1]
    return "\n".join(lines).strip()


def _object_slice(text: str) -> str:
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end <= start:
        return ""
    return text[start : end + 1]


__all__ = ["parse_json_object", "validate_json"]
