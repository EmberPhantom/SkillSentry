"""Poisoned Well canaries, correlation, and attacker-profile construction."""

from __future__ import annotations

import importlib
from typing import Any

__all__ = [
    "IOC",
    "AttackerProfile",
    "CanaryFile",
    "CanarySet",
    "Correlation",
    "ExfilTracker",
    "build_attacker_profile",
    "extract_markers",
    "generate_canary_set",
    "new_marker",
    "normalize_intent",
    "validate_marker",
]

_LAZY: dict[str, tuple[str, str]] = {
    "AttackerProfile": ("skillsentry.core.poisoned_well.attacker_profile", "AttackerProfile"),
    "IOC": ("skillsentry.core.poisoned_well.attacker_profile", "IOC"),
    "build_attacker_profile": (
        "skillsentry.core.poisoned_well.attacker_profile",
        "build_attacker_profile",
    ),
    "CanaryFile": ("skillsentry.core.poisoned_well.canary_gen", "CanaryFile"),
    "CanarySet": ("skillsentry.core.poisoned_well.canary_gen", "CanarySet"),
    "extract_markers": ("skillsentry.core.poisoned_well.canary_gen", "extract_markers"),
    "generate_canary_set": (
        "skillsentry.core.poisoned_well.canary_gen",
        "generate_canary_set",
    ),
    "new_marker": ("skillsentry.core.poisoned_well.canary_gen", "new_marker"),
    "normalize_intent": ("skillsentry.core.poisoned_well.canary_gen", "normalize_intent"),
    "validate_marker": ("skillsentry.core.poisoned_well.canary_gen", "validate_marker"),
    "Correlation": ("skillsentry.core.poisoned_well.exfil_tracker", "Correlation"),
    "ExfilTracker": ("skillsentry.core.poisoned_well.exfil_tracker", "ExfilTracker"),
}


def __getattr__(name: str) -> Any:
    target = _LAZY.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module_name, attribute = target
    value = getattr(importlib.import_module(module_name), attribute)
    globals()[name] = value
    return value
