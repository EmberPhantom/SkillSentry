"""CLI exit codes (docs/07-cli-reference.md §7.5)."""

from __future__ import annotations

from enum import IntEnum


class ExitCode(IntEnum):
    OK = 0
    VERDICT = 1
    USAGE = 2
    OPERATIONAL = 3
    MODEL_UNAVAILABLE = 4
