"""CLI exit codes (docs/reference/cli.md §7.5)."""

from __future__ import annotations

from enum import IntEnum


class ExitCode(IntEnum):
    OK = 0
    VERDICT = 1
    USAGE = 2
    OPERATIONAL = 3
    MODEL_UNAVAILABLE = 4
    # The skill is malformed (bad frontmatter, a symlink, a package that is too large). It is a
    # packaging problem, not a verdict, so --fail-on never turns it into VERDICT.
    INVALID_SKILL = 5
