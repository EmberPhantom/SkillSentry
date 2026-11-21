"""How early a file in a skill should be read, from its path alone.

The parser spends its text budget in this order, and the semantic stage plans its model calls in
the same order, so the files that can act (SKILL.md, scripts, config) are never starved by
reference prose that happens to sort first.
"""

from __future__ import annotations

# Ranking of what the model reads first. Lower is read earlier. A range at or below
# ``LAST_REQUIRED_PRIORITY`` must be read by the model; only the last tier may be static-only.
PRIORITY_SKILL = 0
PRIORITY_ANCHORED = 1
PRIORITY_EXECUTABLE = 2
PRIORITY_INSTRUCTION = 3
PRIORITY_REFERENCE = 4
LAST_REQUIRED_PRIORITY = PRIORITY_INSTRUCTION

SCRIPT_SUFFIXES = frozenset(
    {
        ".py", ".pyw", ".sh", ".bash", ".zsh", ".fish", ".js", ".mjs", ".cjs", ".ts", ".tsx",
        ".jsx", ".ps1", ".psd1", ".psm1", ".rb", ".go", ".rs", ".java", ".kt", ".php", ".pl",
        ".lua", ".c", ".h", ".cc", ".cpp", ".hpp", ".bat", ".cmd", ".vbs", ".sql", ".ipynb",
    }
)  # fmt: skip
CONFIG_SUFFIXES = frozenset(
    {".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".xml", ".html", ".htm", ".svg"}
)
PROSE_SUFFIXES = frozenset({".md", ".markdown", ".txt", ".mdx", ".rst", ".tex"})
# Plain-text data: read like any text, but with the reference material, because it is something
# to look things up in and not something to follow.
DATA_SUFFIXES = frozenset({".csv", ".tsv", ".jsonl", ".ndjson", ".log", ".lock", ".diff", ".patch"})
# A folder with one of these names holds material to look things up in, not instructions to follow.
REFERENCE_DIRS = frozenset(
    {
        "references", "reference", "docs", "doc", "assets", "examples", "example", "templates",
        "template", "samples", "sample", "resources", "data", "fixtures",
    }
)  # fmt: skip


# Files that are code to a build or a container tool, whatever they are called.
BUILD_FILE_NAMES = frozenset(
    {"makefile", "dockerfile", "jenkinsfile", "rakefile", "procfile", "vagrantfile", "justfile"}
)


def file_priority(relative: str) -> int:
    """How early the model should read a file, from its path alone.

    SKILL.md first. Then anything that can run or configure (a script is a script wherever it
    sits). Then instruction text. Reference, asset and example prose comes last. A file the
    path does not clearly mark as reference material is treated as instruction-bearing.
    """

    if relative == "SKILL.md":
        return PRIORITY_SKILL
    parts = relative.lower().split("/")
    suffix = "." + parts[-1].rsplit(".", 1)[-1] if "." in parts[-1] else ""
    if parts[-1] in BUILD_FILE_NAMES:
        return PRIORITY_EXECUTABLE
    if suffix in SCRIPT_SUFFIXES:
        return PRIORITY_EXECUTABLE
    in_reference = any(part in REFERENCE_DIRS for part in parts[:-1])
    if suffix in CONFIG_SUFFIXES and not in_reference:
        return PRIORITY_EXECUTABLE
    if in_reference or suffix in DATA_SUFFIXES:
        return PRIORITY_REFERENCE
    return PRIORITY_INSTRUCTION
