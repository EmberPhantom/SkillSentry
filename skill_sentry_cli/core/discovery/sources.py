"""Where installed agent skills live.

Each :class:`SkillSource` names a folder whose immediate children are skill folders
(each containing ``SKILL.md``). Locations are passed in as ``home`` and ``project_dir``
so that tests can point them at a temporary tree; nothing here reads the real home.

Only the locations marked verified are on by default. Experimental locations are
included only when the caller asks for them.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

Scope = Literal["user", "project", "plugin", "custom"]


@dataclass(frozen=True)
class SkillSource:
    agent: str
    scope: Scope
    base: Path
    experimental: bool = False


def known_sources(home: Path, project_dir: Path | None) -> list[SkillSource]:
    """Built-in skill locations for ``home`` and, when given, ``project_dir``.

    Claude plugin roots are not listed here: they depend on settings and come from
    :func:`skill_sentry_cli.core.discovery.claude_plugins.enabled_plugin_skill_roots`.
    """

    sources: list[SkillSource] = [
        # Verified locations.
        SkillSource("claude", "user", home / ".claude" / "skills"),
        SkillSource("codex", "user", home / ".codex" / "skills"),
        SkillSource("agents", "user", home / ".agents" / "skills"),
    ]
    if project_dir is not None:
        sources.append(SkillSource("claude", "project", project_dir / ".claude" / "skills"))
        sources.append(SkillSource("agents", "project", project_dir / ".agents" / "skills"))

    # Experimental locations: not yet checked against each tool's documentation.
    sources.extend(
        [
            SkillSource("gemini", "user", home / ".gemini" / "skills", experimental=True),
            SkillSource("cursor", "user", home / ".cursor" / "skills", experimental=True),
            SkillSource(
                "opencode", "user", home / ".config" / "opencode" / "skills", experimental=True
            ),
            SkillSource(
                "opencode", "user", home / ".config" / "opencode" / "skill", experimental=True
            ),
        ]
    )
    for extension in _gemini_extension_dirs(home):
        sources.append(SkillSource("gemini", "plugin", extension / "skills", experimental=True))
    if project_dir is not None:
        sources.append(
            SkillSource("copilot", "project", project_dir / ".github" / "skills", experimental=True)
        )
    return sources


def _gemini_extension_dirs(home: Path) -> list[Path]:
    """Existing ``~/.gemini/extensions/*`` folders, sorted. Unreadable means none."""

    root = home / ".gemini" / "extensions"
    try:
        if not root.is_dir():
            return []
        return sorted((child for child in root.iterdir() if child.is_dir()), key=lambda p: p.name)
    except OSError:
        return []
