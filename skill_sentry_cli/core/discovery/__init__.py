"""Installed-skill discovery (pure core; the CLI wiring lives elsewhere)."""

from skill_sentry_cli.core.discovery.claude_plugins import enabled_plugin_skill_roots
from skill_sentry_cli.core.discovery.finder import (
    DiscoveryResult,
    InstalledSkill,
    discover_installed,
)
from skill_sentry_cli.core.discovery.sources import SkillSource, known_sources

__all__ = [
    "DiscoveryResult",
    "InstalledSkill",
    "SkillSource",
    "discover_installed",
    "enabled_plugin_skill_roots",
    "known_sources",
]
