"""Skill folders of enabled Claude Code plugins.

Only plugins that are enabled are returned. ``enabledPlugins`` is read from the user's
``~/.claude/settings.json`` and, when a project folder is given, from the project's
``.claude/settings.json`` and ``.claude/settings.local.json``. For each plugin the most
specific file that mentions it decides (local project > project > user). Plugins that
are merely present in a marketplace checkout are never listed. Install paths come from
``~/.claude/plugins/installed_plugins.json`` when it is present; the marketplace checkout
is used as a fallback. The JSON layout is not a stable contract, so it is read
defensively: problems become notes, never exceptions.
"""

from __future__ import annotations

import json
from pathlib import Path

from skill_sentry_cli.core.discovery.sources import SkillSource


def enabled_plugin_skill_roots(
    home: Path, project_dir: Path | None = None
) -> tuple[list[SkillSource], list[str]]:
    """Return ``(roots, notes)`` for enabled Claude plugins under ``home``.

    ``project_dir`` adds its ``.claude/settings.json`` and ``.claude/settings.local.json``.
    Each root is ``<plugin install>/skills``. ``notes`` explain anything that could not
    be read or resolved.
    """

    notes: list[str] = []
    claude_dir = home / ".claude"
    enabled = _enabled_plugin_ids(_settings_files(home, project_dir), notes)
    if not enabled:
        return [], notes

    installs: dict[str, list[str]] = {}
    installed_file = claude_dir / "plugins" / "installed_plugins.json"
    if installed_file.is_file():
        installs = _install_paths(installed_file, notes)

    roots: list[SkillSource] = []
    seen: set[Path] = set()
    for plugin_id in enabled:
        plugin, _, marketplace = plugin_id.rpartition("@")
        if not _safe_name(plugin) or not _safe_name(marketplace):
            notes.append(f"ignored enabled plugin {plugin_id!r}: expected plugin@marketplace")
            continue

        bases = [
            Path(install) / "skills"
            for install in installs.get(plugin_id, [])
            if Path(install).is_absolute()
        ]
        if not bases:
            checkout = claude_dir / "plugins" / "marketplaces" / marketplace
            candidates = [
                checkout / "plugins" / plugin / "skills",
                checkout / plugin / "skills",
            ]
            bases = [candidate for candidate in candidates if _is_dir(candidate)][:1]
            if not bases:
                notes.append(f"enabled plugin {plugin_id!r} has no installed files; skipped")
                continue

        for base in bases:
            if base in seen:
                continue
            seen.add(base)
            roots.append(SkillSource("claude", "plugin", base))
    return roots, notes


def _settings_files(home: Path, project_dir: Path | None) -> list[Path]:
    """Settings files, least specific first, each file listed once.

    When the project folder is the home folder (or links to the same files), the files are
    read once, at their most specific position.
    """

    files = [home / ".claude" / "settings.json"]
    if project_dir is not None:
        project_claude = project_dir / ".claude"
        files.append(project_claude / "settings.json")
        files.append(project_claude / "settings.local.json")

    kept: list[Path] = []
    seen: set[Path] = set()
    for path in reversed(files):
        key = _resolved(path)
        if key in seen:
            continue
        seen.add(key)
        kept.append(path)
    kept.reverse()
    return kept


def _enabled_plugin_ids(settings_files: list[Path], notes: list[str]) -> list[str]:
    """Plugin ids that end up enabled. A more specific file overrides a less specific one."""

    merged: dict[str, bool] = {}
    for settings_path in settings_files:
        for plugin_id, value in _plugin_flags(settings_path, notes).items():
            merged[plugin_id] = value
    return sorted(plugin_id for plugin_id, value in merged.items() if value)


def _plugin_flags(settings_path: Path, notes: list[str]) -> dict[str, bool]:
    """Explicit true/false values in one settings file. Missing or unreadable files give none."""

    try:
        text = settings_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return {}  # Not a Claude Code user, or no plugins: nothing to report.
    except (OSError, UnicodeDecodeError) as exc:
        notes.append(f"could not read {settings_path}: {exc}")
        return {}
    try:
        data = json.loads(text)
    except ValueError as exc:
        notes.append(f"could not parse {settings_path}: {exc}")
        return {}
    if not isinstance(data, dict):
        notes.append(f"unexpected shape in {settings_path}; expected a JSON object")
        return {}
    enabled = data.get("enabledPlugins", {})
    if not isinstance(enabled, dict):
        notes.append(f"unexpected 'enabledPlugins' in {settings_path}; expected an object")
        return {}
    return {
        key: value
        for key, value in enabled.items()
        if isinstance(key, str) and isinstance(value, bool)
    }


def _resolved(path: Path) -> Path:
    try:
        return path.resolve()
    except OSError:
        return path


def _install_paths(path: Path, notes: list[str]) -> dict[str, list[str]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        notes.append(f"could not read {path}: {exc}")
        return {}
    found: dict[str, list[str]] = {}
    _collect_install_paths(data, None, found)
    return found


def _collect_install_paths(node: object, owner: str | None, out: dict[str, list[str]]) -> None:
    """Map ``plugin@marketplace`` keys to every ``installPath`` found beneath them."""

    if isinstance(node, dict):
        for key, value in node.items():
            if isinstance(key, str) and "@" in key:
                _collect_install_paths(value, key, out)
            elif key == "installPath" and isinstance(value, str) and owner is not None:
                out.setdefault(owner, []).append(value)
            else:
                _collect_install_paths(value, owner, out)
    elif isinstance(node, list):
        for item in node:
            _collect_install_paths(item, owner, out)


def _safe_name(name: str) -> bool:
    return bool(name) and name not in {".", ".."} and "/" not in name and "\\" not in name


def _is_dir(path: Path) -> bool:
    try:
        return path.is_dir()
    except OSError:
        return False
