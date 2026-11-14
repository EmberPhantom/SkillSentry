"""Find every installed skill the built-in sources and the caller's extra paths name.

Rules:

* Each source base is listed one level deep. A child counts as a skill when it is a
  folder (symlinks followed) whose resolved path holds a regular ``SKILL.md``.
* Broken links, files and folders without ``SKILL.md`` are recorded in ``skipped``.
  Nothing here raises for filesystem trouble.
* Skills are deduplicated by resolved path. The first declaration wins; the others
  are kept as ``aliases`` and counted in ``duplicates_merged``.
* At most :data:`MAX_DISCOVERED_SKILLS` unique skills are kept. A note says when the
  cap cut the search short.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from skill_sentry_cli.core.discovery.claude_plugins import enabled_plugin_skill_roots
from skill_sentry_cli.core.discovery.sources import Scope, SkillSource, known_sources
from skill_sentry_cli.core.engine import MAX_DISCOVERED_SKILLS

SKILL_MANIFEST = "SKILL.md"

_SCOPE_RANK = {"project": 0, "user": 1, "plugin": 2}
_AGENT_RANK = {"claude": 0, "codex": 1, "agents": 2}
# How many folder levels below a source base a skill may sit (``synced/<id>/<skill>``).
_GROUP_DEPTH = 2


@dataclass(frozen=True)
class InstalledSkill:
    name: str
    agent: str
    scope: Scope
    declared_path: Path
    real_path: Path
    is_symlink: bool
    aliases: tuple[Path, ...] = ()


@dataclass
class DiscoveryResult:
    skills: list[InstalledSkill] = field(default_factory=list)
    checked: list[Path] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    duplicates_merged: int = 0


@dataclass(frozen=True)
class _Job:
    source: SkillSource
    path: Path
    direct: bool  # True when ``path`` is itself a skill folder, not a folder of skills


def discover_installed(
    *,
    home: Path,
    project_dir: Path | None,
    extra_paths: Sequence[Path] = (),
    agents: Sequence[str] = (),
    include_experimental: bool = False,
) -> DiscoveryResult:
    wanted = {name.strip().lower() for name in agents if name.strip()}

    def selected(agent: str) -> bool:
        return not wanted or agent in wanted

    result = DiscoveryResult()
    sources: list[SkillSource] = [
        source
        for source in known_sources(home, project_dir)
        if selected(source.agent) and (include_experimental or not source.experimental)
    ]
    if selected("claude"):
        plugin_roots, notes = enabled_plugin_skill_roots(home)
        sources.extend(plugin_roots)
        result.skipped.extend(notes)

    jobs: list[_Job] = [_Job(source, source.base, direct=False) for source in sources]
    # Custom paths were named by the user, so ``agents`` never filters them out.
    for raw in extra_paths:
        path = Path(raw).expanduser()
        source = SkillSource("custom", "custom", path)
        jobs.append(_Job(source, path, direct=_is_skill_folder(path)))

    # Stable sort: project, then user, then plugin, then the rest; claude, codex, agents
    # next. Experimental sources come last.
    jobs.sort(key=_job_rank)

    truncated = False
    for job in jobs:
        result.checked.append(job.path)
        if job.direct:
            if _consider(job.path, job.source, result):
                truncated = True
                break
            continue
        if job.source.agent == "custom" and not _is_dir(job.path):
            result.skipped.append(f"{job.path}: custom path not found or not a folder")
            continue
        truncated = _scan_base(job.source, result) or truncated
        if truncated:
            break

    if truncated:
        result.skipped.append(
            f"stopped after {MAX_DISCOVERED_SKILLS} skills; scan fewer locations "
            "(for example with --agent) to see the rest"
        )
    return result


def _job_rank(job: _Job) -> tuple[bool, int, int]:
    source = job.source
    return (
        source.experimental,
        _SCOPE_RANK.get(source.scope, 3),
        _AGENT_RANK.get(source.agent, 3),
    )


def _scan_base(source: SkillSource, result: DiscoveryResult) -> bool:
    """List ``source.base``. Returns True when the skill cap was reached."""

    return _scan_folder(source.base, source, result, depth=0)


def _scan_folder(folder: Path, source: SkillSource, result: DiscoveryResult, depth: int) -> bool:
    if not _is_dir(folder):
        return False
    try:
        children = sorted(folder.iterdir(), key=lambda child: child.name)
    except OSError as exc:
        result.skipped.append(f"{folder}: cannot list folder ({_reason(exc)})")
        return False

    for child in children:
        try:
            if child.is_symlink() and not child.exists():
                result.skipped.append(f"{child}: broken symlink")
                continue
            if not child.is_dir():
                if depth == 0:
                    result.skipped.append(f"{child}: not a skill folder")
                continue
            if child.name.startswith(".") and depth > 0:
                continue
            if not (child / SKILL_MANIFEST).is_file() and depth < _GROUP_DEPTH:
                # A group folder (for example ``skills/synced/<id>/<skill>``): look one
                # level further down, within a fixed bound.
                before = (len(result.skills), result.duplicates_merged)
                if _scan_folder(child, source, result, depth + 1):
                    return True
                if depth == 0 and before == (len(result.skills), result.duplicates_merged):
                    result.skipped.append(f"{child}: no {SKILL_MANIFEST}")
                continue
        except OSError as exc:
            result.skipped.append(f"{child}: cannot read ({_reason(exc)})")
            continue
        if _consider(child, source, result):
            return True
    return False


def _consider(declared: Path, source: SkillSource, result: DiscoveryResult) -> bool:
    """Record ``declared`` as a skill, or as a duplicate or skip. True when the cap stops us."""

    try:
        real = declared.resolve()
        has_manifest = (real / SKILL_MANIFEST).is_file()
    except OSError as exc:
        result.skipped.append(f"{declared}: cannot read ({_reason(exc)})")
        return False
    if not has_manifest:
        result.skipped.append(f"{declared}: no {SKILL_MANIFEST}")
        return False

    for index, existing in enumerate(result.skills):
        if existing.real_path == real:
            result.duplicates_merged += 1
            if declared != existing.declared_path and declared not in existing.aliases:
                result.skills[index] = dataclasses.replace(
                    existing, aliases=(*existing.aliases, declared)
                )
            return False

    if len(result.skills) >= MAX_DISCOVERED_SKILLS:
        return True
    result.skills.append(
        InstalledSkill(
            name=declared.name,
            agent=source.agent,
            scope=source.scope,
            declared_path=declared,
            real_path=real,
            is_symlink=declared.is_symlink(),
        )
    )
    return False


def _is_skill_folder(path: Path) -> bool:
    try:
        return (path / SKILL_MANIFEST).is_file()
    except OSError:
        return False


def _is_dir(path: Path) -> bool:
    try:
        return path.is_dir()
    except OSError:
        return False


def _reason(exc: OSError) -> str:
    return exc.strerror or type(exc).__name__
