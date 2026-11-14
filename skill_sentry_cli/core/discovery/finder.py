"""Find every installed skill the built-in sources and the caller's extra paths name.

Rules:

* Each source base is listed one level deep. A child counts as a skill when it is a
  folder (symlinks followed) whose resolved path holds a regular ``SKILL.md``.
* Broken links, files and folders without ``SKILL.md`` are recorded in ``skipped``.
  Nothing here raises for filesystem trouble.
* Skills are deduplicated by resolved path. The first declaration wins; the others
  are kept as ``aliases`` and counted in ``duplicates_merged``.
* At most :data:`MAX_DISCOVERED_SKILLS` unique skills are kept. When the cap cuts the
  search short, the remaining unique skills are counted (up to a fixed bound) and reported
  in :attr:`DiscoveryResult.not_scanned`.
* Hidden (dot) folders and files inside a source base are skipped silently, at every
  depth. Dot folders named directly as extra paths are still scanned.
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
# Upper bound on how many skills beyond the cap are counted (not recorded) for the note.
_COUNT_BOUND = 10_000


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
    # Unique skills found beyond the cap (counted, not recorded) when the search was cut short.
    not_scanned: int = 0
    # Resolved real path -> index into ``skills``; keeps the duplicate check O(1).
    _index: dict[Path, int] = field(default_factory=dict, repr=False, compare=False)
    _capped: bool = field(default=False, repr=False, compare=False)
    _count_bound_hit: bool = field(default=False, repr=False, compare=False)
    _beyond_cap: set[Path] = field(default_factory=set, repr=False, compare=False)


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
        plugin_roots, notes = enabled_plugin_skill_roots(home, project_dir)
        sources.extend(plugin_roots)
        result.skipped.extend(notes)

    sources = _drop_project_sources_shadowed_by_user(sources)
    jobs: list[_Job] = [_Job(source, source.base, direct=False) for source in sources]
    # Custom paths were named by the user, so ``agents`` never filters them out.
    for raw in extra_paths:
        path = Path(raw).expanduser()
        source = SkillSource("custom", "custom", path)
        jobs.append(_Job(source, path, direct=_is_skill_folder(path)))

    # Stable sort: project, then user, then plugin, then the rest; claude, codex, agents
    # next. Experimental sources come last.
    jobs.sort(key=_job_rank)

    for job in jobs:
        result.checked.append(job.path)
        if job.direct:
            if _consider(job.path, job.source, result):
                break
            continue
        if job.source.agent == "custom" and not _is_dir(job.path):
            result.skipped.append(f"{job.path}: custom path not found or not a folder")
            continue
        if _scan_base(job.source, result):
            break

    if result._capped:
        counted = len(result._beyond_cap)
        result.not_scanned = counted
        qualifier = "at least " if result._count_bound_hit else ""
        result.skipped.append(
            f"stopped after {MAX_DISCOVERED_SKILLS} skills; {qualifier}{counted} more not "
            "scanned; narrow the search (for example with --agent)"
        )
    return result


def _drop_project_sources_shadowed_by_user(sources: list[SkillSource]) -> list[SkillSource]:
    """Remove project sources that point at the same folder as a user source.

    When the project folder is the home folder (or a link to it), ``<project>/.claude/skills``
    is ``~/.claude/skills``. The user scope wins so the skills are not labelled project skills.
    """

    user_bases = {_resolved(source.base) for source in sources if source.scope == "user"}
    return [
        source
        for source in sources
        if not (source.scope == "project" and _resolved(source.base) in user_bases)
    ]


def _resolved(path: Path) -> Path:
    try:
        return path.resolve()
    except OSError:
        return path


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
        if child.name.startswith("."):
            continue  # Hidden entries are never skills here, however deep they sit.
        try:
            if child.is_symlink() and not child.exists():
                result.skipped.append(f"{child}: broken symlink")
                continue
            if not child.is_dir():
                if depth == 0:
                    result.skipped.append(f"{child}: not a skill folder")
                continue
            if not (child / SKILL_MANIFEST).is_file() and depth < _GROUP_DEPTH:
                # A group folder (for example ``skills/synced/<id>/<skill>``): look one
                # level further down, within a fixed bound.
                before = _progress(result)
                if _scan_folder(child, source, result, depth + 1):
                    return True
                if depth == 0 and before == _progress(result):
                    result.skipped.append(f"{child}: no {SKILL_MANIFEST}")
                continue
        except OSError as exc:
            result.skipped.append(f"{child}: cannot read ({_reason(exc)})")
            continue
        if _consider(child, source, result):
            return True
    return False


def _progress(result: DiscoveryResult) -> tuple[int, int, int]:
    """Changes that show a folder held skills, whether recorded, merged or only counted."""
    return (len(result.skills), result.duplicates_merged, len(result._beyond_cap))


def _consider(declared: Path, source: SkillSource, result: DiscoveryResult) -> bool:
    """Record ``declared`` as a skill, a duplicate or a skip.

    Returns True only when the search must stop altogether: the cap was reached and the
    count of skills beyond it reached :data:`_COUNT_BOUND`.
    """

    try:
        real = declared.resolve()
        has_manifest = (real / SKILL_MANIFEST).is_file()
    except OSError as exc:
        result.skipped.append(f"{declared}: cannot read ({_reason(exc)})")
        return False
    if not has_manifest:
        result.skipped.append(f"{declared}: no {SKILL_MANIFEST}")
        return False

    known = result._index.get(real)
    if known is not None:
        existing = result.skills[known]
        # Only a different declared path is a duplicate. Meeting the same path again
        # (two sources that cover one folder) is not.
        if declared != existing.declared_path and declared not in existing.aliases:
            result.duplicates_merged += 1
            result.skills[known] = dataclasses.replace(
                existing, aliases=(*existing.aliases, declared)
            )
        return False

    if len(result.skills) >= MAX_DISCOVERED_SKILLS:
        result._capped = True
        if real in result._beyond_cap:
            return False
        if len(result._beyond_cap) >= _COUNT_BOUND:
            result._count_bound_hit = True
            return True
        result._beyond_cap.add(real)
        return False
    result._index[real] = len(result.skills)
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
