"""SKILL.md / package parsing and manifest validation."""

from __future__ import annotations

import os
import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from skill_sentry_cli.core.cache.hash_utils import HashError, hash_skill_dir

MAX_SKILL_MD_BYTES = 1024 * 1024
MAX_TEXT_FILE_BYTES = 1024 * 1024
MAX_TEXT_TOTAL_BYTES = 4 * 1024 * 1024
FRONTMATTER_MAX_BYTES = 256 * 1024

_TEXT_SUFFIXES = frozenset(
    {
        ".md",
        ".markdown",
        ".txt",
        ".py",
        ".sh",
        ".bash",
        ".zsh",
        ".fish",
        ".js",
        ".mjs",
        ".cjs",
        ".ts",
        ".tsx",
        ".jsx",
        ".json",
        ".yaml",
        ".yml",
        ".toml",
        ".ini",
        ".cfg",
        ".ps1",
        ".rb",
        ".go",
        ".rs",
        ".java",
        ".kt",
        ".php",
        ".pl",
        ".lua",
        ".c",
        ".h",
        ".cc",
        ".cpp",
        ".hpp",
        ".bat",
        ".cmd",
        ".vbs",
        ".pyw",
        ".psd1",
        ".psm1",
        ".html",
        ".htm",
        ".xml",
        ".sql",
        ".svg",
    }
)

# Raster and vector images are analysed by the vision stage, not read as text.
IMAGE_SUFFIXES = frozenset(
    {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".tif", ".tiff", ".svg"}
)

_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_INTERPRETERS = frozenset({"python", "python3", "bash", "sh", "node", "deno", "ruby", "php"})
_ENTRYPOINT_KEYS = (
    "entrypoint",
    "entry_point",
    "entry",
    "command",
    "run",
)


class SkillParseError(RuntimeError):
    """The directory is not a usable Agent Skill package."""


@dataclass(frozen=True)
class PackageIssue:
    severity: str  # low | medium | high | critical
    message: str
    file: str = "SKILL.md"
    line: int = 1
    code: str | None = None
    # True when the issue reports content the scan did not read.  Such a gap keeps
    # the stage degraded, so the verdict can never be SAFE.
    coverage: bool = False


@dataclass(frozen=True)
class TextFile:
    path: Path
    relative: str
    text: str
    line_count: int
    truncated: bool = False

    def line(self, number: int) -> str | None:
        if number < 1 or number > self.line_count:
            return None
        return self.text.splitlines()[number - 1]


@dataclass
class SkillPackage:
    root: Path
    name: str
    description: str
    declared_intent: str
    manifest: dict[str, Any]
    frontmatter: dict[str, Any]
    body: str
    skill_md: str
    files: list[Path]
    text_files: list[TextFile]
    entrypoint: list[str] | None
    entrypoint_declared: bool
    content_hash: str
    issues: list[PackageIssue] = field(default_factory=list)

    @property
    def metadata(self) -> dict[str, Any]:
        return (
            self.frontmatter.get("metadata")
            if isinstance(self.frontmatter.get("metadata"), dict)
            else {}
        )

    @property
    def declared_network(self) -> list[str]:
        permissions = self.frontmatter.get("permissions")
        values: list[str] = []
        if isinstance(permissions, str):
            values.append(permissions)
        elif isinstance(permissions, list):
            values.extend(str(item) for item in permissions)
        elif isinstance(permissions, dict):
            network = permissions.get("network")
            if isinstance(network, str):
                values.append(network)
            elif isinstance(network, list):
                values.extend(str(item) for item in network)
        for key in ("network", "networks", "allowed_domains"):
            value = self.frontmatter.get(key)
            if isinstance(value, str):
                values.append(value)
            elif isinstance(value, list):
                values.extend(str(item) for item in value)
        return values


def _split_frontmatter(text: str) -> tuple[str, str, bool]:
    """Return ``(yaml_text, body, present)`` for a leading YAML block."""

    if not text.startswith("---"):
        return "", text, False
    first_newline = text.find("\n")
    if first_newline == -1:
        return "", text, False
    if text[:first_newline].strip() != "---":
        return "", text, False
    # Accept CRLF as well as LF.  On Windows, checked-out SKILL.md files and
    # Path.write_text() both commonly use CRLF; treating the trailing carriage
    # return as content made every such manifest look like it had no
    # frontmatter (and therefore produced a spurious high-severity issue).
    closing = re.search(r"(?m)^---[ \t]*\r?$", text[first_newline + 1 :])
    if closing is None:
        return "", text, False
    start = first_newline + 1
    end = start + closing.start()
    yaml_text = text[start:end]
    body = text[start + closing.end() :]
    return yaml_text, body.lstrip("\n"), True


MAX_YAML_DEPTH = 10
MAX_YAML_EVENTS = 20_000

# Windows device names are reserved in every directory and with any extension.
_RESERVED_DEVICE_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL"}
    | {f"COM{index}" for index in range(1, 10)}
    | {f"LPT{index}" for index in range(1, 10)}
)


def _path_name_issue(relative: str) -> str | None:
    """Return an issue message for reserved device names or alternate data streams."""

    for component in relative.split("/"):
        base = component.split(".", 1)[0].rstrip(" ").upper()
        if base in _RESERVED_DEVICE_NAMES:
            return f"reserved device name in path: {relative}"
        if ":" in component:
            return f"alternate data stream notation in path: {relative}"
    return None


def _check_yaml_structure(yaml_text: str) -> None:
    """Reject YAML that is deeply nested, uses aliases, or has too many nodes.

    Aliases are refused outright: they are the vehicle for "billion laughs"
    expansion, and skill frontmatter has no legitimate need for them.  The check
    walks parser events, so nothing is expanded before it is judged.
    """

    depth = 0
    events = 0
    try:
        for event in yaml.parse(yaml_text, Loader=yaml.SafeLoader):
            events += 1
            if events > MAX_YAML_EVENTS:
                raise SkillParseError("frontmatter has too many YAML nodes")
            if isinstance(event, yaml.AliasEvent):
                raise SkillParseError("YAML aliases are not allowed in frontmatter")
            if isinstance(event, (yaml.MappingStartEvent, yaml.SequenceStartEvent)):
                depth += 1
                if depth > MAX_YAML_DEPTH:
                    raise SkillParseError(f"frontmatter nests deeper than {MAX_YAML_DEPTH} levels")
            elif isinstance(event, (yaml.MappingEndEvent, yaml.SequenceEndEvent)):
                depth -= 1
    except yaml.YAMLError as exc:
        raise SkillParseError(f"invalid YAML frontmatter: {exc}") from exc


def _safe_yaml(yaml_text: str) -> dict[str, Any]:
    if len(yaml_text.encode("utf-8", "replace")) > FRONTMATTER_MAX_BYTES:
        raise SkillParseError("frontmatter exceeds 256 KiB")
    _check_yaml_structure(yaml_text)
    try:
        loaded = yaml.safe_load(yaml_text)
    except yaml.YAMLError as exc:
        raise SkillParseError(f"invalid YAML frontmatter: {exc}") from exc
    if loaded is None:
        return {}
    if not isinstance(loaded, dict):
        raise SkillParseError("frontmatter must be a YAML mapping")
    return loaded


def _unread_reason(path: Path, remaining: int) -> str:
    """Why a text candidate was not read, for the finding that reports it."""

    try:
        size = path.stat().st_size
    except OSError:
        return "unreadable"
    if size > MAX_TEXT_FILE_BYTES:
        return f"larger than {MAX_TEXT_FILE_BYTES // (1024 * 1024)} MiB"
    if remaining <= 0:
        return "skill text budget exhausted"
    return "binary or unreadable content"


def _read_text(path: Path, relative: str, remaining: int) -> TextFile | None:
    try:
        size = path.stat().st_size
    except OSError:
        return None
    if size > MAX_TEXT_FILE_BYTES or remaining <= 0:
        return None
    limit = min(size, remaining)
    try:
        with open(path, "rb") as handle:
            data = handle.read(limit)
    except OSError:
        return None
    if b"\x00" in data[:4096]:
        return None
    text = data.decode("utf-8", "replace")
    return TextFile(
        path=path,
        relative=relative,
        text=text,
        line_count=len(text.splitlines()) or 1,
        truncated=limit < size,
    )


def _is_text(relative: str) -> bool:
    suffix = Path(relative).suffix.lower()
    if suffix in _TEXT_SUFFIXES:
        return True
    # Extensionless scripts are common in skills (run, install, setup), at the
    # root as well as in subdirectories.  Binary content is excluded later by
    # the NUL-byte check in _read_text.
    return suffix == ""


def _walk_entries(root: Path) -> list[Path]:
    """Return every entry beneath ``root`` (files, directories, links), iteratively.

    Symlinks are listed but never descended into.  An explicit stack keeps deep
    trees from exhausting the recursion limit.
    """

    found: list[Path] = []
    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            entries = list(os.scandir(directory))
        except OSError as exc:
            raise SkillParseError(f"could not read {directory}: {exc}") from exc
        for entry in entries:
            path = Path(entry.path)
            found.append(path)
            if entry.is_dir(follow_symlinks=False):
                pending.append(path)
    return found


def _resolve_entrypoint(
    manifest: dict[str, Any], root: Path
) -> tuple[list[str] | None, bool, PackageIssue | None]:
    declared = False
    raw: Any = None
    for key in _ENTRYPOINT_KEYS:
        if manifest.get(key) is not None:
            raw = manifest[key]
            declared = True
            break
    if not declared:
        scripts = manifest.get("scripts")
        if isinstance(scripts, dict) and scripts:
            # Conventional package manifests map names to commands.  Pick
            # ``start``/``run`` when present, otherwise the first entry, but
            # remember that the author declared a launch surface.
            for key in ("start", "run", "main"):
                if key in scripts:
                    raw = scripts[key]
                    declared = True
                    break
            else:
                raw = next(iter(scripts.values()))
                declared = True
        elif isinstance(scripts, str) and scripts.strip():
            raw = scripts
            declared = True
    if not declared:
        return None, False, None

    if isinstance(raw, dict):
        # e.g. {"command": "python main.py", "args": [...]}
        command = raw.get("command") or raw.get("path")
        args = raw.get("args") or []
        if command is None:
            return None, True, PackageIssue("high", "manifest entrypoint object has no command")
        raw = [command, *args] if isinstance(args, list) else str(command)
    if isinstance(raw, str):
        try:
            tokens = shlex.split(raw, posix=True)
        except ValueError as exc:
            return (
                None,
                True,
                PackageIssue("high", f"manifest entrypoint is not shell-parseable: {exc}"),
            )
    elif isinstance(raw, (list, tuple)) and all(isinstance(item, (str, int)) for item in raw):
        tokens = [str(item) for item in raw]
    else:
        return None, True, PackageIssue("high", "manifest entrypoint must be a string or list")
    if not tokens:
        return None, True, PackageIssue("high", "manifest entrypoint is empty")

    candidate_index = 0
    if Path(tokens[0]).name in _INTERPRETERS:
        # python scripts/main.py --flag
        if len(tokens) < 2:
            return None, True, PackageIssue("high", "interpreter entrypoint has no script path")
        candidate_index = 1
    candidate = tokens[candidate_index]
    if candidate.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:[\\/]", candidate):
        return (
            None,
            True,
            PackageIssue("high", "manifest entrypoint must be relative to the skill root"),
        )
    rel = Path(candidate)
    if ".." in rel.parts:
        return None, True, PackageIssue("high", "manifest entrypoint escapes the skill root")
    target = (root / rel).resolve()
    try:
        target.relative_to(root.resolve())
    except ValueError:
        return None, True, PackageIssue("high", "manifest entrypoint escapes the skill root")
    if not target.is_file():
        return (
            None,
            True,
            PackageIssue(
                "high",
                f"declared entrypoint does not exist: {candidate}",
                code=candidate,
            ),
        )
    normalised = list(tokens)
    normalised[candidate_index] = str(rel).replace("\\", "/")
    if not normalised[0].startswith((".", "/")):
        # Preserve interpreter names; the sandbox image provides python/sh/node.
        normalised[0] = tokens[0]
    return normalised, True, None


def parse_skill(path: str | Path) -> SkillPackage:
    """Parse and validate a skill package without executing any of its code."""

    root = Path(path).expanduser()
    try:
        root = root.resolve(strict=True)
    except OSError as exc:
        raise SkillParseError(f"skill directory does not exist: {path}") from exc
    if not root.is_dir():
        raise SkillParseError(f"not a directory: {root}")
    skill_md_path = root / "SKILL.md"
    if not skill_md_path.is_file() or skill_md_path.is_symlink():
        raise SkillParseError(f"no SKILL.md found in {root}")
    try:
        raw_skill_md = skill_md_path.read_bytes()
    except OSError as exc:
        raise SkillParseError(f"could not read SKILL.md: {exc}") from exc
    if len(raw_skill_md) > MAX_SKILL_MD_BYTES:
        raise SkillParseError("SKILL.md exceeds 1 MiB")
    issues: list[PackageIssue] = []
    try:
        skill_md = raw_skill_md.decode("utf-8")
    except UnicodeDecodeError:
        # Analysed with replacement characters rather than refused: an invalid
        # byte must not hide the rest of the file from the scan.
        skill_md = raw_skill_md.decode("utf-8", "replace")
        issues.append(PackageIssue("high", "SKILL.md is not valid UTF-8"))
    yaml_text, body, present = _split_frontmatter(skill_md)
    manifest: dict[str, Any] = {}
    if not present:
        issues.append(PackageIssue("medium", "SKILL.md has no YAML frontmatter"))
    else:
        try:
            manifest = _safe_yaml(yaml_text)
        except SkillParseError as exc:
            issues.append(PackageIssue("high", str(exc)))
            manifest = {}

    name_raw = manifest.get("name")
    if isinstance(name_raw, str) and _NAME_RE.match(name_raw.strip()):
        name = name_raw.strip()
    else:
        name = root.name
        if name_raw is None:
            issues.append(PackageIssue("high", "frontmatter is missing required field: name"))
        else:
            issues.append(PackageIssue("high", "frontmatter name is not a valid skill identifier"))
        if not _NAME_RE.match(name):
            name = re.sub(r"[^A-Za-z0-9._-]+", "-", name).strip("-") or "unknown-skill"

    description_raw = manifest.get("description")
    if not isinstance(description_raw, str) or not description_raw.strip():
        description = ""
        issues.append(PackageIssue("high", "frontmatter is missing required field: description"))
    else:
        description = description_raw.strip()
        if len(description) > 4096:
            issues.append(PackageIssue("medium", "description exceeds 4096 characters"))
            description = description[:4096]

    entrypoint, entrypoint_declared, entry_issue = _resolve_entrypoint(manifest, root)
    if entry_issue is not None:
        issues.append(entry_issue)

    files: list[Path] = []
    text_files: list[TextFile] = []
    text_budget = MAX_TEXT_TOTAL_BYTES
    for candidate in sorted(_walk_entries(root), key=lambda p: p.relative_to(root).as_posix()):
        if candidate.is_symlink():
            issues.append(
                PackageIssue(
                    "high",
                    f"symlink is not allowed in a skill package: {candidate.relative_to(root).as_posix()}",
                )
            )
            continue
        name_issue = _path_name_issue(candidate.relative_to(root).as_posix())
        if name_issue is not None:
            # Reported as high, and the file is still analysed: a reserved name
            # must not hide content from the scan.
            issues.append(PackageIssue("high", name_issue))
        if candidate.is_dir():
            continue
        if not candidate.is_file():
            issues.append(
                PackageIssue(
                    "medium",
                    f"unsupported file type: {candidate.relative_to(root).as_posix()}",
                    coverage=True,
                )
            )
            continue
        files.append(candidate)
        relative = candidate.relative_to(root).as_posix()
        if relative == "SKILL.md":
            text_files.append(
                TextFile(
                    path=candidate,
                    relative=relative,
                    text=skill_md,
                    line_count=len(skill_md.splitlines()) or 1,
                )
            )
            text_budget -= len(raw_skill_md)
            continue
        if _is_text(relative):
            parsed = _read_text(candidate, relative, text_budget)
            if parsed is not None:
                text_files.append(parsed)
                text_budget -= len(parsed.text.encode("utf-8", "replace"))
                if parsed.truncated:
                    # The text budget ran out part-way through this file.  The
                    # unread tail is a gap, so it degrades the scan like any other.
                    issues.append(
                        PackageIssue(
                            "high",
                            f"text file only partially analysed: {relative} "
                            "(skill text budget exhausted)",
                            file=relative,
                            coverage=True,
                        )
                    )
            else:
                # A script the scan did not read is a gap, not a clean file.
                # The HIGH issue degrades the spec stage, so the verdict cannot be SAFE.
                issues.append(
                    PackageIssue(
                        "high",
                        f"text file not analysed: {relative} ({_unread_reason(candidate, text_budget)})",
                        file=relative,
                        coverage=True,
                    )
                )
        elif (suffix := Path(relative).suffix.lower()) not in IMAGE_SUFFIXES:
            # Neither text nor an image: the scan has no reader for it.  Images are
            # covered by the vision stage, so only other files are reported here.
            issues.append(
                PackageIssue(
                    "medium",
                    f"file not analysed: {relative} (unsupported file type {suffix}); "
                    "SkillSentry reads text, scripts and images only, so the package is "
                    "UNSCANNED. Review the file by hand, or remove it, before installing",
                    file=relative,
                    coverage=True,
                )
            )

    try:
        package_hash = hash_skill_dir(root)
    except HashError as exc:
        raise SkillParseError(str(exc)) from exc

    return SkillPackage(
        root=root,
        name=name,
        description=description,
        declared_intent=description,
        manifest=manifest,
        frontmatter=manifest,
        body=body,
        skill_md=skill_md,
        files=files,
        text_files=text_files,
        entrypoint=entrypoint,
        entrypoint_declared=entrypoint_declared,
        content_hash=package_hash.digest,
        issues=issues,
    )


__all__ = [
    "MAX_SKILL_MD_BYTES",
    "PackageIssue",
    "SkillPackage",
    "SkillParseError",
    "TextFile",
    "parse_skill",
]
