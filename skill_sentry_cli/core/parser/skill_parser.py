"""SKILL.md / package parsing and manifest validation."""

from __future__ import annotations

import hashlib
import os
import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from skill_sentry_cli.core.cache.hash_utils import MAX_TOTAL_BYTES, HashError, hash_skill_dir
from skill_sentry_cli.core.contracts import COVERAGE_GAP
from skill_sentry_cli.core.parser.opaque import (
    AUDIO_VIDEO_KINDS,
    MAX_BENIGN_AV_BYTES,
    MAX_BENIGN_MEDIA_BYTES,
    NEAR_CAP_BYTES,
    classify,
    image_mismatch,
)
from skill_sentry_cli.core.parser.opaque import sniff as _sniff
from skill_sentry_cli.core.parser.priority import PRIORITY_EXECUTABLE, file_priority
from skill_sentry_cli.core.parser.readers import is_reader_file, read_special

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
        # Plain-text data and documents. Read as text, last (see ``priority.DATA_SUFFIXES``).
        ".mdx",
        ".rst",
        ".tex",
        ".csv",
        ".tsv",
        ".jsonl",
        ".ndjson",
        ".log",
        ".lock",
        ".diff",
        ".patch",
        # Style sheets and property files, read as text.
        ".css",
        ".scss",
        ".sass",
        ".less",
        ".plist",
        ".properties",
        ".conf",
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
    severity: str  # note | low | medium | high | critical
    message: str
    file: str = "SKILL.md"
    line: int = 1
    code: str | None = None
    # True when the issue reports content the scan did not read.  Such a gap keeps
    # the stage degraded, so the verdict can never be SAFE.
    coverage: bool = False
    # Finding type for the report; None means a manifest issue.
    kind: str | None = None


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


@dataclass(frozen=True)
class AssetInfo:
    """A file listed by type and hash, not read: an image, font, audio or video file.

    Only its header was checked. Nothing reads or runs such a file, so it is not a coverage gap;
    an executable, an unrecognised binary, or a file whose header does not fit its name is.
    """

    relative: str
    kind: str
    size: int
    sha256: str


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
    assets: list[AssetInfo] = field(default_factory=list)

    @property
    def metadata(self) -> dict[str, Any]:
        # Read once into a local so the isinstance check narrows the type.
        metadata = self.frontmatter.get("metadata")
        return metadata if isinstance(metadata, dict) else {}

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


def _check_package_size(entries: list[Path]) -> None:
    """Refuse a package over the size cap before any file is read or any model is called."""

    total = 0
    for entry in entries:
        try:
            info = entry.lstat()
        except OSError:
            continue
        if entry.is_symlink() or not entry.is_file():
            continue
        total += info.st_size
        if total > MAX_TOTAL_BYTES:
            raise SkillParseError(
                f"skill package is larger than {MAX_TOTAL_BYTES // (1024 * 1024)} MiB, the most "
                "SkillSentry will scan. Remove large or generated files (models, datasets, "
                "archives, build output) from the skill"
            )


def _mib(size: int) -> str:
    return f"{size / (1024 * 1024):.1f} MiB" if size >= 1024 * 1024 else f"{size // 1024} KiB"


def _size_of(path: Path) -> int:
    try:
        return path.stat().st_size
    except OSError:
        return 0


def _opaque_issue(path: Path, relative: str, *, text_reason: str | None) -> PackageIssue:
    """The issue for a file the scan could not read.

    ``text_reason`` is set for a file that should have been text (a script or a document).
    Severity: a program (ELF, PE, Mach-O) or a file close to the package size cap is HIGH;
    an unread script is HIGH, because it is code the scan could not see; a small image or font
    is a NOTE; anything else is MEDIUM.
    """

    size = _size_of(path)
    info = classify(path, size)
    size_text = _mib(size)
    if info.kind == "executable":
        return PackageIssue(
            "high",
            f"opaque content: {relative} is an {info.label} ({size_text}). The scan cannot "
            "inspect compiled code. Ship the source instead, or remove the file",
            file=relative,
            coverage=True,
            kind="opaque-content",
        )
    if size >= NEAR_CAP_BYTES:
        return PackageIssue(
            "high",
            f"opaque content: {relative} is {size_text}, close to the {MAX_TOTAL_BYTES // (1024 * 1024)} "
            "MiB package limit, and was not analysed",
            file=relative,
            coverage=True,
            kind=COVERAGE_GAP,
        )
    if text_reason is not None:
        return PackageIssue(
            "high",
            f"text file not analysed: {relative} ({text_reason}; {info.label}, {size_text})",
            file=relative,
            coverage=True,
            kind=COVERAGE_GAP,
        )
    if info.kind == "media" and size <= _media_limit(info):
        return PackageIssue(
            "note",
            f"{relative} is a {info.label} ({size_text}). It is recognised by its header only "
            "and its content is not analysed",
            file=relative,
            kind="opaque-content",
        )
    suffix = Path(relative).suffix.lower() or "(no extension)"
    return PackageIssue(
        "medium",
        f"file not analysed: {relative} ({info.label}, {size_text}, file type {suffix}). "
        "SkillSentry reads text, scripts and images only, so the package is UNSCANNED. "
        "Review the file by hand, or remove it, before installing",
        file=relative,
        coverage=True,
        kind="opaque-content",
    )


def _media_kind(info: Any) -> str:
    """The media format of a recognised file, from its label (``"mp3 file"`` is ``mp3``)."""

    return str(info.label).split(" ", 1)[0]


def _media_limit(info: Any) -> int:
    return MAX_BENIGN_AV_BYTES if _media_kind(info) in AUDIO_VIDEO_KINDS else MAX_BENIGN_MEDIA_BYTES


def _asset_info(path: Path, relative: str) -> AssetInfo | None:
    """Type and hash a recognised, small-enough media file. ``None`` for anything else."""

    size = _size_of(path)
    info = classify(path, size)
    if info.kind != "media" or size > _media_limit(info):
        return None
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
    except OSError:
        return None
    return AssetInfo(relative, _media_kind(info), size, digest.hexdigest())


def _read_order(path: Path, relative: str) -> tuple[int, int, str]:
    """Where a text file stands in the budget queue: tier, then smaller first, then path.

    A file that starts with ``#!`` is a script whatever it is called, so it is read with the
    scripts. Smaller files go first inside a tier, so one large file cannot starve many small ones.
    """

    tier = file_priority(relative)
    if tier > PRIORITY_EXECUTABLE:
        try:
            with path.open("rb") as handle:
                if handle.read(2) == b"#!":
                    tier = PRIORITY_EXECUTABLE
        except OSError:
            pass
    return tier, _size_of(path), relative


def _image_issue(path: Path, relative: str) -> PackageIssue | None:
    """An issue when a file named like an image is not one (or is a program)."""

    size = _size_of(path)
    mismatch = image_mismatch(path)
    if mismatch is not None and mismatch.kind == "executable":
        return _opaque_issue(path, relative, text_reason=None)
    if mismatch is not None:
        return PackageIssue(
            "medium",
            f"image not analysed: {relative} has {mismatch.label} ({_mib(size)}), so the "
            "vision stage cannot read it",
            file=relative,
            coverage=True,
            kind="opaque-content",
        )
    if size >= NEAR_CAP_BYTES:
        return _opaque_issue(path, relative, text_reason=None)
    return None


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


_BINARY_SUFFIXES = frozenset(
    {
        ".exe", ".dll", ".so", ".dylib", ".bin", ".o", ".a", ".class", ".pyc", ".pyd", ".jar",
        ".war", ".apk", ".wasm", ".db", ".sqlite", ".sqlite3", ".pkl", ".pickle", ".npy", ".npz",
        ".parquet", ".onnx", ".pt", ".pth", ".safetensors", ".ckpt", ".h5", ".7z", ".rar", ".iso",
        ".dmg", ".ico", ".icns", ".mp3", ".mp4", ".wav", ".ogg", ".flac", ".mov", ".webm", ".avi",
        ".mkv", ".woff", ".woff2", ".ttf", ".otf", ".eot", ".doc", ".xls", ".ppt", ".pdf",
    }
)  # fmt: skip


def classify_header(head: bytes) -> bool:
    """True when the bytes start like a program or a known media file."""

    executable, media = _sniff(head)
    return bool(executable or media)


def _looks_like_text(path: Path, relative: str) -> bool:
    """A file with a suffix the scan does not know, but whose bytes are plain text.

    Source and template files come in many suffixes (``.xsd``, ``.j2``, ``.tmpl``, ``.vue``,
    ``.swift``, ``.gd``). Reading them as text costs nothing, and a file with a NUL byte, a
    program header or mostly undecodable bytes is not text, so it stays an unread file.
    """

    suffix = Path(relative).suffix.lower()
    if suffix in _BINARY_SUFFIXES or suffix in IMAGE_SUFFIXES:
        return False
    try:
        with path.open("rb") as handle:
            head = handle.read(8192)
    except OSError:
        return False
    if not head or b"\x00" in head or classify_header(head):
        return False
    decoded = head.decode("utf-8", "replace")
    return decoded.count("\ufffd") <= max(2, len(decoded) // 100)


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


def _names_installed_command(candidate: str, candidate_index: int) -> bool:
    """True for a bare command name: no directory, no suffix, and not an interpreter's script."""

    return (
        candidate_index == 0
        and re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{1,63}", candidate) is not None
        and not Path(candidate).suffix
    )


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
            return (
                None,
                True,
                PackageIssue(
                    "high", "manifest entrypoint object has no command", kind="manifest-entrypoint"
                ),
            )
        raw = [command, *args] if isinstance(args, list) else str(command)
    if isinstance(raw, str):
        try:
            tokens = shlex.split(raw, posix=True)
        except ValueError as exc:
            return (
                None,
                True,
                PackageIssue(
                    "high",
                    f"manifest entrypoint is not shell-parseable: {exc}",
                    kind="manifest-entrypoint",
                ),
            )
    elif isinstance(raw, (list, tuple)) and all(isinstance(item, (str, int)) for item in raw):
        tokens = [str(item) for item in raw]
    else:
        return (
            None,
            True,
            PackageIssue(
                "high", "manifest entrypoint must be a string or list", kind="manifest-entrypoint"
            ),
        )
    if not tokens:
        return (
            None,
            True,
            PackageIssue("high", "manifest entrypoint is empty", kind="manifest-entrypoint"),
        )

    candidate_index = 0
    if Path(tokens[0]).name in _INTERPRETERS:
        # python scripts/main.py --flag
        if len(tokens) < 2:
            return (
                None,
                True,
                PackageIssue(
                    "high", "interpreter entrypoint has no script path", kind="manifest-entrypoint"
                ),
            )
        candidate_index = 1
    candidate = tokens[candidate_index]
    if candidate.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:[\\/]", candidate):
        return (
            None,
            True,
            PackageIssue(
                "high",
                "manifest entrypoint must be relative to the skill root",
                kind="manifest-entrypoint",
            ),
        )
    rel = Path(candidate)
    if ".." in rel.parts:
        return (
            None,
            True,
            PackageIssue(
                "high", "manifest entrypoint escapes the skill root", kind="manifest-entrypoint"
            ),
        )
    target = (root / rel).resolve()
    try:
        target.relative_to(root.resolve())
    except ValueError:
        return (
            None,
            True,
            PackageIssue(
                "high", "manifest entrypoint escapes the skill root", kind="manifest-entrypoint"
            ),
        )
    if not target.is_file() and _names_installed_command(candidate, candidate_index):
        # ``entry_point: some-cli`` names a program installed elsewhere, as a Python or npm
        # package does. It is not a file in this package and nothing here can run it, so it is
        # recorded and not run. A path, a file name with a suffix, or a script for an
        # interpreter that does not exist is still an error.
        return (
            None,
            False,
            PackageIssue(
                # A note, not a finding: a finding of any severity would count as independent
                # evidence for a model's claim, and this one says nothing is wrong.
                "note",
                f"entrypoint {candidate!r} names an installed command, not a file in the "
                "package; it was not run",
                code=candidate,
                kind="manifest-entrypoint-command",
            ),
        )
    if not target.is_file():
        return (
            None,
            True,
            PackageIssue(
                "high",
                f"declared entrypoint does not exist: {candidate}",
                code=candidate,
                kind="manifest-entrypoint",
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
        issues.append(PackageIssue("high", "SKILL.md is not valid UTF-8", kind="package-encoding"))
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
    assets: list[AssetInfo] = []
    # SKILL.md is already in memory and always counts first against the budget.
    text_budget = MAX_TEXT_TOTAL_BYTES - len(raw_skill_md)
    text_files.append(
        TextFile(
            path=skill_md_path,
            relative="SKILL.md",
            text=skill_md,
            line_count=len(skill_md.splitlines()) or 1,
        )
    )
    files.append(skill_md_path)
    entries = _walk_entries(root)
    _check_package_size(entries)
    pending_text: list[tuple[Path, str]] = []
    pending_special: list[tuple[Path, str]] = []
    for candidate in sorted(entries, key=lambda p: p.relative_to(root).as_posix()):
        if candidate.is_symlink():
            issues.append(
                PackageIssue(
                    "high",
                    f"symlink is not allowed in a skill package: {candidate.relative_to(root).as_posix()}",
                    file=candidate.relative_to(root).as_posix(),
                    kind="package-symlink",
                )
            )
            continue
        name_issue = _path_name_issue(candidate.relative_to(root).as_posix())
        if name_issue is not None:
            # Reported as high, and the file is still analysed: a reserved name
            # must not hide content from the scan.
            issues.append(
                PackageIssue(
                    "high",
                    name_issue,
                    file=candidate.relative_to(root).as_posix(),
                    kind="package-name",
                )
            )
        if candidate.is_dir():
            continue
        if not candidate.is_file():
            issues.append(
                PackageIssue(
                    "medium",
                    f"unsupported file type: {candidate.relative_to(root).as_posix()}",
                    coverage=True,
                    kind=COVERAGE_GAP,
                )
            )
            continue
        relative = candidate.relative_to(root).as_posix()
        if relative == "SKILL.md":
            continue  # already read above
        files.append(candidate)
        if _is_text(relative):
            # Reading is deferred: the text budget is spent in priority order, below, and not in
            # the order the paths happen to sort.
            pending_text.append((candidate, relative))
        elif _looks_like_text(candidate, relative) and not is_reader_file(relative):
            pending_text.append((candidate, relative))
        elif is_reader_file(relative):
            # A notebook, an office document, a PDF or an archive: read in memory below.
            pending_special.append((candidate, relative))
        elif Path(relative).suffix.lower() not in IMAGE_SUFFIXES:
            # Neither text nor an image: the scan has no reader for it.  A recognised audio,
            # video or font file is listed by type and hash; anything else is reported.
            # A recognised one is only a note; the issue says so.
            asset = _asset_info(candidate, relative)
            if asset is not None:
                assets.append(asset)
            issues.append(_opaque_issue(candidate, relative, text_reason=None))
        else:
            # An image is read by the vision stage, but only if it is an image: a program
            # or random data with an image name must not pass as one.
            image_issue = _image_issue(candidate, relative)
            if image_issue is not None:
                issues.append(image_issue)
            else:
                asset = _asset_info(candidate, relative)
                if asset is not None:
                    assets.append(asset)

    # Spend the text budget on the files that can act first: scripts and config, then
    # instruction text, then reference material and data. A script that sorts last is read
    # before a huge docs folder that sorts first.
    for candidate, relative in sorted(pending_text, key=lambda item: _read_order(item[0], item[1])):
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
                        kind=COVERAGE_GAP,
                    )
                )
        else:
            # A script the scan did not read is a gap, not a clean file.
            # The HIGH issue degrades the spec stage, so the verdict cannot be SAFE.
            issues.append(
                _opaque_issue(
                    candidate, relative, text_reason=_unread_reason(candidate, text_budget)
                )
            )
    # Notebooks, documents, PDFs and archives are read in memory, after the text, with what is
    # left of the budget. Nothing is extracted to disk or run.
    for candidate, relative in pending_special:
        outcome = read_special(candidate, relative)
        issues.extend(outcome.issues)
        for label, text in outcome.texts:
            room = text_budget
            if room <= 0:
                issues.append(
                    PackageIssue(
                        "high",
                        f"text file not analysed: {label} (skill text budget exhausted)",
                        file=relative,
                        coverage=True,
                        kind=COVERAGE_GAP,
                    )
                )
                continue
            clipped = text.encode("utf-8", "replace")[:room].decode("utf-8", "ignore")
            text_files.append(
                TextFile(
                    path=candidate,
                    relative=label,
                    text=clipped,
                    line_count=len(clipped.splitlines()) or 1,
                    truncated=len(clipped) < len(text),
                )
            )
            text_budget -= len(clipped.encode("utf-8", "replace"))
            if len(clipped) < len(text):
                issues.append(
                    PackageIssue(
                        "high",
                        f"text file only partially analysed: {label} (skill text budget exhausted)",
                        file=relative,
                        coverage=True,
                        kind=COVERAGE_GAP,
                    )
                )
    # Downstream code and tests see files in path order, as before.
    text_files.sort(key=lambda item: item.relative)
    files.sort(key=lambda item: item.relative_to(root).as_posix())

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
        assets=assets,
    )


__all__ = [
    "MAX_SKILL_MD_BYTES",
    "AssetInfo",
    "PackageIssue",
    "SkillPackage",
    "SkillParseError",
    "TextFile",
    "parse_skill",
]
