"""
Skill Package Parser & Spec Validator (Stage 1).

Parses SKILL.md frontmatter, inventories scripts and assets, enforces
resource limits, validates against the Agent Skill Open Standard, and
defends against parser-level exploits (path traversal, YAML bombs,
Windows path anomalies).

CL-D2-1 · REQ-SPEC-01/02 · Source: docs/02-architecture.md §2.3,
docs/04-security.md §4.6, developer-2/03-functional-specifications.md Cap A.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
from pathlib import Path, PurePosixPath
from typing import Any, Optional

import frontmatter
import yaml

from skillsentry_dev2.contracts import (
    AssetFile,
    Finding,
    PackageManifest,
    ScriptFile,
    StageResult,
)

# ── Constants ───────────────────────────────────────────────────────────

# Max file sizes and counts (docs/04-security.md §4.6, spec Cap A §4)
MAX_FILE_COUNT = 1000
MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024        # 10 MB per file
MAX_PACKAGE_SIZE_BYTES = 50 * 1024 * 1024     # 50 MB total
MAX_YAML_DEPTH = 10
MAX_DESCRIPTION_LENGTH = 1024
MAX_NAME_LENGTH = 64
MAX_SKILLMD_SIZE = 1 * 1024 * 1024            # 1 MB for SKILL.md itself

# Skill name validation pattern (alphanumeric with dashes/underscores)
SKILL_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9_-]+$")

# Reserved Windows/DOS device names (CWE-22, CWE-66)
WINDOWS_RESERVED_NAMES = frozenset({
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
})

# Directories and files to exclude from inventory
EXCLUDED_DIRS = frozenset({".git", "__pycache__", ".mypy_cache", ".pytest_cache", "node_modules"})
EXCLUDED_FILES = frozenset({".DS_Store"})
EXCLUDED_EXTENSIONS = frozenset({".pyc", ".pyo"})

# Script file extensions
SCRIPT_EXTENSIONS = frozenset({".py", ".sh", ".bash", ".js", ".mjs", ".ts"})

# Image/asset extensions
IMAGE_EXTENSIONS = frozenset({".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".svg"})


# ── Path Safety ─────────────────────────────────────────────────────────

def _normalize_windows_path(path_str: str) -> str:
    """Normalize a Windows path input to a clean string.

    Strips surrounding quotes (PowerShell auto-completion), extended-length
    prefixes (\\\\?\\), and normalizes separators.
    """
    # Strip surrounding quotes
    path_str = path_str.strip().strip('"').strip("'")
    # Strip Windows extended-length prefix
    if path_str.startswith("\\\\?\\"):
        path_str = path_str[4:]
    return path_str


def _check_reserved_device_name(name: str) -> bool:
    """Check if a filename is a reserved Windows/DOS device name."""
    # Device names are case-insensitive and may have extensions
    base = name.split(".")[0].upper()
    return base in WINDOWS_RESERVED_NAMES


def _check_alternate_data_stream(path_str: str) -> bool:
    """Check for NTFS Alternate Data Stream separators."""
    # After removing drive letter (e.g., C:), check for remaining colons
    # Drive letter pattern: single letter followed by colon at start
    cleaned = path_str
    if len(cleaned) >= 2 and cleaned[1] == ":" and cleaned[0].isalpha():
        cleaned = cleaned[2:]
    return ":" in cleaned


def _is_path_safe(file_path: Path, root: Path) -> bool:
    """Verify a path is contained within the package root.

    Resolves symlinks and checks containment. Returns False for
    paths that escape the root boundary.
    """
    try:
        resolved = file_path.resolve()
        root_resolved = root.resolve()
        # Use os.path.commonpath for robust containment check
        common = os.path.commonpath([str(root_resolved), str(resolved)])
        return common == str(root_resolved)
    except (ValueError, OSError):
        return False


def _to_posix_relative(file_path: Path, root: Path) -> str:
    """Convert a path to a POSIX-normalized relative path."""
    try:
        rel = file_path.resolve().relative_to(root.resolve())
        return str(PurePosixPath(rel))
    except ValueError:
        # Should not happen if _is_path_safe passed
        raise ValueError(f"Path {file_path} is not relative to {root}")


# ── YAML Safety ─────────────────────────────────────────────────────────

class _DepthLimitedLoader(yaml.SafeLoader):
    """SafeLoader with recursion depth limit to prevent YAML bombs."""
    MAX_DEPTH = MAX_YAML_DEPTH
    _depth = 0


def _depth_limited_construct(loader: _DepthLimitedLoader, node: yaml.Node) -> Any:
    loader._depth += 1
    if loader._depth > _DepthLimitedLoader.MAX_DEPTH:
        raise yaml.YAMLError(
            f"YAML nesting depth exceeds maximum of {_DepthLimitedLoader.MAX_DEPTH}"
        )
    if isinstance(node, yaml.MappingNode):
        result = loader.construct_mapping(node, deep=True)
    elif isinstance(node, yaml.SequenceNode):
        result = loader.construct_sequence(node, deep=True)
    else:
        result = loader.construct_scalar(node)
    loader._depth -= 1
    return result


# Register the depth-limited constructors
for _tag in ("tag:yaml.org,2002:map", "tag:yaml.org,2002:seq"):
    _DepthLimitedLoader.add_constructor(_tag, _depth_limited_construct)


# ── Core Parser ─────────────────────────────────────────────────────────

def parse_package(skill_dir: str | Path) -> tuple[PackageManifest | None, StageResult]:
    """Parse a skill package directory and return manifest + StageResult.

    This is the entry point for Stage 1 of the pipeline.

    Args:
        skill_dir: Path to the skill package directory.

    Returns:
        Tuple of (PackageManifest or None if critically malformed, StageResult).
    """
    findings: list[Finding] = []
    skill_path = Path(_normalize_windows_path(str(skill_dir)))

    if not skill_path.exists():
        findings.append(Finding(
            stage="spec",
            severity="critical",
            message=f"Skill package path does not exist: {skill_path}",
        ))
        return None, StageResult(stage="spec", findings=findings, degraded=True)

    if not skill_path.is_dir():
        findings.append(Finding(
            stage="spec",
            severity="critical",
            message=f"Skill package path is not a directory: {skill_path}",
        ))
        return None, StageResult(stage="spec", findings=findings, degraded=True)

    root = skill_path.resolve()

    # Parse SKILL.md frontmatter
    name, description, trigger_keywords, raw_fm, fm_findings = _parse_frontmatter(root)
    findings.extend(fm_findings)

    # Inventory files
    scripts, assets, total_size, inv_findings = _inventory_files(root)
    findings.extend(inv_findings)

    manifest = PackageManifest(
        name=name or root.name,
        description=description or "",
        trigger_keywords=trigger_keywords or [],
        canonical_root_posix=str(PurePosixPath(root)),
        scripts=scripts,
        assets=assets,
        total_size_bytes=total_size,
        raw_frontmatter=raw_fm,
    )

    return manifest, StageResult(stage="spec", findings=findings)


def _parse_frontmatter(
    root: Path,
) -> tuple[Optional[str], Optional[str], Optional[list[str]], Optional[dict], list[Finding]]:
    """Parse SKILL.md frontmatter and validate against spec.

    Returns (name, description, trigger_keywords, raw_frontmatter, findings).
    """
    findings: list[Finding] = []
    skill_md = root / "SKILL.md"

    if not skill_md.exists():
        findings.append(Finding(
            stage="spec",
            severity="high",
            message="No SKILL.md found in package root",
        ))
        return None, None, None, None, findings

    # Check SKILL.md size
    md_size = skill_md.stat().st_size
    if md_size > MAX_SKILLMD_SIZE:
        findings.append(Finding(
            stage="spec",
            severity="medium",
            message=f"SKILL.md exceeds size limit ({md_size} bytes > {MAX_SKILLMD_SIZE})",
            file="SKILL.md",
        ))

    # Read with UTF-8 BOM handling and replacement fallback
    try:
        content = skill_md.read_text(encoding="utf-8-sig", errors="replace")
    except OSError as e:
        findings.append(Finding(
            stage="spec",
            severity="medium",
            message=f"Cannot read SKILL.md: {e}",
            file="SKILL.md",
        ))
        return None, None, None, None, findings

    # Parse frontmatter
    try:
        post = frontmatter.loads(content)
        metadata = dict(post.metadata)
    except Exception as e:
        findings.append(Finding(
            stage="spec",
            severity="medium",
            message=f"Invalid YAML frontmatter: {e}",
            file="SKILL.md",
        ))
        # Attempt regex fallback extraction
        name = _regex_extract_field(content, "name")
        desc = _regex_extract_field(content, "description")
        return name, desc, None, None, findings

    # Validate name
    name = metadata.get("name")
    if not name or not isinstance(name, str):
        findings.append(Finding(
            stage="spec",
            severity="high",
            message="Missing or empty 'name' field in frontmatter",
            file="SKILL.md",
        ))
        name = None
    elif not SKILL_NAME_PATTERN.match(name):
        findings.append(Finding(
            stage="spec",
            severity="high",
            message=f"Skill name '{name}' contains invalid characters (must match ^[a-zA-Z0-9_-]+$)",
            file="SKILL.md",
        ))
    elif len(name) > MAX_NAME_LENGTH:
        findings.append(Finding(
            stage="spec",
            severity="medium",
            message=f"Skill name exceeds {MAX_NAME_LENGTH} characters",
            file="SKILL.md",
        ))

    # Validate description
    description = metadata.get("description")
    if not description or not isinstance(description, str):
        findings.append(Finding(
            stage="spec",
            severity="high",
            message="Missing or empty 'description' field in frontmatter",
            file="SKILL.md",
        ))
        description = None
    elif len(description) > MAX_DESCRIPTION_LENGTH:
        findings.append(Finding(
            stage="spec",
            severity="medium",
            message=f"Description exceeds {MAX_DESCRIPTION_LENGTH} characters ({len(description)})",
            file="SKILL.md",
        ))

    # Extract trigger keywords from description
    trigger_keywords: list[str] = []
    if description:
        # Look for "Trigger keywords:" line in description
        kw_match = re.search(
            r"[Tt]rigger\s+keywords?\s*:\s*(.+?)(?:\n|$)", description
        )
        if kw_match:
            raw_kw = kw_match.group(1)
            trigger_keywords = [kw.strip() for kw in raw_kw.split(",") if kw.strip()]

    return name, description, trigger_keywords, metadata, findings


def _regex_extract_field(content: str, field_name: str) -> Optional[str]:
    """Fallback regex extraction for a YAML field from raw content."""
    pattern = rf"^{field_name}\s*:\s*(.+?)$"
    match = re.search(pattern, content, re.MULTILINE)
    if match:
        return match.group(1).strip().strip('"').strip("'")
    return None


def _inventory_files(
    root: Path,
) -> tuple[dict[str, ScriptFile], dict[str, AssetFile], int, list[Finding]]:
    """Walk the package directory and build file inventories.

    Enforces path safety, resource limits, and file classification.
    Returns (scripts, assets, total_size_bytes, findings).
    """
    findings: list[Finding] = []
    scripts: dict[str, ScriptFile] = {}
    assets: dict[str, AssetFile] = {}
    total_size = 0
    file_count = 0

    for dirpath_str, dirnames, filenames in os.walk(root, followlinks=False):
        dirpath = Path(dirpath_str)

        # Filter excluded directories in-place
        dirnames[:] = [
            d for d in dirnames
            if d not in EXCLUDED_DIRS
            and not d.startswith(".")  # skip hidden dirs
        ]

        for fname in filenames:
            if fname in EXCLUDED_FILES:
                continue

            file_path = dirpath / fname
            ext = file_path.suffix.lower()

            if ext in EXCLUDED_EXTENSIONS:
                continue

            # Check file count limit
            file_count += 1
            if file_count > MAX_FILE_COUNT:
                findings.append(Finding(
                    stage="spec",
                    severity="high",
                    message=f"Package exceeds maximum file count ({MAX_FILE_COUNT})",
                ))
                return scripts, assets, total_size, findings

            # Path safety checks
            rel_path_str = _to_posix_relative(file_path, root)

            # Check for path traversal
            if ".." in rel_path_str.split("/"):
                findings.append(Finding(
                    stage="spec",
                    severity="critical",
                    message=f"Path traversal attempted: {rel_path_str}",
                    file=rel_path_str,
                ))
                continue

            # Check for symlinks escaping root
            if file_path.is_symlink():
                if not _is_path_safe(file_path, root):
                    findings.append(Finding(
                        stage="spec",
                        severity="critical",
                        message=f"Symlink escapes package root: {rel_path_str}",
                        file=rel_path_str,
                    ))
                    continue

            # Check for reserved device names
            if _check_reserved_device_name(fname):
                findings.append(Finding(
                    stage="spec",
                    severity="critical",
                    message=f"Reserved device name in package: {fname}",
                    file=rel_path_str,
                ))
                continue

            # Check for alternate data streams
            if _check_alternate_data_stream(rel_path_str):
                findings.append(Finding(
                    stage="spec",
                    severity="critical",
                    message=f"NTFS alternate data stream detected: {rel_path_str}",
                    file=rel_path_str,
                ))
                continue

            # Get file size
            try:
                file_size = file_path.stat().st_size
            except OSError:
                findings.append(Finding(
                    stage="spec",
                    severity="note",
                    message=f"Cannot stat file: {rel_path_str}",
                    file=rel_path_str,
                ))
                continue

            total_size += file_size

            # Check total package size
            if total_size > MAX_PACKAGE_SIZE_BYTES:
                findings.append(Finding(
                    stage="spec",
                    severity="high",
                    message=f"Package exceeds maximum total size ({MAX_PACKAGE_SIZE_BYTES // (1024*1024)} MB)",
                ))
                return scripts, assets, total_size, findings

            # Compute content hash
            try:
                content_bytes = file_path.read_bytes()
                content_hash = hashlib.sha256(content_bytes).hexdigest()
            except OSError:
                findings.append(Finding(
                    stage="spec",
                    severity="note",
                    message=f"Cannot read file: {rel_path_str}",
                    file=rel_path_str,
                ))
                continue

            # Classify and inventory
            truncated = file_size > MAX_FILE_SIZE_BYTES

            if ext in SCRIPT_EXTENSIONS or fname == "SKILL.md":
                # Read as text with line numbers
                if truncated:
                    findings.append(Finding(
                        stage="spec",
                        severity="note",
                        message=f"File exceeds {MAX_FILE_SIZE_BYTES // (1024*1024)} MB, content truncated for analysis: {rel_path_str}",
                        file=rel_path_str,
                    ))
                    lines: list[str] = []
                else:
                    try:
                        text = content_bytes.decode("utf-8-sig", errors="replace")
                        lines = text.splitlines(keepends=True)
                    except Exception:
                        lines = []

                scripts[rel_path_str] = ScriptFile(
                    relative_path=rel_path_str,
                    lines=lines,
                    size_bytes=file_size,
                    content_hash=content_hash,
                    truncated=truncated,
                )
            elif ext in IMAGE_EXTENSIONS:
                import mimetypes
                mime = mimetypes.guess_type(fname)[0] or "application/octet-stream"
                assets[rel_path_str] = AssetFile(
                    relative_path=rel_path_str,
                    mime_type=mime,
                    size_bytes=file_size,
                    content_hash=content_hash,
                )
            else:
                # Other files — inventory as assets with generic type
                import mimetypes
                mime = mimetypes.guess_type(fname)[0] or "application/octet-stream"
                assets[rel_path_str] = AssetFile(
                    relative_path=rel_path_str,
                    mime_type=mime,
                    size_bytes=file_size,
                    content_hash=content_hash,
                )

    return scripts, assets, total_size, findings

