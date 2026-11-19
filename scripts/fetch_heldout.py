#!/usr/bin/env python3
"""Fetch the held-out skills named in ``tests/heldout/manifest.json``, safely.

The skills are untrusted, and half of them are known-bad. This script treats
them as data only:

* Everything goes into a cache directory OUTSIDE the repository
  (``~/.cache/skillsentry-heldout`` by default); a cache inside the repo is
  refused, so nothing from a skill can ever be committed by accident.
* A source is fetched with ``git fetch --depth 1`` of one pinned commit, with
  hooks, submodules, LFS filters, templates and the user's git config all off.
  Only ``https://`` URLs are accepted.
* Nothing is checked out. File contents are read straight from the git object
  store (or out of a pinned archive) and written by this script, so no
  post-checkout hook, smudge filter or ``.gitattributes`` rule can run.
* Symlinks, submodules, devices, hard links, absolute paths, ``..`` parts,
  ``.git`` parts and over-long or oversized members make the whole skill be
  refused. Files are written without any execute bit.
* Nothing is run, imported, installed or opened by an interpreter. The only
  thing computed from a skill is a SHA-256 over its bytes.
* Each skill's tree hash is compared with the manifest; a mismatch deletes it.

Commands: ``fetch`` (download and verify), ``verify`` (re-hash what is in the
cache, no network), ``pin`` (maintainer only: record the hash of entries that
have none), ``list``.

Standard library only.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = REPO_ROOT / "tests" / "heldout" / "manifest.json"
DEFAULT_CACHE = Path(
    os.environ.get("SKILLSENTRY_HELDOUT_CACHE", "~/.cache/skillsentry-heldout")
).expanduser()

MAX_FILE_BYTES = 10 * 1024 * 1024
MAX_SKILL_BYTES = 50 * 1024 * 1024
MAX_FILES = 2000
MAX_ARCHIVE_BYTES = 200 * 1024 * 1024
MAX_PATH_CHARS = 240
GIT_TIMEOUT = 600

_SHA1 = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,120}$")
LABELS = ("benign", "malicious", "ambiguous")


class FetchError(Exception):
    """A source or a skill was refused or did not verify."""


# --------------------------------------------------------------------------
# Safe paths and tree hash


def safe_relpath(raw: str) -> str:
    """Return ``raw`` as a clean relative POSIX path, or raise ``FetchError``."""
    if not raw or "\x00" in raw or "\\" in raw or raw.startswith("/"):
        raise FetchError(f"unsafe path {raw!r}")
    if len(raw) > MAX_PATH_CHARS:
        raise FetchError(f"path too long {raw[:40]!r}")
    parts = raw.split("/")
    for part in parts:
        if part in ("", ".", "..") or part.lower() == ".git" or part.endswith(" "):
            raise FetchError(f"unsafe path {raw!r}")
        if re.match(r"^[A-Za-z]:", part):
            raise FetchError(f"unsafe path {raw!r}")
    return "/".join(parts)


def tree_sha256(files: dict[str, bytes]) -> str:
    """Hash a skill: sorted paths, each with the SHA-256 of its bytes.

    Modes are not part of the hash, because execute bits are stripped.
    """
    outer = hashlib.sha256()
    for rel in sorted(files, key=lambda p: p.encode("utf-8")):
        outer.update(rel.encode("utf-8"))
        outer.update(b"\x00")
        outer.update(hashlib.sha256(files[rel]).hexdigest().encode("ascii"))
        outer.update(b"\n")
    return outer.hexdigest()


def _check_bundle(files: dict[str, bytes]) -> None:
    if not files:
        raise FetchError("no files found at the pinned path")
    if len(files) > MAX_FILES:
        raise FetchError(f"{len(files)} files is over the {MAX_FILES} limit")
    if sum(len(v) for v in files.values()) > MAX_SKILL_BYTES:
        raise FetchError("skill is over the size limit")
    lowered: dict[str, str] = {}
    for rel in files:
        key = rel.lower()
        if key in lowered:
            raise FetchError(f"paths differ only by case: {rel!r}, {lowered[key]!r}")
        lowered[key] = rel
    if not any(rel.lower() == "skill.md" for rel in files):
        raise FetchError("no SKILL.md at the skill root")


# --------------------------------------------------------------------------
# git (object store only, nothing checked out)


def _git_env() -> dict[str, str]:
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", "/nonexistent"),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_LFS_SKIP_SMUDGE": "1",
        "GIT_ASKPASS": "true",
        "GIT_ATTR_NOSYSTEM": "1",
        "LC_ALL": "C",
    }
    return env


def _git_base(*, allow_file: bool) -> list[str]:
    base = [
        "git",
        "-c",
        f"core.hooksPath={os.devnull}",
        "-c",
        "core.symlinks=false",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.autocrlf=false",
        "-c",
        "filter.lfs.smudge=",
        "-c",
        "filter.lfs.process=",
        "-c",
        "filter.lfs.required=false",
        "-c",
        "submodule.recurse=false",
        "-c",
        "fetch.recurseSubmodules=false",
        "-c",
        "transfer.fsckObjects=true",
        "-c",
        "protocol.allow=never",
        "-c",
        "protocol.https.allow=always",
        "-c",
        f"protocol.file.allow={'always' if allow_file else 'never'}",
        "--literal-pathspecs",
    ]
    return base


def _run_git(
    args: list[str], cwd: Path, *, allow_file: bool, input_bytes: bytes | None = None
) -> bytes:
    cmd = _git_base(allow_file=allow_file) + args
    try:
        proc = subprocess.run(
            cmd,
            cwd=cwd,
            env=_git_env(),
            input=input_bytes,
            capture_output=True,
            timeout=GIT_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise FetchError(f"git {args[0]} timed out") from exc
    if proc.returncode != 0:
        msg = proc.stderr.decode("utf-8", "replace").strip().splitlines()
        raise FetchError(f"git {args[0]} failed: {msg[-1] if msg else proc.returncode}")
    return proc.stdout


def check_source_url(url: str, *, allow_file: bool) -> None:
    if url.startswith("https://") and " " not in url and "@" not in url.split("/")[2]:
        return
    if allow_file and url.startswith("file://"):
        return
    raise FetchError(f"source URL must be https:// without credentials: {url!r}")


def ensure_commit(source_id: str, url: str, commit: str, cache: Path, *, allow_file: bool) -> Path:
    """Make sure the pinned commit is in the cache's repo for this source."""
    if not _SHA1.match(commit):
        raise FetchError(f"source {source_id}: commit must be a full 40-hex SHA")
    check_source_url(url, allow_file=allow_file)
    repo = cache / "git" / source_id
    repo.mkdir(parents=True, exist_ok=True)
    if not (repo / "HEAD").exists():
        _run_git(["init", "--bare", "--template=", "-q", str(repo)], cache, allow_file=allow_file)
    have = subprocess.run(
        [*_git_base(allow_file=allow_file), "cat-file", "-e", f"{commit}^{{commit}}"],
        cwd=repo,
        env=_git_env(),
        capture_output=True,
        check=False,
    )
    if have.returncode != 0:
        _run_git(
            ["fetch", "--depth", "1", "--no-tags", "--no-recurse-submodules", url, commit],
            repo,
            allow_file=allow_file,
        )
        _run_git(["cat-file", "-e", f"{commit}^{{commit}}"], repo, allow_file=allow_file)
    return repo


def _ls_tree(
    repo: Path, commit: str, path: str, *, allow_file: bool
) -> list[tuple[str, str, str, str]]:
    out = _run_git(["ls-tree", "-r", "-z", commit, "--", path], repo, allow_file=allow_file)
    rows = []
    for rec in out.split(b"\x00"):
        if not rec:
            continue
        meta, _, name = rec.partition(b"\t")
        mode, typ, oid = meta.decode("ascii").split()
        rows.append((mode, typ, oid, name.decode("utf-8", "surrogateescape")))
    return rows


def _cat_blobs(repo: Path, oids: list[str], *, allow_file: bool) -> dict[str, bytes]:
    if not oids:
        return {}
    data = ("\n".join(oids) + "\n").encode("ascii")
    out = _run_git(["cat-file", "--batch"], repo, allow_file=allow_file, input_bytes=data)
    blobs: dict[str, bytes] = {}
    pos = 0
    for oid in oids:
        nl = out.index(b"\n", pos)
        header = out[pos:nl].decode("ascii").split()
        if len(header) != 3 or header[1] != "blob":
            raise FetchError(f"object {oid} is not a blob")
        size = int(header[2])
        if size > MAX_ARCHIVE_BYTES:
            raise FetchError(f"object {oid} is too large")
        blobs[oid] = out[nl + 1 : nl + 1 + size]
        pos = nl + 1 + size + 1
    return blobs


def read_git_skill(repo: Path, commit: str, path: str, *, allow_file: bool) -> dict[str, bytes]:
    """Read one skill directory out of the object store, refusing anything unsafe."""
    prefix = safe_relpath(path.strip("/"))
    rows = _ls_tree(repo, commit, prefix, allow_file=allow_file)
    if not rows:
        raise FetchError(f"path {prefix!r} not found at the pinned commit")
    entries: list[tuple[str, str]] = []
    for mode, typ, oid, name in rows:
        if mode == "120000":
            raise FetchError(f"symlink in skill: {name!r}")
        if mode == "160000" or typ == "commit":
            raise FetchError(f"submodule in skill: {name!r}")
        if mode not in ("100644", "100755"):
            raise FetchError(f"unsupported file mode {mode} for {name!r}")
        if not name.startswith(prefix + "/"):
            raise FetchError(f"{prefix!r} is not a directory")
        entries.append((safe_relpath(name[len(prefix) + 1 :]), oid))
    if len(entries) > MAX_FILES:
        raise FetchError(f"{len(entries)} files is over the {MAX_FILES} limit")
    blobs = _cat_blobs(repo, sorted({oid for _, oid in entries}), allow_file=allow_file)
    files: dict[str, bytes] = {}
    for rel, oid in entries:
        if len(blobs[oid]) > MAX_FILE_BYTES:
            raise FetchError(f"file over the size limit: {rel!r}")
        files[rel] = blobs[oid]
    return files


def read_archive_skill(archive: bytes, path: str) -> dict[str, bytes]:
    """Read one directory out of a tar archive without extracting it."""
    prefix = safe_relpath(path.strip("/"))
    files: dict[str, bytes] = {}
    try:
        tar = tarfile.open(fileobj=io.BytesIO(archive), mode="r:*")  # noqa: SIM115
    except tarfile.TarError as exc:
        raise FetchError(f"unreadable archive: {exc}") from exc
    total = 0
    with tar:
        for member in tar:
            name = member.name[2:] if member.name.startswith("./") else member.name
            if member.isdir():
                continue
            inside = name.startswith(prefix + "/")
            if not member.isreg():
                if inside or name == prefix:
                    raise FetchError(f"link or special file in archive skill: {name!r}")
                continue
            if not inside:
                continue
            if member.size > MAX_FILE_BYTES:
                raise FetchError(f"file over the size limit: {name!r}")
            total += member.size
            if total > MAX_SKILL_BYTES or len(files) >= MAX_FILES:
                raise FetchError("skill is over the size limit")
            rel = safe_relpath(name[len(prefix) + 1 :])
            handle = tar.extractfile(member)
            if handle is None:
                raise FetchError(f"cannot read {name!r}")
            files[rel] = handle.read(MAX_FILE_BYTES + 1)
    return files


# --------------------------------------------------------------------------
# Writing to the cache


def _write_tree(dest: Path, files: dict[str, bytes]) -> None:
    """Write files under ``dest`` (which must not exist) with no execute bits."""
    tmp = Path(tempfile.mkdtemp(prefix=".incoming-", dir=dest.parent))
    try:
        root = tmp.resolve()
        for rel, data in files.items():
            target = (root / rel).resolve()
            if root not in target.parents:
                raise FetchError(f"path escapes the skill directory: {rel!r}")
            target.parent.mkdir(parents=True, exist_ok=True)
            with open(target, "xb") as fh:
                fh.write(data)
            os.chmod(target, 0o644)
        for d in [p for p in tmp.rglob("*") if p.is_dir()]:
            os.chmod(d, 0o755)
        os.chmod(tmp, 0o755)
        os.rename(tmp, dest)
    except BaseException:
        shutil.rmtree(tmp, ignore_errors=True)
        raise


def read_cached_skill(directory: Path) -> dict[str, bytes]:
    """Read a materialised skill back, refusing symlinks and executables."""
    files: dict[str, bytes] = {}
    root = directory.resolve()
    for dirpath, dirnames, filenames in os.walk(directory, followlinks=False):
        for name in list(dirnames) + filenames:
            full = Path(dirpath) / name
            if full.is_symlink():
                raise FetchError(f"symlink in cache: {full}")
        for name in filenames:
            full = Path(dirpath) / name
            st = full.lstat()
            if st.st_mode & 0o111:
                raise FetchError(f"execute bit set in cache: {full}")
            if root not in full.resolve().parents:
                raise FetchError(f"path escapes the cache: {full}")
            files[full.relative_to(directory).as_posix()] = full.read_bytes()
    return files


# --------------------------------------------------------------------------
# Manifest


@dataclass(frozen=True)
class Entry:
    id: str
    source: str
    path: str
    archive: str | None
    tree_sha256: str
    label: str
    group: str  # "entries" or "reserve"


def load_manifest(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("version") != 1:
        raise FetchError("manifest version must be 1")
    return data


def iter_entries(manifest: dict, which: str = "all") -> Iterable[Entry]:
    seen: set[str] = set()
    for group in ("entries", "reserve"):
        if which not in ("all", group):
            continue
        for raw in manifest.get(group, []):
            if not _ID.match(raw["id"]):
                raise FetchError(f"bad entry id {raw['id']!r}")
            if raw["id"] in seen:
                raise FetchError(f"duplicate entry id {raw['id']!r}")
            seen.add(raw["id"])
            if raw.get("label") not in LABELS:
                raise FetchError(f"{raw['id']}: label must be one of {LABELS}")
            if raw["source"] not in manifest["sources"]:
                raise FetchError(f"{raw['id']}: unknown source {raw['source']!r}")
            digest = raw.get("tree_sha256", "")
            if digest and not _SHA256.match(digest):
                raise FetchError(f"{raw['id']}: bad tree_sha256")
            yield Entry(
                raw["id"],
                raw["source"],
                raw["path"],
                raw.get("archive"),
                digest,
                raw["label"],
                group,
            )


def skill_dir(cache: Path, entry: Entry) -> Path:
    return cache / "skills" / entry.id


def obtain(manifest: dict, entry: Entry, cache: Path, *, allow_file: bool) -> dict[str, bytes]:
    """Download one entry's files (not yet verified)."""
    src = manifest["sources"][entry.source]
    repo = ensure_commit(entry.source, src["url"], src["commit"], cache, allow_file=allow_file)
    if entry.archive:
        archive_path = safe_relpath(entry.archive)
        wanted = src.get("archives", {}).get(archive_path)
        rows = _ls_tree(repo, src["commit"], archive_path, allow_file=allow_file)
        if len(rows) != 1 or rows[0][0] not in ("100644", "100755"):
            raise FetchError(f"archive {archive_path!r} not found at the pinned commit")
        blob = _cat_blobs(repo, [rows[0][2]], allow_file=allow_file)[rows[0][2]]
        if wanted and hashlib.sha256(blob).hexdigest() != wanted:
            raise FetchError(f"archive {archive_path!r} does not match its pinned sha256")
        files = read_archive_skill(blob, entry.path)
    else:
        files = read_git_skill(repo, src["commit"], entry.path, allow_file=allow_file)
    _check_bundle(files)
    return files


def check_cache_location(cache: Path) -> Path:
    cache = cache.expanduser().resolve()
    if cache == REPO_ROOT or REPO_ROOT in cache.parents:
        raise FetchError("the cache must be outside the repository")
    return cache


def fetch_entry(
    manifest: dict, entry: Entry, cache: Path, *, allow_file: bool = False, pin: bool = False
) -> str:
    """Fetch, verify and store one entry. Returns its tree hash."""
    dest = skill_dir(cache, entry)
    if dest.exists():
        try:
            digest = tree_sha256(read_cached_skill(dest))
            if entry.tree_sha256 and digest == entry.tree_sha256:
                return digest
        except FetchError:
            pass
        shutil.rmtree(dest)
    files = obtain(manifest, entry, cache, allow_file=allow_file)
    digest = tree_sha256(files)
    if entry.tree_sha256 and digest != entry.tree_sha256:
        raise FetchError(f"hash mismatch: manifest {entry.tree_sha256[:12]}, got {digest[:12]}")
    if not entry.tree_sha256 and not pin:
        raise FetchError("manifest has no tree_sha256 for this entry (use pin)")
    dest.parent.mkdir(parents=True, exist_ok=True)
    _write_tree(dest, files)
    return digest


def verify_entry(entry: Entry, cache: Path) -> str:
    dest = skill_dir(cache, entry)
    if not dest.is_dir():
        raise FetchError("not fetched")
    digest = tree_sha256(read_cached_skill(dest))
    if digest != entry.tree_sha256:
        raise FetchError(f"hash mismatch: manifest {entry.tree_sha256[:12]}, got {digest[:12]}")
    return digest


# --------------------------------------------------------------------------
# CLI


def _select(manifest: dict, which: str, only: list[str] | None) -> list[Entry]:
    entries = list(iter_entries(manifest, which))
    if only:
        wanted = set(only)
        entries = [e for e in entries if e.id in wanted]
        missing = wanted - {e.id for e in entries}
        if missing:
            raise FetchError(f"not in the manifest: {sorted(missing)}")
    return entries


def _write_manifest(path: Path, manifest: dict) -> None:
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("command", choices=["fetch", "verify", "pin", "list"])
    ap.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    ap.add_argument("--cache", type=Path, default=DEFAULT_CACHE)
    ap.add_argument("--set", dest="which", choices=["all", "entries", "reserve"], default="entries")
    ap.add_argument("--only", nargs="*", help="entry ids")
    ap.add_argument("--allow-file", action="store_true", help=argparse.SUPPRESS)
    args = ap.parse_args(argv)

    try:
        cache = check_cache_location(args.cache)
        manifest = load_manifest(args.manifest)
        entries = _select(manifest, args.which, args.only)
    except (FetchError, OSError, ValueError, KeyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.command == "list":
        for e in entries:
            print(f"{e.id}\t{e.label}\t{e.source}\t{e.path}")
        return 0

    cache.mkdir(parents=True, exist_ok=True)
    os.chmod(cache, 0o700)
    failures = 0
    pinned = 0
    raw_index = {r["id"]: r for g in ("entries", "reserve") for r in manifest.get(g, [])}
    for e in entries:
        try:
            if args.command == "verify":
                verify_entry(e, cache)
            else:
                digest = fetch_entry(
                    manifest, e, cache, allow_file=args.allow_file, pin=args.command == "pin"
                )
                if args.command == "pin" and not e.tree_sha256:
                    raw_index[e.id]["tree_sha256"] = digest
                    pinned += 1
            print(f"ok    {e.id}")
        except (FetchError, OSError) as exc:
            failures += 1
            print(f"FAIL  {e.id}: {exc}", file=sys.stderr)
    if pinned:
        _write_manifest(args.manifest, manifest)
        print(f"pinned {pinned} entries")
    print(f"{len(entries) - failures} ok, {failures} failed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
