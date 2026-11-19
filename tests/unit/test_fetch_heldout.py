"""The held-out fetcher: safe against hostile repositories, and checks hashes.

Every repository here is a throw-away local one, so no network is used. The
hostile content is inert text; the tests assert that nothing from it runs.
"""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import fetch_heldout as fh  # noqa: E402

GIT_ENV = {
    "GIT_AUTHOR_NAME": "t",
    "GIT_AUTHOR_EMAIL": "t@example.invalid",
    "GIT_COMMITTER_NAME": "t",
    "GIT_COMMITTER_EMAIL": "t@example.invalid",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
}


def _git(cwd: Path, *args: str) -> str:
    env = {**os.environ, **GIT_ENV}
    out = subprocess.run(
        ["git", "-c", "protocol.file.allow=always", *args],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    return out.stdout.strip()


@pytest.fixture
def hostile_repo(tmp_path):
    """A repository with a good skill, a symlink skill, an executable file and a hook."""
    if sys.platform == "win32":
        pytest.skip("needs symlinks and POSIX modes")
    repo = tmp_path / "upstream"
    repo.mkdir()
    _git(repo, "init", "-q")
    good = repo / "skills" / "good"
    good.mkdir(parents=True)
    (good / "SKILL.md").write_text("---\nname: good\n---\nhello\n")
    (good / "run.sh").write_text('#!/bin/sh\ntouch "$HOME/pwned-by-run"\n')
    (good / "run.sh").chmod(0o755)
    bad = repo / "skills" / "linked"
    bad.mkdir(parents=True)
    (bad / "SKILL.md").write_text("---\nname: linked\n---\nbody\n")
    os.symlink("/etc/passwd", bad / "leak")
    odd = repo / "skills" / "up-and-out"
    odd.mkdir(parents=True)
    (odd / "SKILL.md").write_text("x\n")
    os.symlink("../../", odd / "parent")
    # A repo hook that would create a marker if git ever ran it.
    hooks = repo / ".git" / "hooks"
    marker = tmp_path / "hook-ran"
    for name in ("post-checkout", "post-merge", "post-commit", "reference-transaction"):
        hook = hooks / name
        hook.write_text(f"#!/bin/sh\ntouch {marker}\n")
        hook.chmod(0o755)
    # An attributes file that would run a filter on checkout.
    (repo / ".gitattributes").write_text("* filter=evil\n")
    _git(repo, "config", "filter.evil.smudge", f"touch {marker}; cat")
    _git(repo, "config", "uploadpack.allowAnySHA1InWant", "true")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "init")
    # The commit hook would fire on the commit above; remove the marker, then keep hooks in place.
    marker.unlink(missing_ok=True)
    return repo, _git(repo, "rev-parse", "HEAD"), marker


def _manifest(repo: Path, commit: str, entries: list[dict]) -> dict:
    return {
        "version": 1,
        "sources": {"s": {"url": f"file://{repo}", "commit": commit, "licence": "MIT"}},
        "entries": entries,
        "reserve": [],
    }


def _entry(eid: str, path: str, digest: str = "", label: str = "benign", **extra) -> dict:
    return {"id": eid, "source": "s", "path": path, "tree_sha256": digest, "label": label, **extra}


def _cache(tmp_path: Path) -> Path:
    return tmp_path / "cache"


def test_good_skill_is_fetched_without_exec_bit_and_nothing_runs(hostile_repo, tmp_path):
    repo, commit, marker = hostile_repo
    cache = _cache(tmp_path)
    cache.mkdir()
    m = _manifest(repo, commit, [_entry("good", "skills/good")])
    entry = next(fh.iter_entries(m))
    digest = fh.fetch_entry(m, entry, cache, allow_file=True, pin=True)
    out = cache / "skills" / "good"
    assert sorted(p.name for p in out.iterdir()) == ["SKILL.md", "run.sh"]
    for f in out.iterdir():
        assert not (f.stat().st_mode & 0o111), f"{f} is executable"
    assert not marker.exists(), "a hook or filter ran"
    assert not (Path.home() / "pwned-by-run").exists()
    # A second pass with the pinned hash verifies and reuses the copy.
    m["entries"][0]["tree_sha256"] = digest
    entry = next(fh.iter_entries(m))
    assert fh.fetch_entry(m, entry, cache, allow_file=True) == digest
    assert fh.verify_entry(entry, cache) == digest


def test_a_symlink_makes_the_whole_skill_be_refused(hostile_repo, tmp_path):
    repo, commit, _ = hostile_repo
    cache = _cache(tmp_path)
    cache.mkdir()
    for path in ("skills/linked", "skills/up-and-out"):
        m = _manifest(repo, commit, [_entry("x", path)])
        entry = next(fh.iter_entries(m))
        with pytest.raises(fh.FetchError, match="symlink"):
            fh.fetch_entry(m, entry, cache, allow_file=True, pin=True)
    assert not (cache / "skills" / "x").exists()
    assert not list((cache / "skills").glob(".incoming-*")) if (cache / "skills").exists() else True


def test_hash_mismatch_refuses_and_leaves_nothing(hostile_repo, tmp_path):
    repo, commit, _ = hostile_repo
    cache = _cache(tmp_path)
    cache.mkdir()
    m = _manifest(repo, commit, [_entry("good", "skills/good", "0" * 64)])
    entry = next(fh.iter_entries(m))
    with pytest.raises(fh.FetchError, match="hash mismatch"):
        fh.fetch_entry(m, entry, cache, allow_file=True)
    assert not (cache / "skills" / "good").exists()


def test_a_missing_hash_is_refused_unless_pinning(hostile_repo, tmp_path):
    repo, commit, _ = hostile_repo
    cache = _cache(tmp_path)
    cache.mkdir()
    m = _manifest(repo, commit, [_entry("good", "skills/good")])
    entry = next(fh.iter_entries(m))
    with pytest.raises(fh.FetchError, match="no tree_sha256"):
        fh.fetch_entry(m, entry, cache, allow_file=True)


def test_a_tampered_cache_copy_is_detected_and_replaced(hostile_repo, tmp_path):
    repo, commit, _ = hostile_repo
    cache = _cache(tmp_path)
    cache.mkdir()
    m = _manifest(repo, commit, [_entry("good", "skills/good")])
    digest = fh.fetch_entry(m, next(fh.iter_entries(m)), cache, allow_file=True, pin=True)
    m["entries"][0]["tree_sha256"] = digest
    entry = next(fh.iter_entries(m))
    target = cache / "skills" / "good" / "SKILL.md"
    target.write_text("tampered")
    with pytest.raises(fh.FetchError, match="hash mismatch"):
        fh.verify_entry(entry, cache)
    assert fh.fetch_entry(m, entry, cache, allow_file=True) == digest
    assert target.read_text().startswith("---")


def test_a_cached_symlink_or_exec_bit_fails_verification(hostile_repo, tmp_path):
    repo, commit, _ = hostile_repo
    cache = _cache(tmp_path)
    cache.mkdir()
    m = _manifest(repo, commit, [_entry("good", "skills/good")])
    digest = fh.fetch_entry(m, next(fh.iter_entries(m)), cache, allow_file=True, pin=True)
    m["entries"][0]["tree_sha256"] = digest
    entry = next(fh.iter_entries(m))
    run = cache / "skills" / "good" / "run.sh"
    run.chmod(0o755)
    with pytest.raises(fh.FetchError, match="execute bit"):
        fh.verify_entry(entry, cache)
    run.chmod(0o644)
    run.unlink()
    os.symlink("/etc/passwd", run)
    with pytest.raises(fh.FetchError, match="symlink"):
        fh.verify_entry(entry, cache)


def test_a_cache_inside_the_repo_is_refused():
    with pytest.raises(fh.FetchError, match="outside the repository"):
        fh.check_cache_location(ROOT / "tests" / "heldout" / "cache")
    assert fh.check_cache_location(Path("~/.cache/x").expanduser())


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com/a.git",
        "git://example.com/a.git",
        "ssh://git@example.com/a.git",
        "file:///tmp/x",
        "https://user:pw@example.com/a.git",
        "/tmp/local",
    ],
)
def test_only_plain_https_sources_are_accepted(url):
    with pytest.raises(fh.FetchError):
        fh.check_source_url(url, allow_file=False)
    fh.check_source_url("https://github.com/o/r.git", allow_file=False)


@pytest.mark.parametrize(
    "path",
    [
        "",
        "/etc/passwd",
        "../x",
        "a/../b",
        "a//b",
        ".git/config",
        "a/.GIT/x",
        "a\\b",
        "a/\x00b",
        "C:/x",
        "a/ ",
    ],
)
def test_unsafe_paths_are_refused(path):
    with pytest.raises(fh.FetchError):
        fh.safe_relpath(path)


def test_the_commit_must_be_a_full_sha(tmp_path):
    with pytest.raises(fh.FetchError, match="40-hex"):
        fh.ensure_commit("s", "https://github.com/o/r.git", "main", tmp_path, allow_file=False)


def test_tree_hash_ignores_order_but_not_content_or_names():
    a = {"SKILL.md": b"x", "b.txt": b"y"}
    assert fh.tree_sha256(a) == fh.tree_sha256({"b.txt": b"y", "SKILL.md": b"x"})
    assert fh.tree_sha256(a) != fh.tree_sha256({"SKILL.md": b"x", "b.txt": b"z"})
    assert fh.tree_sha256(a) != fh.tree_sha256({"SKILL.md": b"x", "c.txt": b"y"})


# -- archives ---------------------------------------------------------------------------
def _tar(members: list[tuple[str, bytes | None, str]]) -> bytes:
    """members: (name, data, kind) with kind file | symlink | hardlink | dir."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, data, kind in members:
            info = tarfile.TarInfo(name)
            if kind == "file":
                assert data is not None
                info.size = len(data)
                info.mode = 0o755
                tar.addfile(info, io.BytesIO(data))
            elif kind == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = "/etc/passwd"
                tar.addfile(info)
            elif kind == "hardlink":
                info.type = tarfile.LNKTYPE
                info.linkname = "packages/ok/SKILL.md"
                tar.addfile(info)
            else:
                info.type = tarfile.DIRTYPE
                tar.addfile(info)
    return buf.getvalue()


def test_archive_skill_is_read_without_extracting():
    blob = _tar(
        [
            ("packages/ok", None, "dir"),
            ("packages/ok/SKILL.md", b"hello", "file"),
            ("packages/ok/scripts/a.py", b"print(1)", "file"),
            ("packages/other/SKILL.md", b"other", "file"),
        ]
    )
    files = fh.read_archive_skill(blob, "packages/ok")
    assert files == {"SKILL.md": b"hello", "scripts/a.py": b"print(1)"}


@pytest.mark.parametrize("kind", ["symlink", "hardlink"])
def test_archive_links_inside_the_skill_are_refused(kind):
    blob = _tar([("packages/ok/SKILL.md", b"hello", "file"), ("packages/ok/leak", None, kind)])
    with pytest.raises(fh.FetchError, match="link or special"):
        fh.read_archive_skill(blob, "packages/ok")


def test_archive_traversal_member_is_refused():
    blob = _tar([("packages/ok/../../evil", b"x", "file")])
    with pytest.raises(fh.FetchError, match="unsafe path"):
        fh.read_archive_skill(blob, "packages/ok")


def test_archive_entry_through_a_git_source_checks_the_archive_hash(hostile_repo, tmp_path):
    repo, _, _ = hostile_repo
    blob = _tar([("p/a/SKILL.md", b"hello", "file")])
    (repo / "pack.tar.gz").write_bytes(blob)
    _git(repo, "add", "pack.tar.gz")
    _git(repo, "commit", "-q", "-m", "archive")
    commit = _git(repo, "rev-parse", "HEAD")
    cache = _cache(tmp_path)
    cache.mkdir()
    import hashlib

    good = hashlib.sha256(blob).hexdigest()
    m = _manifest(repo, commit, [_entry("a", "p/a", archive="pack.tar.gz")])
    m["sources"]["s"]["archives"] = {"pack.tar.gz": good}
    entry = next(fh.iter_entries(m))
    digest = fh.fetch_entry(m, entry, cache, allow_file=True, pin=True)
    assert digest == fh.tree_sha256({"SKILL.md": b"hello"})
    m["sources"]["s"]["archives"] = {"pack.tar.gz": "1" * 64}
    (cache / "skills" / "a").rename(cache / "skills" / "gone")
    with pytest.raises(fh.FetchError, match="archive"):
        fh.fetch_entry(m, entry, cache, allow_file=True, pin=True)


# -- manifest and command line --------------------------------------------------------
def test_manifest_rules(tmp_path):
    base = {"version": 1, "sources": {"s": {}}, "reserve": []}
    with pytest.raises(fh.FetchError, match="label"):
        list(fh.iter_entries({**base, "entries": [_entry("a", "p", label="evil")]}))
    with pytest.raises(fh.FetchError, match="duplicate"):
        list(fh.iter_entries({**base, "entries": [_entry("a", "p"), _entry("a", "q")]}))
    with pytest.raises(fh.FetchError, match="unknown source"):
        list(fh.iter_entries({**base, "entries": [{**_entry("a", "p"), "source": "zz"}]}))
    with pytest.raises(fh.FetchError, match="bad entry id"):
        list(fh.iter_entries({**base, "entries": [_entry("../a", "p")]}))
    with pytest.raises(fh.FetchError, match="tree_sha256"):
        list(fh.iter_entries({**base, "entries": [_entry("a", "p", "zz")]}))


def test_command_line_pin_then_fetch_then_verify(hostile_repo, tmp_path, capsys):
    repo, commit, marker = hostile_repo
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps(_manifest(repo, commit, [_entry("good", "skills/good")])))
    cache = _cache(tmp_path)
    common = ["--manifest", str(manifest), "--cache", str(cache), "--allow-file"]
    assert fh.main(["fetch", *common]) == 1  # no hash yet
    assert fh.main(["pin", *common]) == 0
    assert json.loads(manifest.read_text())["entries"][0]["tree_sha256"]
    assert fh.main(["fetch", *common]) == 0
    assert fh.main(["verify", *common]) == 0
    assert oct(cache.stat().st_mode & 0o777) == "0o700"
    assert not marker.exists()
    assert fh.main(["list", *common]) == 0
    assert "good" in capsys.readouterr().out


def test_command_line_refuses_a_cache_in_the_repo(tmp_path):
    manifest = tmp_path / "m.json"
    manifest.write_text(json.dumps({"version": 1, "sources": {}, "entries": [], "reserve": []}))
    assert fh.main(["list", "--manifest", str(manifest), "--cache", str(ROOT / "cache-x")]) == 2
