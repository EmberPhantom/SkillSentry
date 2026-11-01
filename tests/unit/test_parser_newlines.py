"""Cross-platform frontmatter parsing regressions."""

from __future__ import annotations

from pathlib import Path

from skill_sentry.core.parser import parse_skill


def _write_manifest(tmp_path: Path, newline: bytes) -> Path:
    skill = tmp_path / "pdf-summarizer"
    skill.mkdir()
    manifest = (
        b"---\n"
        b"name: pdf-summarizer\n"
        b"description: Summarize local PDF files.\n"
        b"---\n"
        b"\n"
        b"# PDF Summarizer\n"
    )
    (skill / "SKILL.md").write_bytes(manifest.replace(b"\n", newline))
    return skill


def test_parse_skill_accepts_lf_frontmatter(tmp_path: Path):
    package = parse_skill(_write_manifest(tmp_path, b"\n"))
    assert package.name == "pdf-summarizer"
    assert package.description == "Summarize local PDF files."
    assert not package.issues


def test_parse_skill_accepts_crlf_frontmatter(tmp_path: Path):
    package = parse_skill(_write_manifest(tmp_path, b"\r\n"))
    assert package.name == "pdf-summarizer"
    assert package.description == "Summarize local PDF files."
    assert not package.issues
