"""Content the scan cannot read is flagged by what it is, never passed as clean."""

from __future__ import annotations

import io
from pathlib import Path

import pytest
from PIL import Image
from skill_sentry_cli.core.cache import SQLiteStore
from skill_sentry_cli.core.config import SkillsEntryConfig
from skill_sentry_cli.core.contracts import ScanOptions
from skill_sentry_cli.core.engine import ScanEngine, ScanError
from skill_sentry_cli.core.models.mock import MockGemma
from skill_sentry_cli.core.parser import SkillParseError, parse_skill
from skill_sentry_cli.core.parser.opaque import sniff

MIB = 1024 * 1024
ELF = b"\x7fELF\x02\x01\x01" + bytes(512)


def _skill(root: Path) -> Path:
    root.mkdir(parents=True)
    (root / "SKILL.md").write_text(
        "---\nname: demo\ndescription: Print a note.\n---\n\nBody\n", encoding="utf-8"
    )
    return root


def _put(skill: Path, relative: str, data: bytes) -> None:
    target = skill / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)


def _sparse(skill: Path, relative: str, size: int, head: bytes = b"") -> None:
    target = skill / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("wb") as handle:
        handle.write(head)
        handle.truncate(size)


def _png() -> bytes:
    buffer = io.BytesIO()
    Image.new("RGB", (16, 16), (10, 20, 200)).save(buffer, "PNG")
    return buffer.getvalue()


def _issues(skill: Path):  # type: ignore[no-untyped-def]
    return {issue.file: issue for issue in parse_skill(skill).issues if issue.kind}


def test_a_50_mib_file_is_high_and_not_clean(tmp_path: Path):
    skill = _skill(tmp_path / "big")
    _sparse(skill, "assets/blob.bin", 50 * MIB)

    issue = _issues(skill)["assets/blob.bin"]

    assert issue.severity == "high"
    assert issue.coverage is True
    assert "close to the 64 MiB package limit" in issue.message


def test_a_small_png_is_not_flagged(tmp_path: Path):
    skill = _skill(tmp_path / "png")
    _put(skill, "assets/logo.png", _png())

    assert _issues(skill) == {}


@pytest.mark.parametrize(
    ("name", "head"),
    [
        ("assets/f.woff2", b"wOF2"),
        ("assets/f.ttf", b"\x00\x01\x00\x00"),
        ("assets/i.ico", b"\x00\x00\x01\x00"),
    ],
)
def test_a_small_font_or_icon_is_a_note_and_does_not_degrade(
    tmp_path: Path, name: str, head: bytes
):
    skill = _skill(tmp_path / "font")
    _put(skill, name, head + bytes(500))

    issue = _issues(skill)[name]

    assert issue.severity == "note"
    assert issue.coverage is False


def test_an_elf_in_scripts_is_high(tmp_path: Path):
    skill = _skill(tmp_path / "elf")
    _put(skill, "scripts/helper", ELF)

    issue = _issues(skill)["scripts/helper"]

    assert issue.severity == "high"
    assert "executable binary (ELF)" in issue.message
    assert issue.coverage is True


def test_an_elf_with_an_image_name_is_high(tmp_path: Path):
    skill = _skill(tmp_path / "disguised")
    _put(skill, "assets/logo.png", ELF)

    issue = _issues(skill)["assets/logo.png"]

    assert issue.severity == "high"
    assert "executable binary (ELF)" in issue.message


def test_random_data_with_an_image_name_is_medium(tmp_path: Path):
    skill = _skill(tmp_path / "fake")
    _put(skill, "assets/logo.png", bytes(range(256)) * 8)

    issue = _issues(skill)["assets/logo.png"]

    assert issue.severity == "medium"
    assert issue.coverage is True
    assert "not a png image" in issue.message


def test_an_unknown_binary_file_is_medium(tmp_path: Path):
    skill = _skill(tmp_path / "bin")
    _put(skill, "data/model.dat", bytes(range(256)) * 40)

    issue = _issues(skill)["data/model.dat"]

    assert issue.severity == "medium"
    assert issue.coverage is True


def test_an_unread_script_stays_high(tmp_path: Path):
    skill = _skill(tmp_path / "oversize")
    _put(skill, "scripts/run.py", b"x = 1\n" * (MIB // 6 + 10))

    issue = _issues(skill)["scripts/run.py"]

    assert issue.severity == "high"
    assert "larger than 1 MiB" in issue.message


def test_executable_formats_are_recognised_by_header():
    pe = bytearray(256)
    pe[:2] = b"MZ"
    pe[0x3C:0x40] = (0x80).to_bytes(4, "little")
    pe[0x80:0x84] = b"PE\x00\x00"
    assert sniff(bytes(pe))[0] == "PE (Windows executable)"
    assert sniff(b"\xcf\xfa\xed\xfe" + bytes(64))[0] == "Mach-O"
    assert sniff(ELF)[0] == "ELF"


def test_text_that_starts_with_mz_is_not_a_pe():
    assert sniff(b"MZ is a short note about a file format.\n" + bytes(64))[0] is None


def test_a_package_over_the_size_cap_is_refused_before_any_file_is_read(tmp_path: Path):
    skill = _skill(tmp_path / "huge")
    _sparse(skill, "payload.bin", 65 * MIB)

    with pytest.raises(SkillParseError, match="larger than 64 MiB"):
        parse_skill(skill)


class _NeverCalled(MockGemma):
    def generate_json(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        raise AssertionError("the model must not be called for an oversized package")


def _scan(tmp_path: Path, skill: Path):  # type: ignore[no-untyped-def]
    config = SkillsEntryConfig()
    config.model.backend = "demo"
    store = SQLiteStore(tmp_path / "o.sqlite")
    engine = ScanEngine(config, store=store, model=_NeverCalled())
    try:
        return engine.scan(skill, options=ScanOptions(sandbox=False, no_cache=True))
    finally:
        engine.close()
        store.close()


def test_an_oversized_package_fails_early_in_the_engine(tmp_path: Path):
    skill = _skill(tmp_path / "huge")
    _sparse(skill, "payload.bin", 65 * MIB)

    with pytest.raises(ScanError, match="larger than 64 MiB"):
        _scan(tmp_path, skill)


def test_the_finding_reaches_the_verdict_and_is_never_safe(tmp_path: Path):
    skill = _skill(tmp_path / "elf")
    _put(skill, "scripts/helper", ELF)
    config = SkillsEntryConfig()
    config.model.backend = "demo"
    store = SQLiteStore(tmp_path / "v.sqlite")
    engine = ScanEngine(config, store=store, model=MockGemma(profile="benign"))
    try:
        outcome = engine.scan(skill, options=ScanOptions(sandbox=False, no_cache=True))
    finally:
        engine.close()
        store.close()

    found = [f for f in outcome.verdict.findings if f.finding_type == "opaque-content"]
    assert found and found[0].severity.value == "high"
    assert outcome.verdict.verdict.value != "SAFE"


def test_a_small_font_scans_as_safe(tmp_path: Path):
    skill = _skill(tmp_path / "font")
    _put(skill, "assets/f.woff2", b"wOF2" + bytes(500))
    config = SkillsEntryConfig()
    config.model.backend = "demo"
    store = SQLiteStore(tmp_path / "f.sqlite")
    engine = ScanEngine(config, store=store, model=MockGemma(profile="benign"))
    try:
        outcome = engine.scan(skill, options=ScanOptions(sandbox=False, no_cache=True))
    finally:
        engine.close()
        store.close()

    assert outcome.verdict.verdict.value == "SAFE"
    assert any(f.finding_type == "opaque-content" for f in outcome.verdict.findings)
