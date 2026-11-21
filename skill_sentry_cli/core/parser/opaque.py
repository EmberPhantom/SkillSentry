"""Classify files the scan cannot read as text, by their first bytes.

A skill is text, scripts and a few media files. Anything else is content the scan cannot
inspect, and "cannot inspect" must never read as "clean". This module says what such a file
is, so the finding can say how serious it is: an executable binary is HIGH, a recognised
image or font that is small is only a NOTE, and everything else is MEDIUM.

Only the header is read, never the whole file, and nothing here executes or decodes the
content. A media file is recognised by its header alone, so a file that has the right header
and hostile content after it is still reported as a media file.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

HEADER_BYTES = 4096

# A file this close to the package cap is suspicious by size alone.
NEAR_CAP_BYTES = 48 * 1024 * 1024
# Recognised media at or below this size is a NOTE; above it, it is unusual enough to flag.
MAX_BENIGN_MEDIA_BYTES = 5 * 1024 * 1024
# Audio and video are normally larger than an icon, and nothing reads or runs them, so they
# are listed as media up to this size. A file close to the package cap is still flagged.
MAX_BENIGN_AV_BYTES = 40 * 1024 * 1024
AUDIO_VIDEO_KINDS = frozenset({"mp3", "wav", "ogg", "flac", "mp4", "webm", "avi"})

_MACHO_MAGICS = (
    b"\xfe\xed\xfa\xce",
    b"\xfe\xed\xfa\xcf",
    b"\xce\xfa\xed\xfe",
    b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",  # universal binary (also a Java class file)
)

# Header signatures of media that is safe to list without a finding.
_MEDIA_BY_SUFFIX: dict[str, tuple[str, ...]] = {
    ".png": ("png",),
    ".jpg": ("jpeg",),
    ".jpeg": ("jpeg",),
    ".gif": ("gif",),
    ".webp": ("webp",),
    ".bmp": ("bmp",),
    ".tif": ("tiff",),
    ".tiff": ("tiff",),
    ".ico": ("ico",),
    ".woff": ("woff",),
    ".woff2": ("woff2",),
    ".ttf": ("ttf",),
    ".otf": ("otf",),
    ".mp3": ("mp3",),
    ".wav": ("wav",),
    ".ogg": ("ogg",),
    ".oga": ("ogg",),
    ".opus": ("ogg",),
    ".flac": ("flac",),
    ".m4a": ("mp4",),
    ".mp4": ("mp4",),
    ".m4v": ("mp4",),
    ".mov": ("mp4",),
    ".webm": ("webm",),
    ".mkv": ("webm",),
    ".avi": ("avi",),
}


@dataclass(frozen=True)
class OpaqueFile:
    """What an unreadable file is. ``executable`` names the format when it is a program."""

    kind: str  # executable | media | other
    label: str
    executable: str | None = None


def sniff(header: bytes) -> tuple[str | None, str | None]:
    """Return ``(executable_format, media_format)`` for a file's first bytes."""

    if header.startswith(b"\x7fELF"):
        return "ELF", None
    if header.startswith(b"MZ") and _is_pe(header):
        return "PE (Windows executable)", None
    if header[:4] in _MACHO_MAGICS:
        return "Mach-O", None
    if header.startswith(b"\x89PNG\r\n\x1a\n"):
        return None, "png"
    if header.startswith(b"\xff\xd8\xff"):
        return None, "jpeg"
    if header.startswith((b"GIF87a", b"GIF89a")):
        return None, "gif"
    if header[:4] == b"RIFF" and header[8:12] == b"WEBP":
        return None, "webp"
    if header.startswith(b"BM") and len(header) > 14:
        return None, "bmp"
    if header[:4] in (b"II*\x00", b"MM\x00*"):
        return None, "tiff"
    if header[:4] == b"\x00\x00\x01\x00":
        return None, "ico"
    if header.startswith(b"ID3") or (
        len(header) > 1 and header[0] == 0xFF and header[1] & 0xE0 == 0xE0
    ):
        return None, "mp3"
    if header[:4] == b"RIFF" and header[8:12] == b"WAVE":
        return None, "wav"
    if header[:4] == b"RIFF" and header[8:12] == b"AVI ":
        return None, "avi"
    if header[:4] == b"OggS":
        return None, "ogg"
    if header[:4] == b"fLaC":
        return None, "flac"
    if header[4:8] == b"ftyp":
        return None, "mp4"
    if header[:4] == b"\x1aE\xdf\xa3":
        return None, "webm"
    if header[:4] == b"wOFF":
        return None, "woff"
    if header[:4] == b"wOF2":
        return None, "woff2"
    if header[:4] in (b"\x00\x01\x00\x00", b"true"):
        return None, "ttf"
    if header[:4] == b"OTTO":
        return None, "otf"
    return None, None


def _is_pe(header: bytes) -> bool:
    """``MZ`` alone also starts plain text, so require the PE header it points at."""

    if len(header) < 0x40:
        return False
    offset = int.from_bytes(header[0x3C:0x40], "little")
    return offset + 4 <= len(header) and header[offset : offset + 4] == b"PE\x00\x00"


def classify(path: Path, size: int) -> OpaqueFile:
    """Say what an unread file is. ``size`` is its size in bytes."""

    try:
        with path.open("rb") as handle:
            header = handle.read(HEADER_BYTES)
    except OSError:
        return OpaqueFile("other", "unreadable")
    executable, media = sniff(header)
    if executable:
        return OpaqueFile("executable", f"executable binary ({executable})", executable)
    suffix = path.suffix.lower()
    expected = _MEDIA_BY_SUFFIX.get(suffix)
    if media is not None and expected is not None and media in expected:
        return OpaqueFile("media", f"{media} file")
    if media is not None:
        return OpaqueFile("other", f"{media} data in a file named *{suffix or '(no extension)'}")
    return OpaqueFile("other", "binary or unrecognised content")


def image_mismatch(path: Path) -> OpaqueFile | None:
    """For a file with an image suffix: ``None`` when its header fits, else what it really is.

    Only suffixes with a known header are checked, and SVG (text) is not.
    """

    suffix = path.suffix.lower()
    expected = _MEDIA_BY_SUFFIX.get(suffix)
    if expected is None:
        return None
    try:
        with path.open("rb") as handle:
            header = handle.read(HEADER_BYTES)
    except OSError:
        return None
    executable, media = sniff(header)
    if executable:
        return OpaqueFile("executable", f"executable binary ({executable})", executable)
    if media in expected:
        return None
    return OpaqueFile("other", f"content that is not a {expected[0]} image")
