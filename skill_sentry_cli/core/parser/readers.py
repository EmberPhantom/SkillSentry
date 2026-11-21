"""Readers for files that are not plain text: notebooks, office documents, PDFs and archives.

Each reader turns a file into text the checks can read, and into issues for what is dangerous in
it. Everything happens in memory: nothing is extracted to disk, nothing is run, and nothing is
rendered. Every reader is bounded, so a decompression bomb or an endless archive stops at a cap
and is reported as a coverage gap (the scan is then UNSCANNED), never as clean.

What a reader returns is a list of ``(label, text)`` pairs and a list of ``PackageIssue``. A label
names the part: ``report.docx!/word/document.xml`` or ``bundle.zip!/lib/run.py``.
"""

from __future__ import annotations

import gzip
import io
import json
import re
import tarfile
import zipfile
import zlib
from dataclasses import dataclass, field
from html import unescape
from pathlib import Path, PurePosixPath

from skill_sentry_cli.core.contracts import COVERAGE_GAP
from skill_sentry_cli.core.parser.opaque import sniff

# --- limits ----------------------------------------------------------------------------------
MAX_FILE_BYTES = 32 * 1024 * 1024  # the most of one file a reader looks at
MAX_MEMBERS = 2_000
MAX_MEMBER_BYTES = 1024 * 1024  # a text member is read up to this size
MAX_TEXT_BYTES = 4 * 1024 * 1024  # all text one container may give
MAX_EXPANDED_BYTES = 64 * 1024 * 1024  # declared size of everything in an archive
MAX_RATIO = 200  # declared size over compressed size, above which an archive is a bomb
MAX_NOTEBOOK_CELL_CHARS = 200_000
MAX_PDF_STREAM_BYTES = 4 * 1024 * 1024
MAX_PDF_STREAMS = 400

ARCHIVE_SUFFIXES = (".zip", ".tar", ".tgz", ".tar.gz", ".tar.bz2", ".tar.xz", ".gz")
OFFICE_SUFFIXES = frozenset(
    {".docx", ".docm", ".dotx", ".dotm", ".pptx", ".pptm", ".potx", ".xlsx", ".xlsm", ".xltx"}
)
READ_SUFFIXES = frozenset({".ipynb", ".pdf", *OFFICE_SUFFIXES})
_TEXT_MEMBER_SUFFIXES = frozenset(
    {
        ".md", ".txt", ".py", ".sh", ".bash", ".js", ".mjs", ".ts", ".tsx", ".jsx", ".json",
        ".yaml", ".yml", ".toml", ".ini", ".cfg", ".ps1", ".rb", ".go", ".rs", ".java", ".php",
        ".pl", ".lua", ".c", ".h", ".cpp", ".bat", ".cmd", ".html", ".htm", ".xml", ".sql",
        ".svg", ".css", ".scss", ".csv", ".tsv", ".plist", ".env", ".conf", ".rst", ".log",
    }
)  # fmt: skip
_EXECUTABLE_MEMBER_SUFFIXES = frozenset({".exe", ".dll", ".so", ".dylib", ".bin", ".com", ".scr"})


@dataclass
class ReadResult:
    texts: list[tuple[str, str]] = field(default_factory=list)
    issues: list = field(default_factory=list)  # PackageIssue; typed loosely to avoid a cycle


def is_reader_file(relative: str) -> bool:
    lowered = relative.lower()
    return lowered.endswith(tuple(READ_SUFFIXES) + ARCHIVE_SUFFIXES)


def _issue(severity: str, message: str, relative: str, *, kind: str, gap: bool = False):
    from skill_sentry_cli.core.parser.skill_parser import PackageIssue

    return PackageIssue(
        severity,
        message,
        file=relative,
        coverage=gap,
        kind=COVERAGE_GAP if gap else kind,
    )


def read_special(path: Path, relative: str) -> ReadResult:
    """Read ``path`` with the reader for its kind. Always returns; a failure is an issue."""

    result = ReadResult()
    try:
        size = path.stat().st_size
        if size > MAX_FILE_BYTES:
            result.issues.append(
                _issue(
                    "high",
                    f"file not analysed: {relative} is larger than {MAX_FILE_BYTES >> 20} MiB",
                    relative,
                    kind=COVERAGE_GAP,
                    gap=True,
                )
            )
            return result
        lowered = relative.lower()
        if lowered.endswith(".ipynb"):
            _notebook(path.read_bytes(), relative, result)
        elif lowered.endswith(".pdf"):
            _pdf(path.read_bytes(), relative, result)
        elif lowered.endswith(tuple(OFFICE_SUFFIXES)):
            _office(path.read_bytes(), relative, result)
        else:
            _archive(path.read_bytes(), relative, result, depth=0)
    except Exception as exc:  # a reader that fails leaves the file unread, which is a gap
        result.issues.append(
            _issue(
                "high",
                f"file not analysed: {relative} could not be read ({type(exc).__name__})",
                relative,
                kind=COVERAGE_GAP,
                gap=True,
            )
        )
    return result


# --- notebooks -------------------------------------------------------------------------------
def _output_text(output: dict) -> str:
    parts: list[str] = []
    if isinstance(output.get("text"), (str, list)):
        parts.append(
            "".join(output["text"]) if isinstance(output["text"], list) else output["text"]
        )
    data = output.get("data")
    if isinstance(data, dict):
        for mime, value in data.items():
            if str(mime).startswith("image/"):
                continue  # base64 pictures are not text
            parts.append("".join(value) if isinstance(value, list) else str(value))
    if isinstance(output.get("traceback"), list):
        parts.append("\n".join(str(t) for t in output["traceback"]))
    if isinstance(output.get("evalue"), str):
        parts.append(output["evalue"])
    return "\n".join(parts)


def _notebook(data: bytes, relative: str, result: ReadResult) -> None:
    try:
        notebook = json.loads(data.decode("utf-8", "replace"))
        cells = notebook["cells"] if "cells" in notebook else notebook["worksheets"][0]["cells"]
    except (ValueError, KeyError, IndexError, TypeError, RecursionError):
        result.issues.append(
            _issue(
                "high",
                f"notebook not analysed: {relative} is not a readable notebook",
                relative,
                kind=COVERAGE_GAP,
                gap=True,
            )
        )
        return
    lines: list[str] = []
    for number, cell in enumerate(cells if isinstance(cells, list) else []):
        if not isinstance(cell, dict):
            continue
        source = cell.get("source", cell.get("input", ""))
        text = "".join(source) if isinstance(source, list) else str(source)
        lines.append(f"# --- cell {number} ({cell.get('cell_type', 'code')}) ---")
        lines.append(text[:MAX_NOTEBOOK_CELL_CHARS])
        for output in cell.get("outputs", []) if isinstance(cell.get("outputs"), list) else []:
            if isinstance(output, dict):
                shown = _output_text(output)
                if shown:
                    lines.append(f"# --- output of cell {number} ---")
                    lines.append(shown[:MAX_NOTEBOOK_CELL_CHARS])
    result.texts.append((relative, "\n".join(lines)[:MAX_TEXT_BYTES]))


# --- office documents ------------------------------------------------------------------------
_TAGS = re.compile(r"<[^>]+>")
_REL_TARGET = re.compile(
    r"<Relationship\b[^>]*?Type=\"[^\"]*/(?P<kind>[A-Za-z]+)\"[^>]*?Target=\"(?P<target>[^\"]*)\""
    r"[^>]*?TargetMode=\"External\"|"
    r"<Relationship\b[^>]*?Target=\"(?P<target2>[^\"]*)\"[^>]*?Type=\"[^\"]*/(?P<kind2>[A-Za-z]+)\""
    r"[^>]*?TargetMode=\"External\"",
    re.I,
)
_ACTIVE_RELATIONSHIPS = frozenset(
    {"attachedtemplate", "oleobject", "externallink", "frame", "subdocument", "package", "control"}
)
_TEXT_PARTS = re.compile(
    r"^(word/(document|header\d*|footer\d*|comments|footnotes|endnotes)|ppt/(slides/slide\d+|"
    r"notesSlides/notesSlide\d+|comments/.*)|xl/(sharedStrings|worksheets/sheet\d+)|"
    r"docProps/(core|app|custom))\.xml$",
    re.I,
)


def _xml_text(xml: str) -> str:
    return re.sub(r"[ \t]+", " ", unescape(_TAGS.sub(" ", xml))).strip()


def _office(data: bytes, relative: str, result: ReadResult) -> None:
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        result.issues.append(
            _issue(
                "high",
                f"document not analysed: {relative} is not a readable Office file",
                relative,
                kind=COVERAGE_GAP,
                gap=True,
            )
        )
        return
    if not _zip_is_safe(archive, relative, result):
        return
    total = 0
    for info in archive.infolist():
        name = info.filename
        lowered = name.lower()
        if (
            lowered.endswith("vbaproject.bin")
            or "/macros/" in lowered
            or lowered.endswith(("vbadata.xml", "vbaprojectsignature.bin"))
        ):
            result.issues.append(
                _issue(
                    "high",
                    f"document with a macro: {relative} contains {name}. A macro runs code when "
                    "the document is opened",
                    relative,
                    kind="document-active-content",
                )
            )
        elif "/embeddings/" in lowered or lowered.startswith("embeddings/"):
            result.issues.append(
                _issue(
                    "medium",
                    f"document with an embedded object: {relative} contains {name}",
                    relative,
                    kind="document-active-content",
                )
            )
        elif "activex" in lowered and lowered.endswith(".bin"):
            result.issues.append(
                _issue(
                    "high",
                    f"document with an ActiveX control: {relative} contains {name}",
                    relative,
                    kind="document-active-content",
                )
            )
        if lowered.endswith(".rels"):
            xml = _read_member(archive, info, 512 * 1024)
            for found in _REL_TARGET.finditer(xml):
                kind = (found.group("kind") or found.group("kind2") or "").lower()
                target = found.group("target") or found.group("target2") or ""
                if kind in _ACTIVE_RELATIONSHIPS:
                    result.issues.append(
                        _issue(
                            "high",
                            f"document that reaches outside itself: {relative} has an external "
                            f"{kind} ({target[:120]})",
                            relative,
                            kind="document-active-content",
                        )
                    )
                elif kind == "hyperlink":
                    result.texts.append((f"{relative}!/{name}", f"link: {target}"))
        elif _TEXT_PARTS.match(name) and total < MAX_TEXT_BYTES:
            text = _xml_text(_read_member(archive, info, MAX_MEMBER_BYTES))
            total += len(text)
            if text:
                result.texts.append((f"{relative}!/{name}", text))


# --- PDF -------------------------------------------------------------------------------------
_PDF_HIGH = (b"/JavaScript", b"/JS", b"/Launch", b"/SubmitForm", b"/RichMedia", b"/XFA")
_PDF_MEDIUM = (b"/OpenAction", b"/AA", b"/GoToR", b"/EmbeddedFile", b"/ImportData")
_PDF_STREAM = re.compile(rb"stream\r?\n(.*?)\r?\nendstream", re.S)
_PDF_TEXT = re.compile(rb"\((?P<s>(?:\\.|[^\\()])*)\)\s*Tj|\[(?P<a>[^\]]*)\]\s*TJ", re.S)
_PDF_ESC = re.compile(rb"\\([nrtbf()\\]|[0-7]{1,3})")


def _pdf_unescape(raw: bytes) -> str:
    table = {b"n": b"\n", b"r": b"\r", b"t": b"\t", b"b": b"", b"f": b"", b"(": b"(", b")": b")"}

    def one(match: re.Match[bytes]) -> bytes:
        body = match.group(1)
        if body in table:
            return table[body]
        if body == b"\\":
            return b"\\"
        return bytes([int(body, 8) & 0xFF])

    return _PDF_ESC.sub(one, raw).decode("latin-1", "replace")


def _inflate(data: bytes) -> bytes | None:
    inflater = zlib.decompressobj()
    try:
        out = inflater.decompress(data, MAX_PDF_STREAM_BYTES)
    except zlib.error:
        return None
    return out


def _pdf(data: bytes, relative: str, result: ReadResult) -> None:
    if not data.startswith(b"%PDF"):
        result.issues.append(
            _issue(
                "medium",
                f"document not analysed: {relative} is not a PDF",
                relative,
                kind="opaque-content",
                gap=True,
            )
        )
        return
    haystacks = [data]
    texts: list[bytes] = []
    for streams, match in enumerate(_PDF_STREAM.finditer(data), start=1):
        if streams > MAX_PDF_STREAMS:
            result.issues.append(
                _issue(
                    "high",
                    f"document not fully analysed: {relative} has more than {MAX_PDF_STREAMS} streams",
                    relative,
                    kind=COVERAGE_GAP,
                    gap=True,
                )
            )
            break
        inflated = _inflate(match.group(1))
        if inflated is not None:
            haystacks.append(inflated)
            texts.append(inflated)
    if b"/Encrypt" in data:
        result.issues.append(
            _issue(
                "high",
                f"document not analysed: {relative} is encrypted, so its content cannot be read",
                relative,
                kind=COVERAGE_GAP,
                gap=True,
            )
        )
    joined = b"\n".join(haystacks)
    for name in _PDF_HIGH:
        if re.search(re.escape(name) + rb"(?![A-Za-z])", joined):
            result.issues.append(
                _issue(
                    "high",
                    f"PDF with an active action: {relative} contains {name.decode()}",
                    relative,
                    kind="document-active-content",
                )
            )
    for name in _PDF_MEDIUM:
        if re.search(re.escape(name) + rb"(?![A-Za-z])", joined):
            result.issues.append(
                _issue(
                    "medium",
                    f"PDF with an automatic action or attachment: {relative} contains "
                    f"{name.decode()}",
                    relative,
                    kind="document-active-content",
                )
            )
    pieces: list[str] = []
    for blob in texts:
        for found in _PDF_TEXT.finditer(blob):
            if found.group("s") is not None:
                pieces.append(_pdf_unescape(found.group("s")))
            else:
                pieces.extend(
                    _pdf_unescape(part)
                    for part in re.findall(rb"\(((?:\\.|[^\\()])*)\)", found.group("a"))
                )
        if sum(len(p) for p in pieces) > MAX_TEXT_BYTES:
            break
    text = " ".join(pieces)[:MAX_TEXT_BYTES]
    if text.strip():
        result.texts.append((f"{relative}!/text", text))


# --- archives --------------------------------------------------------------------------------
def _unsafe_name(name: str) -> bool:
    normal = name.replace("\\", "/")
    parts = PurePosixPath(normal).parts
    return normal.startswith("/") or bool(re.match(r"^[A-Za-z]:", normal)) or ".." in parts


def _read_member(archive: zipfile.ZipFile, info: zipfile.ZipInfo, limit: int) -> str:
    with archive.open(info) as handle:
        return handle.read(limit).decode("utf-8", "replace")


def _zip_is_safe(archive: zipfile.ZipFile, relative: str, result: ReadResult) -> bool:
    infos = archive.infolist()
    declared = sum(i.file_size for i in infos)
    packed = max(1, sum(i.compress_size for i in infos))
    if (
        len(infos) > MAX_MEMBERS
        or declared > MAX_EXPANDED_BYTES
        or (declared > 1024 * 1024 and declared / packed > MAX_RATIO)
    ):
        result.issues.append(
            _issue(
                "high",
                f"archive not analysed: {relative} expands too much to open safely "
                f"({len(infos)} members, {declared >> 20} MiB declared)",
                relative,
                kind=COVERAGE_GAP,
                gap=True,
            )
        )
        return False
    return True


def _exec_magic(head: bytes) -> str | None:
    executable, _media = sniff(head)
    return executable


def _text_member(name: str) -> bool:
    suffix = PurePosixPath(name).suffix.lower()
    return suffix in _TEXT_MEMBER_SUFFIXES or suffix == ""


def _members_zip(data: bytes, relative: str, result: ReadResult, depth: int) -> None:
    archive = zipfile.ZipFile(io.BytesIO(data))
    if not _zip_is_safe(archive, relative, result):
        return
    total = 0
    for info in archive.infolist():
        name = info.filename
        label = f"{relative}!/{name}"
        if info.is_dir():
            continue
        if _unsafe_name(name):
            result.issues.append(
                _issue(
                    "high",
                    f"archive path traversal: {relative} has the member {name!r}",
                    relative,
                    kind="archive-unsafe",
                )
            )
            continue
        if (info.external_attr >> 16) & 0o170000 == 0o120000:
            result.issues.append(
                _issue(
                    "high",
                    f"archive symlink: {relative} has the link {name!r}",
                    relative,
                    kind="archive-unsafe",
                )
            )
            continue
        if info.flag_bits & 0x1:
            result.issues.append(
                _issue(
                    "high",
                    f"archive member not analysed: {label} is encrypted",
                    relative,
                    kind=COVERAGE_GAP,
                    gap=True,
                )
            )
            continue
        with archive.open(info) as handle:
            head = handle.read(4096)
        _member(
            name,
            label,
            relative,
            head,
            lambda limit, i=info: archive.open(i).read(limit),
            result,
            depth,
        )
        total += min(info.file_size, MAX_MEMBER_BYTES)
        if total > MAX_TEXT_BYTES:
            result.issues.append(
                _issue(
                    "high",
                    f"archive not fully analysed: {relative} has more text than the limit",
                    relative,
                    kind=COVERAGE_GAP,
                    gap=True,
                )
            )
            break


def _member(name, label, relative, head, read, result, depth):
    suffix = PurePosixPath(name).suffix.lower()
    if _exec_magic(head) or suffix in _EXECUTABLE_MEMBER_SUFFIXES:
        result.issues.append(
            _issue(
                "high",
                f"archive with a program: {label} is a compiled executable",
                relative,
                kind="opaque-content",
            )
        )
        return
    if name.lower().endswith(ARCHIVE_SUFFIXES):
        if depth >= 1:
            result.issues.append(
                _issue(
                    "high",
                    f"archive not fully analysed: {label} is nested more than one level deep",
                    relative,
                    kind=COVERAGE_GAP,
                    gap=True,
                )
            )
            return
        data = read(MAX_FILE_BYTES)
        inner = ReadResult()
        _archive(data, label, inner, depth + 1)
        result.texts.extend(inner.texts)
        result.issues.extend(inner.issues)
        return
    if _text_member(name):
        body = read(MAX_MEMBER_BYTES + 1)
        if b"\x00" in body[:4096]:
            result.issues.append(
                _issue(
                    "medium",
                    f"archive member not analysed: {label} is binary",
                    relative,
                    kind="opaque-content",
                    gap=True,
                )
            )
            return
        if len(body) > MAX_MEMBER_BYTES:
            result.issues.append(
                _issue(
                    "high",
                    f"archive member not fully analysed: {label} is over {MAX_MEMBER_BYTES >> 20} MiB",
                    relative,
                    kind=COVERAGE_GAP,
                    gap=True,
                )
            )
            body = body[:MAX_MEMBER_BYTES]
        result.texts.append((label, body.decode("utf-8", "replace")))
        return
    _exe, media = sniff(head)
    if media is None:
        result.issues.append(
            _issue(
                "medium",
                f"archive member not analysed: {label} is not text or a known media file",
                relative,
                kind="opaque-content",
                gap=True,
            )
        )


def _tar_read(tar: tarfile.TarFile, info: tarfile.TarInfo, limit: int) -> bytes:
    handle = tar.extractfile(info)
    return handle.read(limit) if handle is not None else b""


def _archive(data: bytes, relative: str, result: ReadResult, depth: int) -> None:
    lowered = relative.lower()
    if data[:2] == b"PK":
        _members_zip(data, relative, result, depth)
        return
    if lowered.endswith(".gz") and not lowered.endswith((".tar.gz", ".tgz")):
        raw = gzip.GzipFile(fileobj=io.BytesIO(data)).read(MAX_MEMBER_BYTES + 1)
        if len(raw) > MAX_MEMBER_BYTES:
            result.issues.append(
                _issue(
                    "high",
                    f"archive not fully analysed: {relative} expands past {MAX_MEMBER_BYTES >> 20} MiB",
                    relative,
                    kind=COVERAGE_GAP,
                    gap=True,
                )
            )
            return
        inner = relative[:-3]
        _member(
            inner,
            f"{relative}!/{PurePosixPath(inner).name}",
            relative,
            raw[:4096],
            lambda limit: raw[:limit],
            result,
            depth,
        )
        return
    # tar, tgz, tar.gz, tar.bz2, tar.xz: opened as a stream, never extracted.
    members = 0
    declared = 0
    total = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tar:
        for info in tar:
            members += 1
            declared += info.size
            if members > MAX_MEMBERS or declared > MAX_EXPANDED_BYTES:
                result.issues.append(
                    _issue(
                        "high",
                        f"archive not analysed: {relative} expands too much to open safely",
                        relative,
                        kind=COVERAGE_GAP,
                        gap=True,
                    )
                )
                return
            name = info.name
            label = f"{relative}!/{name}"
            if info.isdir():
                continue
            if _unsafe_name(name):
                result.issues.append(
                    _issue(
                        "high",
                        f"archive path traversal: {relative} has the member {name!r}",
                        relative,
                        kind="archive-unsafe",
                    )
                )
                continue
            if info.issym() or info.islnk() or info.isdev() or info.isfifo():
                result.issues.append(
                    _issue(
                        "high",
                        f"archive link or device: {relative} has {name!r}",
                        relative,
                        kind="archive-unsafe",
                    )
                )
                continue
            handle = tar.extractfile(info)
            if handle is None:
                continue
            head = handle.read(4096)
            _member(
                name,
                label,
                relative,
                head,
                lambda limit, i=info: _tar_read(tar, i, limit),
                result,
                depth,
            )
            total += min(info.size, MAX_MEMBER_BYTES)
            if total > MAX_TEXT_BYTES:
                result.issues.append(
                    _issue(
                        "high",
                        f"archive not fully analysed: {relative} has more text than the limit",
                        relative,
                        kind=COVERAGE_GAP,
                        gap=True,
                    )
                )
                return


__all__ = ["ReadResult", "is_reader_file", "read_special"]
