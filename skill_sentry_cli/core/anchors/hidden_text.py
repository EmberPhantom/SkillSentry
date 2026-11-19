"""Hidden text: runs of invisible characters, and messages encoded in them.

A message can be written with characters that draw nothing: one of two zero-width characters
for each bit, eight bits to a byte; Unicode "tag" characters, which are ASCII shifted into an
invisible block; variation selectors used as bytes. A person reading the file sees nothing, and
a model that reads it as text may not see anything either, but an agent tokenising the raw
characters can read it.

Two things are checked, per line:

* **A run.** A sequence of eight or more invisible characters in a row is a finding on its own.
  Real text does not contain one: an emoji sequence has one joiner between emoji, Persian and
  Indic text have one joiner or non-joiner at a time, a right-to-left mark is a single character.
  A run of 64 or more is long enough to carry a message and is HIGH.
* **A message.** The invisible characters of a line are decoded as tag characters, variation
  selectors, or two symbols read as bits. If the result is readable ASCII, it is reported as
  hidden text (HIGH), and the caller matches it against the instruction and credential rules,
  with the original file and line as the evidence.

A line with only a few scattered invisible characters, however many lines there are, is not
reported.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Characters that draw nothing: zero-width space and joiners, direction marks and overrides,
# word joiner and invisible operators, the byte order mark, the soft hyphen, the combining grapheme
# joiner, the Arabic letter mark, the Mongolian vowel separator, variation selectors, and the
# tag block.
_INVISIBLE_CLASS = "­͏؜᠎​-‏‪-‮⁠-⁤⁦-⁩︀-️﻿\U000e0000-\U000e007f\U000e0100-\U000e01ef"
_RUN = re.compile(f"[{_INVISIBLE_CLASS}]+")
_INVISIBLE_ONE = re.compile(f"[{_INVISIBLE_CLASS}]")

MIN_RUN = 8
LONG_RUN = 64
# Two symbols are only read as bits when the line has at least this many.
MIN_BITS = 16
MIN_TEXT = 4


@dataclass(frozen=True)
class HiddenFinding:
    """What a line hides: the longest run, and any text decoded from the invisible characters."""

    longest_run: int
    total: int
    decoded: str | None
    encoding: str | None


def invisible_chars(line: str) -> list[str]:
    return _INVISIBLE_ONE.findall(line)


def longest_run(line: str) -> int:
    return max((len(match.group(0)) for match in _RUN.finditer(line)), default=0)


def _printable(data: bytes) -> str | None:
    """The text if ``data`` is readable ASCII (letters, digits, punctuation, spaces)."""

    if len(data) < MIN_TEXT:
        return None
    text = "".join(chr(byte) if 32 <= byte < 127 or byte in (9, 10) else "\x00" for byte in data)
    good = sum(1 for char in text if char != "\x00")
    if good < MIN_TEXT or good / len(text) < 0.9:
        return None
    cleaned = text.replace("\x00", "").strip()
    if sum(1 for char in cleaned if char.isalpha()) < MIN_TEXT:
        return None
    return cleaned


def _decode_tags(chars: list[str]) -> str | None:
    tags = [ord(char) - 0xE0000 for char in chars if 0xE0000 <= ord(char) <= 0xE007F]
    return _printable(bytes(tags)) if len(tags) >= MIN_TEXT else None


def _decode_variation_selectors(chars: list[str]) -> str | None:
    values: list[int] = []
    for char in chars:
        code = ord(char)
        if 0xFE00 <= code <= 0xFE0F:
            values.append(code - 0xFE00)
        elif 0xE0100 <= code <= 0xE01EF:
            values.append(16 + code - 0xE0100)
    return _printable(bytes(values)) if len(values) >= MIN_TEXT else None


def _decode_bits(chars: list[str]) -> str | None:
    """Two distinct symbols as bits, eight to a byte, most significant bit first, either way round."""

    symbols = sorted(set(chars))
    if len(symbols) != 2 or len(chars) < MIN_BITS:
        return None
    for zero in symbols:
        bits = "".join("0" if char == zero else "1" for char in chars)
        usable = len(bits) - len(bits) % 8
        data = bytes(int(bits[index : index + 8], 2) for index in range(0, usable, 8))
        text = _printable(data)
        if text is not None:
            return text
    return None


def inspect_line(line: str) -> HiddenFinding | None:
    """What the invisible characters of ``line`` amount to, or ``None`` when nothing."""

    if line.isascii():
        return None
    chars = invisible_chars(line)
    if not chars:
        return None
    run = longest_run(line)
    decoded: str | None = None
    encoding: str | None = None
    for name, decoder in (
        ("tag characters", _decode_tags),
        ("variation selectors", _decode_variation_selectors),
        ("zero-width bits", _decode_bits),
    ):
        decoded = decoder(chars)
        if decoded is not None:
            encoding = name
            break
    if run < MIN_RUN and decoded is None:
        return None
    return HiddenFinding(longest_run=run, total=len(chars), decoded=decoded, encoding=encoding)


__all__ = ["LONG_RUN", "MIN_RUN", "HiddenFinding", "inspect_line", "invisible_chars", "longest_run"]
