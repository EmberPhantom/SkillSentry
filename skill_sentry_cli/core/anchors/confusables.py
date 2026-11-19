"""Make text comparable for the deterministic checks when it is written with lookalikes.

A pattern for ``curl ... | bash`` does not match ``сurl`` when the first letter is Cyrillic, but
a person, or an agent that follows ``SKILL.md``, reads it as the command. This module gives the
anchors a second view of each line:

* NFKC folds compatibility forms: full-width ``ｃｕｒｌ``, mathematical bold letters, ligatures.
* A table of confusables maps letters of other alphabets that look the same as a Latin letter
  (Cyrillic ``с``, Greek ``ο``) to that letter. The table is deliberately short: only
  characters that are visually identical in common fonts, so ordinary Russian or Greek prose is
  not turned into Latin words.
* Invisible characters (zero-width spaces and joiners, bidirectional controls, the soft hyphen)
  are dropped.

The normalised view is only used to match. A finding keeps the file, the line and the original
text, and a line is always normalised on its own, so line numbers do not move. The anchors match
both the original and the normalised line, so this can only add findings, never remove one.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

# Cyrillic and Greek letters that look like a Latin letter. Lowercase and uppercase.
_CONFUSABLES: dict[str, str] = {
    # Cyrillic lowercase
    "а": "a",
    "с": "c",
    "е": "e",
    "о": "o",
    "р": "p",
    "х": "x",
    "у": "y",
    "і": "i",
    "ј": "j",
    "ѕ": "s",
    "ԁ": "d",
    "һ": "h",
    "ԛ": "q",
    "ԝ": "w",
    "ӏ": "l",
    "ѵ": "v",
    # Cyrillic uppercase
    "А": "A",
    "В": "B",
    "Е": "E",
    "К": "K",
    "М": "M",
    "Н": "H",
    "О": "O",
    "Р": "P",
    "С": "C",
    "Т": "T",
    "Х": "X",
    "У": "Y",
    "І": "I",
    "Ј": "J",
    "Ѕ": "S",
    "Ԍ": "G",
    "Ԛ": "Q",
    "Ԝ": "W",
    # Greek lowercase
    "ο": "o",
    "ν": "v",
    "ι": "i",
    "κ": "k",
    "ρ": "p",
    "υ": "u",
    "χ": "x",
    "α": "a",
    "ε": "e",
    "γ": "y",
    # Greek uppercase
    "Α": "A",
    "Β": "B",
    "Ε": "E",
    "Ζ": "Z",
    "Η": "H",
    "Ι": "I",
    "Κ": "K",
    "Μ": "M",
    "Ν": "N",
    "Ο": "O",
    "Ρ": "P",
    "Τ": "T",
    "Υ": "Y",
    "Χ": "X",
    # Other lookalikes
    "ɑ": "a",
    "ɡ": "g",
    "ⅰ": "i",
    "ⅼ": "l",
    "ǀ": "l",
    "Ӏ": "I",
}

# Characters with no width or no meaning in a command: dropped before matching.
_INVISIBLE = dict.fromkeys(
    [
        0x00AD,
        0x034F,
        0x061C,
        0x180E,
        0x200B,
        0x200C,
        0x200D,
        0x200E,
        0x200F,
        0x2060,
        0x2061,
        0x2062,
        0x2063,
        0x2064,
        0xFEFF,
        *range(0x202A, 0x202F),
        *range(0x2066, 0x206A),
    ]
)
_TRANSLATION = {ord(char): latin for char, latin in _CONFUSABLES.items()} | {
    codepoint: None for codepoint in _INVISIBLE
}
_LINE_BREAKS = re.compile(r"(\r\n|\r|\n)")
_WORD = re.compile(r"[^\W\d_]+(?:['’][^\W\d_]+)?", re.UNICODE)


def normalise_line(line: str) -> str:
    """The comparable form of one line (NFKC, lookalikes mapped, invisibles dropped)."""

    if line.isascii():
        return line
    return unicodedata.normalize("NFKC", line).translate(_TRANSLATION)


def normalise_text(text: str) -> str:
    """The comparable form of a whole text, with every line break kept where it was.

    Each line is normalised on its own, so a line number in the result is the line number in
    the original. Python's own parser counts the same breaks (``\\n``, ``\\r``, ``\\r\\n``).
    """

    if text.isascii():
        return text
    parts = _LINE_BREAKS.split(text)
    return "".join(part if index % 2 else normalise_line(part) for index, part in enumerate(parts))


@dataclass(frozen=True)
class MixedScriptWord:
    """A word that mixes Latin letters with lookalike letters from another alphabet."""

    word: str
    looks_like: str
    scripts: tuple[str, ...]


def _script(char: str) -> str:
    name = unicodedata.name(char, "")
    for script in ("CYRILLIC", "GREEK", "LATIN"):
        if name.startswith(script):
            return script.title()
    return "Other"


def mixed_script_words(line: str) -> list[MixedScriptWord]:
    """Words in ``line`` made of Latin letters and lookalikes, which read as an ASCII word.

    A word is reported only when it contains both a Latin letter and a confusable letter and
    every non-Latin letter in it is a confusable. That is a spoofed word (``сurl``). A word of
    one alphabet (a Russian or Greek sentence) is never reported, and neither is a word that
    carries a non-confusable letter of another alphabet, so ordinary mixed prose such as a
    Cyrillic suffix on a product name does not trigger.
    """

    if line.isascii():
        return []
    found: list[MixedScriptWord] = []
    for match in _WORD.finditer(unicodedata.normalize("NFKC", line)):
        word = match.group(0)
        if word.isascii():
            continue
        letters = [char for char in word if char.isalpha()]
        latin = [char for char in letters if char.isascii()]
        foreign = [char for char in letters if not char.isascii()]
        if not latin or not foreign:
            continue
        if not all(char in _CONFUSABLES for char in foreign):
            continue
        scripts = tuple(sorted({_script(char) for char in foreign}))
        found.append(MixedScriptWord(word, word.translate(_TRANSLATION), scripts))
    return found


__all__ = ["MixedScriptWord", "mixed_script_words", "normalise_line", "normalise_text"]
