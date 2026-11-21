"""A model-free score for how much a piece of text looks like it could carry an instruction attack.

The model's reading is limited, so it should read the risky text first and the rest last. This
module says how risky a chunk is without a model, from signals that need no judgement: invisible
characters, a very long line, override and secrecy wording in English and in five other
languages, execution and credential vocabulary, a blob with no spaces, a request to fetch and
follow something.

The signals are deliberately broad. A chunk with no signal at all is *static-cleared*: ordinary
prose that the static checks read and that nothing in it asks for a second look. A chunk with a
signal is read by the model as required text. A signal is not a finding: it never raises a
verdict, it only moves text earlier in the queue and makes it required.

What this cannot do: an instruction attack written in plain words that match none of the signals
reads as clean prose. That is the documented limit of static-cleared text (see
``docs/security/evasion-limits.md``).
"""

from __future__ import annotations

import re
import unicodedata

# The static anchor rules read the first 4000 characters of a line. Text past that is not seen
# by them, so a line longer than this is never static-cleared.
LINE_CAP = 4000

_OVERRIDE = re.compile(
    r"\b(ignore|disregard|forget|override|bypass|overrule|supersede|skip)\b[^.\n]{0,60}"
    r"\b(instruction|instructions|rule|rules|prompt|guideline|guidelines|polic(?:y|ies)|"
    r"safety|restriction|restrictions|previous|prior|above|earlier|system)\b",
    re.I,
)
_SECRECY = re.compile(
    r"\b(do not|don't|never|without)\b[^.\n]{0,30}\b(tell|inform|mention|reveal|notify|alert|show|"
    r"disclose|let)\b[^.\n]{0,30}\b(user|human|operator|owner|anyone|them)\b"
    r"|\b(secretly|silently|covertly|quietly|stealthily|in the background|without (?:their|the "
    r"user's) (?:knowledge|knowing|consent|permission))\b",
    re.I,
)
_ROLE = re.compile(
    r"\b(you are now|from now on you|new instructions|system prompt|developer mode|jailbreak|"
    r"act as (?:an? )?(?:root|admin|administrator|unrestricted)|pretend (?:that )?you)\b",
    re.I,
)
_EXEC = re.compile(
    r"\b(curl|wget|sudo|chmod|chown|eval|exec|base64|powershell|netcat|ncat|socat|nc -|"
    r"bash -c|sh -c|rm -rf|crontab|systemctl|launchctl|schtasks|reg add|certutil|bitsadmin|"
    r"mshta|rundll32|regsvr32|osascript|xattr|nohup|disown|mkfifo)\b"
    r"|/dev/tcp/|\|\s*(?:ba|z)?sh\b|\$\(|`[^`\n]*\b(?:curl|wget|nc|bash)\b",
    re.I,
)
_RUN_SCRIPT = re.compile(
    r"\b(run|runs|running|execute|executes|executing|invoke|launch|source|install|pipe)\b"
    r"[^.\n]{0,50}(?:\S+\.(?:sh|py|js|ps1|bat|cmd|rb|pl)\b|\bscript\b|\bbinary\b|\binstaller\b)",
    re.I,
)
_SECRET = re.compile(
    r"\b(api[_ -]?keys?|secrets?|tokens?|passwords?|credentials?|private keys?|ssh keys?|"
    r"id_rsa|\.ssh|\.aws|\.env|keychain|cookies|wallet|seed phrase|mnemonic)\b",
    re.I,
)
_FETCH_FOLLOW = re.compile(
    r"\b(fetch|download|open|visit|load|read|follow|obey|execute|run)\b[^.\n]{0,60}"
    r"(?:https?://|ftp://|www\.)",
    re.I,
)
_EXFIL = re.compile(
    r"\b(exfiltrat\w*|send (?:it|them|this|the \w+) to|upload (?:it|them|this)|post (?:it|them|this) "
    r"to|forward (?:it|them|this) to|webhook|pastebin|ngrok|requestbin|interactsh)\b",
    re.I,
)
# Override, secrecy and secret-handling words in other languages. Substrings, lower-cased.
_FOREIGN = (
    # Spanish
    "ignora las instrucciones", "ignore las instrucciones", "ignora todas las", "no le digas",
    "no se lo digas", "sin que el usuario", "en secreto", "olvida las instrucciones",
    "instrucciones anteriores", "contraseña", "clave privada",
    # French
    "ignorez les instructions", "ignore les instructions", "ne dites pas", "ne le dis pas",
    "à l'insu", "en secret", "oubliez les instructions", "instructions précédentes",
    "mot de passe", "clé privée",
    # German
    "ignoriere die", "ignoriere alle", "ignorieren sie", "sage dem benutzer nicht",
    "ohne dass der benutzer", "heimlich", "vergiss die anweisungen", "vorherigen anweisungen",
    "vorherige anweisungen", "passwort", "privaten schlüssel",
    # Chinese
    "忽略", "无视", "无视之前", "不要告诉", "别告诉", "不要让用户", "悄悄", "偷偷", "秘密地",
    "以前的指令", "之前的指令", "上述指令", "系统提示", "密码", "私钥", "密钥",
    # Japanese
    "無視して", "無視し", "指示を無視", "前の指示", "以前の指示", "ユーザーに言わない",
    "ユーザーには伝えない", "秘密裏", "こっそり", "システムプロンプト", "パスワード", "秘密鍵",
)  # fmt: skip

_INVISIBLE = re.compile("[​-‏‪-‮⁠-⁤⁦-⁯﻿­᠎\U000e0000-\U000e007f]")
_LONG_TOKEN = re.compile(r"\S{200,}")
_SCRIPTS = ("LATIN", "GREEK", "CYRILLIC", "ARMENIAN")


def _mixed_script_word(text: str) -> bool:
    """A word that mixes Latin letters with Greek or Cyrillic ones: a lookalike."""

    for word in re.findall(r"\w{3,40}", text):
        if word.isascii():
            continue
        found = set()
        for char in word:
            if char.isalpha():
                try:
                    found.add(unicodedata.name(char).split(" ", 1)[0])
                except ValueError:
                    continue
        if "LATIN" in found and found & {"GREEK", "CYRILLIC"}:
            return True
    return False


def signals(text: str) -> list[str]:
    """The reasons a chunk is not ordinary prose. Empty means static-cleared."""

    found: list[str] = []
    if _INVISIBLE.search(text):
        found.append("invisible characters")
    if any(len(line) > LINE_CAP for line in text.splitlines()):
        found.append(f"a line longer than {LINE_CAP} characters")
    if _LONG_TOKEN.search(text):
        found.append("a long unbroken blob")
    if _mixed_script_word(text):
        found.append("a word that mixes alphabets")
    for label, pattern in (
        ("override wording", _OVERRIDE),
        ("secrecy wording", _SECRECY),
        ("role or system-prompt wording", _ROLE),
        ("execution vocabulary", _EXEC),
        ("a request to run a script", _RUN_SCRIPT),
        ("secret or credential wording", _SECRET),
        ("a request to fetch and follow a link", _FETCH_FOLLOW),
        ("exfiltration wording", _EXFIL),
    ):
        if pattern.search(text):
            found.append(label)
    lowered = text.lower()
    if any(phrase in lowered for phrase in _FOREIGN):
        found.append("override or secrecy wording in another language")
    return found


def score(text: str) -> int:
    """How many different signals a chunk carries. Used only to order calls."""

    return len(signals(text))


__all__ = ["LINE_CAP", "score", "signals"]
