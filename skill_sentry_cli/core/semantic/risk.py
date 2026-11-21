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


# --- code and config -------------------------------------------------------------------------
#
# A script or config file is required reading for the model unless the static checks found
# nothing in it AND none of the signals below is present. The signals are deliberately broad:
# any one of them keeps the file required. Only plain code that does none of these things (a
# formatter, a test file, a JSON schema, a stylesheet, a UI component) is static-cleared.

# Kinds of file that may be cleared at all. Shell, PowerShell, batch, Ruby, Perl, PHP and the like
# are never cleared: running programs is what they are for.
CLEARABLE_SUFFIXES = frozenset(
    {
        ".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".json", ".yaml", ".yml", ".toml",
        ".ini", ".cfg", ".xml", ".svg", ".html", ".htm", ".css", ".scss", ".sql",
    }
)  # fmt: skip

_CODE_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "runs programs or evaluates code",
        re.compile(
            r"\b(subprocess|os\.(?:system|popen|exec\w*|spawn\w*|fork)|popen|child_process|"
            r"execsync|execfile|spawn|exec|eval|compile|execv\w*|__import__|importlib|getattr|"
            r"setattr|globals|locals|vars|pickle|marshal|ctypes|cffi|dlopen|runpy|pty|vm|"
            r"shell_exec|passthru|proc_open|processbuilder|invoke-expression|start-process|"
            r"new function|function\s*\(\s*['\"]|settimeout\s*\(\s*['\"]|import\s*\(\s*[^'\"\s)]|"
            r"require\s*\(\s*[^'\"\s)]|bash -c|sh -c|cmd /c)\b|\$\(|`[^`\n]*`\s*\)",
            re.I,
        ),
    ),
    (
        "network access",
        re.compile(
            r"\b(socket|requests|urllib|httpx|aiohttp|http\.client|http\.request|https\.request|"
            r"ftplib|smtplib|telnetlib|paramiko|fetch|axios|xmlhttprequest|websocket|eventsource|"
            r"sendbeacon|net\.connect|dgram|net/http|curl|wget|invoke-webrequest|invoke-restmethod|"
            r"netcat|ncat|webhook|boto3|googleapiclient|dns|resolver|upload|download|"
            r"navigator\.clipboard|window\.open|location\.(?:href|assign|replace))\b|/dev/tcp",
            re.I,
        ),
    ),
    (
        "encoding or obfuscation",
        re.compile(
            r"\b(base64|b64decode|b64encode|atob|btoa|fromcharcode|rot13|unhexlify|fromhex|"
            r"zlib|gzip|bz2|lzma|marshal|codecs\.decode|charcodeat)\b|(?:\\x[0-9a-f]{2}){4,}|"
            r"(?:\\u[0-9a-f]{4}){4,}|[A-Za-z0-9+/=]{80,}|(?:[0-9a-f]{2}){40,}",
            re.I,
        ),
    ),
    (
        "credential, secret or home-directory path",
        re.compile(
            r"\.ssh|\.aws|\.gnupg|\.npmrc|\.pypirc|\.netrc|\.docker|\.kube|\.config/|\.env\b|"
            r"id_rsa|keychain|credential|password|passwd|secret|token|api[_-]?key|cookie|wallet|"
            r"/etc/(?:passwd|shadow|hosts)|os\.environ|process\.env|getenv|expanduser|homedir|"
            r"path\.home|~/|\$home|%userprofile%|%appdata%|localstorage|sessionstorage|"
            r"document\.cookie|indexeddb",
            re.I,
        ),
    ),
    (
        "persistence or startup hook",
        re.compile(
            r"crontab|systemd|launchd|launchagents|schtasks|\.bashrc|\.zshrc|\.profile|autostart|"
            r"rc\.local|hkey_|atexit|postinstall|preinstall|prepare\b|\binstall\b|\bhooks?\b|"
            r"entrypoint|entry_point|\bscripts\b|\bcommand\b|\brun\b|\bexecutable\b|"
            r"onstartup|runonce|service worker|serviceworker",
            re.I,
        ),
    ),
    (
        "changes or deletes files, or depends on time, host or chance",
        re.compile(
            r"\b(rmtree|unlink|os\.remove|rm -rf|chmod|chown|setuid|shutil|datetime|time\.time|"
            r"date\.now|new date|random|sleep|setinterval|schedule|getpass|getuser|hostname|"
            r"platform|uname|isatty|argv|username|writefile|appendfile|createwritestream|"
            r"fs\.write\w*|open\s*\([^)]*['\"][wa]b?['\"])\b",
            re.I,
        ),
    ),
)
_CODE_LONG_LINE = 1000


def _top_level_effects(text: str) -> bool:
    """True when a Python file does something at import time other than define things."""

    import ast

    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        return True  # code that does not parse is not understood, so it is not cleared
    for node in tree.body:
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant):
            continue  # a docstring
        if isinstance(node, ast.Expr | ast.With | ast.For | ast.While | ast.Try):
            return True
        if isinstance(node, ast.If) and not _is_main_guard(node):
            return True
    return False


def _is_main_guard(node: object) -> bool:
    import ast

    test = getattr(node, "test", None)
    return (
        isinstance(test, ast.Compare)
        and isinstance(test.left, ast.Name)
        and test.left.id == "__name__"
    )


def code_signals(text: str, relative: str) -> list[str]:
    """The reasons a script or config file is not plain. Empty means it may be static-cleared.

    A file kind that can never be cleared (a shell script, say) always reports one.
    """

    suffix = "." + relative.rsplit(".", 1)[-1].lower() if "." in relative.rsplit("/", 1)[-1] else ""
    if suffix not in CLEARABLE_SUFFIXES:
        return ["a kind of file that is never cleared"]
    if text.startswith("#!"):
        return ["starts with a #! line"]
    found: list[str] = []
    if _INVISIBLE.search(text):
        found.append("invisible characters")
    if any(len(line) > _CODE_LONG_LINE for line in text.splitlines()):
        found.append(f"a line longer than {_CODE_LONG_LINE} characters")
    if _mixed_script_word(text):
        found.append("a word that mixes alphabets")
    for label, pattern in _CODE_RULES:
        if pattern.search(text):
            found.append(label)
    if suffix == ".py" and _top_level_effects(text):
        found.append("does something when it is imported")
    if suffix in {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"} and re.search(
        r"^\s*(?:\(\s*(?:async\s*)?(?:function|\()|(?:async\s+)?function\s*\(|!function|void\s+function)",
        text,
        re.M,
    ):
        found.append("runs at load time")
    return found


__all__ = ["CLEARABLE_SUFFIXES", "LINE_CAP", "code_signals", "score", "signals"]
