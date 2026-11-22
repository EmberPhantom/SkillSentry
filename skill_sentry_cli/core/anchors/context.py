"""Context for the pattern anchors: the same text is a threat in one place and ordinary in another.

An anchor matches a pattern on a line. Many of those patterns are normal in the right place:
a skill that explains how to set up a shell profile, a script that posts to the API its
description names, a security guide that quotes an attack string. This module lowers a finding
to LOW, with the reason in its message, only when the place makes the benign reading the likely
one, and only when nothing in the skill corroborates the threat reading.

It never raises a severity and never removes a finding. A pattern in an executable context
keeps the severity it had, and so does a match that has any of these:

- a destination that is a bare IP address, a tunnel, a paste or webhook site, or a cheap TLD;
- a strong credential read in the same file;
- real hidden characters in the same file;
- a download piped into a shell from a host that is not a known vendor installer.

Every relaxation here has a paired hostile case in ``tests/unit/test_context_anchors.py``.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import NamedTuple

from skill_sentry_cli.core.anchors.credential_flow import is_credential_bound
from skill_sentry_cli.core.contracts import Finding, Severity
from skill_sentry_cli.core.parser import SkillPackage, TextFile

_MARKDOWN = (".md", ".markdown", ".txt")

# A destination nobody would call a vendor API: a tunnel, a paste or webhook site, a
# request-capture service, or a TLD that is mostly used for throwaway hosts. (A bare address and an
# oddly written address are caught by parse_destination.)
_SUSPECT_HOST_WORDS = re.compile(
    r"ngrok|webhook\.site|pastebin|transfer\.sh|oast|interact\.sh|requestbin|pipedream|"
    r"burpcollaborator|canarytokens",
    re.IGNORECASE,
)
_CHEAP_TLDS = frozenset({"tk", "ml", "ga", "cf", "top", "xyz", "ru", "su", "zip", "click"})
_URL_TOKEN = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^\s'\"`<>|]*")
# A template variable in an authority: $TARGET, ${HOST}, {{host}}, {name}, <host> or %s.
_PLACEHOLDER_PIECE = re.compile(r"\$\{\w+\}|\$\w+|\{\{\s*\w+\s*\}\}|\{\w+\}|<[\w -]+>|%s")
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


class Destination(NamedTuple):
    """Where a URL really goes, read the way a client reads it."""

    host: str  # lower-case, no userinfo, no port, no trailing dot; "" when it cannot be read
    odd: bool  # written in a way a plain URL never is: not to be trusted as a name
    placeholder: bool = False  # a template such as https://$TARGET/: the host is not written


def parse_destination(url: str) -> Destination:
    """The host a URL reaches.

    The authority ends at the first ``/``, ``?`` or ``#``. Anything up to the last ``@`` is
    userinfo and is dropped: ``https://brew.sh@203.0.113.9/`` goes to 203.0.113.9. A backslash,
    a percent sign, a space or a non-ASCII character in the authority, a dotted userinfo, a
    punycode label, a bad port or an empty host all make the destination ``odd``, which is never
    trusted as a vendor and counts as suspect. A single trailing dot is a genuine form and is
    dropped.
    """

    rest = url.split("://", 1)[1] if "://" in url else url
    end = len(rest)
    for mark in "/?#":
        position = rest.find(mark)
        if position != -1:
            end = min(end, position)
    authority = rest[:end]
    if "@" not in authority and _PLACEHOLDER_PIECE.search(authority):
        # A template in documentation, not an address. With every variable replaced the rest must
        # still read as a host with an optional port; anything else is odd, as below.
        plain = _PLACEHOLDER_PIECE.sub("x", authority)
        name, _, port = plain.partition(":")
        if (not port or port.isdigit()) and all(_LABEL.fullmatch(part) for part in name.split(".")):
            return Destination("", False, True)
    odd = (
        not authority
        or not authority.isascii()
        or any(ch in authority for ch in "\\% \t")
        or any(ord(ch) < 0x21 for ch in authority)
    )
    userinfo, at, hostport = authority.rpartition("@")
    if at and ("." in userinfo or (":" in userinfo and "." in userinfo.split(":", 1)[0])):
        odd = True  # a host-like name before the @ is how a vendor name is faked
    if hostport.startswith("["):
        return Destination(hostport.lower(), True)  # an IPv6 literal is not a vendor name
    host, colon, port = hostport.partition(":")
    if colon and not port.isdigit():
        odd = True
    host = host.lower()
    if host.endswith(".") and not host.endswith(".."):
        host = host[:-1]
    labels = host.split(".")
    if not host or not all(_LABEL.fullmatch(label) for label in labels):
        odd = True
    if any(label.startswith("xn--") for label in labels):
        odd = True
    return Destination(host, odd)


def _bare_address(host: str) -> bool:
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
        return True
    return bool(re.fullmatch(r"(?:0x[0-9a-f]+|\d+)", host))  # 0x7f000001, 3232235777


def suspect_url(url: str) -> bool:
    """A URL whose destination nobody would call a vendor: odd, a bare address, a tunnel,
    a paste or webhook site, a throwaway TLD, or a Discord webhook."""

    where = parse_destination(url)
    if where.placeholder:
        return False  # not written; the file as a whole is checked for a bare address instead
    if where.odd or _bare_address(where.host):
        return True
    if _SUSPECT_HOST_WORDS.search(where.host):
        return True
    if where.host.rsplit(".", 1)[-1] in _CHEAP_TLDS:
        return True
    return bool(re.search(r"discord(?:app)?\.com/api/webhooks", url, re.IGNORECASE))


def suspect_destination(text: str) -> bool:
    """Any URL in ``text`` is suspect."""

    return any(suspect_url(match.group(0)) for match in _URL_TOKEN.finditer(text))


def first_host(text: str) -> str | None:
    """The real host of the first http(s) URL in ``text``, or None when there is none or its
    destination is odd."""

    for match in _URL_TOKEN.finditer(text):
        if match.group(0).lower().startswith(("http://", "https://")):
            where = parse_destination(match.group(0))
            return None if where.odd else where.host
    return None


# A credential read that is not just a mention of a setting: key files, cloud credential files,
# keychains, browser logins, wallets, and a dump of the whole environment.
STRONG_CREDENTIAL = re.compile(
    r"\.ssh/id_|\bid_rsa\b|\.aws/credentials|\.npmrc|\.netrc|\.git-credentials|\bkeychain\b|"
    r"Login Data|wallet\.dat|/etc/shadow|\.gnupg|\.docker/config|dict\(\s*os\.environ|"
    r"os\.environ\.(?:items|copy)\(|json\.dumps\(\s*(?:dict\()?os\.environ|\bprintenv\b|"
    r"cookies\.sqlite|\.kube/config|data\s*=\s*(?:dict\()?os\.environ",
    re.IGNORECASE,
)
# Anything that can send data off the machine.
SEND = re.compile(
    r"\bcurl\b|\bwget\b|requests\.(?:post|put|patch)|httpx\.(?:post|put)|urllib\.request|"
    r"\bfetch\s*\(|\bnc\s|\bsocat\b|--upload-file|\bsendmail\b|smtplib|webhook",
    re.IGNORECASE,
)
_BARE_ADDRESS_ANYWHERE = re.compile(r"(?<![\d.])(?!127\.|0\.)\d{1,3}(?:\.\d{1,3}){3}(?![\d.])")
_HIDDEN_CHARS = re.compile("[​-‏‪-‮⁠-⁤﻿\U000e0000-\U000e007f]")
_PIPE_TO_SHELL = re.compile(
    r"(?:curl|wget)\s(?P<fetch>[^\n|]*)\|\s*(?:sudo\s+)?(?:sh|bash|zsh)\b", re.IGNORECASE
)
# Install scripts that a tool's own site publishes. A match on one of these is documentation of
# an install, not a download from a stranger. raw.githubusercontent.com and gist hosts are NOT here:
# anyone can publish there, and attackers do.
_VENDOR_INSTALL_HOSTS = frozenset(
    {
        "brew.sh", "sh.rustup.rs", "rustup.rs", "get.docker.com", "bun.sh", "deno.land",
        "astral.sh", "install.python-poetry.org", "get.helm.sh", "ollama.com", "claude.ai",
        "opencode.ai", "sdk.cloud.google.com", "antigravity.google", "cli.github.com",
        "get.sdkman.io", "volta.sh", "fnm.vercel.app", "mise.run", "just.systems",
        "install.julialang.org", "get.pnpm.io", "pixi.sh", "starship.rs", "cursor.com",
        "tailscale.com", "get.k3s.io", "k3s.io", "install.astronomer.io", "fly.io",
        "railway.com", "cli.heroku.com", "toolbelt.heroku.com", "vercel.com", "sentry.io",
        "istio.io", "run.linkerd.io", "linkerd.io", "get.submariner.io",
    }
)  # fmt: skip
# Content delivery networks that publish libraries and fonts. A script or style sheet from one of
# these, by name and exactly, is ordinary. Anyone can publish on raw.githubusercontent.com or a
# gist host, so those are not here.
_VENDOR_CDN_HOSTS = frozenset(
    {
        "cdnjs.cloudflare.com", "cdn.jsdelivr.net", "unpkg.com", "fonts.googleapis.com",
        "fonts.gstatic.com", "ajax.googleapis.com", "code.jquery.com", "cdn.tailwindcss.com",
        "stackpath.bootstrapcdn.com", "maxcdn.bootstrapcdn.com", "cdn.skypack.dev", "esm.sh",
        "use.fontawesome.com", "kit.fontawesome.com", "www.googletagmanager.com",
    }
)  # fmt: skip
_LITERAL_SHELL_CALL = re.compile(
    r"\bos\.(?:system|popen)\(\s*(?:r?\"[^\"{}%$`\\]*\"|r?'[^'{}%$`\\]*')\s*\)"
    r"|\bsubprocess\.\w+\(\s*(?:r?\"[^\"{}%$`\\]*\"|r?'[^'{}%$`\\]*')\s*,\s*shell\s*=\s*True"
)
_RISKY_LITERAL = re.compile(
    r"\bcurl\b|\bwget\b|\bnc\b|\bncat\b|base64|/dev/tcp|\|\s*(?:ba|z)?sh\b|\beval\b|chmod\s+\+x|"
    r"https?://",
    re.IGNORECASE,
)
_DOCUMENTED_SETTING = re.compile(
    r"AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|\.aws[/\\]credentials|\.npmrc|\.pypirc|"
    r"\.docker/config|\.kube/config|\.config/gcloud|\.netrc|\.git-credentials",
    re.IGNORECASE,
)
_PRIVATE_STORE = re.compile(
    r"\.ssh|id_rsa|id_ed25519|keychain|Login Data|logins\.json|key4\.db|cookies|\.gnupg|wallet",
    re.IGNORECASE,
)
_WRITE_OPERATION = re.compile(r">>|\btee\b|\becho\b[^\n]*>|\bcat\b[^\n]*>|\bsed\s+-i\b")


class _FileContext:
    """What is known about one text file, computed once."""

    def __init__(self, text_file: TextFile) -> None:
        self.relative = text_file.relative.replace("\\", "/")
        self.text = text_file.text
        self.lines = text_file.text.splitlines()
        self.is_markdown = self.relative.lower().endswith(_MARKDOWN)
        self.fenced: set[int] = set()
        if self.is_markdown:
            inside = False
            for number, line in enumerate(self.lines, start=1):
                if line.lstrip().startswith(("```", "~~~")):
                    inside = not inside
                    continue
                if inside:
                    self.fenced.add(number)
        self.strong_credential = bool(STRONG_CREDENTIAL.search(self.text))
        self.can_send = bool(SEND.search(self.text))
        self.suspect_destination = suspect_destination(self.text)
        self.hidden_characters = bool(_HIDDEN_CHARS.search(self.text))
        self.bare_address = bool(_BARE_ADDRESS_ANYWHERE.search(self.text))


# Code that reads like a program run but is not one.
_REGEX_EXEC = re.compile(r"(?:/[^/\n]+/[gimsuy]*|\b[A-Z][A-Z0-9_]{2,})\s*\.exec\(")
_SQL_START = re.compile(
    r"^\s*[`'\"(]?\s*(?:SELECT|INSERT|CREATE|ALTER|BEGIN|COMMIT|ROLLBACK|PRAGMA|DROP|UPDATE|"
    r"DELETE|WITH|REPLACE|VACUUM)\b",
    re.IGNORECASE,
)
_DB_EXEC = re.compile(r"\b(?:db|database|conn|connection|sqlite|sql|client)\.exec\(", re.IGNORECASE)
_REGEX_LOOP_EXEC = re.compile(
    r"(?:\bwhile\s*\(\s*\(?|\bif\s*\(\s*\(?|\b(?:const|let|var)\s+)?\w+\s*=\s*\w+\.exec\([^)]*\)\s*\)?"
    r"\s*(?:!==?\s*null|\)|;|$)|\b\w+\.exec\([^)]*\)\s*!==?\s*null|\bmatch\w*\s*=\s*\w+\.exec\("
)
_SAFE_MODULES = frozenset(
    {"pathlib", "re", "sys", "json", "math", "time", "datetime", "collections", "itertools",
     "functools", "typing", "string", "textwrap", "shutil", "tempfile"}
)  # fmt: skip
_LITERAL_IMPORT = re.compile(r"__import__\(\s*['\"]([A-Za-z_][\w]*)['\"]\s*\)")
_PROGRAM_WORDS = re.compile(
    r"child_process|\bcp\.exec|\bsh\b|\bbash\b|\bcurl\b|\bwget\b|\bsudo\b|rm\s+-|"
    r"\.system\(|\.popen\(|subprocess|execSync|spawn",
    re.IGNORECASE,
)
_MODEL_EVAL = re.compile(r"\b[\w.]+\.eval\(\s*\)")
_VERSION_IMPORT = re.compile(
    r"getattr\(\s*__import__\(\s*['\"][\w.-]+['\"]\s*\)\s*,\s*['\"]__version__['\"]"
)
_IMPORT_GUARD = re.compile(r"except\s*\(?\s*(?:ImportError|ModuleNotFoundError)")
_AUTH_HEADER = re.compile(
    r"(?:-H\s+['\"]?|--header\s+['\"]?)?(?:x-api-key|authorization|api-key)\s*:[^\n$]*"
    r"\$\{?(?P<var>[A-Z][A-Z0-9_]+)\}?",
    re.IGNORECASE,
)
_HTTPS_URL = re.compile(r"https://[^\s'\"`)\\]+")
_COMMENT_START = re.compile(r"^\s*(?:#|//|\*|<!--)")


_EXISTENCE_TEST = re.compile(
    r"\[\[?\s*-[nz]\s+[\"']?\$\{?[A-Z][A-Z0-9_]+(?::-[^}]*)?\}?[\"']?\s*\]\]?"
)


def _only_checked_or_mentioned(line: str, file: _FileContext, number: int) -> bool:
    """A credential variable that is only tested (``[ -n "$TOKEN" ]``) or named in a comment, with
    no send, no address and no ``$(...)`` within three lines."""

    stripped = line.strip()
    if not (_EXISTENCE_TEST.search(line) or stripped.startswith(("#", "//"))):
        return False
    around = _window(file, number, 3, 3)
    return not re.search(
        r"https?://|\bcurl\b|\bwget\b|\bfetch\b|\bnc\s|\bsocat\b|requests\.", around
    )


_VAR_IN_URL = re.compile(
    r"[\"']?\$\{?(\w+)\}?|\{(\w+)\}|\b(\w*(?:BASE|URL|ENDPOINT|HOST)\w*)\b", re.IGNORECASE
)


def _resolved_host(line: str, file: _FileContext) -> str | None:
    """The host behind a variable in a request line, when the same file assigns that variable one
    literal https URL and nothing else. A name assigned twice, or to an address read from settings,
    is not resolved."""

    names = {g for m in _VAR_IN_URL.finditer(line) for g in m.groups() if g}
    for name in names:
        pattern = re.compile(
            rf"^\s*(?:export\s+|const\s+|let\s+|var\s+|readonly\s+)?{re.escape(name)}\s*[:=]\s*"
            r"[\"']?(?P<url>https://[^\s\"'`)]+)",
            re.IGNORECASE,
        )
        found = [m.group("url") for text in file.lines if (m := pattern.match(text))]
        if len(found) == 1:
            where = parse_destination(found[0])
            if not where.odd and not where.placeholder:
                return where.host
    return None


def _window(file: _FileContext, number: int, before: int, after: int) -> str:
    return "\n".join(file.lines[max(0, number - 1 - before) : number + after])


def _code_reason(line: str, file: _FileContext, number: int) -> str | None:
    """Why a dynamic-code finding is ordinary code: a regular expression, a database, a model."""

    if file.relative.lower().endswith(
        (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".html", ".htm")
    ):
        if (
            _REGEX_EXEC.search(line) or _REGEX_LOOP_EXEC.search(line)
        ) and not _PROGRAM_WORDS.search(line):
            return "a regular expression match (exec), not a program run"
        if _DB_EXEC.search(line) and not _PROGRAM_WORDS.search(line):
            tail = line.split("exec(", 1)[-1]
            following = file.lines[number] if number < len(file.lines) else ""
            if _SQL_START.search(tail) or _SQL_START.search(following):
                return "a database statement, not a program run"
    if file.relative.lower().endswith((".py", ".ipynb")):
        if _MODEL_EVAL.search(line) and "eval(" in line and not re.search(r"eval\(\s*[^\s)]", line):
            return "a model switched to evaluation mode: eval() with no argument runs nothing"
        if _VERSION_IMPORT.search(line) and not re.search(r"\.(?:system|popen|run|call)\b", line):
            return "the version of a named module is read"
        literal = _LITERAL_IMPORT.search(line)
        if (
            literal is not None
            and literal.group(1) in _SAFE_MODULES
            and line.count("__import__(") == 1
            and not re.search(r"\beval\b|\bexec\b", line)
        ):
            return f"a standard module ({literal.group(1)}) imported by name"
        if (
            "__import__(" in line
            and not re.search(
                r"__import__\([^)]*\)\s*\.|\.(?:system|popen|run|call|Popen)\b|eval|exec", line
            )
            and _IMPORT_GUARD.search(_window(file, number, 3, 6))
        ):
            return "a dependency check inside an ImportError handler"
    return None


_NEARBY_ACTION = re.compile(
    r"\bcurl\b|\bwget\b|https?://|\bssh\b|\btoken\b|\bpassword\b|\bcredential|\bsecret\b|"
    r"\bupload|\bexfil|\bsend\b|\bpost\b|\binstall|\bexecute\b|\brun\b|\bdelete\b|"
    r"\bsudo\b|\bchmod\b|\beval\b|\.env\b|/etc/|~/",
    re.IGNORECASE,
)


def _only_a_wording_rule(finding: Finding, file: _FileContext) -> bool:
    """The "never tell the user" rule, with no action, address or secret within two lines.

    Only that rule: the phrases that override earlier instructions or ask for a key are never
    lowered here.
    """

    if "conceal" not in finding.message:
        return False
    number = finding.evidence.line or 0
    window = file.lines[max(0, number - 3) : number + 2]
    return not _NEARBY_ACTION.search(" ".join(window))


def _brand(host: str) -> str:
    parts = host.lower().strip(".").split(".")
    return parts[-2] if len(parts) >= 2 else parts[0]


def _named_by_description(host: str, description: str) -> bool:
    """The skill's declared description names this host or its brand. SKILL.md as a whole does not
    count: the line being judged is in it, so every host on it would name itself."""

    host = host.lower().strip(".")
    brand = _brand(host)
    tokens = set(re.split(r"[^a-z0-9]+", description))
    return bool(
        host
        and (host in description or (len(brand) >= 4 and brand in description) or brand in tokens)
        and len(brand) >= 3
    )


def _documented(host: str, description: str, skill_md: str) -> bool:
    """The host is one the skill's own description or SKILL.md names."""

    host = host.lower().strip(".")
    brand = _brand(host)
    return bool(host and (host in skill_md or (len(brand) >= 4 and brand in description)))


def _lower(finding: Finding, reason: str) -> Finding:
    return finding.model_copy(
        update={
            "severity": Severity.LOW,
            "message": f"{finding.message} (lowered to LOW: {reason})",
        }
    )


def relax_findings(findings: Iterable[Finding], package: SkillPackage) -> list[Finding]:
    """The findings, with the ones the context makes ordinary lowered to LOW."""

    files = {
        text_file.relative.replace("\\", "/"): _FileContext(text_file)
        for text_file in package.text_files
    }
    skill_md = (files["SKILL.md"].text if "SKILL.md" in files else "").lower()
    description = f"{package.name or ''} {package.description or ''}".lower()
    package_credential = any(item.strong_credential for item in files.values())
    out: list[Finding] = []
    for finding in findings:
        file = files.get((finding.evidence.file or "").replace("\\", "/"))
        if file is None or finding.severity.rank < Severity.MEDIUM.rank:
            out.append(finding)
            continue
        reason = _reason(finding, file, description, skill_md, package_credential)
        out.append(_lower(finding, reason) if reason else finding)
    return out


def _reason(
    finding: Finding,
    file: _FileContext,
    description: str,
    skill_md: str,
    package_credential: bool,
) -> str | None:
    kind = finding.finding_type or ""
    if "invisible characters" in finding.message or "lookalike" in finding.message:
        return None  # text written to evade the checks is never ordinary
    line = finding.evidence.code or ""
    number = finding.evidence.line or 0
    in_fence = number in file.fenced
    prose = file.is_markdown and not in_fence

    if kind == "remote-resource" and finding.severity.value == "medium":
        host = first_host(line)
        if host in _VENDOR_CDN_HOSTS and not suspect_url(line):
            return "a script or style sheet from a well-known CDN"
    if kind == "dns-lookup" and prose and not line.lstrip().startswith(("$", ">")):
        return "the words host or dig in a sentence, not a command"
    if (
        kind == "persistence"
        and file.is_markdown
        and not re.search(r"https?://|\bcurl\b|\bwget\b|\|\s*(?:ba|z)?sh\b", line)
    ):
        return "documentation of a shell profile or service, with no download on the line"
    if kind == "hidden-instruction" and not file.hidden_characters:
        return "a phrase about hidden text, and no hidden characters in this file"
    # Cloud and registry settings that documentation names. A private key, a keychain or a
    # browser store is never lowered: a guide has little reason to point at one.
    if (
        kind in {"credential-path", "credential-store"}
        and file.is_markdown
        and _DOCUMENTED_SETTING.search(line)
        and not _PRIVATE_STORE.search(line)
        and not re.search(r"https?://", line)
        and not SEND.search(line)
        and not file.suspect_destination
    ):
        return "a credential setting named in documentation that cannot send anything"
    if kind == "dns-lookup" and not re.search(r"[$`]|%s|\{\}|base64|xxd", line):
        return "a lookup of a fixed name: no data is put into the request"
    if (
        kind == "obfuscation"
        and file.is_markdown
        and not re.search(
            r"\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b|\|\s*(?:python3?|perl|ruby|node)\b|\beval\b", line
        )
    ):
        return "a decode shown in documentation that is not run as code"
    if kind == "instruction-injection" and file.is_markdown and _only_a_wording_rule(finding, file):
        return "a wording rule for the agent's replies, with no action or secret near it"
    if kind == "dynamic-code" and file.is_markdown:
        return "code shown in documentation"
    if kind == "dynamic-code":
        reason = _code_reason(line, file, number)
        if reason is not None:
            return reason
    if kind == "secret-access" and _only_checked_or_mentioned(line, file, number):
        return "the variable is tested for or named in a comment, and nothing near it sends"
    if kind == "secret-access" and not file.suspect_destination:
        header = _AUTH_HEADER.search(line)
        if header is not None:
            urls = _HTTPS_URL.findall(_window(file, number, 8, 4))
            hosts = [parse_destination(u) for u in urls]
            if (
                hosts
                and all(not h.odd and not h.placeholder for h in hosts)
                and all(
                    is_credential_bound(frozenset({("env", header.group("var"))}), h.host)
                    for h in hosts
                )
            ):
                return "a vendor's own key sent in a header to that vendor's host, shown in documentation"
    if kind == "destructive-command" and file.is_markdown and not file.can_send:
        return "a cleanup command named in documentation"
    if kind == "shell-exec":
        piped = _PIPE_TO_SHELL.search(line)
        if piped:
            # Every address fetched must be a genuine vendor install host, compared by exact
            # equality after the authority is read properly. One other URL on the line is enough
            # to keep the finding.
            urls = [m.group(0) for m in _URL_TOKEN.finditer(piped.group("fetch"))]
            hosts = [parse_destination(url) for url in urls]
            vendor_or_named = bool(hosts) and all(
                not h.odd
                and (h.host in _VENDOR_INSTALL_HOSTS or _named_by_description(h.host, description))
                for h in hosts
            )
            if file.is_markdown and vendor_or_named and not suspect_destination(line):
                return f"a documented install script from {hosts[0].host}"
            if _COMMENT_START.match(line) and vendor_or_named and not suspect_destination(line):
                return "an install command written in a comment, which is not run"
        elif _LITERAL_SHELL_CALL.search(line) and not _RISKY_LITERAL.search(line):
            return "a fixed command string with nothing built from input"
    if kind == "exfil-http-post":
        if suspect_destination(line) or file.strong_credential or file.suspect_destination:
            return None
        if file.is_markdown:
            if (
                any(parse_destination(m.group(0)).placeholder for m in _URL_TOKEN.finditer(line))
                and file.bare_address
            ):
                return None  # the address behind a placeholder may be the bare one in this file
            return "an API call shown in documentation"
        host = first_host(line) or _resolved_host(line, file)
        if package_credential or host is None:
            return None  # an address from settings or input says nothing about where data goes
        if _documented(host, description, skill_md):
            return f"a request to {host}, which the skill's own description names"
    return None


__all__ = ["parse_destination", "relax_findings", "suspect_destination", "suspect_url"]
