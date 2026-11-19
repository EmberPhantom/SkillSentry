"""Cross-file download-then-execute: one file saves content, another file runs it.

Each file alone can look ordinary: a script that downloads to ``/tmp/payload.sh`` and a
script that runs ``/tmp/payload.sh`` match no single-file pattern. This check collects, per
file, the paths it writes (and whether the write is a network download) and the paths it
executes, then reports every path that one file writes and a *different* file in the package
executes. The finding names both places.

What counts as executing a path: running it as a command (``/tmp/x.sh``, ``./x.sh``), as the
script of an interpreter (``bash x.sh``, ``python x.py``, ``node x.js``, ``source x``),
``chmod +x``, and in Python ``subprocess``/``os.system``/``runpy.run_path``/``exec(open(x))``,
and in JavaScript ``child_process`` and ``require``. A path that is only *read* (``cat x``,
``open(x)``, an argument to some other program) does not count, so a script that downloads
data and another that processes it stays quiet.

This is a heuristic over literal and simply computed paths (string constants, f-strings,
``+``, ``os.path.join``, ``Path / x``, shell variables). A path built any other way is not
seen. It does not look at the same file writing and running its own download; the
single-file anchors cover the piped forms.
"""

from __future__ import annotations

import ast
import re
import shlex
from collections.abc import Iterable
from dataclasses import dataclass

from skill_sentry_cli.core.anchors.confusables import normalise_line, normalise_text
from skill_sentry_cli.core.contracts import Finding, FindingEvidence, Severity, Stage
from skill_sentry_cli.core.parser import SkillPackage, TextFile

MAX_FINDINGS = 10

_SHELL_SUFFIXES = (".sh", ".bash", ".zsh", ".ksh")
_PY_SUFFIXES = (".py",)
_JS_SUFFIXES = (".js", ".mjs", ".cjs", ".ts")
_PS_SUFFIXES = (".ps1",)

_SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "ash"}
_SOURCERS = {"source", "."}
_INTERPRETERS = {
    "python",
    "python2",
    "python3",
    "node",
    "nodejs",
    "deno",
    "bun",
    "perl",
    "ruby",
    "php",
    "pwsh",
    "powershell",
    "lua",
    "tsx",
    "ts-node",
}
_WRAPPERS = {"sudo", "nohup", "time", "exec", "command", "env", "nice", "stdbuf", "setsid", "doas"}
_NETWORK_FETCHERS = {"curl", "wget", "aria2c", "fetch"}
_OPERATORS = {";", "&&", "||", "|", "&", "(", ")", "|&"}
_EXEC_MODE = re.compile(r"^(?:[ugoa]*\+[rwx]*x[rwx]*|[0-7]?[0-7][0-7][0-7])$")
_PY_NETWORK = re.compile(
    r"\b(?:requests|httpx|urllib\.request|urlopen|urlretrieve|http\.client|aiohttp|"
    r"pycurl|wget\.download)\b"
)
_JS_NETWORK = re.compile(r"\b(?:fetch\(|https?\.get\(|https?\.request\(|axios|node-fetch|got\()")


@dataclass(frozen=True)
class _Site:
    path: str
    file: str
    line: int
    code: str
    kind: str  # download | write | exec
    how: str = "run"  # run | chmod


def _norm_path(value: str) -> str | None:
    """A comparable path, or ``None`` when it still contains something unresolved."""

    value = value.strip().strip("'\"")
    if not value:
        return None
    value = value.replace("${TMPDIR:-/tmp}", "/tmp").replace("$TMPDIR", "/tmp")
    value = value.replace("${HOME}", "~").replace("$HOME", "~")
    if "$" in value or "{" in value or "`" in value or "*" in value:
        return None
    value = re.sub(r"/{2,}", "/", value)
    while value.startswith("./"):
        value = value[2:]
    return value or None


_CODE_SUFFIXES = (
    ".sh",
    ".bash",
    ".zsh",
    ".ksh",
    ".py",
    ".js",
    ".mjs",
    ".cjs",
    ".ts",
    ".ps1",
    ".pl",
    ".rb",
    ".php",
    ".bat",
    ".cmd",
    ".so",
    ".dll",
    ".exe",
    ".bin",
    ".run",
    ".command",
)


def _code_like(path: str) -> bool:
    """A path that looks like a program or script, not a configuration or data file.

    A file one script generates and another runs is common (a sourced ``.env`` or a ``.conf``),
    so a plain local write is reported only when the target looks like code, or has no suffix
    at all, which is how executables are usually named. A download is always reported.
    """

    name = path.rsplit("/", 1)[-1].lower()
    return name.endswith(_CODE_SUFFIXES) or "." not in name


def _same_path(a: str, b: str) -> bool:
    return a == b


# ---------------------------------------------------------------------------
# Shell command lines (also used for Python subprocess argument lists)
# ---------------------------------------------------------------------------
def _split_commands(tokens: list[str]) -> list[list[str]]:
    commands: list[list[str]] = [[]]
    for token in tokens:
        if token in _OPERATORS:
            commands.append([])
        else:
            commands[-1].append(token)
    return [command for command in commands if command]


def _tokenise(line: str) -> list[str] | None:
    try:
        lexer = shlex.shlex(line, posix=True, punctuation_chars=True)
        lexer.whitespace_split = True
        lexer.commenters = "#"
        return list(lexer)
    except ValueError:
        return None


def _strip_wrappers(command: list[str]) -> list[str]:
    index = 0
    while index < len(command):
        token = command[index]
        if (
            re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", token)
            or token in _WRAPPERS
            or (token.startswith("-") and index > 0 and command[index - 1] in _WRAPPERS)
        ):
            index += 1
            continue
        break
    return command[index:]


def _first_operand(args: list[str]) -> str | None:
    """The script an interpreter runs: the first argument that is not an option."""

    skip = False
    for arg in args:
        if skip:
            skip = False
            continue
        if arg in {"-c", "-e", "-E", "-m", "-r", "--eval", "--print", "-p"}:
            return None  # runs a string, not a file
        if arg in {"-File", "-file", "-f", "--file"}:
            skip = False
            continue
        if arg.startswith("-"):
            continue
        return arg
    return None


def _command_sites(
    command: list[str], *, file: str, line: int, code: str, network_file: bool
) -> list[_Site]:
    """Writes and executions in one simple command."""

    sites: list[_Site] = []
    command = _strip_wrappers(command)
    if not command:
        return sites

    # Redirections: `... > path` writes the command's output.
    cleaned: list[str] = []
    index = 0
    while index < len(command):
        token = command[index]
        if token in {">", ">>", ">|", "1>", "1>>", "2>", "&>"} and index + 1 < len(command):
            if token not in {"2>"}:
                target = _norm_path(command[index + 1])
                if target and not target.startswith("/dev/"):
                    head = command[0].rsplit("/", 1)[-1]
                    kind = "download" if head in _NETWORK_FETCHERS else "write"
                    sites.append(_Site(target, file, line, code, kind))
            index += 2
            continue
        cleaned.append(token)
        index += 1
    command = cleaned
    if not command:
        return sites

    head = command[0]
    name = head.rsplit("/", 1)[-1]
    args = command[1:]

    if name in {"curl", "wget"}:
        target = _norm_path(_fetch_output(name, args) or "")
        if target and target != "-":
            sites.append(_Site(target, file, line, code, "download"))
        return sites
    if name == "tee":
        for arg in args:
            target = _norm_path(arg) if not arg.startswith("-") else None
            if target:
                sites.append(_Site(target, file, line, code, "write"))
        return sites
    if name == "chmod":
        modes = [a for a in args if _EXEC_MODE.match(a)]
        if modes:
            for arg in args:
                if arg in modes or arg.startswith("-"):
                    continue
                target = _norm_path(arg)
                if target:
                    sites.append(_Site(target, file, line, code, "exec", "chmod"))
        return sites
    if name in _SHELLS:
        if "-c" in args:
            position = args.index("-c")
            if position + 1 < len(args):
                tokens = _tokenise(args[position + 1])
                for inner in _split_commands(tokens or []):
                    sites.extend(
                        _command_sites(
                            inner, file=file, line=line, code=code, network_file=network_file
                        )
                    )
            return sites
        operand = _first_operand(args)
        target = _norm_path(operand) if operand else None
        if target:
            sites.append(_Site(target, file, line, code, "exec"))
        return sites
    if name in _SOURCERS:
        operand = _first_operand(args)
        target = _norm_path(operand) if operand else None
        if target:
            sites.append(_Site(target, file, line, code, "exec"))
        return sites
    if name in _INTERPRETERS:
        operand = _first_operand(args)
        target = _norm_path(operand) if operand else None
        if target:
            sites.append(_Site(target, file, line, code, "exec"))
        return sites
    if name in {"Start-Process", "&"}:
        operand = _first_operand(args)
        target = _norm_path(operand) if operand else None
        if target:
            sites.append(_Site(target, file, line, code, "exec"))
        return sites
    if "/" in head or head.startswith("./") or head.startswith("~"):
        # The command itself is a path: it is being run.
        target = _norm_path(head)
        if target:
            sites.append(_Site(target, file, line, code, "exec"))
    return sites


# Short options that take a value, so that in a bundle like `-sSLo FILE` the letters after one of
# them are its value and not more flags.
_CURL_VALUE_SHORT = frozenset("oHduAeXxbcwmyYzKTrFDECPQtUZ")
_WGET_VALUE_SHORT = frozenset("OoPaetTwQUiBlIXDAR")


def _short_option_values(args: list[str], value_letters: frozenset[str]) -> list[tuple[str, str]]:
    """``(letter, value)`` for each value-taking short option, in a bundle or on its own.

    Handles ``-o file``, ``-ofile`` and ``-sSLo file`` (the file-taking letter last in a
    bundle). A bundle stops at the first letter that takes a value: what follows it is the
    value, or, when nothing follows, the next argument is.
    """

    found: list[tuple[str, str]] = []
    index = 0
    while index < len(args):
        arg = args[index]
        index += 1
        if not arg.startswith("-") or arg.startswith("--") or arg == "-":
            continue
        for position, letter in enumerate(arg[1:], start=1):
            if letter not in value_letters:
                continue
            attached = arg[position + 1 :]
            if attached:
                value = attached[1:] if attached.startswith("=") and letter != "H" else attached
            elif index < len(args):
                value = args[index]
                index += 1
            else:
                value = ""
            found.append((letter, value))
            break
    return found


def _long_option(args: list[str], names: tuple[str, ...]) -> str | None:
    for position, arg in enumerate(args):
        for name in names:
            if arg == name and position + 1 < len(args):
                return args[position + 1]
            if arg.startswith(name + "="):
                return arg.split("=", 1)[1]
    return None


def _fetch_output(name: str, args: list[str]) -> str | None:
    """The path a ``curl`` or ``wget`` command saves to, or ``None``.

    curl: ``-o FILE`` (also bundled, ``-sSLo FILE``, or attached, ``-oFILE``), ``--output FILE``
    or ``--output=FILE``; ``-O`` saves under the name in the URL. wget: ``-O FILE`` (also
    ``-qO FILE``, ``-OFILE``, ``--output-document=FILE``), ``-P DIR`` for the directory, and the
    URL's name when no file is given. ``wget -o`` is the log file, not the download.
    """

    url = next((a for a in args if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", a)), "")
    base = url.split("?", 1)[0].split("#", 1)[0].rstrip("/").rsplit("/", 1)[-1] if url else ""
    if base and "://" in base:
        base = ""
    if name == "curl":
        out = _long_option(args, ("--output",))
        for letter, value in _short_option_values(args, _CURL_VALUE_SHORT):
            if letter == "o":
                out = value
        remote_name = "--remote-name" in args or any(
            a.startswith("-")
            and not a.startswith("--")
            and "O" in _flag_letters(a, _CURL_VALUE_SHORT)
            for a in args
        )
        if out:
            return out
        return base if remote_name and base else None
    out = _long_option(args, ("--output-document",))
    directory = _long_option(args, ("--directory-prefix",)) or ""
    for letter, value in _short_option_values(args, _WGET_VALUE_SHORT):
        if letter == "O":
            out = value
        elif letter == "P":
            directory = value
    if out:
        return out
    if base:
        return (directory.rstrip("/") + "/" if directory else "") + base
    return None


def _flag_letters(bundle: str, value_letters: frozenset[str]) -> str:
    """The flag letters of a short-option bundle, up to the first one that takes a value."""

    letters = ""
    for letter in bundle[1:]:
        letters += letter
        if letter in value_letters:
            break
    return letters


def _shell_constants(lines: list[str]) -> dict[str, str]:
    constants: dict[str, str] = {}
    for line in lines:
        match = re.match(
            r"^\s*(?:export\s+|readonly\s+|local\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$", line
        )
        if not match:
            continue
        tokens = _tokenise(match.group(2))
        if tokens and len(tokens) == 1:
            constants[match.group(1)] = _substitute(tokens[0], constants)
    return constants


def _substitute(value: str, constants: dict[str, str]) -> str:
    def replace(match: re.Match[str]) -> str:
        name = match.group(1) or match.group(2)
        return constants.get(name, match.group(0))

    return re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)", replace, value)


_ASSIGNMENT = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", re.DOTALL)
_DECLARERS = {"export", "readonly", "local", "declare", "typeset"}


def _shell_sites(text_file: TextFile) -> list[_Site]:
    lines = text_file.text.splitlines()
    normalised = [normalise_line(line) for line in lines]
    constants = _shell_constants(normalised)
    sites: list[_Site] = []
    for number, (raw, line) in enumerate(zip(lines, normalised, strict=True), start=1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if len(line) > 4000:
            continue
        tokens = _tokenise(line)
        if not tokens:
            continue
        # Variables set earlier on the same line (`D=/tmp/w; curl -o $D/z`) or just before a
        # command (`D=/tmp/w curl -o $D/z`) are known to the commands that follow. The second
        # form is not what a shell does, but treating it as visible can only find more.
        local = dict(constants)
        for command in _split_commands(tokens):
            while command and command[0] in _DECLARERS:
                command = command[1:]
            assigned = 0
            for token in command:
                match = _ASSIGNMENT.match(token)
                if not match:
                    break
                local[match.group(1)] = _substitute(match.group(2), local)
                assigned += 1
            command = command[assigned:]
            if not command:
                continue
            sites.extend(
                _command_sites(
                    [_substitute(token, local) for token in command],
                    file=text_file.relative,
                    line=number,
                    code=raw.strip()[:200],
                    network_file=False,
                )
            )
    return sites


# ---------------------------------------------------------------------------
# Python (AST)
# ---------------------------------------------------------------------------
class _PyEval:
    """Evaluate a path expression made of constants, names, f-strings, ``+`` and joins."""

    def __init__(self) -> None:
        self.names: dict[str, str] = {}

    def text(self, node: ast.AST | None) -> str | None:
        if node is None:
            return None
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.Name):
            return self.names.get(node.id)
        if isinstance(node, ast.JoinedStr):
            parts: list[str] = []
            for value in node.values:
                if isinstance(value, ast.Constant):
                    parts.append(str(value.value))
                elif isinstance(value, ast.FormattedValue):
                    inner = self.text(value.value)
                    if inner is None:
                        return None
                    parts.append(inner)
            return "".join(parts)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left, right = self.text(node.left), self.text(node.right)
            return left + right if left is not None and right is not None else None
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            left, right = self.text(node.left), self.text(node.right)
            return f"{left}/{right}" if left is not None and right is not None else None
        if isinstance(node, ast.Call):
            callee = _call_name(node)
            if callee in {"Path", "PurePath", "str", "os.fspath", "pathlib.Path"} and node.args:
                return self.text(node.args[0])
            if callee in {"os.path.join", "posixpath.join"} and node.args:
                pieces = [self.text(arg) for arg in node.args]
                resolved = [part for part in pieces if part is not None]
                if len(resolved) != len(pieces):
                    return None
                return "/".join(
                    part.strip("/") if index else part.rstrip("/")
                    for index, part in enumerate(resolved)
                )
            if callee in {"os.path.expanduser"} and node.args:
                return self.text(node.args[0])
            if callee in {"tempfile.gettempdir"}:
                return "/tmp"
        return None

    def tokens(self, node: ast.AST) -> list[str] | None:
        """The argv of a ``subprocess``/``os.system`` call, or ``None`` when not computable."""

        if isinstance(node, (ast.List, ast.Tuple)):
            parts = [self.text(element) for element in node.elts]
            return (
                None if any(part is None for part in parts) else [p for p in parts if p is not None]
            )
        value = self.text(node)
        if value is None:
            return None
        return _tokenise(value)


def _call_name(node: ast.Call) -> str:
    func = node.func
    parts: list[str] = []
    while isinstance(func, ast.Attribute):
        parts.append(func.attr)
        func = func.value
    if isinstance(func, ast.Name):
        parts.append(func.id)
    return ".".join(reversed(parts))


_PY_EXEC_CALLS = {
    "subprocess.run",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "subprocess.Popen",
    "os.system",
    "os.popen",
    "Popen",
    "check_call",
    "check_output",
}
_PY_EXECV = ("os.exec", "os.spawn", "os.posix_spawn")


def _python_sites(text_file: TextFile) -> list[_Site]:
    text = normalise_text(text_file.text)
    try:
        tree = ast.parse(text, filename=text_file.relative)
    except (SyntaxError, ValueError):
        return []
    lines = text_file.text.splitlines()
    network_file = bool(_PY_NETWORK.search(text))
    evaluator = _PyEval()
    # Constants first (module level and function level), in source order.
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            if isinstance(target, ast.Name):
                value = evaluator.text(node.value)
                if value is not None:
                    evaluator.names[target.id] = value
    sites: list[_Site] = []

    def code_at(node: ast.AST) -> str:
        number = getattr(node, "lineno", 1)
        return lines[number - 1].strip()[:200] if 1 <= number <= len(lines) else ""

    def add(path: str | None, node: ast.AST, kind: str, how: str = "run") -> None:
        normalised = _norm_path(path) if path else None
        if normalised:
            sites.append(
                _Site(
                    normalised,
                    text_file.relative,
                    getattr(node, "lineno", 1),
                    code_at(node),
                    kind,
                    how,
                )
            )

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node)
        short = name.rsplit(".", 1)[-1]
        if short == "urlretrieve" and len(node.args) >= 2:
            add(evaluator.text(node.args[1]), node, "download")
        elif name == "open" or (name.endswith(".open") and name.startswith(("io.", "codecs."))):
            mode = evaluator.text(node.args[1]) if len(node.args) > 1 else None
            for keyword in node.keywords:
                if keyword.arg == "mode":
                    mode = evaluator.text(keyword.value)
            if mode and any(flag in mode for flag in "wax") and node.args:
                add(evaluator.text(node.args[0]), node, "download" if network_file else "write")
        elif short in {"write_text", "write_bytes"} and isinstance(node.func, ast.Attribute):
            add(evaluator.text(node.func.value), node, "download" if network_file else "write")
        elif name in _PY_EXEC_CALLS or short in {"Popen", "check_call", "check_output"}:
            if node.args:
                tokens = evaluator.tokens(node.args[0])
                if tokens:
                    for command in _split_commands(tokens):
                        for item in _command_sites(
                            command,
                            file=text_file.relative,
                            line=getattr(node, "lineno", 1),
                            code=code_at(node),
                            network_file=network_file,
                        ):
                            sites.append(item)
        elif name.startswith(_PY_EXECV) and node.args:
            candidates = [evaluator.text(arg) for arg in node.args[:3]]
            for candidate in candidates:
                add(candidate, node, "exec")
                if candidate:
                    break
        elif short in {"run_path", "run_module"} and "runpy" in name and node.args:
            add(evaluator.text(node.args[0]), node, "exec")
        elif short == "spec_from_file_location" and len(node.args) >= 2:
            add(evaluator.text(node.args[1]), node, "exec")
        elif short == "chmod" and name.startswith("os.") and len(node.args) >= 2:
            mode_node = node.args[1]
            if (
                isinstance(mode_node, ast.Constant)
                and isinstance(mode_node.value, int)
                and mode_node.value & 0o111
            ):
                add(evaluator.text(node.args[0]), node, "exec", "chmod")
        elif name in {"exec", "eval"} and node.args:
            for inner in ast.walk(node.args[0]):
                if (
                    isinstance(inner, ast.Call)
                    and _call_name(inner) in {"open", "Path"}
                    and inner.args
                ):
                    add(evaluator.text(inner.args[0]), node, "exec")
    return sites


# ---------------------------------------------------------------------------
# JavaScript (patterns)
# ---------------------------------------------------------------------------
_JS_STRING = r"""(?:'([^'\n]*)'|"([^"\n]*)"|`([^`\n$]*)`)"""
_JS_CONST = re.compile(
    r"""^\s*(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*""" + _JS_STRING + r"\s*;?\s*$"
)
_JS_WRITE = re.compile(
    r"\b(?:fs\.)?(?:writeFileSync|writeFile|appendFileSync|appendFile|createWriteStream)\s*\(\s*"
    r"(?:" + _JS_STRING + r"|([A-Za-z_$][\w$]*))"
)
_JS_EXEC_CALL = re.compile(
    r"\b(?:child_process\.)?(?:execSync|exec|spawnSync|spawn|execFileSync|execFile)\s*\(\s*"
    r"(?:" + _JS_STRING + r"|([A-Za-z_$][\w$]*))"
)
_JS_REQUIRE = re.compile(r"\brequire\s*\(\s*" + _JS_STRING + r"\s*\)")
_JS_CHMOD = re.compile(
    r"\bchmod(?:Sync)?\s*\(\s*(?:" + _JS_STRING + r"|([A-Za-z_$][\w$]*))\s*,\s*(0o?[0-7]{3,4}|\d+)"
)


def _javascript_sites(text_file: TextFile) -> list[_Site]:
    lines = text_file.text.splitlines()
    network_file = bool(_JS_NETWORK.search(text_file.text))
    constants: dict[str, str] = {}
    for raw in lines:
        match = _JS_CONST.match(normalise_line(raw))
        if match:
            constants[match.group(1)] = next(g for g in match.groups()[1:] if g is not None)
    sites: list[_Site] = []

    def literal(groups: Iterable[str | None]) -> str | None:
        values = list(groups)
        text = next((v for v in values[:3] if v is not None), None)
        if text is not None:
            return text
        name = values[3] if len(values) > 3 else None
        return constants.get(name) if name else None

    for number, raw in enumerate(lines, start=1):
        line = normalise_line(raw)
        code = raw.strip()[:200]
        for match in _JS_WRITE.finditer(line):
            path = _norm_path(literal(match.groups()) or "")
            if path:
                sites.append(
                    _Site(
                        path,
                        text_file.relative,
                        number,
                        code,
                        "download" if network_file else "write",
                    )
                )
        for match in _JS_EXEC_CALL.finditer(line):
            text = literal(match.groups())
            if text is None:
                continue
            tokens = _tokenise(text) or []
            for command in _split_commands(tokens):
                sites.extend(
                    _command_sites(
                        command,
                        file=text_file.relative,
                        line=number,
                        code=code,
                        network_file=network_file,
                    )
                )
        for match in _JS_REQUIRE.finditer(line):
            text = next((g for g in match.groups() if g is not None), None)
            path = _norm_path(text or "")
            if path and (
                path.startswith(("/", "~")) or "/" in path or path.endswith((".js", ".cjs", ".mjs"))
            ):
                sites.append(_Site(path, text_file.relative, number, code, "exec"))
        for match in _JS_CHMOD.finditer(line):
            mode = match.group(5)
            text = literal(match.groups()[:4])
            try:
                executable = bool(int(mode, 8 if mode.startswith("0") else 10) & 0o111)
            except ValueError:
                executable = False
            path = _norm_path(text or "")
            if path and executable:
                sites.append(_Site(path, text_file.relative, number, code, "exec", "chmod"))
    return sites


# ---------------------------------------------------------------------------
# PowerShell
# ---------------------------------------------------------------------------
_PS_OUTFILE = re.compile(r"-OutFile\s+(?:\"([^\"]+)\"|'([^']+)'|(\S+))", re.IGNORECASE)
_PS_SETCONTENT = re.compile(
    r"\b(?:Set-Content|Out-File|Add-Content)\s+(?:-Path\s+)?(?:\"([^\"]+)\"|'([^']+)'|(\S+))",
    re.IGNORECASE,
)
_PS_RUN = re.compile(
    r"(?:^\s*&\s*|\bStart-Process\s+(?:-FilePath\s+)?|^\s*\.\s+|\b(?:powershell|pwsh)\b[^\n]*-File\s+)"
    r"(?:\"([^\"]+)\"|'([^']+)'|(\S+))",
    re.IGNORECASE,
)


def _powershell_sites(text_file: TextFile) -> list[_Site]:
    sites: list[_Site] = []
    for number, raw in enumerate(text_file.text.splitlines(), start=1):
        line = normalise_line(raw)
        code = raw.strip()[:200]
        for match in _PS_OUTFILE.finditer(line):
            path = _norm_path(next(g for g in match.groups() if g))
            if path:
                sites.append(_Site(path, text_file.relative, number, code, "download"))
        for match in _PS_SETCONTENT.finditer(line):
            path = _norm_path(next(g for g in match.groups() if g))
            if path:
                sites.append(_Site(path, text_file.relative, number, code, "write"))
        for match in _PS_RUN.finditer(line):
            path = _norm_path(next(g for g in match.groups() if g))
            if path:
                sites.append(_Site(path, text_file.relative, number, code, "exec"))
    return sites


# ---------------------------------------------------------------------------
# Putting it together
# ---------------------------------------------------------------------------
def _language(text_file: TextFile) -> str | None:
    relative = text_file.relative.lower()
    if relative.endswith(_SHELL_SUFFIXES):
        return "shell"
    if relative.endswith(_PY_SUFFIXES):
        return "python"
    if relative.endswith(_JS_SUFFIXES):
        return "javascript"
    if relative.endswith(_PS_SUFFIXES):
        return "powershell"
    first = text_file.text.split("\n", 1)[0]
    if first.startswith("#!"):
        if re.search(r"\b(?:ba|z|da|k|a)?sh\b", first):
            return "shell"
        if "python" in first:
            return "python"
        if "node" in first or "deno" in first or "bun" in first:
            return "javascript"
    return None


def collect_sites(package: SkillPackage) -> list[_Site]:
    sites: list[_Site] = []
    for text_file in package.text_files:
        language = _language(text_file)
        if language == "shell":
            sites.extend(_shell_sites(text_file))
        elif language == "python":
            sites.extend(_python_sites(text_file))
        elif language == "javascript":
            sites.extend(_javascript_sites(text_file))
        elif language == "powershell":
            sites.extend(_powershell_sites(text_file))
    return sites


def analyze_cross_file(package: SkillPackage) -> list[Finding]:
    """Findings for a path that one file writes and a different file runs."""

    sites = collect_sites(package)
    writers = [site for site in sites if site.kind in {"download", "write"}]
    executors = [site for site in sites if site.kind == "exec"]
    findings: list[Finding] = []
    for writer in writers:
        # One finding per writer and per file that runs the path. A line that really runs it
        # is preferred over a bare `chmod +x`, which only prepares it.
        by_file: dict[str, _Site] = {}
        for executor in executors:
            if executor.file == writer.file or not _same_path(writer.path, executor.path):
                continue
            current = by_file.get(executor.file)
            if current is None or (current.how == "chmod" and executor.how == "run"):
                by_file[executor.file] = executor
        for executor in by_file.values():
            downloaded = writer.kind == "download"
            if not downloaded and not _code_like(writer.path):
                # A config or data file that one script generates and another sources is a
                # normal pattern, and its content is the skill's own text. Only a download, or
                # a local write of something that looks like a program, is reported.
                continue
            findings.append(
                Finding(
                    stage=Stage.DETERMINISTIC_ANCHOR,
                    severity=Severity.HIGH,
                    message=(
                        f"{writer.file}:{writer.line} {'downloads to' if downloaded else 'writes'} "
                        f"{writer.path}, and {executor.file}:{executor.line} "
                        f"{'makes it executable' if executor.how == 'chmod' else 'runs it'}"
                    ),
                    finding_type="download-then-exec" if downloaded else "write-then-exec",
                    evidence=FindingEvidence.model_validate(
                        {
                            "file": executor.file,
                            "line": executor.line,
                            "code": executor.code or None,
                            "path": writer.path,
                            "writerFile": writer.file,
                            "writerLine": writer.line,
                            "writerCode": writer.code or None,
                        }
                    ),
                )
            )
            if len(findings) >= MAX_FINDINGS:
                return findings
    return findings


__all__ = ["analyze_cross_file", "collect_sites"]
