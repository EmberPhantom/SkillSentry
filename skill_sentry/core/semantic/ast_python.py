"""AST-based detection for Python scripts.

Regex anchors miss aliased calls such as ``from subprocess import Popen as P``.
This visitor records import aliases and resolves each call to its real dotted
name before matching it against the rule table below.  Findings use the same
finding types as the regex anchors, so fusion and reports treat them alike.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass

from skill_sentry.core.contracts import Finding, FindingEvidence, Severity, Stage


@dataclass(frozen=True)
class _Rule:
    finding_type: str
    severity: Severity
    message: str


_CALL_RULES: dict[str, _Rule] = {
    "os.system": _Rule("shell-exec", Severity.HIGH, "Shell command execution via os.system"),
    "os.popen": _Rule("shell-exec", Severity.HIGH, "Shell command execution via os.popen"),
    "pty.spawn": _Rule("shell-exec", Severity.HIGH, "Interactive shell spawn via pty.spawn"),
    "eval": _Rule("dynamic-code", Severity.HIGH, "Dynamic code evaluation via eval"),
    "exec": _Rule("dynamic-code", Severity.HIGH, "Dynamic code execution via exec"),
    "compile": _Rule("dynamic-code", Severity.MEDIUM, "Runtime code compilation via compile"),
    "pickle.loads": _Rule(
        "unsafe-deserialization", Severity.HIGH, "Unsafe deserialization via pickle.loads"
    ),
    "pickle.load": _Rule(
        "unsafe-deserialization", Severity.HIGH, "Unsafe deserialization via pickle.load"
    ),
    "marshal.loads": _Rule(
        "unsafe-deserialization", Severity.HIGH, "Unsafe deserialization via marshal.loads"
    ),
    "socket.socket": _Rule("raw-socket", Severity.MEDIUM, "Raw socket creation"),
    "socket.create_connection": _Rule("raw-socket", Severity.MEDIUM, "Outbound socket connection"),
    "requests.post": _Rule("exfil-http-post", Severity.HIGH, "HTTP POST to a remote host"),
    "requests.put": _Rule("exfil-http-post", Severity.HIGH, "HTTP PUT to a remote host"),
    "requests.patch": _Rule("exfil-http-post", Severity.HIGH, "HTTP PATCH to a remote host"),
    "httpx.post": _Rule("exfil-http-post", Severity.HIGH, "HTTP POST to a remote host"),
    "urllib.request.urlopen": _Rule("exfil-http-post", Severity.MEDIUM, "URL fetch via urlopen"),
    "dict": _Rule("secret-access", Severity.MEDIUM, "Whole-environment read"),
}

_ENV_DUMP_CALLS = frozenset({"os.environ.copy", "os.environ.items", "os.environ.keys"})


class _Visitor(ast.NodeVisitor):
    def __init__(self, filename: str) -> None:
        self.filename = filename
        self.aliases: dict[str, str] = {}
        self.findings: list[Finding] = []

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.aliases[alias.asname or alias.name.split(".")[0]] = (
                alias.name if alias.asname else alias.name.split(".")[0]
            )
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module and node.level == 0:
            for alias in node.names:
                self.aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
        self.generic_visit(node)

    def _resolve(self, node: ast.expr) -> str | None:
        if isinstance(node, ast.Name):
            return self.aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            base = self._resolve(node.value)
            return f"{base}.{node.attr}" if base else None
        return None

    def visit_Call(self, node: ast.Call) -> None:
        name = self._resolve(node.func)
        if name is not None:
            self._check(node, name)
        self.generic_visit(node)

    def _check(self, node: ast.Call, name: str) -> None:
        if name in (
            "subprocess.run",
            "subprocess.call",
            "subprocess.Popen",
            "subprocess.check_output",
            "subprocess.check_call",
            "subprocess.getoutput",
            "subprocess.getstatusoutput",
        ):
            if any(
                keyword.arg == "shell"
                and isinstance(keyword.value, ast.Constant)
                and keyword.value.value is True
                for keyword in node.keywords
            ):
                self._add(
                    node, "shell-exec", Severity.HIGH, f"Shell execution with shell=True via {name}"
                )
            return
        if name in _ENV_DUMP_CALLS:
            self._add(node, "secret-access", Severity.MEDIUM, f"Whole-environment read via {name}")
            return
        if name == "yaml.load" and not any(keyword.arg == "Loader" for keyword in node.keywords):
            self._add(
                node, "unsafe-deserialization", Severity.HIGH, "Unsafe YAML load without SafeLoader"
            )
            return
        rule = _CALL_RULES.get(name)
        if rule is None:
            return
        if name == "dict" and not (node.args and self._is_environ(node.args[0])):
            return
        if name == "urllib.request.urlopen" and not any(
            keyword.arg == "data" for keyword in node.keywords
        ):
            return
        self._add(node, rule.finding_type, rule.severity, rule.message)

    def _is_environ(self, node: ast.expr) -> bool:
        return self._resolve(node) == "os.environ"

    def _add(self, node: ast.Call, kind: str, severity: Severity, message: str) -> None:
        line = getattr(node, "lineno", 1)
        self.findings.append(
            Finding(
                stage=Stage.DETERMINISTIC_ANCHOR,
                severity=severity,
                message=message,
                type=kind,
                evidence=FindingEvidence(file=self.filename, line=line, code=f"line {line}"),
            )
        )


def scan_python_ast(filename: str, text: str) -> tuple[list[Finding], str | None]:
    """Return findings for one Python file, and an error message when it does not parse.

    An unparseable file is never skipped silently: the caller marks the stage degraded.
    """

    try:
        tree = ast.parse(text, filename=filename)
    except (SyntaxError, ValueError, RecursionError) as exc:
        return [], f"could not parse {filename}: {type(exc).__name__}"
    visitor = _Visitor(filename)
    visitor.visit(tree)
    return visitor.findings, None


__all__ = ["scan_python_ast"]
