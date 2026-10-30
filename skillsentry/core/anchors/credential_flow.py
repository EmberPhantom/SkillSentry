"""Credential flow analysis: sensitive material reaching a network or system sink.

Python scripts are analysed with a small AST taint tracker.  Shell and JavaScript
scripts get a weaker pattern check, because a regex cannot prove a flow.

Severity maps onto main's fusion floors (CRITICAL 95, HIGH 70, MEDIUM 30):

* credential data sent to an undeclared host, or put into a DNS query: CRITICAL
* credential data sent to an unresolved (dynamic) host: HIGH
* credential data sent to a host the skill declares: MEDIUM (reported, not cleared)
* unverified shell or JavaScript pattern match: MEDIUM

The taint tracker is conservative in one direction only: it over-approximates
flows through calls, and it clears a name when that name is reassigned from an
untainted value.
"""

from __future__ import annotations

import ast
import fnmatch
import os
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from skillsentry.core.anchors.declared_hosts import extract_declared_hosts, is_host_declared
from skillsentry.core.contracts import Finding, FindingEvidence, Severity, Stage
from skillsentry.core.parser import SkillPackage

RULES_PATH = Path(__file__).resolve().parent.parent.parent / "rules" / "credential_rules.toml"


@dataclass(frozen=True)
class CredentialRules:
    version: int
    env_patterns: tuple[re.Pattern[str], ...]
    path_globs: tuple[str, ...]
    python_sinks: frozenset[str]
    script_sinks: tuple[re.Pattern[str], ...]


def _load_rules(path: Path = RULES_PATH) -> CredentialRules:
    """Load the rules.  A missing or malformed file is an error, never a silent default."""

    if not path.is_file():
        raise RuntimeError(f"credential rules file is missing: {path}")
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    sources = data.get("sources", {})
    sinks = data.get("sinks", {})
    return CredentialRules(
        version=int(data.get("version", 1)),
        env_patterns=tuple(re.compile(p) for p in sources.get("env_name_patterns", [])),
        path_globs=tuple(sources.get("path_globs", [])),
        python_sinks=frozenset(sinks.get("python_calls", [])),
        script_sinks=tuple(
            re.compile(p)
            for p in list(sinks.get("js_patterns", [])) + list(sinks.get("shell_patterns", []))
        ),
    )


RULES = _load_rules()
RULES_VERSION = RULES.version


def _evidence(file: str, line: int, code: str) -> FindingEvidence:
    return FindingEvidence(file=file, line=line, code=code[:200] or None)


def _first_string_arg(node: ast.Call) -> str | None:
    """The first argument when it is a string literal, otherwise None."""

    if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
        return node.args[0].value
    return None


@dataclass
class _Tracker(ast.NodeVisitor):
    filename: str
    declared_hosts: set[str]
    tainted_vars: set[str] = field(default_factory=set)
    tainted_functions: set[str] = field(default_factory=set)
    string_constants: dict[str, str] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)

    # -- sources ------------------------------------------------------------
    def _secret_name(self, name: str) -> bool:
        return any(pattern.search(name) for pattern in RULES.env_patterns)

    def _sensitive_path(self, path: str) -> bool:
        normalised = path.replace("\\", "/")
        expanded = os.path.expanduser(normalised).replace("\\", "/")
        for glob in RULES.path_globs:
            if fnmatch.fnmatch(normalised, glob) or fnmatch.fnmatch(expanded, glob):
                return True
            if glob.startswith("~/") and normalised.startswith(glob[2:]):
                return True
        return False

    def _call_name(self, node: ast.Call) -> str:
        parts: list[str] = []
        current: ast.AST = node.func
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        return ".".join(reversed(parts))

    def _tainted(self, node: ast.AST | None) -> bool:
        if node is None:
            return False
        if isinstance(node, ast.Name):
            return node.id in self.tainted_vars
        if isinstance(node, ast.Subscript):
            value = node.value
            if (
                isinstance(value, ast.Attribute)
                and value.attr == "environ"
                and isinstance(node.slice, ast.Constant)
                and isinstance(node.slice.value, str)
            ):
                return self._secret_name(node.slice.value)
            return self._tainted(node.value)
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and self._tainted(node.func.value):
                return True
            name = self._call_name(node)
            literal = _first_string_arg(node)
            if name in ("os.getenv", "os.environ.get") and literal is not None:
                return self._secret_name(literal)
            if (
                name in ("open", "Path", "Path.read_text", "Path.read_bytes")
                and literal is not None
            ):
                return self._sensitive_path(literal)
            if any(
                token in name
                for token in ("b64encode", "b64decode", "dumps", "encode", "decode", "str", "bytes")
            ):
                return any(self._tainted(arg) for arg in node.args)
            if isinstance(node.func, ast.Name) and node.func.id in self.tainted_functions:
                return True
            return any(self._tainted(arg) for arg in node.args)
        if isinstance(node, ast.JoinedStr):
            return any(
                isinstance(part, ast.FormattedValue) and self._tainted(part.value)
                for part in node.values
            )
        if isinstance(node, ast.BinOp):
            return self._tainted(node.left) or self._tainted(node.right)
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return any(self._tainted(element) for element in node.elts)
        if isinstance(node, ast.Dict):
            return any(self._tainted(value) for value in node.values)
        return False

    # -- propagation --------------------------------------------------------
    def _bind(self, targets: list[ast.expr], value: ast.AST | None) -> None:
        tainted = self._tainted(value)
        literal = (
            value.value
            if isinstance(value, ast.Constant) and isinstance(value.value, str)
            else None
        )
        for target in targets:
            if not isinstance(target, ast.Name):
                continue
            if tainted:
                self.tainted_vars.add(target.id)
            else:
                # Reassignment from an untainted value clears the taint.
                self.tainted_vars.discard(target.id)
            if literal is not None:
                self.string_constants[target.id] = literal
            else:
                self.string_constants.pop(target.id, None)

    def visit_Assign(self, node: ast.Assign) -> None:
        self._bind(node.targets, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self._bind([node.target], node.value)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        for sub in ast.walk(node):
            if isinstance(sub, ast.Return) and self._tainted(sub.value):
                self.tainted_functions.add(node.name)
                break
        self.generic_visit(node)

    # -- sinks --------------------------------------------------------------
    def _url_text(self, node: ast.AST | None) -> str | None:
        if node is None:
            return None
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.Name):
            return self.string_constants.get(node.id)
        if isinstance(node, ast.JoinedStr) and node.values:
            first = node.values[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                return first.value
        return None

    def _report(
        self, node: ast.Call, call: str, severity: Severity, kind: str, message: str
    ) -> None:
        line = getattr(node, "lineno", 1)
        self.findings.append(
            Finding(
                stage=Stage.DETERMINISTIC_ANCHOR,
                severity=severity,
                message=message,
                type=kind,
                evidence=_evidence(self.filename, line, f"{call}(...)"),
            )
        )

    def visit_Call(self, node: ast.Call) -> None:
        call = self._call_name(node)
        is_sink = any(
            call == sink or call.endswith("." + sink) or sink.endswith("." + call)
            for sink in RULES.python_sinks
        )
        if is_sink and ("gethostbyname" in call or "getaddrinfo" in call):
            if node.args and self._tainted(node.args[0]):
                self._report(
                    node,
                    call,
                    Severity.CRITICAL,
                    "credential-flow-dns",
                    f"Credential material is placed in a DNS query via {call}",
                )
        elif is_sink:
            self._check_network_sink(node, call)
        self.generic_visit(node)

    def _check_network_sink(self, node: ast.Call, call: str) -> None:
        url_node = node.args[0] if node.args else None
        payload = self._tainted(url_node) or any(self._tainted(arg) for arg in node.args[1:])
        payload = payload or any(
            keyword.arg in ("data", "json", "params", "headers", "content", "auth")
            and self._tainted(keyword.value)
            for keyword in node.keywords
        )
        if not payload:
            return
        destination = self._url_text(url_node)
        if destination is None:
            self._report(
                node,
                call,
                Severity.HIGH,
                "credential-flow-unresolved-host",
                f"Credential material flows to a dynamic destination in {call}",
            )
        elif is_host_declared(destination, self.declared_hosts):
            self._report(
                node,
                call,
                Severity.MEDIUM,
                "credential-flow-declared-host",
                f"Credential material is sent to a declared service host: {destination}",
            )
        else:
            self._report(
                node,
                call,
                Severity.CRITICAL,
                "credential-flow-undeclared-host",
                f"Credential material flows into {call} contacting undeclared host {destination}",
            )


def analyze_credential_flows(package: SkillPackage) -> list[Finding]:
    """Return credential-flow findings for every script in the package."""

    declared = extract_declared_hosts(package.frontmatter)
    findings: list[Finding] = []
    for text_file in package.text_files:
        relative = text_file.relative.replace("\\", "/")
        lowered = relative.lower()
        if lowered.endswith(".py"):
            try:
                tree = ast.parse(text_file.text, filename=relative)
            except (SyntaxError, ValueError):
                # Unparseable Python is reported by the AST anchor stage as degraded.
                continue
            tracker = _Tracker(filename=relative, declared_hosts=declared)
            tracker.visit(tree)
            findings.extend(tracker.findings)
        elif lowered.endswith((".sh", ".bash", ".js", ".mjs", ".ts", ".ps1")):
            has_source = any(p.search(text_file.text) for p in RULES.env_patterns) or any(
                glob.replace("*", "") in text_file.text for glob in RULES.path_globs
            )
            has_sink = any(p.search(text_file.text) for p in RULES.script_sinks)
            if has_source and has_sink:
                findings.append(
                    Finding(
                        stage=Stage.DETERMINISTIC_ANCHOR,
                        severity=Severity.MEDIUM,
                        message=f"Possible credential flow in {relative} (unverified pattern match)",
                        type="credential-flow-unverified",
                        evidence=_evidence(relative, 1, text_file.text[:200]),
                    )
                )
    return findings


__all__ = ["RULES_VERSION", "analyze_credential_flows"]
