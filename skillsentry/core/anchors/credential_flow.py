"""Credential flow analysis: sensitive material reaching a network or system sink.

Python scripts are analysed with a small AST taint tracker.  Shell and JavaScript
scripts get a weaker pattern check, because a regex cannot prove a flow.

Every tainted value carries its sources (the environment variable or the path it
came from).  A destination is judged against those sources:

* credential data sent to a host the skill declares, and bound to that credential's
  vendor (for example SLACK_TOKEN to slack.com): NOTE, informational
* credential data sent to a declared host that the credential is not bound to: MEDIUM
* credential data sent to an undeclared host that the credential is bound to: MEDIUM
* credential data sent to an undeclared host with no binding: CRITICAL
* credential data put into a DNS query: CRITICAL
* credential data sent to an unresolved (dynamic) host: HIGH
* unverified shell or JavaScript pattern match: MEDIUM

A binding does not count when the request is plain HTTP, disables certificate
verification, or routes through a custom proxy.

Severity maps onto main's fusion floors (CRITICAL 95, HIGH 70, MEDIUM 30).  The
taint tracker over-approximates flows through calls, and it clears a name when that
name is reassigned from an untainted value.

Binding table: feature/developer-2 (chauhanaman41), adopted into rules/credential_rules.toml.
"""

from __future__ import annotations

import ast
import fnmatch
import hashlib
import os
import re
import tomllib
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from skillsentry.core.anchors.declared_hosts import extract_declared_hosts, is_host_declared
from skillsentry.core.contracts import Finding, FindingEvidence, Severity, Stage
from skillsentry.core.parser import SkillPackage

RULES_PATH = Path(__file__).resolve().parent.parent.parent / "rules" / "credential_rules.toml"

# A credential source is ("env", NAME) for an environment variable or ("path", PATH).
Source = tuple[str, str]
_NONE: frozenset[Source] = frozenset()


@dataclass(frozen=True)
class ServiceBinding:
    """A credential that belongs to the vendor behind ``hosts``."""

    name: str
    credential_env: tuple[re.Pattern[str], ...]
    credential_paths: tuple[str, ...]
    hosts: tuple[str, ...]


@dataclass(frozen=True)
class CredentialRules:
    version: int
    env_patterns: tuple[re.Pattern[str], ...]
    path_globs: tuple[str, ...]
    python_sinks: frozenset[str]
    script_sinks: tuple[re.Pattern[str], ...]
    bindings: tuple[ServiceBinding, ...]


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
        bindings=tuple(
            ServiceBinding(
                name=str(item.get("name", "unnamed")),
                credential_env=tuple(re.compile(p) for p in item.get("credential_env", [])),
                credential_paths=tuple(item.get("credential_paths", [])),
                hosts=tuple(str(host).lower() for host in item.get("hosts", [])),
            )
            for item in data.get("service_bindings", [])
        ),
    )


RULES = _load_rules()
RULES_VERSION = RULES.version
# Any edit to the rules file changes this, so cached verdicts never outlive the rules.
RULES_FINGERPRINT = hashlib.sha256(RULES_PATH.read_bytes()).hexdigest()[:12]


def _evidence(file: str, line: int, code: str) -> FindingEvidence:
    return FindingEvidence(file=file, line=line, code=code[:200] or None)


def _union(parts: Iterable[frozenset[Source]]) -> frozenset[Source]:
    merged: set[Source] = set()
    for part in parts:
        merged |= part
    return frozenset(merged)


def _first_string_arg(node: ast.Call) -> str | None:
    """The first argument when it is a string literal, otherwise None."""

    if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
        return node.args[0].value
    return None


def _host_of(destination: str) -> str:
    parsed = urlparse(destination if "://" in destination else f"//{destination}")
    return (parsed.hostname or destination).lower()


def _path_matches(path: str, glob: str) -> bool:
    expanded_path = os.path.expanduser(path.replace("\\", "/")).replace("\\", "/")
    expanded_glob = os.path.expanduser(glob)
    return fnmatch.fnmatch(expanded_path, expanded_glob)


def is_credential_bound(sources: frozenset[Source], destination: str) -> bool:
    """True when a credential the payload carries belongs to the vendor behind ``destination``."""

    host = _host_of(destination)
    for binding in RULES.bindings:
        if not any(host == bound or host.endswith("." + bound) for bound in binding.hosts):
            continue
        for kind, value in sources:
            if kind == "env" and any(p.search(value) for p in binding.credential_env):
                return True
            if kind == "path" and any(_path_matches(value, g) for g in binding.credential_paths):
                return True
    return False


def _weakens_binding(node: ast.Call, destination: str) -> bool:
    """Plain HTTP, disabled verification or a custom proxy means a binding does not count."""

    if destination.lower().startswith("http://"):
        return True
    for keyword in node.keywords:
        if (
            keyword.arg == "verify"
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value is False
        ):
            return True
        if keyword.arg in ("proxies", "proxy"):
            return True
    return False


@dataclass
class _Tracker(ast.NodeVisitor):
    filename: str
    declared_hosts: set[str]
    tainted_vars: dict[str, frozenset[Source]] = field(default_factory=dict)
    tainted_functions: dict[str, frozenset[Source]] = field(default_factory=dict)
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

    def _sources(self, node: ast.AST | None) -> frozenset[Source]:
        if node is None:
            return _NONE
        if isinstance(node, ast.Name):
            return self.tainted_vars.get(node.id, _NONE)
        if isinstance(node, ast.Subscript):
            value = node.value
            if (
                isinstance(value, ast.Attribute)
                and value.attr == "environ"
                and isinstance(node.slice, ast.Constant)
                and isinstance(node.slice.value, str)
            ):
                name = node.slice.value
                return frozenset({("env", name)}) if self._secret_name(name) else _NONE
            return self._sources(node.value)
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                inherited = self._sources(node.func.value)
                if inherited:
                    return inherited
            name = self._call_name(node)
            literal = _first_string_arg(node)
            if name in ("os.getenv", "os.environ.get") and literal is not None:
                return frozenset({("env", literal)}) if self._secret_name(literal) else _NONE
            if (
                name in ("open", "Path", "Path.read_text", "Path.read_bytes")
                and literal is not None
            ):
                return frozenset({("path", literal)}) if self._sensitive_path(literal) else _NONE
            if any(
                token in name
                for token in ("b64encode", "b64decode", "dumps", "encode", "decode", "str", "bytes")
            ):
                return _union(self._sources(arg) for arg in node.args)
            if isinstance(node.func, ast.Name) and node.func.id in self.tainted_functions:
                return self.tainted_functions[node.func.id]
            return _union(self._sources(arg) for arg in node.args)
        if isinstance(node, ast.JoinedStr):
            return _union(
                self._sources(part.value)
                for part in node.values
                if isinstance(part, ast.FormattedValue)
            )
        if isinstance(node, ast.BinOp):
            return self._sources(node.left) | self._sources(node.right)
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return _union(self._sources(element) for element in node.elts)
        if isinstance(node, ast.Dict):
            return _union(self._sources(value) for value in node.values)
        return _NONE

    def _tainted(self, node: ast.AST | None) -> bool:
        return bool(self._sources(node))

    # -- propagation --------------------------------------------------------
    def _bind(self, targets: list[ast.expr], value: ast.AST | None) -> None:
        sources = self._sources(value)
        literal = (
            value.value
            if isinstance(value, ast.Constant) and isinstance(value.value, str)
            else None
        )
        for target in targets:
            if not isinstance(target, ast.Name):
                continue
            if sources:
                self.tainted_vars[target.id] = sources
            else:
                # Reassignment from an untainted value clears the taint.
                self.tainted_vars.pop(target.id, None)
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
        returned = _union(
            self._sources(sub.value) for sub in ast.walk(node) if isinstance(sub, ast.Return)
        )
        if returned:
            self.tainted_functions[node.name] = returned
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
        payload = _union(
            [
                self._sources(url_node),
                *(self._sources(arg) for arg in node.args[1:]),
                *(
                    self._sources(keyword.value)
                    for keyword in node.keywords
                    if keyword.arg in ("data", "json", "params", "headers", "content", "auth")
                ),
            ]
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
            return
        bound = is_credential_bound(payload, destination) and not _weakens_binding(
            node, destination
        )
        if is_host_declared(destination, self.declared_hosts):
            if bound:
                self._report(
                    node,
                    call,
                    Severity.NOTE,
                    "credential-flow-declared-bound",
                    f"Credential sent to its own declared service host: {destination}",
                )
            else:
                self._report(
                    node,
                    call,
                    Severity.MEDIUM,
                    "credential-flow-declared-host",
                    f"Credential material is sent to a declared service host: {destination}",
                )
        elif bound:
            self._report(
                node,
                call,
                Severity.MEDIUM,
                "credential-flow-undeclared-bound",
                f"Credential for {destination}'s vendor is sent to undeclared host {destination}",
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


__all__ = ["RULES_FINGERPRINT", "RULES_VERSION", "analyze_credential_flows", "is_credential_bound"]
