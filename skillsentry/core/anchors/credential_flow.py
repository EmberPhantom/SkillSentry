"""Taint-lite credential flow analysis for Python scripts and non-Python scripts."""

from __future__ import annotations

import ast
import fnmatch
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Set, Tuple

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib  # type: ignore[no-redef]

from skillsentry.core.anchors.declared_hosts import extract_declared_hosts, is_host_declared
from skillsentry.core.contracts import Finding, FindingEvidence, Severity, Stage
from skillsentry.core.parser import SkillPackage, TextFile


@dataclass(frozen=True)
class Floor:
    """Authoritative risk floor derived from typed evidence."""
    level: Literal["SUSPICIOUS", "MALICIOUS"]
    kind: Literal["hard", "soft"]
    source: str
    reason: str
    score: int
    evidence: List[FindingEvidence] = field(default_factory=list)


def _load_credential_rules() -> tuple[int, list[re.Pattern], list[str], set[str], list[re.Pattern], list[re.Pattern]]:
    """Loads credential sources and sinks from credential_rules.toml."""
    rules_path = Path(__file__).resolve().parent.parent.parent / "rules" / "credential_rules.toml"
    if not rules_path.is_file():
        # Fallback to defaults if file missing
        version = 1
        env_patterns = [re.compile(r"(?i)(token|secret|password|passwd|api[_-]?key|access[_-]?key|credential|private[_-]?key)")]
        path_globs = ["~/.aws/*", "~/.ssh/*", "~/.config/gcloud/*", "~/.netrc", "~/.docker/config.json", "**/.env"]
        py_calls = {"requests.post", "requests.get", "requests.put", "httpx.post", "socket.gethostbyname"}
        js_patterns = [re.compile(p) for p in [r"fetch\(", r"axios\."]]
        sh_patterns = [re.compile(p) for p in [r"curl\s", r"wget\s", r"nslookup\s"]]
        return version, env_patterns, path_globs, py_calls, js_patterns, sh_patterns

    with open(rules_path, "rb") as f:
        data = tomllib.load(f)

    version = int(data.get("version", 1))
    sources = data.get("sources", {})
    env_patterns = [re.compile(p) for p in sources.get("env_name_patterns", [])]
    path_globs = list(sources.get("path_globs", []))

    sinks = data.get("sinks", {})
    py_calls = set(sinks.get("python_calls", []))
    js_patterns = [re.compile(p) for p in sinks.get("js_patterns", [])]
    sh_patterns = [re.compile(p) for p in sinks.get("shell_patterns", [])]

    return version, env_patterns, path_globs, py_calls, js_patterns, sh_patterns


CREDENTIAL_RULES_VERSION, ENV_PATTERNS, PATH_GLOBS, PYTHON_SINKS, JS_SINKS, SHELL_SINKS = _load_credential_rules()


class PythonTaintTracker(ast.NodeVisitor):
    """Tracks flow of sensitive credentials into network or system sinks."""

    def __init__(self, filename: str, declared_hosts: Set[str]) -> None:
        self.filename = filename
        self.declared_hosts = declared_hosts
        self.tainted_vars: Set[str] = set()
        self.tainted_functions: Set[str] = set()
        self.string_constants: Dict[str, str] = {}
        self.floors: List[Floor] = []
        self.findings: List[Finding] = []

    def _matches_env_secret(self, key_str: str) -> bool:
        return any(p.search(key_str) for p in ENV_PATTERNS)

    def _matches_path_glob(self, path_str: str) -> bool:
        norm = path_str.replace("\\", "/")
        norm_expanded = os.path.expanduser(norm).replace("\\", "/")
        for g in PATH_GLOBS:
            if fnmatch.fnmatch(norm, g) or fnmatch.fnmatch(norm_expanded, g):
                return True
            if g.startswith("~/") and norm.startswith(g[2:]):
                return True
        return False

    def _is_tainted_expr(self, node: Optional[ast.AST]) -> bool:
        if node is None:
            return False

        if isinstance(node, ast.Name):
            return node.id in self.tainted_vars

        if isinstance(node, ast.Subscript):
            # os.environ["KEY"]
            if isinstance(node.value, ast.Attribute) and node.value.attr == "environ":
                if isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str):
                    return self._matches_env_secret(node.slice.value)
            # dict lookup on tainted var
            return self._is_tainted_expr(node.value)

        if isinstance(node, ast.Call):
            # If method is called on a tainted expression (e.g. key.encode(), data.strip())
            if isinstance(node.func, ast.Attribute) and self._is_tainted_expr(node.func.value):
                return True

            # os.getenv("KEY") or os.environ.get("KEY")
            func_name = self._get_call_name(node)
            if func_name in ("os.getenv", "os.environ.get"):
                if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                    return self._matches_env_secret(node.args[0].value)

            # open("~/.aws/credentials")
            if func_name in ("open", "Path", "Path.read_text", "Path.read_bytes"):
                if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                    return self._matches_path_glob(node.args[0].value)

            # base64 / json / encode / decode / str / bytes
            if any(k in func_name for k in ("b64encode", "b64decode", "dumps", "encode", "decode", "str", "bytes")):
                return any(self._is_tainted_expr(a) for a in node.args)

            # Call to tainted function in same module
            if isinstance(node.func, ast.Name) and node.func.id in self.tainted_functions:
                return True

            # If function argument is tainted
            return any(self._is_tainted_expr(a) for a in node.args)

        if isinstance(node, ast.JoinedStr):  # f-string
            return any(isinstance(v, ast.FormattedValue) and self._is_tainted_expr(v.value) for v in node.values)

        if isinstance(node, ast.BinOp):  # concat or % format
            return self._is_tainted_expr(node.left) or self._is_tainted_expr(node.right)

        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return any(self._is_tainted_expr(elt) for elt in node.elts)

        if isinstance(node, ast.Dict):
            return any(self._is_tainted_expr(v) for v in node.values)

        return False

    def _get_call_name(self, node: ast.Call) -> str:
        parts: List[str] = []
        cur: ast.AST = node.func
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        return ".".join(reversed(parts))

    def _extract_url_or_host(self, arg_node: Optional[ast.AST]) -> Optional[str]:
        if arg_node is None:
            return None
        if isinstance(arg_node, ast.Constant) and isinstance(arg_node.value, str):
            return arg_node.value
        if isinstance(arg_node, ast.Name) and arg_node.id in self.string_constants:
            return self.string_constants[arg_node.id]
        if isinstance(arg_node, ast.JoinedStr):
            # Check if leading part of f-string is literal url
            first = arg_node.values[0] if arg_node.values else None
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                return first.value
        return None

    def visit_Assign(self, node: ast.Assign) -> None:
        # Check if right-hand side is a string constant
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    self.string_constants[t.id] = node.value.value

        # Check if right-hand side is tainted
        if self._is_tainted_expr(node.value):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    self.tainted_vars.add(t.id)

        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        # Check if function returns tainted value
        for sub in ast.walk(node):
            if isinstance(sub, ast.Return) and self._is_tainted_expr(sub.value):
                self.tainted_functions.add(node.name)
                break
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        call_name = self._get_call_name(node)

        # Check if call matches a Python network sink
        is_sink = any(call_name == s or call_name.endswith("." + s) or s.endswith("." + call_name) for s in PYTHON_SINKS)

        if is_sink:
            # Check for DNS sink
            is_dns = "gethostbyname" in call_name or "getaddrinfo" in call_name
            if is_dns:
                arg0 = node.args[0] if node.args else None
                if self._is_tainted_expr(arg0):
                    ev = FindingEvidence(
                        file=self.filename,
                        line=getattr(node, "lineno", 1),
                        code=f"{call_name}(...)",
                    )
                    self.floors.append(
                        Floor(
                            level="MALICIOUS",
                            kind="hard",
                            source="credential-flow-dns",
                            reason=f"Credential data flows directly into DNS query ({call_name})",
                            score=75,
                            evidence=[ev],
                        )
                    )
                    self.findings.append(
                        Finding(
                            stage=Stage.DETERMINISTIC_ANCHOR,
                            severity=Severity.HIGH,
                            message=f"Tainted credential material transmitted in DNS hostname via {call_name}",
                            type="credential-flow-dns",
                            evidence=ev,
                        )
                    )
                self.generic_visit(node)
                return

            # Check network sink arguments: url, data, json, params, headers
            url_node = node.args[0] if node.args else None
            url_str = self._extract_url_or_host(url_node)

            # Check if any payload contains tainted var
            payload_tainted = False
            for a in node.args[1:]:
                if self._is_tainted_expr(a):
                    payload_tainted = True
                    break
            for kw in node.keywords:
                if kw.arg in ("data", "json", "params", "headers", "content", "auth"):
                    if self._is_tainted_expr(kw.value):
                        payload_tainted = True
                        break

            # Also if the URL itself is tainted
            if self._is_tainted_expr(url_node):
                payload_tainted = True

            if payload_tainted:
                ev = FindingEvidence(
                    file=self.filename,
                    line=getattr(node, "lineno", 1),
                    code=f"{call_name}({url_str or '...'})",
                )
                if url_str is None:
                    # Dynamic / unresolved host
                    self.floors.append(
                        Floor(
                            level="SUSPICIOUS",
                            kind="soft",
                            source="credential-flow-unresolved-host",
                            reason="Credential transmitted to dynamic or unresolved network host",
                            score=55,
                            evidence=[ev],
                        )
                    )
                    self.findings.append(
                        Finding(
                            stage=Stage.DETERMINISTIC_ANCHOR,
                            severity=Severity.HIGH,
                            message=f"Credential flows to dynamic/unresolved destination in {call_name}",
                            type="credential-flow-unresolved-host",
                            evidence=ev,
                        )
                    )
                elif is_host_declared(url_str, self.declared_hosts):
                    # Declared host: soft SUSPICIOUS
                    self.floors.append(
                        Floor(
                            level="SUSPICIOUS",
                            kind="soft",
                            source="credential-flow-declared-host",
                            reason=f"Credential sent to declared service host ({url_str})",
                            score=55,
                            evidence=[ev],
                        )
                    )
                    self.findings.append(
                        Finding(
                            stage=Stage.DETERMINISTIC_ANCHOR,
                            severity=Severity.HIGH,
                            message=f"Credential sent to declared service destination: {url_str}",
                            type="credential-flow-declared-host",
                            evidence=ev,
                        )
                    )
                else:
                    # Undeclared host: hard MALICIOUS
                    self.floors.append(
                        Floor(
                            level="MALICIOUS",
                            kind="hard",
                            source="credential-flow-undeclared-host",
                            reason=f"Credential exfiltration to undeclared host ({url_str})",
                            score=75,
                            evidence=[ev],
                        )
                    )
                    self.findings.append(
                        Finding(
                            stage=Stage.DETERMINISTIC_ANCHOR,
                            severity=Severity.HIGH,
                            message=f"Credential flows into network sink {call_name} contacting undeclared host {url_str}",
                            type="credential-flow-undeclared-host",
                            evidence=ev,
                        )
                    )

        self.generic_visit(node)


def analyze_credential_flows(package: SkillPackage) -> tuple[list[Floor], list[Finding]]:
    """Analyzes skill package for credential flows and returns authoritative floors and findings."""
    declared_hosts = extract_declared_hosts(package.frontmatter)
    floors: List[Floor] = []
    findings: List[Finding] = []

    for tf in package.text_files:
        rel = tf.relative.replace("\\", "/").lstrip("./")

        # Python files: AST taint tracking
        if rel.lower().endswith(".py"):
            try:
                tree = ast.parse(tf.text, filename=rel)
                tracker = PythonTaintTracker(rel, declared_hosts)
                tracker.visit(tree)
                floors.extend(tracker.floors)
                findings.extend(tracker.findings)
            except SyntaxError:
                pass
        # Non-Python files (shell, JS, etc.): Pattern heuristics (soft floor)
        elif any(rel.lower().endswith(ext) for ext in (".sh", ".bash", ".js", ".mjs", ".ts", ".ps1")):
            has_source = any(p.search(tf.text) for p in ENV_PATTERNS) or any(
                g.replace("*", "") in tf.text for g in PATH_GLOBS
            )
            has_sink = any(p.search(tf.text) for p in (JS_SINKS + SHELL_SINKS))
            if has_source and has_sink:
                ev = FindingEvidence(file=rel, line=1, code=tf.text[:200])
                floors.append(
                    Floor(
                        level="SUSPICIOUS",
                        kind="soft",
                        source="credential-flow-unverified",
                        reason=f"Unverified credential source and network sink patterns in {rel}",
                        score=55,
                        evidence=[ev],
                    )
                )
                findings.append(
                    Finding(
                        stage=Stage.DETERMINISTIC_ANCHOR,
                        severity=Severity.HIGH,
                        message=f"Possible credential flow in {rel} (unverified script regex match)",
                        type="credential-flow-unverified",
                        evidence=ev,
                    )
                )

    return floors, findings
