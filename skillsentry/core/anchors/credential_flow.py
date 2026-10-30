"""Taint-lite credential flow analysis for Python scripts and non-Python scripts."""

from __future__ import annotations

import ast
import fnmatch
import hashlib
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Set, Tuple

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib  # type: ignore[no-redef]

from skillsentry.core.anchors.declared_hosts import _extract_host, extract_declared_hosts, is_host_declared
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


@dataclass(frozen=True)
class ServiceBinding:
    """Declared relationship between credential types and allowed vendor hosts."""
    name: str
    credential_env: list[re.Pattern]
    credential_paths: list[str]
    hosts: list[str]


def _load_credential_rules() -> tuple[int, str, list[re.Pattern], list[str], set[str], list[re.Pattern], list[re.Pattern], list[ServiceBinding]]:
    """Loads credential sources, sinks, and service bindings from credential_rules.toml."""
    rules_path = Path(__file__).resolve().parent.parent.parent / "rules" / "credential_rules.toml"
    if not rules_path.is_file():
        # Fallback to defaults if file missing
        version = 1
        rules_hash = "defaults"
        env_patterns = [re.compile(r"(?i)(token|secret|password|passwd|api[_-]?key|access[_-]?key|credential|private[_-]?key)")]
        path_globs = ["~/.aws/*", "~/.ssh/*", "~/.config/gcloud/*", "~/.netrc", "~/.docker/config.json", "**/.env"]
        py_calls = {"requests.post", "requests.get", "requests.put", "httpx.post", "socket.gethostbyname"}
        js_patterns = [re.compile(p) for p in [r"fetch\(", r"axios\."]]
        sh_patterns = [re.compile(p) for p in [r"curl\s", r"wget\s", r"nslookup\s"]]
        bindings = [
            ServiceBinding("github", [re.compile(r"(?i)^(GITHUB|GH)_(TOKEN|PAT)$")], [], ["github.com", "githubusercontent.com"]),
            ServiceBinding("slack", [re.compile(r"(?i)^SLACK_.*(TOKEN|WEBHOOK|SECRET|URL)$")], [], ["slack.com"]),
            ServiceBinding("aws", [re.compile(r"(?i)^AWS_.*")], ["~/.aws/*"], ["amazonaws.com"]),
        ]
        return version, rules_hash, env_patterns, path_globs, py_calls, js_patterns, sh_patterns, bindings

    content_bytes = rules_path.read_bytes()
    rules_hash = hashlib.sha256(content_bytes).hexdigest()[:12]
    data = tomllib.loads(content_bytes.decode("utf-8"))

    version = int(data.get("version", 1))
    sources = data.get("sources", {})
    env_patterns = [re.compile(p) for p in sources.get("env_name_patterns", [])]
    path_globs = list(sources.get("path_globs", []))

    sinks = data.get("sinks", {})
    py_calls = set(sinks.get("python_calls", []))
    js_patterns = [re.compile(p) for p in sinks.get("js_patterns", [])]
    sh_patterns = [re.compile(p) for p in sinks.get("shell_patterns", [])]

    raw_bindings = data.get("service_bindings", [])
    bindings = [
        ServiceBinding(
            name=b.get("name", ""),
            credential_env=[re.compile(p) for p in b.get("credential_env", [])],
            credential_paths=list(b.get("credential_paths", [])),
            hosts=list(b.get("hosts", [])),
        )
        for b in raw_bindings
    ]

    return version, rules_hash, env_patterns, path_globs, py_calls, js_patterns, sh_patterns, bindings


CREDENTIAL_RULES_VERSION, CREDENTIAL_RULES_HASH, ENV_PATTERNS, PATH_GLOBS, PYTHON_SINKS, JS_SINKS, SHELL_SINKS, SERVICE_BINDINGS = _load_credential_rules()


def get_rules_version() -> int:
    return CREDENTIAL_RULES_VERSION


def get_rules_hash() -> str:
    return CREDENTIAL_RULES_HASH


def is_credential_bound(cred_name: str | None, host_str: str, bindings: list[ServiceBinding]) -> bool:
    """Checks whether a credential name or path is legitimately bound to the target host."""
    if not cred_name:
        return False
    cand = _extract_host(host_str)
    if not cand:
        return False
    for b in bindings:
        env_match = any(p.search(cred_name) for p in b.credential_env)
        path_match = any(
            fnmatch.fnmatch(cred_name, g) or fnmatch.fnmatch(os.path.expanduser(cred_name), g)
            for g in b.credential_paths
        )
        if env_match or path_match:
            for bound_h in b.hosts:
                bound_h = bound_h.lower().strip()
                if cand == bound_h or cand.endswith("." + bound_h):
                    return True
    return False


class PythonTaintTracker(ast.NodeVisitor):
    """Tracks flow of sensitive credentials into network or system sinks with two-axis classification."""

    def __init__(
        self,
        filename: str,
        declared_hosts: Set[str],
        service_bindings: List[ServiceBinding] | None = None,
        policy: str = "bound",
    ) -> None:
        self.filename = filename
        self.declared_hosts = declared_hosts
        self.service_bindings = service_bindings if service_bindings is not None else SERVICE_BINDINGS
        self.policy = policy
        self.tainted_origins: Dict[str, str] = {}  # var_name -> credential source (e.g. GITHUB_TOKEN)
        self.tainted_functions: Dict[str, str] = {}
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

    def _extract_path_from_node(self, node: ast.AST) -> Optional[str]:
        for sub in ast.walk(node):
            if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                if self._matches_path_glob(sub.value):
                    return sub.value
        return None

    def _get_taint_source(self, node: Optional[ast.AST]) -> Optional[str]:
        """Returns the credential name/path if the expression is tainted, or None."""
        if node is None:
            return None

        if isinstance(node, ast.Name):
            return self.tainted_origins.get(node.id)

        if isinstance(node, ast.Subscript):
            # os.environ["KEY"]
            if isinstance(node.value, ast.Attribute) and node.value.attr == "environ":
                if isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str):
                    if self._matches_env_secret(node.slice.value):
                        return node.slice.value
            return self._get_taint_source(node.value)

        if isinstance(node, ast.Call):
            func_name = self._get_call_name(node)
            # os.getenv("KEY") or os.environ.get("KEY")
            if func_name in ("os.getenv", "os.environ.get"):
                if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                    if self._matches_env_secret(node.args[0].value):
                        return node.args[0].value

            # open("~/.aws/credentials") or open(os.path.expanduser(...))
            if any(k in func_name for k in ("open", "Path", "read_text", "read_bytes")):
                for arg in node.args:
                    p = self._extract_path_from_node(arg)
                    if p:
                        return p

            # Method called on tainted expression (tok.encode(), data.strip(), f.read())
            if isinstance(node.func, ast.Attribute):
                sub = self._get_taint_source(node.func.value)
                if sub:
                    return sub

            # Transformation calls (b64encode, str, bytes, etc.)
            if any(k in func_name for k in ("b64encode", "b64decode", "dumps", "encode", "decode", "str", "bytes")):
                for a in node.args:
                    src = self._get_taint_source(a)
                    if src:
                        return src

            # Call to tainted function in same module
            if isinstance(node.func, ast.Name) and node.func.id in self.tainted_functions:
                return self.tainted_functions[node.func.id]

            for a in node.args:
                src = self._get_taint_source(a)
                if src:
                    return src

        if isinstance(node, ast.JoinedStr):
            for v in node.values:
                if isinstance(v, ast.FormattedValue):
                    src = self._get_taint_source(v.value)
                    if src:
                        return src

        if isinstance(node, ast.BinOp):
            return self._get_taint_source(node.left) or self._get_taint_source(node.right)

        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            for elt in node.elts:
                src = self._get_taint_source(elt)
                if src:
                    return src

        if isinstance(node, ast.Dict):
            for v in node.values:
                src = self._get_taint_source(v)
                if src:
                    return src

        return None

    def _is_tainted_expr(self, node: Optional[ast.AST]) -> bool:
        return self._get_taint_source(node) is not None

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
            first = arg_node.values[0] if arg_node.values else None
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                return first.value
        return None

    def visit_Assign(self, node: ast.Assign) -> None:
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    self.string_constants[t.id] = node.value.value

        taint_src = self._get_taint_source(node.value)
        if taint_src:
            for t in node.targets:
                if isinstance(t, ast.Name):
                    self.tainted_origins[t.id] = taint_src

        self.generic_visit(node)

    def visit_With(self, node: ast.With) -> None:
        for item in node.items:
            taint_src = self._get_taint_source(item.context_expr)
            if taint_src and item.optional_vars and isinstance(item.optional_vars, ast.Name):
                self.tainted_origins[item.optional_vars.id] = taint_src
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        for sub in ast.walk(node):
            if isinstance(sub, ast.Return):
                src = self._get_taint_source(sub.value)
                if src:
                    self.tainted_functions[node.name] = src
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
                taint_src = self._get_taint_source(arg0)
                if taint_src:
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
                            reason=f"Credential data ({taint_src}) flows directly into DNS query ({call_name})",
                            score=75,
                            evidence=[ev],
                        )
                    )
                    self.findings.append(
                        Finding(
                            stage=Stage.DETERMINISTIC_ANCHOR,
                            severity=Severity.HIGH,
                            message=f"Tainted credential material ({taint_src}) transmitted in DNS hostname via {call_name}",
                            type="credential-flow-dns",
                            evidence=ev,
                        )
                    )
                self.generic_visit(node)
                return

            # Check network sink arguments: url, data, json, params, headers, content, auth
            url_node = node.args[0] if node.args else None
            url_str = self._extract_url_or_host(url_node)

            # Check if any payload contains tainted credential
            detected_taint_src: Optional[str] = None
            for a in node.args[1:]:
                detected_taint_src = self._get_taint_source(a)
                if detected_taint_src:
                    break
            if not detected_taint_src:
                for kw in node.keywords:
                    if kw.arg in ("data", "json", "params", "headers", "content", "auth"):
                        detected_taint_src = self._get_taint_source(kw.value)
                        if detected_taint_src:
                            break
            if not detected_taint_src:
                detected_taint_src = self._get_taint_source(url_node)

            if detected_taint_src:
                ev = FindingEvidence(
                    file=self.filename,
                    line=getattr(node, "lineno", 1),
                    code=f"{call_name}({url_str or '...'})",
                )
                if url_str is None:
                    # Dynamic / unresolved host: soft SUSPICIOUS
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
                else:
                    is_declared = is_host_declared(url_str, self.declared_hosts)
                    is_bound = is_credential_bound(detected_taint_src, url_str, self.service_bindings)

                    # Demotion guards: verify=False, custom proxies, plain http
                    is_insecure_verify = any(
                        kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False
                        for kw in node.keywords
                    )
                    has_custom_proxies = any(kw.arg == "proxies" for kw in node.keywords)
                    is_plain_http = url_str.lower().startswith("http://")

                    if is_bound and (is_insecure_verify or has_custom_proxies or is_plain_http):
                        is_bound = False

                    # Two-axis decision matrix
                    if is_declared and is_bound:
                        if self.policy == "strict":
                            self.floors.append(
                                Floor(
                                    level="SUSPICIOUS",
                                    kind="soft",
                                    source="credential-flow-declared-bound-strict",
                                    reason=f"Credential sent to declared and bound host ({url_str}) under strict policy",
                                    score=55,
                                    evidence=[ev],
                                )
                            )
                            self.findings.append(
                                Finding(
                                    stage=Stage.DETERMINISTIC_ANCHOR,
                                    severity=Severity.MEDIUM,
                                    message=f"Credential sent to declared and bound destination {url_str} (strict policy)",
                                    type="credential-flow-declared-bound-strict",
                                    evidence=ev,
                                )
                            )
                        else:
                            # SAFE: No floor! Keep INFO finding in report
                            self.findings.append(
                                Finding(
                                    stage=Stage.DETERMINISTIC_ANCHOR,
                                    severity=Severity.NOTE,
                                    message=f"Credential sent to declared and bound service destination: {url_str}",
                                    type="credential-flow-declared-bound",
                                    evidence=ev,
                                )
                            )
                    elif is_declared and not is_bound:
                        # Declared but unbound: soft SUSPICIOUS + review flag
                        self.floors.append(
                            Floor(
                                level="SUSPICIOUS",
                                kind="soft",
                                source="credential-flow-declared-unbound",
                                reason=f"Credential transmitted to declared host that is not bound to this credential ({url_str})",
                                score=55,
                                evidence=[ev],
                            )
                        )
                        self.findings.append(
                            Finding(
                                stage=Stage.DETERMINISTIC_ANCHOR,
                                severity=Severity.MEDIUM,
                                message=f"Credential sent to declared but unbound destination: {url_str} (requires review)",
                                type="credential-flow-declared-unbound",
                                evidence=ev,
                            )
                        )
                    elif not is_declared and is_bound:
                        # Undeclared but bound: soft SUSPICIOUS
                        self.floors.append(
                            Floor(
                                level="SUSPICIOUS",
                                kind="soft",
                                source="credential-flow-undeclared-bound",
                                reason=f"Credential sent to bound service host ({url_str}) without frontmatter permission declaration",
                                score=55,
                                evidence=[ev],
                            )
                        )
                        self.findings.append(
                            Finding(
                                stage=Stage.DETERMINISTIC_ANCHOR,
                                severity=Severity.MEDIUM,
                                message=f"Credential sent to bound host {url_str} without frontmatter permission declaration",
                                type="credential-flow-undeclared-bound",
                                evidence=ev,
                            )
                        )
                    else:
                        # Undeclared and unbound: hard MALICIOUS
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


def analyze_credential_flows(
    package: SkillPackage,
    policy: str | None = None,
) -> tuple[list[Floor], list[Finding]]:
    """Analyzes skill package for credential flows and returns authoritative floors and findings."""
    declared_hosts = extract_declared_hosts(package.frontmatter)
    effective_policy = policy
    if effective_policy is None:
        effective_policy = (
            package.frontmatter.get("declared_host_policy", "bound")
            if isinstance(package.frontmatter, dict)
            else "bound"
        )

    floors: List[Floor] = []
    findings: List[Finding] = []

    for tf in package.text_files:
        rel = tf.relative.replace("\\", "/").lstrip("./")

        # Python files: AST taint tracking
        if rel.lower().endswith(".py"):
            try:
                tree = ast.parse(tf.text, filename=rel)
                tracker = PythonTaintTracker(rel, declared_hosts, policy=effective_policy)
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
