"""
Deterministic AST & Regex Anchor Scanner (Stage 2).

Scans code files (.py, .sh, .js) to extract hard, verifiable facts
about dangerous APIs, credential access, and network tunneling.
These anchors provide ground truth that powers line-accurate citations
and prevents the LLM from hallucinating that a script is benign.

CL-D2-2 · REQ-ANCH-01/02 · Source: docs/02-architecture.md §2.3,
developer-2/03-functional-specifications.md Cap C.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from typing import Any

from skillsentry_dev2.contracts import Finding, ScriptFile, StageResult

# ── Pattern Catalog ─────────────────────────────────────────────────────

@dataclass(frozen=True)
class DangerousPattern:
    """A dangerous code pattern to detect."""
    name: str
    description: str
    severity: str           # critical | high | medium | low
    weight: int             # Points for signal normalization
    # For Python AST matching
    ast_names: tuple[str, ...] = ()
    ast_attrs: tuple[str, ...] = ()
    # For regex matching (shell/js/fallback)
    regex: str = ""
    languages: tuple[str, ...] = ("py", "sh", "js")


# Complete pattern catalog per docs/02-architecture.md §2.3
DANGEROUS_PATTERNS: list[DangerousPattern] = [
    # Dynamic Execution (high, 25 pts)
    DangerousPattern(
        name="eval",
        description="Dangerous dynamic execution: eval()",
        severity="high", weight=25,
        ast_names=("eval",),
        regex=r"\beval\s*\(",
    ),
    DangerousPattern(
        name="exec",
        description="Dangerous dynamic execution: exec()",
        severity="high", weight=25,
        ast_names=("exec",),
        regex=r"\bexec\s*\(",
    ),
    DangerousPattern(
        name="__import__",
        description="Dynamic import: __import__()",
        severity="high", weight=25,
        ast_names=("__import__",),
        regex=r"\b__import__\s*\(",
    ),
    DangerousPattern(
        name="compile",
        description="Dynamic code compilation: compile()",
        severity="medium", weight=15,
        ast_names=("compile",),
        regex=r"(?<!re\.)\bcompile\s*\(",
        languages=("py",),
    ),

    # Shell Invocation (high, 25 pts)
    DangerousPattern(
        name="os.system",
        description="Shell command execution: os.system()",
        severity="high", weight=25,
        ast_attrs=("os.system",),
        regex=r"\bos\.system\s*\(",
    ),
    DangerousPattern(
        name="os.popen",
        description="Shell command execution: os.popen()",
        severity="high", weight=25,
        ast_attrs=("os.popen",),
        regex=r"\bos\.popen\s*\(",
    ),
    DangerousPattern(
        name="subprocess_shell",
        description="Shell command execution: subprocess with shell=True",
        severity="high", weight=25,
        ast_attrs=("subprocess.call", "subprocess.run", "subprocess.Popen", "subprocess.check_output"),
        regex="",
        languages=("py",),
    ),
    DangerousPattern(
        name="pty.spawn",
        description="Interactive shell spawning: pty.spawn()",
        severity="high", weight=25,
        ast_attrs=("pty.spawn",),
        regex=r"\bpty\.spawn\s*\(",
    ),

    # Sandbox / Container Evasion Probes (DEF-17, high, 35 pts)
    DangerousPattern(
        name="sandbox_evasion",
        description="Sandbox or container evasion probe detected",
        severity="high", weight=35,
        regex=r"(?:/\.dockerenv|/proc/(?:1|self)/cgroup|/sys/class/dmi/id|\bIsDebuggerPresent\b)",
    ),

    # Credential Access (critical, 40 pts)
    DangerousPattern(
        name="credential_read",
        description="Credential file access detected",
        severity="critical", weight=40,
        regex=r"(?:~\/|/home/\w+/)\.(?:aws/credentials|ssh/id_rsa|ssh/config|env|netrc|config/gh/hosts\.yml)|"
              r"\b(?:AWS_SECRET_ACCESS_KEY|GITHUB_TOKEN|SLACK_BOT_TOKEN)\b",
    ),

    # Network Socket Creation (DEF-17, medium, 20 pts)
    DangerousPattern(
        name="socket_connect",
        description="Low-level network socket creation",
        severity="medium", weight=20,
        ast_attrs=("socket.socket", "socket.create_connection"),
        regex=r"\bsocket\.(?:socket|create_connection)\s*\(",
        languages=("py",),
    ),

    # Insecure Deserialization (DEF-17, high, 30 pts)
    DangerousPattern(
        name="pickle_loads",
        description="Insecure deserialization: pickle.loads",
        severity="high", weight=30,
        ast_attrs=("pickle.loads", "pickle.load", "_pickle.loads"),
        regex=r"\bpickle\.(?:loads|load)\s*\(",
        languages=("py",),
    ),

    # Environment Harvest (DEF-17, medium, 15 pts)
    DangerousPattern(
        name="environ_dump",
        description="Environment variables harvest: os.environ",
        severity="medium", weight=15,
        ast_attrs=("os.environ.copy", "os.environ.items", "os.environ.values"),
        regex=r"\bos\.environ\.(?:copy|items|values)\s*\(",
        languages=("py",),
    ),

    # Obfuscation / Decoders (medium, 15 pts)
    DangerousPattern(
        name="base64_decode",
        description="Base64 encoding/decoding detected — potential obfuscation",
        severity="medium", weight=15,
        ast_attrs=("base64.b64decode", "base64.b64encode", "base64.decodebytes", "base64.encodebytes"),
        regex=r"\bbase64[\.\s]+(?:b64decode|b64encode|decodebytes|encodebytes)\s*\(|"
              r"\bbase64\s+(?:-[dDeE]|--decode)\b",
    ),
    DangerousPattern(
        name="codecs_decode",
        description="Codec-based decoding — potential obfuscation",
        severity="medium", weight=15,
        ast_attrs=("codecs.decode",),
        regex=r"\bcodecs\.decode\s*\(",
        languages=("py",),
    ),
    DangerousPattern(
        name="rot13",
        description="ROT13 encoding detected — potential obfuscation",
        severity="medium", weight=15,
        regex=r"\brot13\b|\.encode\s*\(\s*['\"]rot.?13['\"]\s*\)",
    ),

    # Outbound / Exfil Tools (low, 10 pts)
    DangerousPattern(
        name="curl",
        description="External HTTP tool: curl",
        severity="low", weight=10,
        regex=r"\bcurl\s+",
        languages=("sh", "js"),
    ),
    DangerousPattern(
        name="wget",
        description="External HTTP tool: wget",
        severity="low", weight=10,
        regex=r"\bwget\s+",
        languages=("sh",),
    ),
    DangerousPattern(
        name="requests_post",
        description="HTTP POST request — potential data exfiltration",
        severity="low", weight=10,
        ast_attrs=("requests.post", "requests.put"),
        regex=r"\brequests\.(?:post|put)\s*\(",
        languages=("py",),
    ),
    DangerousPattern(
        name="urllib",
        description="URL library usage — potential network access",
        severity="low", weight=10,
        ast_attrs=("urllib.request.urlopen", "urllib.request.urlretrieve"),
        regex=r"\burllib\.request\.\w+\s*\(",
        languages=("py",),
    ),

    # DNS Tunneling Tools (high, 30 pts)
    DangerousPattern(
        name="nslookup",
        description="DNS lookup tool: nslookup — potential DNS tunneling",
        severity="high", weight=30,
        regex=r"\bnslookup\s+",
    ),
    DangerousPattern(
        name="dig",
        description="DNS lookup tool: dig — potential DNS tunneling",
        severity="high", weight=30,
        regex=r"\bdig\s+",
        languages=("sh",),
    ),
    DangerousPattern(
        name="host_lookup",
        description="DNS lookup tool: host command",
        severity="high", weight=30,
        regex=r"\bhost\s+\S+\.\S+",
        languages=("sh",),
    ),
    DangerousPattern(
        name="dnspython",
        description="DNS library (dnspython) — potential DNS tunneling",
        severity="high", weight=30,
        regex=r"\bimport\s+dns\b|\bfrom\s+dns\b",
        languages=("py",),
    ),
]

# Precompiled regex patterns to eliminate repeated re.compile overhead and prevent ReDoS (DEF-11)
_COMPILED_PATTERNS: dict[str, re.Pattern] = {
    p.name: re.compile(p.regex, re.IGNORECASE)
    for p in DANGEROUS_PATTERNS
    if p.regex
}


# ── AST Visitor for Python Files ────────────────────────────────────────

@dataclass
class AnchorFinding:
    """Raw anchor finding before conversion to Finding."""
    file: str
    line: int
    pattern: str
    description: str
    code: str
    severity: str
    weight: int


class _DangerousCallVisitor(ast.NodeVisitor):
    """AST visitor that detects dangerous function calls in Python code."""

    def __init__(self, file_path: str, lines: list[str]) -> None:
        self.file_path = file_path
        self.lines = lines
        self.findings: list[AnchorFinding] = []
        self._import_aliases: dict[str, str] = {}  # alias -> real module

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if alias.asname:
                self._import_aliases[alias.asname] = alias.name
            else:
                self._import_aliases[alias.name] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module:
            for alias in node.names:
                real_name = f"{node.module}.{alias.name}"
                key = alias.asname or alias.name
                self._import_aliases[key] = real_name
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        call_name = self._resolve_call_name(node.func)
        if call_name:
            for pattern in DANGEROUS_PATTERNS:
                if call_name in pattern.ast_names or call_name in pattern.ast_attrs:
                    line_num = node.lineno
                    code_line = self._get_line(line_num)

                    # For subprocess, check for shell=True
                    if pattern.name == "subprocess_shell":
                        has_shell_true = any(
                            isinstance(kw.arg, str)
                            and kw.arg == "shell"
                            and isinstance(kw.value, ast.Constant)
                            and kw.value.value is True
                            for kw in node.keywords
                        )
                        if not has_shell_true:
                            self.generic_visit(node)
                            return

                    self.findings.append(AnchorFinding(
                        file=self.file_path,
                        line=line_num,
                        pattern=pattern.name,
                        description=pattern.description,
                        code=code_line,
                        severity=pattern.severity,
                        weight=pattern.weight,
                    ))
        self.generic_visit(node)

    def _resolve_call_name(self, node: ast.expr) -> str | None:
        """Resolve a call expression to a dotted name string."""
        if isinstance(node, ast.Name):
            return self._import_aliases.get(node.id, node.id)
        elif isinstance(node, ast.Attribute):
            value = self._resolve_call_name(node.value)
            if value:
                full = f"{value}.{node.attr}"
                return self._import_aliases.get(full, full)
        return None

    def _get_line(self, lineno: int) -> str:
        """Get the source line at 1-based line number."""
        if 1 <= lineno <= len(self.lines):
            return self.lines[lineno - 1].rstrip()
        return ""


# ── Regex Scanner for Shell/JS Files ────────────────────────────────────

def _regex_scan_file(
    file_path: str,
    lines: list[str],
    language: str,
) -> list[AnchorFinding]:
    """Scan a file using precompiled regex patterns for the given language (DEF-11)."""
    findings: list[AnchorFinding] = []

    for pattern in DANGEROUS_PATTERNS:
        if language not in pattern.languages:
            continue
        compiled = _COMPILED_PATTERNS.get(pattern.name)
        if not compiled:
            continue

        for lineno_0, line in enumerate(lines):
            # Cap line length to 1000 characters to prevent ReDoS on massive lines (DEF-11)
            line_stripped = line.rstrip()
            line_bounded = line_stripped[:1000]

            # Skip comment lines
            if language in ("sh", "py") and line_bounded.lstrip().startswith("#"):
                continue
            if language == "js" and line_bounded.lstrip().startswith("//"):
                continue

            if compiled.search(line_bounded):
                findings.append(AnchorFinding(
                    file=file_path,
                    line=lineno_0 + 1,
                    pattern=pattern.name,
                    description=pattern.description,
                    code=line_bounded,
                    severity=pattern.severity,
                    weight=pattern.weight,
                ))

    return findings


# ── Python AST Scanner ──────────────────────────────────────────────────

def _ast_scan_python(
    file_path: str,
    lines: list[str],
    return_degraded: bool = False,
) -> list[AnchorFinding] | tuple[list[AnchorFinding], bool]:
    """Scan a Python file using AST walking + regex fallback.

    If return_degraded=True, returns (findings, is_degraded).
    Otherwise returns findings for backward compatibility.
    """
    findings: list[AnchorFinding] = []
    is_degraded = False

    source = "".join(lines)

    # AST walk
    try:
        tree = ast.parse(source, filename=file_path)
        visitor = _DangerousCallVisitor(file_path, lines)
        visitor.visit(tree)
        findings.extend(visitor.findings)
    except SyntaxError:
        # Fall back to regex-only for unparseable Python (DEF-04: fail closed / degraded)
        is_degraded = True

    # Also run regex for patterns that AST may miss (e.g., credential paths in strings)
    regex_findings = _regex_scan_file(file_path, lines, "py")

    # Deduplicate by (file, line, pattern)
    seen: set[tuple[str, int, str]] = {
        (f.file, f.line, f.pattern) for f in findings
    }
    for rf in regex_findings:
        key = (rf.file, rf.line, rf.pattern)
        if key not in seen:
            findings.append(rf)
            seen.add(key)

    if return_degraded:
        return findings, is_degraded
    return findings


# ── Signal Normalization ────────────────────────────────────────────────

# Severity weight mapping for anchor risk sub-score
# Per developer-2/03-functional-specifications.md Cap C §5
SEVERITY_WEIGHTS: dict[str, int] = {
    "critical": 40,
    "high": 25,
    "medium": 15,
    "low": 5,
}


def _compute_anchor_score(findings: list[AnchorFinding]) -> float:
    """Compute the normalized anchor risk sub-score.

    Formula: s_anchor = min(100, Σ SeverityWeight(f))
    """
    total = sum(SEVERITY_WEIGHTS.get(f.severity, 0) for f in findings)
    return min(100.0, float(total))


# ── Anchor Block Serializer ─────────────────────────────────────────────

def serialize_anchor_block(findings: list[AnchorFinding]) -> str:
    """Serialize anchor findings into the {AST_ANCHOR_FINDINGS} text block
    for injection into the semantic analysis prompt.

    Returns a human-readable text listing of confirmed code patterns.
    """
    if not findings:
        return "(No deterministic anchor findings detected)"

    lines: list[str] = []
    for f in findings:
        # Sanitize code snippet to prevent system prompt injection (DEF-06)
        sanitized_code = f.code.replace("\n", " ").replace("`", "'")[:100].strip()
        lines.append(
            f"- [{f.severity.upper()}] {f.description} "
            f"at {f.file}:{f.line} — `{sanitized_code}`"
        )
    return "\n".join(lines)


# ── Public API ──────────────────────────────────────────────────────────

def scan_anchors(
    scripts: dict[str, ScriptFile],
) -> tuple[StageResult, list[AnchorFinding], str]:
    """Scan all script files for dangerous code patterns.

    Args:
        scripts: Map of relative path → ScriptFile from PackageManifest.

    Returns:
        Tuple of (StageResult, raw anchor findings, serialized anchor block).
    """
    all_findings: list[AnchorFinding] = []
    stage_degraded = False

    for rel_path, script in scripts.items():
        if script.truncated:
            # DEF-04: Note truncated file and set stage_degraded
            stage_degraded = True
            continue

        ext = rel_path.rsplit(".", 1)[-1].lower() if "." in rel_path else ""

        if rel_path == "SKILL.md" or ext in ("md", "markdown", "txt"):
            # Documentation files are analyzed by semantic analysis, not AST code scanning
            continue
        elif ext == "py":
            file_findings, py_degraded = _ast_scan_python(rel_path, script.lines, return_degraded=True)
            if py_degraded:
                stage_degraded = True
        elif ext in ("sh", "bash"):
            file_findings = _regex_scan_file(rel_path, script.lines, "sh")
        elif ext in ("js", "mjs", "ts"):
            file_findings = _regex_scan_file(rel_path, script.lines, "js")
        else:
            # For .ps1, .bat, and other scripts, do general regex scan
            file_findings = _regex_scan_file(rel_path, script.lines, "sh")

        all_findings.extend(file_findings)

    # Build StageResult
    stage_findings: list[Finding] = []
    for af in all_findings:
        stage_findings.append(Finding(
            stage="deterministicAnchor",
            severity=af.severity,
            message=af.description,
            file=af.file,
            line=af.line,
            evidence_json={
                "pattern": af.pattern,
                "code": af.code,
            },
        ))

    anchor_score = _compute_anchor_score(all_findings)
    anchor_block = serialize_anchor_block(all_findings)

    result = StageResult(
        stage="deterministicAnchor",
        findings=stage_findings,
        signals={
            "anchor_risk": anchor_score,
            "anchors": anchor_score,
        },
        degraded=stage_degraded,
    )

    return result, all_findings, anchor_block

