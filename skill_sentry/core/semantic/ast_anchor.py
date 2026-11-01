"""Deterministic AST/regex anchors (stage 2).

These facts are computed *before* any model runs and are injected into the
semantic prompt as ground truth.  The rules are intentionally high-signal:
a match is evidence, never merely a suspicion.  Every finding carries the
relative file, a 1-based line, and the exact source line.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from skill_sentry.core.anchors import analyze_credential_flows
from skill_sentry.core.anchors.credential_flow import RULES_VERSION
from skill_sentry.core.contracts import (
    Finding,
    FindingEvidence,
    Severity,
    Stage,
    StageResult,
)
from skill_sentry.core.parser import SkillPackage, TextFile
from skill_sentry.core.semantic.ast_python import scan_python_ast

MAX_FINDINGS = 80


@dataclass(frozen=True)
class AnchorRule:
    type: str
    severity: Severity
    pattern: re.Pattern[str]
    message: str


_RULES: tuple[AnchorRule, ...] = (
    AnchorRule(
        "dns-lookup",
        Severity.HIGH,
        # Only a command in command position: prose such as "external host" is not one.
        re.compile(
            r"(?:^|[;&|`(]|\$\()\s*(?:sudo\s+)?(?:nslookup|dig|host)\s+[\w\"'$@.-]", re.IGNORECASE
        ),
        "DNS lookup command detected - potential DNS tunnelling",
    ),
    AnchorRule(
        "credential-path",
        Severity.CRITICAL,
        re.compile(
            r"(?:~|/home/[^/\s]+|/root)/\.aws/credentials|"
            r"AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|"
            r"\.aws[/\\]credentials",
            re.IGNORECASE,
        ),
        "AWS credential file or environment variable referenced",
    ),
    AnchorRule(
        "credential-path",
        Severity.CRITICAL,
        re.compile(
            r"(?:~|/home/[^/\s]+|/root)/\.ssh/(?:id_[a-z0-9]+|authorized_keys)|"
            r"\.ssh[/\\]id_",
            re.IGNORECASE,
        ),
        "SSH private key referenced",
    ),
    AnchorRule(
        "secret-access",
        Severity.CRITICAL,
        re.compile(
            r"\$\{?(?:SLACK_(?:BOT|USER)_TOKEN|GITHUB_TOKEN|GH_TOKEN|"
            r"AWS_SECRET_ACCESS_KEY|OPENAI_API_KEY|ANTHROPIC_API_KEY)\}?",
            re.IGNORECASE,
        ),
        "High-value secret environment variable referenced",
    ),
    AnchorRule(
        "obfuscation",
        Severity.HIGH,
        re.compile(r"\bbase64\b(?:\s+-[a-zA-Z]*d|\s+--decode|\s+-w0)", re.IGNORECASE),
        "base64 encoding/decoding detected - possible obfuscation",
    ),
    AnchorRule(
        "exfil-http-post",
        Severity.HIGH,
        re.compile(
            r"\b(?:curl|wget)\b[^\n]*(?:-X\s*POST|--data|-d\s|--upload-file)|"
            r"\brequests\.post\s*\(|\bhttpx\.post\s*\(|"
            r"\burllib\.request\.(?:urlopen|Request)\s*\([^\n]*(?:data\s*=|method\s*=\s*['\"]POST)",
            re.IGNORECASE,
        ),
        "Outbound HTTP POST/upload capability detected",
    ),
    AnchorRule(
        "sandbox-artifact",
        Severity.HIGH,
        re.compile(
            r"/\.dockerenv|/proc/(?:1|self)/(?:cgroup|mountinfo)|"
            r"/sys/(?:class/dmi|hypervisor)|/dev/kmsg",
            re.IGNORECASE,
        ),
        "Sandbox/VM artifact probe path detected",
    ),
    AnchorRule(
        "raw-socket",
        Severity.MEDIUM,
        # Ordinary network code uses sockets; the reverse-shell primitives are below.
        re.compile(r"\bsocket\.socket\s*\(|SOCK_STREAM", re.IGNORECASE),
        "Raw socket use detected",
    ),
    AnchorRule(
        "reverse-shell",
        Severity.CRITICAL,
        re.compile(r"/dev/tcp/|\bpty\.spawn\s*\(|\bos\.dup2\s*\(", re.IGNORECASE),
        "Reverse-shell primitive detected (shell redirected to a network connection)",
    ),
    AnchorRule(
        "dynamic-code",
        Severity.MEDIUM,
        re.compile(r"\b(?:eval|exec)\s*\(|\b__import__\s*\(", re.IGNORECASE),
        "Dynamic code execution primitive detected",
    ),
    AnchorRule(
        "shell-exec",
        Severity.HIGH,
        re.compile(
            r"\bos\.system\s*\(|\bsubprocess\.(?:run|call|Popen|check_output)\s*\([^\n]*"
            r"shell\s*=\s*True",
            re.IGNORECASE,
        ),
        "Shell command execution detected",
    ),
    AnchorRule(
        "unsafe-deserialization",
        Severity.HIGH,
        re.compile(r"\b(?:pickle|dill|marshal)\.loads?\s*\(", re.IGNORECASE),
        "Unsafe deserialization primitive detected",
    ),
    AnchorRule(
        "encoded-powershell",
        Severity.HIGH,
        re.compile(r"powershell(?:\.exe)?[^\n]*-e(?:nc(?:odedcommand)?)?\b", re.IGNORECASE),
        "Encoded PowerShell command detected",
    ),
    AnchorRule(
        "permission-change",
        Severity.MEDIUM,
        re.compile(r"\bchmod\s+(?:777|a\+rwx)\b", re.IGNORECASE),
        "World-writable permission change detected",
    ),
    AnchorRule(
        "destructive-command",
        Severity.MEDIUM,
        re.compile(r"\brm\s+-rf\s+(?:/|~|\$HOME|\*)", re.IGNORECASE),
        "Destructive filesystem command detected",
    ),
)

_INSTRUCTION_RULES: tuple[AnchorRule, ...] = (
    AnchorRule(
        "instruction-injection",
        Severity.CRITICAL,
        re.compile(
            r"(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above)\s+"
            r"(?:instructions?|rules?|prompts?)",
            re.IGNORECASE,
        ),
        "Prompt-injection phrase detected",
    ),
    AnchorRule(
        "instruction-injection",
        Severity.CRITICAL,
        re.compile(
            r"(?:read|open|include|send|upload|exfiltrate)[^\n]{0,80}"
            r"(?:~|/home/[^/\s]+)/\.ssh/|"
            r"include\s+its\s+contents[^\n]{0,80}(?:http|request|api)",
            re.IGNORECASE,
        ),
        "Instruction asks the agent to read private keys and transmit them",
    ),
    AnchorRule(
        "instruction-injection",
        Severity.HIGH,
        re.compile(
            r"(?:do\s+not|don't|never)\s+(?:tell|inform|reveal|mention)[^\n]{0,80}"
            r"(?:user|human|operator)",
            re.IGNORECASE,
        ),
        "Instruction asks the agent to conceal behaviour from the user",
    ),
    AnchorRule(
        "hidden-instruction",
        Severity.HIGH,
        re.compile(
            r"(?:white[-\s]on[-\s]white|hidden\s+(?:text|instruction)|"
            r"invisible\s+(?:text|instruction)|zero[-\s]width)",
            re.IGNORECASE,
        ),
        "Hidden or concealed instruction pattern detected",
    ),
)

_SEVERITY_SCORE = {
    Severity.CRITICAL: 95,
    Severity.HIGH: 72,
    Severity.MEDIUM: 42,
    Severity.LOW: 18,
    Severity.NOTE: 0,
}


def _scan_file(
    text_file: TextFile,
    rules: tuple[AnchorRule, ...],
    *,
    seen: set[tuple[str, str, int]],
    findings: list[Finding],
) -> None:
    for line_number, line in enumerate(text_file.text.splitlines(), start=1):
        if len(line) > 4000:
            line = line[:4000]
        for rule in rules:
            if not rule.pattern.search(line):
                continue
            key = (rule.type, text_file.relative, line_number)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                Finding(
                    stage=Stage.DETERMINISTIC_ANCHOR,
                    severity=rule.severity,
                    message=rule.message,
                    type=rule.type,
                    evidence=FindingEvidence(
                        file=text_file.relative,
                        line=line_number,
                        code=line.strip()[:500],
                    ),
                )
            )
            if len(findings) >= MAX_FINDINGS:
                return


_SHELL_AND_PERSISTENCE_RULES: tuple[AnchorRule, ...] = (
    AnchorRule(
        "shell-exec",
        Severity.HIGH,
        # No leading \b: inside code the command often follows a literal "\n" escape.
        re.compile(r"(?:curl|wget)\s[^\n|]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh)\b"),
        "download piped straight into a shell interpreter",
    ),
    AnchorRule(
        "shell-exec",
        Severity.HIGH,
        re.compile(
            r"(?:Invoke-WebRequest|Invoke-RestMethod|\biwr\b|\birm\b|\bcurl\b|\bwget\b)"
            r"[^\n|]*\|\s*(?:Invoke-Expression|\biex\b|powershell|pwsh)\b",
            re.IGNORECASE,
        ),
        "download piped straight into PowerShell execution",
    ),
    AnchorRule(
        "shell-exec",
        Severity.HIGH,
        re.compile(
            r"\b(?:Invoke-Expression|iex)\b[^\n]*"
            r"(?:DownloadString|DownloadFile|Invoke-WebRequest|\biwr\b|\birm\b)",
            re.IGNORECASE,
        ),
        "download passed to PowerShell Invoke-Expression",
    ),
    AnchorRule(
        "log-tampering",
        Severity.HIGH,
        re.compile(
            r"\bhistory\s+-c\b|>\s*~?/?[^\s;]*\.(?:bash_|zsh_)?history\b|"
            r"\brm\s+-[a-z]*f[a-z]*\s+[^\n;]*\.log\b"
        ),
        "shell history or log tampering",
    ),
    AnchorRule(
        "persistence",
        Severity.MEDIUM,
        re.compile(
            r"\.config/autostart/|\.(?:bash|zsh)rc\b|\.profile\b|"
            r"\bcrontab\s+-|/etc/cron\.|\bsystemctl\s+enable\b"
        ),
        "writes to a startup, shell-profile or scheduled-task location",
    ),
)

_SEVERITY_RANK = {
    Severity.NOTE: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def _merge(findings: list[Finding], item: Finding) -> None:
    """Add ``item``, or keep the stronger of two findings for the same file, line and type."""

    for index, existing in enumerate(findings):
        same_site = (
            existing.evidence.file == item.evidence.file
            and existing.evidence.line == item.evidence.line
            and existing.finding_type == item.finding_type
        )
        if same_site:
            if _SEVERITY_RANK[item.severity] > _SEVERITY_RANK[existing.severity]:
                findings[index] = item
            return
    findings.append(item)


def scan_anchors(package: SkillPackage) -> StageResult:
    """Run all deterministic rules and return a normalised stage result."""

    findings: list[Finding] = []
    seen: set[tuple[str, str, int]] = set()
    # SKILL.md first so prompt-injection evidence is prominent in the UI.
    ordered = sorted(
        package.text_files, key=lambda item: (item.relative != "SKILL.md", item.relative)
    )
    for text_file in ordered:
        _scan_file(
            text_file,
            _RULES + _SHELL_AND_PERSISTENCE_RULES + _INSTRUCTION_RULES,
            seen=seen,
            findings=findings,
        )
        if len(findings) >= MAX_FINDINGS:
            break

    parse_errors: list[str] = []
    for text_file in ordered:
        if not text_file.relative.lower().endswith(".py"):
            continue
        ast_findings, error = scan_python_ast(text_file.relative, text_file.text)
        if error:
            parse_errors.append(error)
        for item in ast_findings:
            _merge(findings, item)

    findings.extend(analyze_credential_flows(package))

    score = 0.0
    if findings:
        highest = max(_SEVERITY_SCORE[item.severity] for item in findings)
        score = min(100.0, highest + min(12, (len(findings) - 1) * 3))
    return StageResult(
        stage=Stage.DETERMINISTIC_ANCHOR,
        findings=findings,
        signals={"anchors": score},
        degraded=bool(parse_errors),
        error="; ".join(parse_errors)[:1000] if parse_errors else None,
        telemetry={
            "files_scanned": len(package.text_files),
            "findings": len(findings),
            "prompt_injection_rules": len(_INSTRUCTION_RULES),
            "credential_flow_rules_version": RULES_VERSION,
            "python_parse_errors": len(parse_errors),
        },
    )


__all__ = ["AnchorRule", "scan_anchors"]
