"""Deterministic AST/regex anchors (stage 2).

These facts are computed *before* any model runs and are injected into the
semantic prompt as ground truth.  The rules are intentionally high-signal:
a match is evidence, never merely a suspicion.  Every finding carries the
relative file, a 1-based line, and the exact source line.
"""

from __future__ import annotations

import dataclasses
import re
from dataclasses import dataclass

from skill_sentry_cli.core.anchors import analyze_credential_flows
from skill_sentry_cli.core.anchors.confusables import (
    mixed_script_words,
    normalise_line,
    normalise_text,
)
from skill_sentry_cli.core.anchors.credential_flow import RULES_VERSION
from skill_sentry_cli.core.anchors.cross_file import analyze_cross_file
from skill_sentry_cli.core.anchors.hidden_text import LONG_RUN, inspect_line
from skill_sentry_cli.core.contracts import (
    Finding,
    FindingEvidence,
    Severity,
    Stage,
    StageResult,
)
from skill_sentry_cli.core.parser import SkillPackage, TextFile
from skill_sentry_cli.core.semantic.ast_python import scan_python_ast

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
        "credential-store",
        Severity.HIGH,
        # A user-level credential file named by a home-relative path. A project-relative
        # ".npmrc" or a bare word such as "netrc" is not a match.
        re.compile(
            r"(?:~|\$HOME|\$\{HOME\}|/home/[^/\s]+|/root)/"
            r"(?:\.netrc|\.git-credentials|\.pypirc|\.npmrc|\.docker/config\.json|\.kube/config|"
            r"\.config/gcloud/|\.azure/(?:accessTokens|msal_token_cache)|\.gnupg/private-keys)",
            re.IGNORECASE,
        ),
        "User credential store referenced (netrc, registry, cloud or cluster config)",
    ),
    AnchorRule(
        "credential-store",
        Severity.HIGH,
        # The OS keychain or a browser's saved logins, read from a command or a path. The
        # commands only count in command position, so prose that mentions them does not.
        re.compile(
            r"(?:^|[;&|`(]|\$\()\s*(?:sudo\s+)?(?:security\s+(?:find-(?:generic|internet)-password|"
            r"dump-keychain)|secret-tool\s+lookup|cmdkey\s+/list)\b|"
            r"/(?:Login Data|logins\.json|key4\.db)\b",
            re.IGNORECASE,
        ),
        "OS keychain or browser saved-login store read",
    ),
    AnchorRule(
        "credential-store",
        Severity.HIGH,
        # A browser's cookie store, which holds live session tokens.
        re.compile(r"\bcookies\.sqlite\b|[/\\]Cookies(?:-journal)?\b(?!\s*[:=(])", re.IGNORECASE),
        "browser cookie store referenced",
    ),
    AnchorRule(
        "credential-store",
        Severity.MEDIUM,
        # A browser profile folder, named by its path. A script that reaches into one is
        # reading the user's logins, cookies or history.
        re.compile(
            r"(?:^|[\s/\\'\"])\.mozilla(?:[/\\'\"]|$)|"
            r"\.config[/\\](?:google-chrome|chromium|BraveSoftware|microsoft-edge)\b|"
            r"Application Support[/\\](?:Google[/\\]Chrome|Firefox)\b|"
            r"AppData[/\\]+(?:Local|Roaming)[/\\]+(?:Google[/\\]+Chrome|Mozilla)\b",
            re.IGNORECASE,
        ),
        "browser profile folder referenced",
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
    is_markdown = text_file.relative.lower().endswith((".md", ".markdown", ".txt"))
    in_fence = False
    for line_number, raw_line in enumerate(text_file.text.splitlines(), start=1):
        # Rules look at the first 4000 characters; the check for hidden characters reads the
        # whole line, because a payload can sit after them.
        line = raw_line[:4000]
        if is_markdown and line.lstrip().startswith(("```", "~~~")):
            in_fence = not in_fence
        # Every rule is tried on the line as written and on its normalised form (lookalike
        # letters mapped, compatibility forms folded, invisible characters dropped), so a
        # rule can only gain matches. The finding keeps the original line.
        normalised = normalise_line(line)
        for rule in rules:
            as_written = bool(rule.pattern.search(line))
            if not as_written and not (normalised != line and rule.pattern.search(normalised)):
                continue
            key = (rule.type, text_file.relative, line_number)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                Finding(
                    stage=Stage.DETERMINISTIC_ANCHOR,
                    severity=rule.severity,
                    message=(
                        rule.message
                        if as_written
                        else f"{rule.message} (written with lookalike or invisible characters)"
                    ),
                    finding_type=rule.type,
                    evidence=FindingEvidence(
                        file=text_file.relative,
                        line=line_number,
                        code=line.strip()[:500],
                    ),
                )
            )
            if len(findings) >= MAX_FINDINGS:
                return
        code_context = not is_markdown or in_fence or _looks_like_command(line)
        _flag_mixed_script(
            line,
            line_number,
            text_file.relative,
            code_context=code_context,
            seen=seen,
            findings=findings,
        )
        _flag_hidden_text(
            raw_line,
            line_number,
            text_file.relative,
            code_context=code_context,
            seen=seen,
            findings=findings,
        )


def _flag_hidden_text(
    line: str,
    line_number: int,
    relative: str,
    *,
    code_context: bool,
    seen: set[tuple[str, str, int]],
    findings: list[Finding],
) -> None:
    """Runs of invisible characters, and a message decoded from them.

    A run of 8 or more is MEDIUM in code and LOW in prose, and HIGH from 64 up, long enough to
    carry a message. Readable text decoded from the invisible characters is HIGH, and is run
    through the same rules as visible text, with this file and line as the evidence.
    """

    hidden = inspect_line(line)
    if hidden is None:
        return
    key = ("hidden-characters", relative, line_number)
    if key in seen:
        return
    seen.add(key)
    if hidden.longest_run >= LONG_RUN:
        severity = Severity.HIGH
    elif code_context:
        severity = Severity.MEDIUM
    else:
        severity = Severity.LOW
    if hidden.decoded is not None:
        severity = Severity.HIGH
    summary = (
        f"{hidden.total} invisible character(s) on one line, in a run of {hidden.longest_run}"
        if hidden.longest_run
        else f"{hidden.total} invisible character(s) on one line"
    )
    findings.append(
        Finding(
            stage=Stage.DETERMINISTIC_ANCHOR,
            severity=severity,
            message=f"Invisible characters hide content: {summary}",
            finding_type="hidden-characters",
            evidence=FindingEvidence(file=relative, line=line_number),
        )
    )
    if hidden.decoded is None:
        return
    decoded = hidden.decoded
    shown = decoded if len(decoded) <= 200 else decoded[:200] + "..."
    findings.append(
        Finding(
            stage=Stage.DETERMINISTIC_ANCHOR,
            severity=Severity.HIGH,
            message=f"Hidden text decoded from {hidden.encoding}: {shown!r}",
            finding_type="hidden-text",
            evidence=FindingEvidence(file=relative, line=line_number, code=shown[:500]),
        )
    )
    normalised = normalise_line(decoded)
    for rule in _RULES + _SHELL_AND_PERSISTENCE_RULES + _INSTRUCTION_RULES:
        if not (rule.pattern.search(decoded) or rule.pattern.search(normalised)):
            continue
        rule_key = (rule.type, relative, line_number)
        if rule_key in seen:
            continue
        seen.add(rule_key)
        findings.append(
            Finding(
                stage=Stage.DETERMINISTIC_ANCHOR,
                severity=rule.severity,
                message=f"{rule.message} (in text hidden with invisible characters)",
                finding_type=rule.type,
                evidence=FindingEvidence(file=relative, line=line_number, code=shown[:500]),
            )
        )


def _looks_like_command(line: str) -> bool:
    """A markdown line that is a command rather than prose: indented, a prompt, or in backticks."""

    stripped = line.lstrip()
    return line.startswith(("    ", "\t")) or stripped.startswith(("$ ", "> ", "# ")) or "`" in line


def _flag_mixed_script(
    line: str,
    line_number: int,
    relative: str,
    *,
    code_context: bool,
    seen: set[tuple[str, str, int]],
    findings: list[Finding],
) -> None:
    """A word spelled with Latin and lookalike letters is a spoof, not a language.

    It is MEDIUM in code, a script or a command (where a lookalike hides a command or a name
    from the other checks) and LOW in prose. Text written wholly in one alphabet is never
    reported.
    """

    words = mixed_script_words(line)
    key = ("mixed-script", relative, line_number)
    if not words or key in seen:
        return
    seen.add(key)
    first = words[0]
    shown = ", ".join(f"{item.word!r} (reads as {item.looks_like!r})" for item in words[:3])
    findings.append(
        Finding(
            stage=Stage.DETERMINISTIC_ANCHOR,
            severity=Severity.MEDIUM if code_context else Severity.LOW,
            message=(
                f"Word mixes Latin letters with lookalike {'/'.join(first.scripts)} letters: {shown}"
            ),
            finding_type="mixed-script",
            evidence=FindingEvidence(file=relative, line=line_number, code=line.strip()[:500]),
        )
    )


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
    AnchorRule(
        "privilege-escalation",
        Severity.HIGH,
        re.compile(
            # A passwordless sudo grant, a write to the sudoers files, a setuid bit, or adding an
            # account to the administrator group. Reading or mentioning them is not matched.
            r"\bNOPASSWD\s*:|"
            r"(?:>>?|\btee\b(?:\s+-a)?|\bsed\s+-i|\bcp\b|\bmv\b|\binstall\b)[^\n]*/etc/sudoers|"
            r"\bchmod\s+(?:[ugoa]*\+s\b|0?[4-7][0-7]{3}\b)|"
            r"\busermod\s+-[a-zA-Z]*[aG][a-zA-Z]*\s+(?:-[a-zA-Z]+\s+)?(?:sudo|wheel|root)\b"
        ),
        "grants administrator rights (a sudoers entry, a setuid bit or an admin group)",
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


def _with_original_code(items: list[Finding], original: str) -> list[Finding]:
    """Findings from a normalised pass, with the evidence text taken from the original line."""

    lines = original.splitlines()
    restored: list[Finding] = []
    for item in items:
        line = item.evidence.line
        if item.evidence.code is not None and line is not None and 1 <= line <= len(lines):
            evidence = item.evidence.model_copy(update={"code": lines[line - 1].strip()[:500]})
            item = item.model_copy(update={"evidence": evidence})
        restored.append(item)
    return restored


def _normalised_credential_flows(package: SkillPackage, existing: list[Finding]) -> list[Finding]:
    """Credential-flow findings that only appear once lookalikes are mapped."""

    changed = [
        dataclasses.replace(item, text=normalise_text(item.text))
        for item in package.text_files
        if normalise_text(item.text) != item.text
    ]
    if not changed:
        return []
    names = {item.relative for item in changed}
    view = dataclasses.replace(
        package,
        text_files=[
            *(item for item in package.text_files if item.relative not in names),
            *changed,
        ],
    )
    known = {
        (item.finding_type, item.evidence.file, item.evidence.line, item.message)
        for item in existing
    }
    originals = {item.relative: item.text for item in package.text_files}
    fresh: list[Finding] = []
    for item in analyze_credential_flows(view):
        if (item.finding_type, item.evidence.file, item.evidence.line, item.message) in known:
            continue
        fresh.extend(_with_original_code([item], originals.get(item.evidence.file or "", "")))
    return fresh


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
        normalised_text = normalise_text(text_file.text)
        if normalised_text != text_file.text:
            # The same file read with lookalikes mapped. A parse error here is not reported
            # again; the original text was already judged.
            extra, _ = scan_python_ast(text_file.relative, normalised_text)
            for item in _with_original_code(extra, text_file.text):
                _merge(findings, item)

    findings.extend(analyze_credential_flows(package))
    findings.extend(_normalised_credential_flows(package, findings))
    findings.extend(analyze_cross_file(package))

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
