"""
Dynamic Sandbox Action Instruction Generator (INT-4).

Bridges Developer 2's static, semantic, and visual analysis with
Developer 1's Stage 4 Docker behavioral sandbox. Translates detected
code anchors, intent contradictions, and visual injection payloads into
structured SandboxActionInstruction objects.

CL-D2-2 · REQ-D2-SBX-01/02/03 · Source: developer-2/03-functional-specifications.md Cap J.
"""

from __future__ import annotations

import uuid
from typing import Any, Optional

from skillsentry_dev2.contracts import (
    Finding,
    SandboxActionInstruction,
)
from skillsentry_dev2.core.semantic.ast_anchor import AnchorFinding


def _finding_id(finding: Finding) -> str:
    """Generate a stable finding reference ID."""
    parts = [finding.stage, finding.severity, finding.message[:40]]
    if finding.file:
        parts.append(finding.file)
    if finding.line is not None:
        parts.append(str(finding.line))
    return "-".join(parts).replace(" ", "_")[:80]


def generate_sandbox_instructions(
    anchor_findings: list[AnchorFinding],
    stage_findings: list[Finding],
    intent_keywords: list[str],
    package_name: str,
    has_path_traversal: bool = False,
) -> list[SandboxActionInstruction]:
    """Generate sandbox action instructions from analysis findings.

    Maps detected code patterns to the appropriate sandbox check categories
    per the INT-4 contract.

    Args:
        anchor_findings: Raw anchor findings from ast_anchor.scan_anchors().
        stage_findings: All findings from stages 1-3.
        intent_keywords: Normalized intent keywords (INT-1).
        package_name: Name of the skill package.
        has_path_traversal: True if Stage 1 detected path traversal attempts.

    Returns:
        List of SandboxActionInstruction objects.
    """
    instructions: list[SandboxActionInstruction] = []
    seen_categories: set[str] = set()

    # If path traversal was detected, block all sandbox execution
    if has_path_traversal:
        instructions.append(SandboxActionInstruction(
            instruction_id=str(uuid.uuid4()),
            finding_id=None,
            target_package=package_name,
            entrypoint_script="",
            reason="Package attempted path traversal — sandbox execution blocked for safety",
            check_category="TRIGGER_EXECUTION",
            contextual_intent=intent_keywords,
            execution_parameters={},
            constraints={},
            check_status="blocked",
            status_notes="Host traversal threat detected in Stage 1 spec validation. "
                         "Untrusted code must not be mounted or executed.",
        ))
        return instructions

    # Process anchor findings to generate sandbox checks
    for af in anchor_findings:
        # Credential access → CREDENTIAL_CANARY_MONITOR
        if af.pattern == "credential_read" and "CREDENTIAL_CANARY_MONITOR" not in seen_categories:
            instructions.append(SandboxActionInstruction(
                instruction_id=str(uuid.uuid4()),
                finding_id=f"anchor-{af.file}:{af.line}",
                target_package=package_name,
                entrypoint_script=af.file,
                reason=f"Credential file access detected at {af.file}:{af.line}: {af.code}",
                check_category="CREDENTIAL_CANARY_MONITOR",
                contextual_intent=intent_keywords,
                execution_parameters={"timeout_s": 60, "env_vars": {}, "cli_args": []},
                constraints={"network_isolated": True, "sinkhole_only": True, "max_mem_mb": 512},
                check_status="required",
            ))
            seen_categories.add("CREDENTIAL_CANARY_MONITOR")

        # DNS tunneling tools → DNS_SINKHOLE_WATCH
        if af.pattern in ("nslookup", "dig", "host_lookup", "dnspython") and "DNS_SINKHOLE_WATCH" not in seen_categories:
            instructions.append(SandboxActionInstruction(
                instruction_id=str(uuid.uuid4()),
                finding_id=f"anchor-{af.file}:{af.line}",
                target_package=package_name,
                entrypoint_script=af.file,
                reason=f"DNS tunneling tool detected at {af.file}:{af.line}: {af.code}",
                check_category="DNS_SINKHOLE_WATCH",
                contextual_intent=intent_keywords,
                execution_parameters={"timeout_s": 60, "env_vars": {}, "cli_args": []},
                constraints={"network_isolated": True, "sinkhole_only": True, "max_mem_mb": 512},
                check_status="required",
            ))
            seen_categories.add("DNS_SINKHOLE_WATCH")

        # HTTP exfil tools → HTTP_EXFIL_MONITOR
        if af.pattern in ("curl", "wget", "requests_post", "urllib") and "HTTP_EXFIL_MONITOR" not in seen_categories:
            instructions.append(SandboxActionInstruction(
                instruction_id=str(uuid.uuid4()),
                finding_id=f"anchor-{af.file}:{af.line}",
                target_package=package_name,
                entrypoint_script=af.file,
                reason=f"HTTP exfiltration tool detected at {af.file}:{af.line}: {af.code}",
                check_category="HTTP_EXFIL_MONITOR",
                contextual_intent=intent_keywords,
                execution_parameters={"timeout_s": 60, "env_vars": {}, "cli_args": []},
                constraints={"network_isolated": True, "sinkhole_only": True, "max_mem_mb": 512},
                check_status="required",
            ))
            seen_categories.add("HTTP_EXFIL_MONITOR")

    # Check for evasion-related patterns in findings
    for finding in stage_findings:
        ej = finding.evidence_json or {}
        pattern = ej.get("pattern", "")
        code = ej.get("code", "")
        combined = f"{finding.message} {code} {pattern}".lower()

        if any(x in combined for x in [".dockerenv", "/proc/1/cgroup", "proc/bus"]):
            if "EVASION_PROBE_WATCH" not in seen_categories:
                instructions.append(SandboxActionInstruction(
                    instruction_id=str(uuid.uuid4()),
                    finding_id=_finding_id(finding),
                    target_package=package_name,
                    entrypoint_script=finding.file or "",
                    reason="Sandbox evasion probe pattern detected",
                    check_category="EVASION_PROBE_WATCH",
                    contextual_intent=intent_keywords,
                    execution_parameters={"timeout_s": 60},
                    constraints={"network_isolated": True, "max_mem_mb": 512},
                    check_status="required",
                ))
                seen_categories.add("EVASION_PROBE_WATCH")

    # If no specific checks generated but package has scripts, add baseline execution
    if not instructions:
        # Find any entrypoint script
        entrypoint = ""
        for f in stage_findings:
            if f.file and f.file.endswith((".py", ".sh", ".js")):
                entrypoint = f.file
                break

        instructions.append(SandboxActionInstruction(
            instruction_id=str(uuid.uuid4()),
            finding_id=None,
            target_package=package_name,
            entrypoint_script=entrypoint,
            reason="Standard behavioral verification",
            check_category="TRIGGER_EXECUTION",
            contextual_intent=intent_keywords,
            execution_parameters={"timeout_s": 60, "env_vars": {}, "cli_args": []},
            constraints={"network_isolated": True, "sinkhole_only": True, "max_mem_mb": 512},
            check_status="optional",
        ))

    return instructions

