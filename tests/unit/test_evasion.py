"""Sandbox-evasion detection and attacker-profile assembly."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

from skillsentry.core.contracts import ExfilChannel, Severity, Stage, VerdictTier
from skillsentry.core.evasion.detector import (
    PROBE_COMMANDS,
    EvasionResult,
    classify_probe,
    detect_probes,
    is_probe_command,
    is_probe_path,
    probe_kind_for_path,
    probe_summary_pattern,
)
from skillsentry.core.poisoned_well.attacker_profile import build_attacker_profile
from skillsentry.core.poisoned_well.canary_gen import generate_canary_set
from skillsentry.core.poisoned_well.exfil_tracker import ExfilTracker
from skillsentry.core.sandbox.monitor import MonitorEvent

SCAN_ID = UUID("44444444-4444-4444-8444-444444444444")
MARKER = "SKS-8b2c4d19"
NOW = datetime(2026, 10, 21, 12, 0, tzinfo=UTC)


def _event(event_type: str, path: str, *, marker: str | None = None, detail=None) -> MonitorEvent:
    return MonitorEvent(
        ts=NOW,
        event_type=event_type,
        path_or_channel=path,
        marker=marker,
        process="python",
        detail=detail or {},
    )


def _probe_events() -> list[MonitorEvent]:
    return [
        _event("probe_detected", "/.dockerenv", detail={"kind": "filesystem"}),
        _event("probe_detected", "/proc/1/cgroup", detail={"kind": "filesystem"}),
        _event("probe_detected", "df -h", detail={"kind": "command"}),
        _event("execve", "/usr/bin/lsblk", detail={"kind": "command"}),
    ]


def test_probe_paths_and_commands_are_discoverable():
    assert is_probe_path("/.dockerenv")
    assert is_probe_path("/proc/self/cgroup-extra")
    assert not is_probe_path("/home/sandbox/.aws/credentials")
    assert probe_kind_for_path("/proc/self/cgroup") == "cgroup_probe"
    assert probe_kind_for_path("/sys/class/dmi/id/product_name") == "vm_artifact"
    assert is_probe_command("df -h")
    assert is_probe_command("/usr/bin/systemd-detect-virt")
    assert not is_probe_command("ls -la")
    assert "df" in PROBE_COMMANDS


def test_detect_probes_deduplicates_and_produces_malicious_override():
    result = detect_probes(_probe_events())
    assert result.detected is True
    assert result.masquerade_failed is False
    assert result.targets == ("/.dockerenv", "/proc/1/cgroup", "df", "lsblk")
    assert result.kinds == ("docker_artifact", "cgroup_probe", "command_probe")
    override = result.to_override()
    assert override is not None
    assert override.verdict is VerdictTier.MALICIOUS
    assert override.confidence == 1.0
    assert override.source is Stage.EVASION
    assert override.evidence["sandboxEvasionDetected"] is True
    assert len(override.evidence["probes"]) == 4


def test_detect_probes_ignores_benign_canary_reads():
    result = detect_probes(
        [
            _event("canary_read", "~/.aws/credentials", marker=MARKER),
            _event("probe_detected", "/home/sandbox/.env", detail={"kind": "filesystem"}),
        ]
    )
    assert result.detected is False
    assert result.to_override() is None
    assert result.summary()["evasionDetected"] is False


def test_classify_probe_command_and_path():
    command = classify_probe("dmidecode", ts=NOW, detail={"kind": "command"})
    assert command is not None
    assert command.kind == "command_probe"
    assert command.target == "dmidecode"
    path = classify_probe("/dev/kmsg", ts=NOW)
    assert path is not None
    assert path.kind == "kernel_probe"


def test_engine_error_is_not_a_verdict_signal():
    result = EvasionResult.engine_error("masquerade unavailable")
    assert result.detected is False
    assert result.masquerade_failed is True
    assert result.to_override() is None
    assert "masquerade" in result.summary()["error"]


def test_probe_summary_pattern_matches_only_command_tokens():
    pattern = probe_summary_pattern()
    assert pattern.search("df -h")
    assert pattern.search("true; mount | head")
    assert not pattern.search("notdf -h")


def _correlation():
    canaries = generate_canary_set(
        SCAN_ID, "Slack workspace", marker=MARKER, secondary_marker="SKS-ffffffff"
    )
    tracker = ExfilTracker(canaries)
    tracker.record_canary_read(
        MonitorEvent(
            ts=NOW,
            event_type="canary_read",
            path_or_channel="~/.config/slack/token",
            marker=MARKER,
            process="python",
            detail={},
        )
    )
    result = tracker.observe_http(
        "POST",
        "https://evil-c2.com/collect/drop",
        body=b"token=xoxb-SKS-8b2c4d19",
        ts=NOW + timedelta(seconds=2),
    )
    assert result is not None
    return canaries, result


def test_attacker_profile_combines_exfiltration_and_evasion():
    canaries, correlation = _correlation()
    evasion = detect_probes(_probe_events())
    profile = build_attacker_profile(
        canaries,
        correlation=correlation,
        evasion=evasion,
        secondary_served=True,
        ioc_export="stix",
    )
    assert profile.triggered is True
    assert profile.evasion_detected is True
    assert profile.exfil_channel is ExfilChannel.HTTP_POST
    assert profile.canary_marker == MARKER
    assert profile.secondary_canary == "SKS-ffffffff"
    assert profile.encoding == "raw"
    assert profile.targeted_assets == ("~/.config/slack/token",)
    assert profile.c2_indicators == ("evil-c2.com",)
    assert profile.targeted_assets[0] in profile.actual_behavior
    assert "evil-c2.com" in profile.actual_behavior

    active = profile.to_active_defense()
    assert active.triggered is True
    assert active.exfil_channel is ExfilChannel.HTTP_POST
    assert active.sandbox_evasion_detected is True
    assert active.actual_behavior is not None
    assert active.ioc_export == "stix"

    finding = profile.to_finding()
    assert finding is not None
    assert finding.stage is Stage.POISONED_WELL
    assert finding.severity is Severity.CRITICAL
    assert finding.finding_type == "canary-exfiltration"
    assert finding.evidence is not None
    assert finding.evidence.marker == MARKER
    assert finding.evidence.c2 == "evil-c2.com"

    exported = profile.to_dict()
    assert exported["triggered"] is True
    assert exported["contextAwareCanary"] == "SLACK"
    assert exported["actualBehavior"]
    assert exported["iocs"]
    assert exported["iocs"][0]["type"] == "domain-name"


def test_evasion_only_profile_has_no_canary_marker():
    canaries = generate_canary_set(SCAN_ID, "generic utility", marker=MARKER)
    profile = build_attacker_profile(canaries, evasion=detect_probes(_probe_events()))
    assert profile.triggered is True
    assert profile.canary_marker is None
    assert profile.exfil_channel is None
    assert profile.to_finding() is not None
    assert profile.to_finding().stage is Stage.EVASION
    assert profile.to_finding().finding_type == "sandbox-evasion"


def test_clean_profile_is_not_triggered():
    canaries = generate_canary_set(SCAN_ID, "pdf summarizer", marker=MARKER)
    profile = build_attacker_profile(canaries)
    assert profile.triggered is False
    assert profile.to_finding() is None
    assert profile.to_active_defense().triggered is False
    assert "No canary read" in profile.actual_behavior


def test_ioc_export_includes_url_with_path():
    canaries, correlation = _correlation()
    profile = build_attacker_profile(canaries, correlation=correlation)
    values = {(ioc.ioc_type, ioc.value) for ioc in profile.iocs}
    assert ("domain-name", "evil-c2.com") in values
    assert ("url", "https://evil-c2.com/collect/drop") in values
