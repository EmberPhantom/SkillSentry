"""Report renderers: Markdown citations, SARIF output, STIX bundles."""

from __future__ import annotations

import json

import pytest
from skill_sentry_cli.core.contracts import ExportFormat
from skill_sentry_cli.core.reports import (
    MEDIA_TYPES,
    ReportFiles,
    render_report,
    write_report_files,
)
from skill_sentry_cli.core.verdict.markdown_report import build_markdown
from skill_sentry_cli.core.verdict.stix_report import NoIOCsError, build_stix
from skill_sentry_cli.server.demo_data import build_demo_store


def _verdict(name: str):
    return next(item.verdict for item in build_demo_store() if item.name == name)


def test_markdown_contains_citations_and_money_shot():
    text = build_markdown(_verdict("cloud-sync-pro"))
    assert "# SkillSentry Triage Report — cloud-sync-pro" in text
    assert "**MALICIOUS**" in text
    assert "scripts/sync.sh:7" in text
    assert "evil-collector.net" in text
    assert "SKS-7f3a9c21" in text
    assert "Do not install this skill" in text
    assert "Fully local analysis · open weights" in text


def test_markdown_benign_is_affirmative():
    text = build_markdown(_verdict("pdf-summarizer"))
    assert "Safe to install." in text
    assert "No active-defense events" in text
    assert "Do not install" not in text


def test_stix_bundle_has_indicator_and_relationship():
    verdict = _verdict("slack-notif-mal")
    bundle = build_stix(verdict)
    assert bundle["type"] == "bundle"
    assert bundle["spec_version"] == "2.1"
    types = [obj["type"] for obj in bundle["objects"]]
    assert types.count("indicator") == 1
    assert types.count("relationship") == 1
    assert "malware" in types
    assert "identity" in types

    indicator = next(obj for obj in bundle["objects"] if obj["type"] == "indicator")
    assert indicator["pattern_type"] == "stix"
    assert indicator["pattern"] == "[domain-name:value = 'evil-c2.com']"
    assert indicator["x_skillsentry_channel"] == "HTTP_POST"

    malware = next(obj for obj in bundle["objects"] if obj["type"] == "malware")
    assert malware["name"] == "slack-notif-mal"
    assert malware["x_skillsentry_canary_marker"] == "SKS-8b2c4d19"


def test_stix_identity_names_the_running_version():
    from skill_sentry_cli.core.version import __version__

    bundle = build_stix(_verdict("slack-notif-mal"))
    identity = next(obj for obj in bundle["objects"] if obj["type"] == "identity")
    assert identity["name"] == f"SkillSentry {__version__}"


def test_stix_requires_triggered_active_defense():
    with pytest.raises(NoIOCsError):
        build_stix(_verdict("pdf-summarizer"))


def test_render_report_media_types():
    verdict = _verdict("cloud-sync-pro")
    for fmt in ExportFormat:
        rendered = render_report(verdict, fmt)
        assert rendered.media_type == MEDIA_TYPES[fmt]
        assert rendered.content


def test_write_report_files_writes_expected_bundle(tmp_path):
    cloud = _verdict("cloud-sync-pro")
    links = write_report_files(cloud, root=tmp_path / "cloud")
    assert isinstance(links, ReportFiles)
    assert links.stix is not None and links.stix.is_file()
    assert (tmp_path / "cloud" / "report.sarif").is_file()
    assert (tmp_path / "cloud" / "report.md").is_file()
    assert (tmp_path / "cloud" / "stix-bundle.json").is_file()
    json.loads((tmp_path / "cloud" / "stix-bundle.json").read_text(encoding="utf-8"))

    benign = _verdict("pdf-summarizer")
    benign_links = write_report_files(benign, root=tmp_path / "benign")
    assert benign_links.stix is None
    assert (tmp_path / "benign" / "report.sarif").is_file()
    assert not (tmp_path / "benign" / "stix-bundle.json").exists()


def test_markdown_shows_unscanned_when_a_stage_degraded():
    from skill_sentry_cli.core.contracts import Stage, StageResult

    degraded = [StageResult(stage=Stage.SEMANTIC, degraded=True, error="model unavailable")]
    text = build_markdown(_verdict("git-helper"), stage_results=degraded)
    assert "| Verdict | **UNSCANNED** |" in text
    assert "Do not install until the scan completes" in text
    assert "model unavailable" in text


def test_malicious_verdict_is_not_downgraded_by_a_degraded_stage():
    from skill_sentry_cli.core.contracts import Stage, StageResult

    degraded = [StageResult(stage=Stage.VISION, degraded=True, error="vision unavailable")]
    text = build_markdown(_verdict("cloud-sync-pro"), stage_results=degraded)
    assert "| Verdict | **MALICIOUS** |" in text
    assert "UNSCANNED" not in text


def test_complete_scan_is_not_marked_unscanned():
    from skill_sentry_cli.core.contracts import Stage, StageResult

    complete = [StageResult(stage=Stage.SEMANTIC)]
    text = build_markdown(_verdict("git-helper"), stage_results=complete)
    assert "UNSCANNED" not in text
