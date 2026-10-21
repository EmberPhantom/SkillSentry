"""Report renderers: Markdown citations, SARIF output, STIX bundles."""

from __future__ import annotations

import json

import pytest
from skillsentry.core.contracts import ExportFormat
from skillsentry.core.reports import MEDIA_TYPES, ReportFiles, render_report, write_report_files
from skillsentry.core.verdict.markdown_report import build_markdown
from skillsentry.core.verdict.stix_report import NoIOCsError, build_stix
from skillsentry.server.demo_data import build_demo_store


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
    assert "Powered by Gemma 4 · open weights" in text


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
