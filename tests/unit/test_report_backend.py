"""The banner and the Markdown footer name the analysis backend that ran.

``--backend auto`` is a request. The backend is the model the engine selected for the
scan, read after the scan. The footer is optional on the report renderers, so callers
that do not pass a backend keep the old "not recorded" text.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from skill_sentry_cli import cli
from skill_sentry_cli.core.cache import SQLiteStore
from skill_sentry_cli.core.config import SkillsEntryConfig
from skill_sentry_cli.core.contracts import ExportFormat
from skill_sentry_cli.core.engine import ScanEngine
from skill_sentry_cli.core.models.mock import MockGemma
from skill_sentry_cli.core.reports import render_report, write_report_files
from skill_sentry_cli.core.verdict.markdown_report import build_markdown
from skill_sentry_cli.core.version import (
    CLOUD_BADGE,
    GEMMA_BADGE,
    UNKNOWN_BADGE,
)
from skill_sentry_cli.server.demo_data import build_demo_store
from typer.testing import CliRunner

runner = CliRunner()
NOT_RECORDED = "analysis backend not recorded in this report"


class _CloudModel(MockGemma):
    backend = "gemini-api"


class _LocalModel(MockGemma):
    backend = "ollama"


def _verdict(name: str):
    return next(item.verdict for item in build_demo_store() if item.name == name)


def _skill(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "SKILL.md").write_text(
        f"---\nname: {root.name}\ndescription: Formats local text only.\n---\n\nHi.\n",
        encoding="utf-8",
    )
    return root


@pytest.fixture()
def engine_with(tmp_path, monkeypatch):
    """Route the CLI's engine to one built with the given model, on a temporary store."""

    def install(model) -> None:
        store = SQLiteStore(tmp_path / "scan.sqlite")
        config = SkillsEntryConfig()
        config.sandbox.enabled = False

        def make_engine(_config, _backend):
            return ScanEngine(config, store=store, model=model)

        monkeypatch.setattr(cli, "_make_engine", make_engine)
        monkeypatch.setattr(cli, "_store", lambda: SQLiteStore(tmp_path / "scan.sqlite"))

    return install


# -- the report renderers ------------------------------------------------------


def test_footer_without_a_backend_still_says_not_recorded():
    text = build_markdown(_verdict("cloud-sync-pro"))
    assert NOT_RECORDED in text
    assert "Fully local" not in text


@pytest.mark.parametrize(
    ("backend", "badge"),
    [
        ("gemini-api", CLOUD_BADGE),
        ("ollama", GEMMA_BADGE),
        ("mock", GEMMA_BADGE),
        ("unavailable", UNKNOWN_BADGE),
    ],
)
def test_footer_names_the_badge_for_the_backend_that_ran(backend, badge):
    text = build_markdown(_verdict("pdf-summarizer"), backend=backend)
    assert badge in text
    assert NOT_RECORDED not in text


def test_cloud_footer_never_claims_local_analysis():
    text = build_markdown(_verdict("cloud-sync-pro"), backend="gemini-api")
    assert "Fully local" not in text
    assert CLOUD_BADGE in text


def test_render_report_threads_the_backend_into_markdown_only():
    verdict = _verdict("pdf-summarizer")
    markdown = render_report(verdict, ExportFormat.MARKDOWN, backend="gemini-api")
    assert CLOUD_BADGE in markdown.content.decode("utf-8")
    # SARIF has no footer, so the backend must not add a privacy line to it.
    sarif = render_report(verdict, ExportFormat.SARIF, backend="gemini-api").content.decode()
    assert CLOUD_BADGE not in sarif
    assert "Cloud analysis" not in sarif


def test_write_report_files_writes_the_footer_for_the_backend(tmp_path):
    links = write_report_files(
        _verdict("cloud-sync-pro"), root=tmp_path / "out", backend="gemini-api"
    )
    text = links.markdown.read_text(encoding="utf-8")
    assert CLOUD_BADGE in text
    assert NOT_RECORDED not in text


def test_write_report_files_without_a_backend_is_unchanged(tmp_path):
    links = write_report_files(_verdict("pdf-summarizer"), root=tmp_path / "out")
    assert NOT_RECORDED in links.markdown.read_text(encoding="utf-8")


# -- the backend the engine reports ---------------------------------------------


def test_ran_backend_reads_the_selected_model():
    engine = ScanEngine(SkillsEntryConfig(), store=_NullStore(), model=_CloudModel())
    assert cli._ran_backend(engine) == "gemini-api"


def test_ran_backend_is_unavailable_when_the_engine_cannot_say():
    class Broken:
        def model_identity(self):
            raise RuntimeError("no engine")

    assert cli._ran_backend(Broken()) == "unavailable"


def test_backend_labels_cover_the_names_the_engine_reports():
    assert cli._backend_label("ollama") == "local (ollama)"
    assert cli._backend_label("gemini-api") == "cloud (gemini)"
    assert cli._backend_label("mock") == "demo/mock"
    assert cli._backend_label("auto") == "auto (local -> cloud -> unavailable)"


class _NullStore:
    def close(self) -> None:
        return None


# -- the CLI ---------------------------------------------------------------------


def test_auto_banner_names_the_cloud_backend_that_ran(tmp_path, engine_with):
    engine_with(_CloudModel())
    skill = _skill(tmp_path / "cloud-skill")
    result = runner.invoke(cli.app, ["scan", str(skill), "--no-cache"])
    assert CLOUD_BADGE in result.output
    assert "backend: cloud (gemini)" in result.output
    assert UNKNOWN_BADGE not in result.output


def test_auto_banner_names_the_local_backend_that_ran(tmp_path, engine_with):
    engine_with(_LocalModel())
    skill = _skill(tmp_path / "local-skill")
    result = runner.invoke(cli.app, ["scan", str(skill), "--no-cache"])
    assert GEMMA_BADGE in result.output
    assert "backend: local (ollama)" in result.output
    assert UNKNOWN_BADGE not in result.output


def test_banner_says_unavailable_when_no_model_ran(tmp_path, engine_with, monkeypatch):
    # No model was selected, so the scan is degraded. The banner must not claim one ran.
    monkeypatch.setattr(ScanEngine, "_get_model", lambda self: None)
    engine_with(None)
    skill = _skill(tmp_path / "no-model")
    result = runner.invoke(cli.app, ["scan", str(skill), "--no-cache"])
    assert UNKNOWN_BADGE in result.output
    assert "backend: unavailable" in result.output
    assert GEMMA_BADGE not in result.output
    assert CLOUD_BADGE not in result.output


def test_markdown_output_names_the_backend_that_ran(tmp_path, engine_with):
    engine_with(_CloudModel())
    skill = _skill(tmp_path / "md-skill")
    result = runner.invoke(cli.app, ["scan", str(skill), "--no-cache", "--format", "markdown"])
    assert CLOUD_BADGE in result.output
    assert NOT_RECORDED not in result.output


def test_report_dir_files_name_the_backend_that_ran(tmp_path, engine_with):
    engine_with(_CloudModel())
    skill = _skill(tmp_path / "dir-skill")
    reports = tmp_path / "reports"
    result = runner.invoke(
        cli.app, ["scan", str(skill), "--no-cache", "--report-dir", str(reports)]
    )
    assert result.exit_code in {0, 1}, result.output
    written = [path for path in reports.glob("*.md") if path.name != "summary.md"]
    assert written, result.output
    text = written[0].read_text(encoding="utf-8")
    assert CLOUD_BADGE in text
    assert NOT_RECORDED not in text


def test_export_of_a_stored_scan_names_the_backend_it_ran_with(tmp_path, engine_with):
    engine_with(_CloudModel())
    skill = _skill(tmp_path / "export-skill")
    scanned = runner.invoke(cli.app, ["scan", str(skill), "--no-cache", "--format", "json"])
    scan_id = json.loads(scanned.output)["scanId"]

    exported = runner.invoke(cli.app, ["export", scan_id, "--format", "markdown"])
    assert exported.exit_code == 0, exported.output
    assert CLOUD_BADGE in exported.output
    assert NOT_RECORDED not in exported.output


def test_demo_markdown_keeps_the_not_recorded_footer(monkeypatch):
    # The canned demo store is not an analysis, so its footer must not name a backend.
    monkeypatch.setenv("SKILLSENTRY_DEV", "1")
    result = runner.invoke(
        cli.app, ["scan", "pdf-summarizer", "--demo-mode", "--format", "markdown"]
    )
    assert NOT_RECORDED in result.output
    assert GEMMA_BADGE not in result.output
