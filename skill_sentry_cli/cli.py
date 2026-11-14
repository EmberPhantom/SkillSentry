"""``skill-sentry-cli`` command-line interface.

``serve`` (demo + live), ``init``, live ``scan``, and ``self-audit``.  Demo
mode remains a separate, explicitly labelled path; live scans always go through
the real :class:`ScanEngine`.
"""

from __future__ import annotations

import contextlib
import json
import os
import subprocess
import sys
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TextIO
from uuid import UUID

import click
import typer

from skill_sentry_cli.core.cache import SQLiteStore
from skill_sentry_cli.core.config import (
    DISCOVERY_AGENTS,
    ConfigError,
    SkillsEntryConfig,
    ensure_private_dir,
    load_config,
    reports_dir,
    write_default_config,
)
from skill_sentry_cli.core.contracts import ExportFormat, ScanOptions, Verdict, VerdictTier
from skill_sentry_cli.core.discovery import (
    DiscoveryResult,
    InstalledSkill,
    discover_installed,
)
from skill_sentry_cli.core.engine import ScanEngine, ScanError, ScanOutcome
from skill_sentry_cli.core.exit_codes import ExitCode
from skill_sentry_cli.core.models.gemma_local import ProbeResult
from skill_sentry_cli.core.models.mock import MockGemma
from skill_sentry_cli.core.reports import render_report
from skill_sentry_cli.core.verdict.status import (
    INVALID,
    degraded_reason,
    invalid_reason,
    is_invalid,
    is_unscanned,
    shown_status,
)
from skill_sentry_cli.core.version import __version__, badge_for_backend
from skill_sentry_cli.server.demo_data import build_demo_store


def _configure_stdio() -> None:
    """Make CLI banners safe on legacy Windows consoles and redirected output."""

    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        with contextlib.suppress(OSError, ValueError):
            reconfigure(encoding="utf-8", errors="replace")


_configure_stdio()

app = typer.Typer(
    name="skill-sentry-cli",
    help="Audit AI Agent Skills before installation - fully local.",
    no_args_is_help=True,
    add_completion=False,
)

_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
_FAIL_ON = {"safe", "suspicious", "malicious"}
_RANK = {VerdictTier.SAFE: 0, VerdictTier.SUSPICIOUS: 1, VerdictTier.MALICIOUS: 2}
_FORMATS = {"text", "json", "sarif", "markdown"}
_BACKENDS = {"auto", "local", "cloud", "demo"}
_SAVE_REPORT_CHOICES = {"markdown", "sarif", "none"}
# Formats that --save-report (or the prompt) can write. "none" writes nothing.
_SAVE_NOW = {"markdown", "sarif"}
_AGENT_LABELS = {
    "claude": "Claude Code",
    "codex": "Codex",
    "agents": "Shared agents",
    "gemini": "Gemini",
    "cursor": "Cursor",
    "opencode": "OpenCode",
    "copilot": "Copilot",
    "custom": "Custom path",
}
_SCAN_TIP = "Tip: run `skill-sentry-cli scan` with no path to check everything installed."
# Discovery note for an extra_paths entry (or a configured location) that is not a folder.
_MISSING_EXTRA_PATH = "custom path not found"


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"SkillSentry {__version__}")
        raise typer.Exit(code=int(ExitCode.OK))


@app.callback()
def main(
    version: bool = typer.Option(
        False,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Show the version and exit.",
    ),
) -> None:
    """SkillSentry - a context-aware firewall for the Agent Skill supply chain."""
    del version


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", help="Bind address (loopback only by default)."),
    port: int = typer.Option(8000, min=1, max=65535),
    demo_mode: bool = typer.Option(False, "--demo-mode", help="Serve the canned 7-skill store."),
    speed: float = typer.Option(1.0, min=0.0, help="Demo WS replay speed (0 = instant)."),
) -> None:
    """Run the FastAPI server and dashboard."""
    import uvicorn

    # The API has no authentication. Warn when it is reachable from other machines, unless
    # the official container set SKILLSENTRY_CONTAINER, where publishing is the operator's job.
    if host not in _LOOPBACK_HOSTS and not os.getenv("SKILLSENTRY_CONTAINER"):
        typer.echo(
            f"warning: binding to {host} exposes the API, which has no authentication. "
            "Anyone who can reach this port can read scans and start new ones. Keep the "
            "default 127.0.0.1, or put the server behind an authenticating proxy. "
            "See docs/operations/deployment.md.",
            err=True,
        )

    if demo_mode:
        from skill_sentry_cli.server.demo_mode import create_demo_app

        typer.echo(f"SkillSentry {__version__} - demo mode - http://{host}:{port}")
        uvicorn.run(create_demo_app(speed=speed, bind_host=host), host=host, port=port)
        return

    from skill_sentry_cli.server.app import create_app
    from skill_sentry_cli.server.live_backend import LiveBackend

    typer.echo(f"SkillSentry {__version__} - live mode - http://{host}:{port}")
    uvicorn.run(create_app(LiveBackend(), bind_host=host), host=host, port=port)


@app.command()
def init(
    path: Path = typer.Option(
        Path("skillsentry.toml"), "--path", help="Where to write the config."
    ),
    force: bool = typer.Option(False, "--force", help="Overwrite an existing file."),
) -> None:
    """Write a documented ``skillsentry.toml``."""
    try:
        written = write_default_config(path, force=force)
    except ConfigError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=int(ExitCode.USAGE)) from exc
    except OSError as exc:
        typer.echo(f"error: could not write {path}: {exc.strerror or exc}", err=True)
        raise typer.Exit(code=int(ExitCode.OPERATIONAL)) from exc
    typer.echo(f"wrote {written}")


@app.command()
def scan(
    path: Path | None = typer.Argument(
        None,
        help="Skill directory, or a folder containing skills. Omit to scan every installed skill.",
    ),
    demo_mode: bool = typer.Option(False, "--demo-mode", help="Use the canned demo store."),
    output_format: str = typer.Option("text", "--format", help="text | json | sarif | markdown"),
    fail_on: str = typer.Option("suspicious", "--fail-on", help="safe | suspicious | malicious"),
    quiet: bool = typer.Option(False, "-q", "--quiet", help="Verdict line only."),
    no_cache: bool = typer.Option(False, "--no-cache", help="Bypass the verdict cache."),
    sandbox: bool = typer.Option(
        True, "--sandbox/--no-sandbox", help="Execute the skill in Docker when available."
    ),
    backend: str = typer.Option(
        "auto", "--backend", help="Model backend: auto | local | cloud | demo"
    ),
    timeout_s: int = typer.Option(
        60, "--timeout", min=5, max=600, help="Sandbox timeout (seconds)."
    ),
    output: Path | None = typer.Option(
        None, "--output", help="Write the rendered report to a file."
    ),
    sarif_out: Path | None = typer.Option(
        None, "--sarif-out", help="Write a SARIF 2.1.0 report to a file."
    ),
    report_dir: Path | None = typer.Option(
        None,
        "--report-dir",
        help="Write one Markdown report per skill, plus summary.md for folders.",
    ),
    recursive: bool = typer.Option(
        False,
        "--recursive",
        help="Scan skills nested inside a skill folder too (default: only the folder itself).",
    ),
    project: Path | None = typer.Option(
        None,
        "--project",
        help="Project folder whose skills are included. Without a path only. "
        "Default: the current directory.",
    ),
    agent: list[str] | None = typer.Option(
        None,
        "--agent",
        help="Scan only this agent's skills (repeatable). Without a path only. "
        f"One of: {' | '.join(sorted(DISCOVERY_AGENTS))}.",
    ),
    include_experimental: bool = typer.Option(
        False,
        "--include-experimental",
        help="Also look in the experimental agent locations. Without a path only.",
    ),
    save_report: str | None = typer.Option(
        None,
        "--save-report",
        help="Save a combined report: markdown | sarif | none. Skips the question.",
    ),
    no_prompt: bool = typer.Option(
        False, "--no-prompt", help="Never ask whether to save a report."
    ),
) -> None:
    """Audit one skill directory or a folder of skills. With no path, audit every installed skill."""

    if output_format not in _FORMATS:
        typer.echo(f"error: unsupported --format {output_format!r}", err=True)
        raise typer.Exit(code=int(ExitCode.USAGE))
    if fail_on not in _FAIL_ON:
        typer.echo(f"error: unsupported --fail-on {fail_on!r}", err=True)
        raise typer.Exit(code=int(ExitCode.USAGE))
    if backend not in _BACKENDS:
        typer.echo(f"error: unsupported --backend {backend!r}", err=True)
        raise typer.Exit(code=int(ExitCode.USAGE))
    if save_report is not None and save_report not in _SAVE_REPORT_CHOICES:
        typer.echo(f"error: unsupported --save-report {save_report!r}", err=True)
        raise typer.Exit(code=int(ExitCode.USAGE))
    _refuse_mock_backend(backend)

    if path is None:
        unsupported = [
            flag
            for flag, given in (
                ("--output", output is not None),
                ("--sarif-out", sarif_out is not None),
                ("--report-dir", report_dir is not None),
                ("--recursive", recursive),
            )
            if given
        ]
        if unsupported:
            typer.echo(
                f"error: {', '.join(unsupported)} apply only when scanning a skill path. "
                "With no path use --save-report to keep a report.",
                err=True,
            )
            raise typer.Exit(code=int(ExitCode.USAGE))
        if demo_mode:
            typer.echo(
                "error: --demo-mode needs a skill path; it cannot scan installed skills.",
                err=True,
            )
            raise typer.Exit(code=int(ExitCode.USAGE))
        _scan_installed(
            project=project,
            agents=agent or [],
            include_experimental=include_experimental,
            save_report=save_report,
            no_prompt=no_prompt,
            output_format=output_format,
            quiet=quiet,
            fail_on=fail_on,
            no_cache=no_cache,
            sandbox=sandbox,
            backend=backend,
            timeout_s=timeout_s,
        )
        return
    if project is not None or agent or include_experimental:
        typer.echo(
            "error: --project, --agent and --include-experimental apply only when scanning "
            "installed skills. Leave out the path to use them.",
            err=True,
        )
        raise typer.Exit(code=int(ExitCode.USAGE))

    if demo_mode:
        # The canned store is keyed by directory name. Nothing under PATH is read, so a
        # hostile folder that happens to share a demo name gets the canned verdict.
        typer.echo(
            "WARNING: --demo-mode did not scan this path. The verdict below is a canned "
            "result looked up by the directory name; the files were never read. "
            "Run without --demo-mode before any install decision.",
            err=True,
        )
        verdict = _demo_verdict_for(path)
        if sarif_out is not None:
            _write_file(
                sarif_out, render_report(verdict, ExportFormat.SARIF).content.decode("utf-8")
            )
            if not quiet and output_format == "text":
                typer.echo(f"wrote {sarif_out}")
        rendered = _render_verdict(
            verdict, output_format=output_format, quiet=quiet, backend="demo"
        )
        if output is not None:
            _write_file(output, rendered)
            if output_format == "text":
                typer.echo(rendered.rstrip())
        else:
            typer.echo(rendered.rstrip())
        if _should_fail(verdict, fail_on):
            raise typer.Exit(code=int(ExitCode.VERDICT))
        raise typer.Exit(code=int(ExitCode.OK))

    try:
        config = _config_for_backend(backend)
    except ConfigError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=int(ExitCode.USAGE)) from exc

    engine = _make_engine(config, backend)
    try:
        roots = engine.discover(path, recursive=recursive)
        nested = 0 if recursive else len(engine.discover(path, recursive=True)) - len(roots)
    except ScanError as exc:
        typer.echo(f"error: {exc}", err=True)
        typer.echo(f"hint: {_scan_error_hint(exc)}", err=True)
        raise typer.Exit(code=int(ExitCode.OPERATIONAL)) from exc
    if output_format == "text" and not quiet:
        typer.echo(_scope_line(path, roots))
        if nested > 0:
            typer.echo(
                f"   Warning: {path} is a skill itself; its {nested} nested skill(s) were not "
                "scanned. Pass --recursive to scan them, or scan a subfolder.",
                err=True,
            )

    options = ScanOptions(
        no_cache=no_cache,
        backend=backend,
        sandbox=sandbox,
        timeout_s=timeout_s,
    )
    outcomes, _, failed = _scan_roots(
        engine, roots, options=options, output_format=output_format, quiet=quiet
    )
    # Resolve the backend that ran before the engine is closed. `auto` is only a request.
    ran_backend = _ran_backend(engine) if outcomes else backend
    engine.close()

    if not outcomes:
        raise typer.Exit(code=int(ExitCode.OPERATIONAL))

    # The tip is for a person at a terminal. Piped or redirected runs get no extra line.
    if output_format == "text" and not quiet and _stream_is_tty(sys.stderr):
        typer.echo(_SCAN_TIP, err=True)
    footer = None
    if output is None and report_dir is None:
        footer = _report_footer(path, outcomes)
    skipped = len(roots) - len(outcomes)
    _emit_outcomes(
        outcomes,
        output_format=output_format,
        quiet=quiet,
        backend=ran_backend,
        output=output,
        sarif_out=sarif_out,
        skipped=skipped,
        footer=footer,
    )
    if report_dir is not None:
        _write_report_dir(
            report_dir,
            outcomes,
            skipped=skipped,
            backend=ran_backend,
        )
        if output_format == "text" and not quiet:
            typer.echo(f"wrote {len(outcomes)} report(s) to {report_dir}")
    if save_report in _SAVE_NOW:
        _save_reports_now(
            save_report,
            outcomes,
            skipped=skipped,
            backend=ran_backend,
            announce=output_format == "text" and not quiet,
        )
    if failed:
        raise typer.Exit(code=int(ExitCode.OPERATIONAL))
    if any(_should_fail(outcome.verdict, fail_on) for outcome in outcomes):
        raise typer.Exit(code=int(ExitCode.VERDICT))
    raise typer.Exit(code=int(ExitCode.OK))


@app.command("discover")
def discover(
    project: Path | None = typer.Option(
        None,
        "--project",
        help="Project folder whose skills are included. Default: the current directory.",
    ),
    agent: list[str] | None = typer.Option(
        None, "--agent", help="List only this agent's skills (repeatable)."
    ),
    include_experimental: bool = typer.Option(
        False, "--include-experimental", help="Also look in the experimental agent locations."
    ),
    output_format: str = typer.Option("text", "--format", help="text | json"),
) -> None:
    """List the installed skills that `scan` with no path would check. Scans nothing."""

    if output_format not in {"text", "json"}:
        typer.echo(f"error: unsupported --format {output_format!r}", err=True)
        raise typer.Exit(code=int(ExitCode.USAGE))
    config = _load_config_or_exit()
    result = _discover_with_options(
        config,
        project=project,
        agents=agent or [],
        include_experimental=include_experimental,
    )
    if output_format == "json":
        typer.echo(json.dumps(_discovery_payload(result), indent=2, ensure_ascii=False))
    else:
        _print_discovery_text(result)
    raise typer.Exit(code=int(ExitCode.OK))


@app.command("self-audit")
def self_audit(
    output_format: str = typer.Option("text", "--format", help="text | json | sarif | markdown"),
    fail_on: str = typer.Option("suspicious", "--fail-on", help="safe | suspicious | malicious"),
    quiet: bool = typer.Option(False, "-q", "--quiet", help="Verdict line only."),
    no_cache: bool = typer.Option(False, "--no-cache", help="Bypass the verdict cache."),
    sandbox: bool = typer.Option(True, "--sandbox/--no-sandbox"),
    backend: str = typer.Option("auto", "--backend", help="auto | local | cloud | demo"),
    timeout_s: int = typer.Option(60, "--timeout", min=5, max=600),
) -> None:
    """Audit SkillSentry's own bundled Agent Skill."""

    if output_format not in _FORMATS or fail_on not in _FAIL_ON or backend not in _BACKENDS:
        typer.echo("error: invalid self-audit option", err=True)
        raise typer.Exit(code=int(ExitCode.USAGE))
    _refuse_mock_backend(backend)
    skill_dir = Path(__file__).parent / "skill"
    if output_format == "text" and not quiet:
        typer.echo(f"Scanning {skill_dir}...")
    try:
        config = _config_for_backend(backend)
        engine = _make_engine(config, backend)
        outcome = engine.scan(
            skill_dir,
            options=ScanOptions(
                no_cache=no_cache,
                backend=backend,
                sandbox=sandbox,
                timeout_s=timeout_s,
            ),
        )
        ran_backend = _ran_backend(engine)
        engine.close()
    except (ConfigError, ScanError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=int(ExitCode.OPERATIONAL)) from exc
    _print_verdict(outcome.verdict, output_format=output_format, quiet=quiet, backend=ran_backend)
    if _should_fail(outcome.verdict, fail_on):
        raise typer.Exit(code=int(ExitCode.VERDICT))
    raise typer.Exit(code=int(ExitCode.OK))


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _refuse_mock_backend(backend: str) -> None:
    """``--backend demo`` runs the deterministic mock model; it never produces a real verdict."""

    if backend == "demo" and os.getenv("SKILLSENTRY_DEV") != "1":
        typer.echo(
            "error: --backend demo runs the mock model and is refused for real scans. "
            "Use --demo-mode for the canned store, or set SKILLSENTRY_DEV=1 for development.",
            err=True,
        )
        raise typer.Exit(code=int(ExitCode.USAGE))


def _load_config_or_exit() -> SkillsEntryConfig:
    """Load the configuration; a bad file is a usage error with a message, not a traceback."""

    try:
        return load_config()
    except ConfigError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=int(ExitCode.USAGE)) from exc


def _config_for_backend(backend: str) -> SkillsEntryConfig:
    config = _load_config_or_exit()
    if backend == "auto":
        return config
    config = config.model_copy(deep=True)
    config.model.backend = backend
    return config


def _make_engine(config: SkillsEntryConfig, backend: str) -> ScanEngine:
    model = MockGemma() if backend == "demo" else None
    return ScanEngine(config, model=model)


def _demo_verdict_for(path: Path) -> Verdict:
    name = path.name.lower()
    for item in build_demo_store():
        if item.name == name:
            return item.verdict
    typer.echo(
        f"error: demo store has no skill named {name!r}. "
        "Available: " + ", ".join(item.name for item in build_demo_store()),
        err=True,
    )
    raise typer.Exit(code=int(ExitCode.USAGE))


def _outcome_status(outcome: ScanOutcome) -> str:
    return shown_status(outcome.verdict.verdict, outcome.stage_results)


def _folder_summary(outcomes: list[ScanOutcome], skipped: int) -> str:
    counts = Counter(_outcome_status(outcome) for outcome in outcomes)
    tiers = [tier.value for tier in VerdictTier] + ["UNSCANNED"]
    if counts.get(INVALID):
        # Shown only when present, so the usual summary line does not change.
        tiers.insert(len(VerdictTier), INVALID)
    parts = ", ".join(f"{counts.get(tier, 0)} {tier}" for tier in tiers)
    line = f"Summary: {len(outcomes)} scanned - {parts}"
    return f"{line}, {skipped} failed" if skipped else line


def _md_cell(value: object) -> str:
    return str(value).replace("|", "\\|")


def _folder_summary_table(
    outcomes: list[ScanOutcome],
    skipped: int,
    installs: Sequence[InstalledSkill] | None = None,
) -> str:
    if installs is None:
        rows = [
            f"| {outcome.verdict.skill} | {_outcome_status(outcome)} | {outcome.verdict.risk_score} |"
            for outcome in outcomes
        ]
        header = ["| Skill | Verdict | Risk |", "|:---|:---|---:|"]
    else:
        # The no-path flow adds where each skill was found. Pipes in a path are escaped
        # so they cannot split the row.
        rows = [
            f"| {outcome.verdict.skill} | {_outcome_status(outcome)} | "
            f"{outcome.verdict.risk_score} | {_AGENT_LABELS.get(install.agent, install.agent)} | "
            f"{install.scope} | {_md_cell(install.declared_path)} |"
            for outcome, install in zip(outcomes, installs, strict=True)
        ]
        header = [
            "| Skill | Verdict | Risk | Agent | Scope | Path |",
            "|:---|:---|---:|:---|:---|:---|",
        ]
    lines = [
        "# SkillSentry folder summary",
        "",
        _folder_summary(outcomes, skipped),
        "",
        *header,
        *rows,
    ]
    return "\n".join(lines)


def _write_file(path: Path, text: str) -> None:
    """Write a UTF-8 report or config; an unwritable path is an operational error, not a crash."""

    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    except OSError as exc:
        typer.echo(f"error: could not write {path}: {exc.strerror or exc}", err=True)
        raise typer.Exit(code=int(ExitCode.OPERATIONAL)) from exc


def _emit_outcomes(
    outcomes: list[ScanOutcome],
    *,
    output_format: str,
    quiet: bool,
    backend: str,
    output: Path | None,
    sarif_out: Path | None,
    skipped: int = 0,
    footer: str | None = None,
    installs: Sequence[InstalledSkill] | None = None,
    notes: Sequence[str] = (),
) -> None:
    """Render the run. ``installs`` (one per outcome, no-path flow only) adds where each
    skill was found; ``notes`` are the discovery notes for that run."""
    if sarif_out is not None:
        _write_file(sarif_out, _combined_sarif(outcomes))
        if not quiet and output_format == "text":
            typer.echo(f"wrote {sarif_out}")

    if output_format == "json":
        entries = [outcome.verdict.model_dump(by_alias=True, mode="json") for outcome in outcomes]
        if installs is not None:
            for entry, install in zip(entries, installs, strict=True):
                entry["install"] = _install_payload(install)
                entry["notes"] = list(notes)
        payload: object = entries[0] if len(entries) == 1 else entries
        rendered = json.dumps(payload, indent=2, ensure_ascii=False)
    elif output_format == "sarif":
        rendered = _combined_sarif(outcomes, installs)
    elif output_format == "markdown":
        reports = [
            render_report(
                outcome.verdict,
                ExportFormat.MARKDOWN,
                stage_results=outcome.stage_results,
                backend=backend,
            ).content.decode("utf-8")
            for outcome in outcomes
        ]
        if len(outcomes) > 1:
            reports.insert(0, _folder_summary_table(outcomes, skipped, installs))
        rendered = "\n\n---\n\n".join(reports)
    else:
        # One banner for the whole run, not one per skill.
        lines = []
        for index, outcome in enumerate(outcomes):
            line = _verdict_text(outcome, quiet=True, backend=backend)
            location = _installed_location(installs[index]) if installs is not None else None
            if location and not quiet:
                line += f"\n   installed at {location}"
            lines.append(line)
        if not quiet:
            lines.insert(0, _banner(backend))
            if footer is not None:
                lines.append(footer)
        if len(outcomes) > 1 and not quiet:
            lines.append(_folder_summary(outcomes, skipped))
        rendered = "\n".join(lines)

    if output is not None:
        _write_file(output, rendered)
        if output_format == "text":
            typer.echo(rendered.rstrip())
        return
    typer.echo(rendered.rstrip())


def _scope_line(path: Path, roots: list[Path]) -> str:
    if len(roots) == 1 and roots[0] == path.expanduser():
        return f"Scanning 1 skill: {path}"
    return f"Scanning {len(roots)} skill(s) under {path}"


def _report_footer(path: Path, outcomes: list[ScanOutcome]) -> str:
    """Say where the report is, with the command that writes it to a file."""
    if len(outcomes) == 1:
        scan_id = outcomes[0].scan_id
        return f"Report: skill-sentry-cli export {scan_id} --format markdown -o report.md"
    return (
        f"Reports: skill-sentry-cli scan {path} --report-dir reports\n"
        "Scan IDs are listed by: skill-sentry-cli cache list"
    )


def _write_report_dir(
    directory: Path,
    outcomes: list[ScanOutcome],
    *,
    skipped: int,
    backend: str | None = None,
    installs: Sequence[InstalledSkill] | None = None,
) -> None:
    for outcome in outcomes:
        name = f"{outcome.verdict.skill}-{outcome.scan_id}.md"
        rendered = render_report(
            outcome.verdict,
            ExportFormat.MARKDOWN,
            stage_results=outcome.stage_results,
            backend=backend,
        ).content.decode("utf-8")
        _write_file(directory / name, rendered)
    if len(outcomes) > 1:
        _write_file(directory / "summary.md", _folder_summary_table(outcomes, skipped, installs))


def _scan_error_hint(exc: ScanError) -> str:
    hints = {
        "no_skill_manifest": "point at a folder that contains SKILL.md, or a folder of skills.",
        "too_many_skills": "scan a smaller folder, or scan the skill folders one at a time.",
    }
    return hints.get(exc.code, "run `skill-sentry-cli doctor` to check the setup.")


def _install_payload(skill: InstalledSkill) -> dict[str, object]:
    """Where an installed skill was found. Paths are full, never shortened with ``~``."""
    return {
        "agent": skill.agent,
        "scope": skill.scope,
        "declared_path": str(skill.declared_path),
        "real_path": str(skill.real_path),
        "is_symlink": skill.is_symlink,
        "aliases": [str(alias) for alias in skill.aliases],
    }


def _installed_location(skill: InstalledSkill) -> str | None:
    """The declared path shown as ``~``, when it differs from the real path (a symlink)."""
    return _tilde(skill.declared_path) if skill.declared_path != skill.real_path else None


def _tag_sarif_run(run: dict[str, Any], install: InstalledSkill) -> None:
    """Add where a skill was found to one SARIF run and its results.

    Each result's artifact location becomes the real path of the file it points at.
    """
    declared = str(install.declared_path)
    real = install.real_path.as_uri()  # a file URI; valid on every platform
    context = {"declaredPath": declared, "agent": install.agent, "scope": install.scope}
    run.setdefault("properties", {}).update(context)
    for result in run.get("results", []):
        result.setdefault("properties", {}).update(context)
        for location in result.get("locations", []):
            artifact = location["physicalLocation"]["artifactLocation"]
            # The stored uri is relative to the skill folder; join it onto the real path.
            artifact["uri"] = f"{real}/{artifact['uri']}"


def _combined_sarif(
    outcomes: list[ScanOutcome], installs: Sequence[InstalledSkill] | None = None
) -> str:
    """One SARIF document for the run. ``installs`` (no-path flow) tags each run with where
    its skill was found; without it the output is unchanged."""
    if len(outcomes) == 1 and installs is None:
        return render_report(outcomes[0].verdict, ExportFormat.SARIF).content.decode("utf-8")
    runs = []
    for index, outcome in enumerate(outcomes):
        payload = json.loads(
            render_report(outcome.verdict, ExportFormat.SARIF).content.decode("utf-8")
        )
        for run in payload.get("runs", []):
            if installs is not None:
                _tag_sarif_run(run, installs[index])
            runs.append(run)
    return json.dumps(
        {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": runs,
        },
        indent=2,
        ensure_ascii=False,
    )


def _verdict_text(outcome: ScanOutcome, *, quiet: bool, backend: str) -> str:
    verdict = outcome.verdict
    lines: list[str] = []
    if not quiet:
        lines.append(_banner(backend))
    cache = " (cached)" if verdict.cached else ""
    invalid = not is_unscanned(verdict.verdict, outcome.stage_results) and is_invalid(
        verdict.verdict, outcome.stage_results
    )
    if is_unscanned(verdict.verdict, outcome.stage_results):
        lines.append(
            f"[?] {verdict.skill} - UNSCANNED (verdict {verdict.verdict.value}, "
            f"risk {verdict.risk_score}) - {degraded_reason(outcome.stage_results)}{cache}"
        )
    elif invalid:
        reason = invalid_reason(outcome.stage_results)
        lines.append(f"[?] {verdict.skill} - {INVALID} - {reason}{cache}")
        lines.append(
            "   Fix the SKILL.md frontmatter, then scan again. This is not a malware finding."
        )
    else:
        icon = {"SAFE": "[OK]", "SUSPICIOUS": "[!]", "MALICIOUS": "[X]"}[verdict.verdict.value]
        lines.append(
            f"{icon} {verdict.skill} - {verdict.verdict.value} - "
            f"risk {verdict.risk_score} - confidence {verdict.confidence:.2f}{cache}"
        )
    finding = verdict.key_finding
    if not invalid and finding is not None and finding.severity.value not in {"note"}:
        location = ""
        if finding.evidence.file:
            location = f" ({finding.evidence.file}"
            if finding.evidence.line:
                location += f":{finding.evidence.line}"
            location += ")"
        lines.append(f"   {finding.message}{location}")
    active = verdict.active_defense
    if active is not None and active.triggered:
        channel = active.exfil_channel.value if active.exfil_channel else "egress"
        lines.append(
            f"   Poisoned Well: {channel} -> "
            f"{', '.join(active.c2_indicators) or 'unknown'} (marker {active.canary_marker})"
        )
    return "\n".join(lines)


def _banner(backend: str) -> str:
    return (
        f"SkillSentry {__version__} - {badge_for_backend(backend)} - "
        f"backend: {_backend_label(backend)}"
    )


def _ran_backend(engine: ScanEngine) -> str:
    """The analysis backend that produced the verdicts, as the engine selected it.

    ``--backend auto`` is a request, not a result. The engine memoises its model choice,
    so asking it after the scan names the model that ran without probing again.
    """
    try:
        backend, _model_version = engine.model_identity()
    except Exception:
        # The banner and report are presentation. A failure here must not fail a scan that
        # already finished, so the backend is reported as unknown.
        return "unavailable"
    return backend


def _backend_label(backend: str) -> str:
    return {
        "auto": "auto (local -> cloud -> unavailable)",
        "local": "local (ollama)",
        "ollama": "local (ollama)",
        "cloud": "cloud (gemini)",
        "gemini-api": "cloud (gemini)",
        "demo": "demo/mock",
        "mock": "demo/mock",
        "unavailable": "unavailable (no model ran)",
    }.get(backend, backend)


def _render_verdict(
    verdict: Verdict,
    *,
    output_format: str,
    quiet: bool,
    backend: str = "demo",
) -> str:
    if output_format == "json":
        return verdict.model_dump_json(by_alias=True, indent=2)
    if output_format == "sarif":
        return render_report(verdict, ExportFormat.SARIF).content.decode("utf-8")
    if output_format == "markdown":
        # The demo store is canned, so its report names no analysis backend.
        ran = None if backend == "demo" else backend
        return render_report(verdict, ExportFormat.MARKDOWN, backend=ran).content.decode("utf-8")
    outcome = ScanOutcome(
        scan_id=verdict.scan_id,
        skill_id=verdict.skill_id,
        skill_name=verdict.skill,
        verdict=verdict,
        detail=None,  # type: ignore[arg-type]
        stage_results=[],
        cached=verdict.cached,
        started_at=None,  # type: ignore[arg-type]
        duration_ms=verdict.scan_duration_ms,
    )
    return _verdict_text(outcome, quiet=quiet, backend=backend)


def _print_verdict(
    verdict: Verdict,
    *,
    output_format: str,
    quiet: bool,
    backend: str = "demo",
) -> None:
    typer.echo(
        _render_verdict(verdict, output_format=output_format, quiet=quiet, backend=backend).rstrip()
    )


def _should_fail(verdict: Verdict, fail_on: str) -> bool:
    rank = _RANK[verdict.verdict]
    if fail_on == "safe":
        return rank > 0
    if fail_on == "suspicious":
        return rank >= 1
    return rank >= 2


cache_app = typer.Typer(help="Inspect and clear the local verdict cache.", no_args_is_help=True)
app.add_typer(cache_app, name="cache")


def _store() -> SQLiteStore:
    return SQLiteStore(_load_config_or_exit().db_path)


@cache_app.command("stats")
def cache_stats() -> None:
    """Show the number of cached verdicts and the database size."""

    with contextlib.closing(_store()) as store:
        entries, hit_rate = store.cache_stats()
        db_path = Path(str(store.path))
    size_bytes = db_path.stat().st_size if db_path.is_file() else 0
    typer.echo(f"entries: {entries}")
    typer.echo(f"size_bytes: {size_bytes}")
    typer.echo(f"hit_rate: {hit_rate:.3f}")


@cache_app.command("list")
def cache_list(
    limit: int = typer.Option(20, "--limit", min=1, max=500, help="Rows to show."),
) -> None:
    """List the most recent scans and their verdicts."""

    with contextlib.closing(_store()) as store:
        rows = store.list_scans(limit=limit)
    if not rows:
        typer.echo("no scans recorded")
        return
    for row in rows:
        status = getattr(row.get("status"), "value", row.get("status"))
        verdict = getattr(row.get("verdict"), "value", row.get("verdict"))
        typer.echo(f"{row.get('scan_id')}  {row.get('skill')}  {status}  {verdict or '-'}")


@cache_app.command("clear")
def cache_clear(
    older_than: str | None = typer.Option(
        None, "--older-than", help="Only remove entries older than this, e.g. 7d or 12h."
    ),
) -> None:
    """Remove cached verdicts, optionally only those older than a given age."""

    with contextlib.closing(_store()) as store:
        try:
            deleted, retained = store.clear_cache(older_than)
        except ValueError as exc:
            typer.echo(f"error: {exc}", err=True)
            raise typer.Exit(code=int(ExitCode.USAGE)) from exc
    typer.echo(f"deleted: {deleted}  retained: {retained}")


@app.command("export")
def export_report(
    scan_id: str = typer.Argument(..., help="Scan ID printed by `scan` or `cache list`."),
    fmt: str = typer.Option("markdown", "--format", help="sarif | markdown | stix"),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write to a file."),
) -> None:
    """Re-render the report of a stored scan without re-running it."""

    formats = {
        "sarif": ExportFormat.SARIF,
        "markdown": ExportFormat.MARKDOWN,
        "stix": ExportFormat.STIX,
    }
    if fmt not in formats:
        typer.echo(f"error: unsupported --format {fmt!r}", err=True)
        raise typer.Exit(code=int(ExitCode.USAGE))
    try:
        parsed = UUID(scan_id)
    except ValueError as exc:
        typer.echo(f"error: {scan_id!r} is not a scan ID", err=True)
        raise typer.Exit(code=int(ExitCode.USAGE)) from exc
    with contextlib.closing(_store()) as store:
        stored = store.get_result(parsed)
        record = store.get_scan(parsed) if stored is not None else None
    if stored is None:
        typer.echo(f"error: no stored scan {scan_id}", err=True)
        raise typer.Exit(code=int(ExitCode.USAGE))
    verdict, _detail, stages, _cached = stored
    # The scan history records the backend that ran for this scan.
    ran = record.backend if record is not None else None
    rendered = render_report(
        verdict, formats[fmt], stage_results=stages, backend=ran
    ).content.decode("utf-8")
    if output is None:
        typer.echo(rendered.rstrip())
    else:
        _write_file(output, rendered)
        typer.echo(f"wrote {output}")


@dataclass(frozen=True)
class ReadinessCheck:
    name: str
    ok: bool
    required: bool
    detail: str


def readiness_checks(cfg: SkillsEntryConfig) -> list[ReadinessCheck]:
    """What a full scan needs on this machine.  Used by ``doctor`` and ``setup``.

    Required checks must pass for a full scan.  Docker and the sandbox image are
    optional: without them, scans run with --no-sandbox and the sandbox stage
    reports itself as degraded.
    """

    from skill_sentry_cli.core.models.gemma_local import GemmaLocal
    from skill_sentry_cli.server.app import _default_ui_dist

    checks: list[ReadinessCheck] = []
    probe_error: str | None = None
    try:
        model = GemmaLocal(base_url=cfg.model.ollama_url, model=cfg.model.ollama_model)
        try:
            probe = model.probe()
        finally:
            model.close()
    except Exception as exc:  # any probe failure is a finding, not a crash
        probe = ProbeResult.UNREACHABLE
        probe_error = type(exc).__name__
    if probe == ProbeResult.READY:
        model_detail = f"{cfg.model.ollama_model} is pulled"
    elif probe == ProbeResult.NO_MODEL:
        model_detail = (
            f"{cfg.model.ollama_model} is not pulled; run: ollama pull {cfg.model.ollama_model}"
        )
    else:
        cause = f" ({probe_error})" if probe_error else ""
        model_detail = f"cannot reach the model server at {cfg.model.ollama_url}{cause}"
    checks.append(ReadinessCheck("model", probe == ProbeResult.READY, True, model_detail))

    ui_index = _default_ui_dist() / "index.html"
    checks.append(
        ReadinessCheck(
            "dashboard",
            ui_index.is_file(),
            True,
            "built" if ui_index.is_file() else "not built; run scripts/build_release.sh",
        )
    )

    try:
        with contextlib.closing(_store()):
            db_ok = True
        db_detail = f"writable at {cfg.db_path}"
    except Exception as exc:
        db_ok = False
        db_detail = f"cannot open {cfg.db_path}: {exc}"
    checks.append(ReadinessCheck("database", db_ok, True, db_detail))

    checks.extend(_docker_checks(cfg))
    checks.append(_platform_check())
    return checks


def detect_platform() -> str:
    """Windows, macOS, WSL, or Linux.  WSL is Linux running under Windows."""
    if sys.platform == "win32":
        return "Windows"
    if sys.platform == "darwin":
        return "macOS"
    try:
        kernel = Path("/proc/version").read_text(encoding="utf-8", errors="replace").lower()
    except OSError:
        kernel = ""
    if "microsoft" in kernel or os.environ.get("WSL_DISTRO_NAME"):
        return "WSL"
    return "Linux"


def _platform_check() -> ReadinessCheck:
    """Advice that depends on the platform.  Never a required failure."""
    platform = detect_platform()
    if platform == "WSL":
        on_windows_drive = Path.cwd().as_posix().startswith("/mnt/")
        detail = "WSL: Docker Desktop must have WSL integration enabled for this distro"
        if on_windows_drive:
            detail += (
                "; this folder is on a Windows drive (/mnt/...), so scans are slower. "
                "Copy the skills into the Linux filesystem (~) to speed them up"
            )
            return ReadinessCheck("platform", False, False, detail)
        return ReadinessCheck("platform", True, False, detail)
    if platform == "Windows":
        return ReadinessCheck(
            "platform",
            False,
            False,
            "native Windows: the sandbox needs Docker Desktop; this platform is not yet verified",
        )
    if platform == "macOS":
        return ReadinessCheck(
            "platform", True, False, "macOS: the sandbox needs Docker Desktop; Ollama via Homebrew"
        )
    return ReadinessCheck("platform", True, False, "Linux")


_DOCKER_DOWN = "engine not reachable; sandbox scans are unavailable (use --no-sandbox)"


def _docker_checks(cfg: SkillsEntryConfig) -> list[ReadinessCheck]:
    import docker

    try:
        client = docker.from_env()
        client.ping()
    except Exception:
        return [ReadinessCheck("docker", False, False, _DOCKER_DOWN)]
    try:
        image_check: ReadinessCheck
        try:
            client.images.get(cfg.sandbox.base_image)
            image_check = ReadinessCheck(
                "sandbox image", True, False, f"{cfg.sandbox.base_image} is present"
            )
        except Exception:
            image_check = ReadinessCheck(
                "sandbox image",
                False,
                False,
                f"{cfg.sandbox.base_image} is missing; run: skill-sentry-cli sandbox build",
            )
    finally:
        client.close()
    return [ReadinessCheck("docker", True, False, "engine reachable"), image_check]


@app.command("doctor")
def doctor() -> None:
    """Check what a scan needs on this machine, and say what is missing.

    Required checks must pass for a full scan.  Docker and the sandbox image are
    optional: without them, scans run with --no-sandbox and the sandbox stage
    reports itself as degraded.
    """

    checks = readiness_checks(_load_config_or_exit())
    for check in checks:
        status = "PASS" if check.ok else ("FAIL" if check.required else "WARN")
        typer.echo(f"{status}  {check.name}: {check.detail}")
    if any(check.required and not check.ok for check in checks):
        raise typer.Exit(code=int(ExitCode.OPERATIONAL))
    typer.echo("ready for a full scan")


sandbox_app = typer.Typer(help="Build and inspect the sandbox image.", no_args_is_help=True)
app.add_typer(sandbox_app, name="sandbox")


@sandbox_app.command("build")
def sandbox_build() -> None:
    """Build the sandbox image from the sources packaged with SkillSentry."""

    build_sandbox_image(_load_config_or_exit())


def pinned_sandbox_digest() -> tuple[str, str] | None:
    """The published sandbox image this release was built against, or None for a source checkout.

    The release workflow writes the digest into ``data/sandbox_image.json`` before
    it builds the wheel, so an installed version pulls exactly the image it shipped with.
    """

    import importlib.resources
    import json

    text = (
        importlib.resources.files("skill_sentry_cli.data")
        .joinpath("sandbox_image.json")
        .read_text(encoding="utf-8")
    )
    record = json.loads(text)
    digest = str(record.get("digest") or "").strip()
    repository = str(record.get("repository") or "").strip()
    if not digest or not repository:
        return None
    return repository, digest


def pull_pinned_sandbox(cfg: SkillsEntryConfig) -> bool:
    """Pull the pinned published image and tag it as the configured base image.

    Returns False when no digest is pinned or the pull fails, so the caller can
    fall back to building from the packaged sources.
    """

    pinned = pinned_sandbox_digest()
    if pinned is None:
        return False
    repository, digest = pinned
    import docker

    client = None
    try:
        client = docker.from_env()
        image = client.images.pull(f"{repository}@{digest}")
        image.tag(cfg.sandbox.base_image)
    except docker.errors.DockerException as exc:
        typer.echo(f"could not pull the published sandbox image: {exc}")
        return False
    finally:
        close = getattr(client, "close", None)
        if callable(close):
            close()
    typer.echo(f"pulled the published sandbox image as {cfg.sandbox.base_image}")
    return True


def build_sandbox_image(cfg: SkillsEntryConfig) -> None:
    """Build the sandbox image from the packaged sources; a Docker failure is an operational error."""

    import docker

    assets = Path(__file__).resolve().parent / "core" / "sandbox" / "assets"
    client = None
    try:
        client = docker.from_env()
        client.images.build(
            path=str(assets),
            dockerfile="Dockerfile.sandbox",
            tag=cfg.sandbox.base_image,
            rm=True,
        )
    except docker.errors.DockerException as exc:
        typer.echo(f"error: could not build the sandbox image: {exc}", err=True)
        raise typer.Exit(code=int(ExitCode.OPERATIONAL)) from exc
    finally:
        close = getattr(client, "close", None)
        if callable(close):
            close()
    typer.echo(f"built {cfg.sandbox.base_image}")


def _confirm(question: str, *, default: bool, assume_yes: bool) -> bool:
    """Ask before anything is downloaded or built.  ``--yes`` answers every question."""

    if assume_yes:
        return True
    return typer.confirm(question, default=default)


def _scan_roots(
    engine: ScanEngine,
    roots: list[Path],
    *,
    options: ScanOptions,
    output_format: str,
    quiet: bool,
    always_progress: bool = False,
) -> tuple[list[ScanOutcome], list[int], bool]:
    """Scan each root in turn. Returns the outcomes, the index of each root that scanned,
    and whether any root failed. A failed root is reported and skipped, not fatal.

    Progress goes to stderr. By default it shows only for a text run on a terminal.
    ``always_progress`` (the no-path flow) shows it for every format, terminal or not.
    """

    outcomes: list[ScanOutcome] = []
    indexes: list[int] = []
    failed = False
    if always_progress:
        show_progress = len(roots) > 1 and not quiet
    else:
        show_progress = (
            len(roots) > 1 and output_format == "text" and not quiet and sys.stderr.isatty()
        )
    for index, root in enumerate(roots):
        if show_progress:
            typer.echo(f"[{index + 1}/{len(roots)}] {root.name} ...", err=True)
        try:
            outcome = engine.scan(root, options=options)
        except ScanError as exc:
            failed = True
            typer.echo(f"error: {root}: {exc}", err=True)
            typer.echo(f"hint: {_scan_error_hint(exc)}", err=True)
            continue
        outcomes.append(outcome)
        indexes.append(index)
    return outcomes, indexes, failed


def _new_report_folder() -> Path:
    """Create a fresh private report folder. An existing folder is never reused."""

    ensure_private_dir(reports_dir())
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S-%f")
    for attempt in range(1000):
        suffix = "" if attempt == 0 else f"-{attempt}"
        directory = reports_dir(f"scan-{stamp}{suffix}")
        try:
            directory.mkdir(mode=0o700)
        except FileExistsError:
            continue
        ensure_private_dir(directory)
        return directory
    raise OSError("could not create a unique report folder")


def _save_reports_now(
    fmt: str,
    outcomes: list[ScanOutcome],
    *,
    skipped: int,
    backend: str | None,
    announce: bool,
    installs: Sequence[InstalledSkill] | None = None,
) -> Path:
    """Write the run's reports into a new private folder under the reports directory.

    Markdown gives one file per skill plus summary.md; SARIF gives one merged file.
    """
    directory = _new_report_folder()
    if fmt == "markdown":
        _write_report_dir(directory, outcomes, skipped=skipped, backend=backend, installs=installs)
        written = directory
    else:
        written = directory / "skills.sarif"
        _write_file(written, _combined_sarif(outcomes, installs))
    if announce:
        typer.echo(f"Saved report to {written}")
    return written


def _is_interactive() -> bool:
    return _stream_is_tty(sys.stdin) and _stream_is_tty(sys.stdout)


def _stream_is_tty(stream: TextIO) -> bool:
    try:
        return bool(stream.isatty())
    except (AttributeError, ValueError, OSError):
        return False


_REPORT_ANSWERS = {
    "": "none",
    "n": "none",
    "no": "none",
    "m": "markdown",
    "markdown": "markdown",
    "s": "sarif",
    "sarif": "sarif",
}


def _offer_report() -> str:
    """Ask whether to save a report. Returns markdown | sarif | none.

    Three unrecognised answers, end of input, or Ctrl-C all mean no.
    """
    for _attempt in range(3):
        try:
            answer = typer.prompt(
                "Save a report? [m]arkdown / [s]arif / [n]o (default n)",
                default="n",
                show_default=False,
            )
        except (typer.Abort, click.exceptions.Abort, EOFError, KeyboardInterrupt):
            return "none"
        choice = _REPORT_ANSWERS.get(str(answer).strip().lower())
        if choice is not None:
            return choice
        typer.echo("Please answer m, s or n.", err=True)
    return "none"


def _discover_with_options(
    config: SkillsEntryConfig,
    *,
    project: Path | None,
    agents: list[str],
    include_experimental: bool,
) -> DiscoveryResult:
    """Run discovery with CLI flags layered over ``[discovery]`` in the config.

    ``--agent`` replaces the configured agent list when given. ``--include-experimental``
    turns the experimental locations on in addition to the configured setting.
    """
    wanted = [name.strip().lower() for name in agents if name.strip()]
    for name in wanted:
        if name not in DISCOVERY_AGENTS:
            typer.echo(
                f"error: unknown --agent {name!r}. Use one of: "
                f"{', '.join(sorted(DISCOVERY_AGENTS))}.",
                err=True,
            )
            raise typer.Exit(code=int(ExitCode.USAGE))
    project_dir = project.expanduser() if project is not None else Path.cwd()
    if not _is_dir(project_dir):
        typer.echo(f"error: --project is not a folder: {project}", err=True)
        raise typer.Exit(code=int(ExitCode.USAGE))
    return discover_installed(
        home=Path.home(),
        project_dir=project_dir,
        extra_paths=[Path(entry).expanduser() for entry in config.discovery.extra_paths],
        agents=wanted or list(config.discovery.agents),
        include_experimental=include_experimental or config.discovery.include_experimental,
    )


def _scan_installed(
    *,
    project: Path | None,
    agents: list[str],
    include_experimental: bool,
    save_report: str | None,
    no_prompt: bool,
    output_format: str,
    quiet: bool,
    fail_on: str,
    no_cache: bool,
    sandbox: bool,
    backend: str,
    timeout_s: int,
) -> None:
    """``scan`` with no path: find every installed skill, then scan each one."""

    try:
        config = _config_for_backend(backend)
    except ConfigError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=int(ExitCode.USAGE)) from exc

    # A --project that is not a folder is an explicit location the user named and it is
    # missing: an operational error, whether or not other skills were found.
    if project is not None and not _is_dir(project.expanduser()):
        typer.echo(f"error: --project is not a folder: {project}", err=True)
        raise typer.Exit(code=int(ExitCode.OPERATIONAL))

    result = _discover_with_options(
        config,
        project=project,
        agents=agents,
        include_experimental=include_experimental,
    )
    text = output_format == "text"
    if not result.skills:
        typer.echo("No installed skills found. Looked in:", err=True)
        for location in result.checked:
            typer.echo(f"  {_tilde(location)}", err=True)
        typer.echo(
            "To check a project outside this folder, pass --project DIR. To add folders, set "
            "[discovery] extra_paths in skillsentry.toml. To scan one folder, run "
            "`skill-sentry-cli scan <path>`.",
            err=True,
        )
        if not quiet:
            for note in result.skipped:
                typer.echo(f"note: {_tilde_text(note)}", err=True)
        # An extra_paths entry the user configured that does not exist is an error. An
        # empty result with nothing named is not: it exits 0, like discover.
        if any(_MISSING_EXTRA_PATH in note for note in result.skipped):
            raise typer.Exit(code=int(ExitCode.OPERATIONAL))
        # Machine-readable formats still get a valid, empty document on stdout.
        if output_format == "json":
            typer.echo("[]")
        elif output_format == "sarif":
            typer.echo(_combined_sarif([]))
        raise typer.Exit(code=int(ExitCode.OK))

    if text and not quiet:
        typer.echo(_found_line(result))
    if not quiet:
        for note in result.skipped:
            typer.echo(f"note: {_tilde_text(note)}", err=True)

    roots = [skill.real_path for skill in result.skills]
    engine = _make_engine(config, backend)
    options = ScanOptions(
        no_cache=no_cache,
        backend=backend,
        sandbox=sandbox,
        timeout_s=timeout_s,
    )
    outcomes, indexes, failed = _scan_roots(
        engine,
        roots,
        options=options,
        output_format=output_format,
        quiet=quiet,
        always_progress=True,
    )
    ran_backend = _ran_backend(engine) if outcomes else backend
    engine.close()

    skipped = len(roots) - len(outcomes)
    if not quiet:
        # "skipped" is what discovery set aside (broken links, folders without SKILL.md,
        # unreadable entries); the notes above say why.
        typer.echo(
            f"Scanned {len(outcomes)}, failed {skipped}, skipped {len(result.skipped)}.",
            err=True,
        )
    if not outcomes:
        raise typer.Exit(code=int(ExitCode.OPERATIONAL))

    installs = [result.skills[index] for index in indexes]
    footer = _report_footer(Path("."), outcomes) if len(outcomes) == 1 else None
    _emit_outcomes(
        outcomes,
        output_format=output_format,
        quiet=quiet,
        backend=ran_backend,
        output=None,
        sarif_out=None,
        skipped=skipped,
        footer=footer,
        installs=installs,
        notes=result.skipped,
    )

    chosen = save_report
    if chosen is None and text and not quiet and not no_prompt:
        if _is_interactive():
            chosen = _offer_report()
        else:
            typer.echo("Tip: add --save-report markdown to keep a report.", err=True)
    if chosen in _SAVE_NOW:
        _save_reports_now(
            chosen,
            outcomes,
            skipped=skipped,
            backend=ran_backend,
            announce=text and not quiet,
            installs=installs,
        )

    if failed:
        raise typer.Exit(code=int(ExitCode.OPERATIONAL))
    if any(_should_fail(outcome.verdict, fail_on) for outcome in outcomes):
        raise typer.Exit(code=int(ExitCode.VERDICT))
    raise typer.Exit(code=int(ExitCode.OK))


def _is_dir(path: Path) -> bool:
    try:
        return path.is_dir()
    except OSError:
        return False


def _home_text() -> str:
    return str(Path.home())


def _tilde(path: Path) -> str:
    """The path with the home folder shown as ``~``."""
    return _tilde_text(str(path))


def _tilde_text(text: str) -> str:
    home = _home_text()
    if text == home:
        return "~"
    if text.startswith(home + os.sep):
        return "~" + text[len(home) :]
    return text


def _skill_path_text(skill: InstalledSkill) -> str:
    if skill.is_symlink:
        return f"{_tilde(skill.declared_path)} -> {_tilde(skill.real_path)}"
    return _tilde(skill.declared_path)


def _found_line(result: DiscoveryResult) -> str:
    counts: dict[str, int] = {}
    for skill in result.skills:
        counts[skill.agent] = counts.get(skill.agent, 0) + 1
    by_agent = ", ".join(
        f"{_AGENT_LABELS.get(agent, agent)}: {count}" for agent, count in counts.items()
    )
    total = len(result.skills)
    dups = result.duplicates_merged
    return (
        f"Found {total} skill{'s' if total != 1 else ''} ({by_agent}; "
        f"{dups} duplicate{'s' if dups != 1 else ''} merged)"
    )


def _print_discovery_text(result: DiscoveryResult) -> None:
    if result.skills:
        headers = ("AGENT", "SCOPE", "SKILL", "PATH")
        rows = [
            (skill.agent, skill.scope, skill.name, _skill_path_text(skill))
            for skill in result.skills
        ]
        widths = [
            max(len(header), *(len(row[i]) for row in rows)) for i, header in enumerate(headers)
        ]
        typer.echo(
            "  ".join(
                header.ljust(width) for header, width in zip(headers, widths, strict=True)
            ).rstrip()
        )
        for row in rows:
            typer.echo(
                "  ".join(
                    cell.ljust(width) for cell, width in zip(row, widths, strict=True)
                ).rstrip()
            )
    else:
        typer.echo("No installed skills found. Looked in:")
        for location in result.checked:
            typer.echo(f"  {_tilde(location)}")
    if result.skipped:
        typer.echo("notes:")
        for note in result.skipped:
            typer.echo(f"  - {_tilde_text(note)}")
    if result.duplicates_merged:
        typer.echo(f"{result.duplicates_merged} duplicates merged")


def _discovery_payload(result: DiscoveryResult) -> dict[str, object]:
    return {
        "skills": [{"name": skill.name, **_install_payload(skill)} for skill in result.skills],
        "checked": [str(location) for location in result.checked],
        "notes": list(result.skipped),
        "duplicates_merged": result.duplicates_merged,
    }


@app.command("setup")
def setup(
    assume_yes: bool = typer.Option(
        False, "--yes", help="Answer yes to every prompt (downloads and builds)."
    ),
    skip_model: bool = typer.Option(False, "--skip-model", help="Do not check or pull the model."),
    skip_sandbox: bool = typer.Option(
        False, "--skip-sandbox", help="Do not check or build the sandbox image."
    ),
) -> None:
    """Guided first-time setup.  Asks before every download or build.

    It never installs Docker or Ollama itself; it says what to install.  It ends
    with the same readiness checks as ``doctor``.
    """

    from skill_sentry_cli.core.config import write_default_config
    from skill_sentry_cli.core.models.gemma_local import GemmaLocal

    config_path = Path(os.getenv("SKILLSENTRY_CONFIG") or Path.cwd() / "skillsentry.toml")
    if not config_path.exists() and _confirm(
        f"Write the default configuration to {config_path}?", default=True, assume_yes=assume_yes
    ):
        write_default_config(config_path, force=False)
        typer.echo(f"wrote {config_path}")
    cfg = _load_config_or_exit()

    checks = {check.name: check for check in readiness_checks(cfg)}

    if not skip_sandbox:
        docker_check = checks.get("docker")
        if docker_check is None or not docker_check.ok:
            typer.echo(
                "Docker is not reachable. Install Docker, then make sure your user can run "
                "`docker ps` without sudo (the user guide, section 4, explains the group step)."
            )
        elif (
            not checks["sandbox image"].ok
            and _confirm(
                "Install the sandbox image now? A published copy is downloaded when this release "
                "has one; otherwise it is built from the packaged sources (a few minutes).",
                default=True,
                assume_yes=assume_yes,
            )
            and not pull_pinned_sandbox(cfg)
        ):
            build_sandbox_image(cfg)

    if not skip_model:
        model_name = cfg.model.ollama_model
        probe = GemmaLocal(base_url=cfg.model.ollama_url, model=model_name)
        try:
            state = probe.probe()
        finally:
            probe.close()
        if state == ProbeResult.UNREACHABLE:
            typer.echo(
                f"The model server is not reachable at {cfg.model.ollama_url}. Install Ollama "
                "from https://ollama.com, start it (`ollama serve`), then run setup again."
            )
        elif state == ProbeResult.NO_MODEL and _confirm(
            f"Download the configured model now with `ollama pull {model_name}`? "
            "This is several gigabytes.",
            default=False,
            assume_yes=assume_yes,
        ):
            try:
                result = subprocess.run(["ollama", "pull", model_name], check=False)
            except FileNotFoundError:
                typer.echo("The ollama command was not found. Install Ollama first.")
            else:
                if result.returncode != 0:
                    typer.echo(f"`ollama pull {model_name}` failed (exit {result.returncode}).")

    final = readiness_checks(cfg)
    for check in final:
        status = "PASS" if check.ok else ("FAIL" if check.required else "WARN")
        typer.echo(f"{status}  {check.name}: {check.detail}")
    if any(check.required and not check.ok for check in final):
        typer.echo("Setup is not complete yet. Fix the FAIL lines above, then run setup again.")
        raise typer.Exit(code=int(ExitCode.OPERATIONAL))
    typer.echo("ready for a full scan")


if __name__ == "__main__":  # pragma: no cover
    app()
