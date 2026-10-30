"""``skillsentry`` command-line interface.

``serve`` (demo + live), ``init``, live ``scan``, and ``self-audit``.  Demo
mode remains a separate, explicitly labelled path; live scans always go through
the real :class:`ScanEngine`.
"""

from __future__ import annotations

import contextlib
import json
import sys
from pathlib import Path
from uuid import UUID

import typer

from skillsentry.core.cache import SQLiteStore
from skillsentry.core.config import (
    ConfigError,
    SkillsEntryConfig,
    load_config,
    write_default_config,
)
from skillsentry.core.contracts import ExportFormat, ScanOptions, Verdict, VerdictTier
from skillsentry.core.engine import ScanEngine, ScanError, ScanOutcome
from skillsentry.core.exit_codes import ExitCode
from skillsentry.core.models.mock import MockGemma
from skillsentry.core.reports import render_report
from skillsentry.core.version import GEMMA_BADGE, __version__
from skillsentry.server.demo_data import build_demo_store


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
    name="skillsentry",
    help="Audit AI Agent Skills before installation - fully local.",
    no_args_is_help=True,
    add_completion=False,
)

_FAIL_ON = {"safe", "suspicious", "malicious"}
_RANK = {VerdictTier.SAFE: 0, VerdictTier.SUSPICIOUS: 1, VerdictTier.MALICIOUS: 2}
_FORMATS = {"text", "json", "sarif", "markdown"}
_BACKENDS = {"auto", "local", "cloud", "demo"}


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"SkillSentry {__version__} - {GEMMA_BADGE}")
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

    if demo_mode:
        from skillsentry.server.demo_mode import create_demo_app

        typer.echo(f"SkillSentry {__version__} - demo mode - http://{host}:{port}")
        uvicorn.run(create_demo_app(speed=speed), host=host, port=port)
        return

    from skillsentry.server.app import create_app
    from skillsentry.server.live_backend import LiveBackend

    typer.echo(f"SkillSentry {__version__} - live mode - http://{host}:{port}")
    uvicorn.run(create_app(LiveBackend()), host=host, port=port)


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
    typer.echo(f"wrote {written}")


@app.command()
def scan(
    path: Path = typer.Argument(..., help="Skill directory, or a folder containing skills."),
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
) -> None:
    """Audit one skill directory or a folder of skills."""

    if output_format not in _FORMATS:
        typer.echo(f"error: unsupported --format {output_format!r}", err=True)
        raise typer.Exit(code=int(ExitCode.USAGE))
    if fail_on not in _FAIL_ON:
        typer.echo(f"error: unsupported --fail-on {fail_on!r}", err=True)
        raise typer.Exit(code=int(ExitCode.USAGE))
    if backend not in _BACKENDS:
        typer.echo(f"error: unsupported --backend {backend!r}", err=True)
        raise typer.Exit(code=int(ExitCode.USAGE))

    if demo_mode:
        verdict = _demo_verdict_for(path)
        if sarif_out is not None:
            sarif_out.parent.mkdir(parents=True, exist_ok=True)
            sarif_out.write_text(
                render_report(verdict, ExportFormat.SARIF).content.decode("utf-8"),
                encoding="utf-8",
            )
            if not quiet and output_format == "text":
                typer.echo(f"wrote {sarif_out}")
        rendered = _render_verdict(
            verdict, output_format=output_format, quiet=quiet, backend="demo"
        )
        if output is not None:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(rendered, encoding="utf-8")
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
        roots = engine.discover(path)
    except ScanError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=int(ExitCode.OPERATIONAL)) from exc

    options = ScanOptions(
        no_cache=no_cache,
        backend=backend,  # type: ignore[arg-type]
        sandbox=sandbox,
        timeout_s=timeout_s,
    )
    outcomes: list[ScanOutcome] = []
    failed = False
    for root in roots:
        try:
            outcome = engine.scan(root, options=options)
        except ScanError as exc:
            failed = True
            typer.echo(f"error: {root}: {exc}", err=True)
            continue
        outcomes.append(outcome)
    engine.close()

    if not outcomes:
        raise typer.Exit(code=int(ExitCode.OPERATIONAL))

    _emit_outcomes(
        outcomes,
        output_format=output_format,
        quiet=quiet,
        backend=backend,
        output=output,
        sarif_out=sarif_out,
    )
    if failed:
        raise typer.Exit(code=int(ExitCode.OPERATIONAL))
    if any(_should_fail(outcome.verdict, fail_on) for outcome in outcomes):
        raise typer.Exit(code=int(ExitCode.VERDICT))
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
                backend=backend,  # type: ignore[arg-type]
                sandbox=sandbox,
                timeout_s=timeout_s,
            ),
        )
        engine.close()
    except (ConfigError, ScanError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=int(ExitCode.OPERATIONAL)) from exc
    _print_verdict(outcome.verdict, output_format=output_format, quiet=quiet, backend=backend)
    if _should_fail(outcome.verdict, fail_on):
        raise typer.Exit(code=int(ExitCode.VERDICT))
    raise typer.Exit(code=int(ExitCode.OK))


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _config_for_backend(backend: str) -> SkillsEntryConfig:
    config = load_config()
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


def _emit_outcomes(
    outcomes: list[ScanOutcome],
    *,
    output_format: str,
    quiet: bool,
    backend: str,
    output: Path | None,
    sarif_out: Path | None,
) -> None:
    if sarif_out is not None:
        sarif_out.parent.mkdir(parents=True, exist_ok=True)
        sarif_out.write_text(_combined_sarif(outcomes), encoding="utf-8")
        if not quiet and output_format == "text":
            typer.echo(f"wrote {sarif_out}")

    if output_format == "json":
        payload = outcomes[0].verdict.model_dump(by_alias=True, mode="json")
        if len(outcomes) > 1:
            payload = [
                outcome.verdict.model_dump(by_alias=True, mode="json") for outcome in outcomes
            ]
        rendered = json.dumps(payload, indent=2, ensure_ascii=False)
    elif output_format == "sarif":
        rendered = _combined_sarif(outcomes)
    elif output_format == "markdown":
        rendered = "\n\n---\n\n".join(
            render_report(
                outcome.verdict,
                ExportFormat.MARKDOWN,
                stage_results=outcome.stage_results,
            ).content.decode("utf-8")
            for outcome in outcomes
        )
    else:
        rendered = "\n".join(
            _verdict_text(outcome, quiet=quiet, backend=backend) for outcome in outcomes
        )

    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
        if output_format == "text":
            typer.echo(rendered.rstrip())
        return
    typer.echo(rendered.rstrip())


def _combined_sarif(outcomes: list[ScanOutcome]) -> str:
    if len(outcomes) == 1:
        return render_report(outcomes[0].verdict, ExportFormat.SARIF).content.decode("utf-8")
    runs = []
    for outcome in outcomes:
        payload = json.loads(
            render_report(outcome.verdict, ExportFormat.SARIF).content.decode("utf-8")
        )
        runs.extend(payload.get("runs", []))
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
        lines.append(
            f"SkillSentry {__version__} - {GEMMA_BADGE} - backend: {_backend_label(backend)}"
        )
    icon = {"SAFE": "[OK]", "SUSPICIOUS": "[!]", "MALICIOUS": "[X]"}[verdict.verdict.value]
    cache = " (cached)" if verdict.cached else ""
    lines.append(
        f"{icon} {verdict.skill} - {verdict.verdict.value} - "
        f"risk {verdict.risk_score} - confidence {verdict.confidence:.2f}{cache}"
    )
    finding = verdict.key_finding
    if finding is not None and finding.severity.value not in {"note"}:
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


def _backend_label(backend: str) -> str:
    return {
        "auto": "auto (local -> cloud -> unavailable)",
        "local": "local (ollama)",
        "cloud": "cloud (gemini)",
        "demo": "demo/mock",
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
        return render_report(verdict, ExportFormat.MARKDOWN).content.decode("utf-8")
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
    return SQLiteStore(load_config().db_path)


@cache_app.command("stats")
def cache_stats() -> None:
    """Show the number of cached verdicts and the database size."""

    with contextlib.closing(_store()) as store:
        entries, size_bytes = store.cache_stats()
    typer.echo(f"entries: {entries}")
    typer.echo(f"size_bytes: {int(size_bytes)}")


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
        typer.echo(
            f"{row.get('scanId')}  {row.get('skillName')}  "
            f"{row.get('status')}  {row.get('verdict') or '-'}"
        )


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
    if stored is None:
        typer.echo(f"error: no stored scan {scan_id}", err=True)
        raise typer.Exit(code=int(ExitCode.USAGE))
    verdict, _detail, stages, _cached = stored
    rendered = render_report(verdict, formats[fmt], stage_results=stages).content.decode("utf-8")
    if output is None:
        typer.echo(rendered.rstrip())
    else:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
        typer.echo(f"wrote {output}")


if __name__ == "__main__":  # pragma: no cover
    app()
