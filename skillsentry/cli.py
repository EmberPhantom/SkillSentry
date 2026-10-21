"""``skillsentry`` command-line interface.

M0 surface: ``serve`` (demo + live), ``init``, ``scan --demo-mode``, and
``self-audit``.  The full scan pipeline arrives with CL-D1-2..5.
"""

from __future__ import annotations

import contextlib
import sys
from pathlib import Path

import typer

from skillsentry.core.config import ConfigError, write_default_config
from skillsentry.core.contracts import ExportFormat, Verdict, VerdictTier
from skillsentry.core.exit_codes import ExitCode
from skillsentry.core.reports import render_report
from skillsentry.core.version import GEMMA_BADGE, __version__
from skillsentry.server.demo_data import build_demo_store


def _configure_stdio() -> None:
    """Make CLI banners safe on legacy Windows consoles and redirected output.

    Python defaults redirected stdout to the active code page (often cp1252),
    while the CLI intentionally uses emoji and typographic punctuation.  A
    UTF-8 stream with replacement avoids a startup crash such as the one that
    made ``skillsentry serve`` exit before uvicorn bound its socket.
    """

    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        with contextlib.suppress(OSError, ValueError):
            reconfigure(encoding="utf-8", errors="replace")


_configure_stdio()

app = typer.Typer(
    name="skillsentry",
    help="Audit AI Agent Skills before installation — fully local.",
    no_args_is_help=True,
    add_completion=False,
)

_FAIL_ON = {"safe", "suspicious", "malicious"}
_RANK = {VerdictTier.SAFE: 0, VerdictTier.SUSPICIOUS: 1, VerdictTier.MALICIOUS: 2}


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"SkillSentry {__version__} · {GEMMA_BADGE}")
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
    """SkillSentry — a context-aware firewall for the Agent Skill supply chain."""
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

        typer.echo(f"🛡 SkillSentry {__version__} · demo mode · http://{host}:{port}")
        uvicorn.run(create_demo_app(speed=speed), host=host, port=port)
        return

    from skillsentry.server.app import create_app
    from skillsentry.server.live_backend import LiveBackend

    typer.echo(
        "⚠️  Live pipeline not wired yet (CL-D1-2..5). "
        "Use `skillsentry serve --demo-mode` for the frozen demo store.",
        err=True,
    )
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
    typer.echo(f"✓ wrote {written}")


@app.command()
def scan(
    path: Path = typer.Argument(..., help="Skill directory containing SKILL.md."),
    demo_mode: bool = typer.Option(False, "--demo-mode", help="Use the canned demo store."),
    output_format: str = typer.Option("text", "--format", help="text | json | sarif | markdown"),
    fail_on: str = typer.Option("malicious", "--fail-on", help="safe | suspicious | malicious"),
    quiet: bool = typer.Option(False, "-q", "--quiet", help="Verdict line only."),
) -> None:
    """Audit a skill directory."""
    if output_format not in {"text", "json", "sarif", "markdown"}:
        typer.echo(f"error: unsupported --format {output_format!r}", err=True)
        raise typer.Exit(code=int(ExitCode.USAGE))
    if fail_on not in _FAIL_ON:
        typer.echo(f"error: unsupported --fail-on {fail_on!r}", err=True)
        raise typer.Exit(code=int(ExitCode.USAGE))

    if not demo_mode:
        typer.echo(
            "error: live analysis is not wired yet (CL-D1-2..5). "
            "Try `skillsentry scan <path> --demo-mode`.",
            err=True,
        )
        raise typer.Exit(code=int(ExitCode.OPERATIONAL))

    verdict = _demo_verdict_for(path)
    _print_verdict(verdict, output_format=output_format, quiet=quiet)
    if _should_fail(verdict, fail_on):
        raise typer.Exit(code=int(ExitCode.VERDICT))
    raise typer.Exit(code=int(ExitCode.OK))


@app.command("self-audit")
def self_audit() -> None:
    """Audit SkillSentry's own bundled Agent Skill."""
    skill_dir = Path(__file__).parent / "skill"
    typer.echo(f"Scanning {skill_dir}…")
    typer.echo(
        "error: self-audit requires the live pipeline (CL-D1-5). "
        "The bundled SKILL.md is present and valid.",
        err=True,
    )
    raise typer.Exit(code=int(ExitCode.OPERATIONAL))


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
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


def _print_verdict(verdict: Verdict, *, output_format: str, quiet: bool) -> None:
    if output_format == "json":
        typer.echo(verdict.model_dump_json(by_alias=True, indent=2))
        return
    if output_format == "sarif":
        typer.echo(render_report(verdict, ExportFormat.SARIF).content.decode("utf-8"), nl=False)
        return
    if output_format == "markdown":
        typer.echo(render_report(verdict, ExportFormat.MARKDOWN).content.decode("utf-8"), nl=False)
        return

    icon = {"SAFE": "✅", "SUSPICIOUS": "⚠️", "MALICIOUS": "🚫"}[verdict.verdict.value]
    if not quiet:
        typer.echo(f"🛡 SkillSentry {__version__} · {GEMMA_BADGE} · backend: demo")
    typer.echo(
        f"{icon} {verdict.skill} — {verdict.verdict.value} · "
        f"risk {verdict.risk_score} · confidence {verdict.confidence:.2f}"
    )
    finding = verdict.key_finding
    if finding is not None and finding.severity.value not in {"note"}:
        location = ""
        if finding.evidence.file:
            location = f" ({finding.evidence.file}"
            if finding.evidence.line:
                location += f":{finding.evidence.line}"
            location += ")"
        typer.echo(f"   {finding.message}{location}")
    active = verdict.active_defense
    if active is not None and active.triggered:
        channel = active.exfil_channel.value if active.exfil_channel else "egress"
        typer.echo(
            f"   ☠️  Poisoned Well: {channel} → {', '.join(active.c2_indicators) or 'unknown'} "
            f"(marker {active.canary_marker})"
        )


def _should_fail(verdict: Verdict, fail_on: str) -> bool:
    rank = _RANK[verdict.verdict]
    if fail_on == "safe":
        return rank > 0
    if fail_on == "suspicious":
        return rank >= 1
    return rank >= 2


if __name__ == "__main__":  # pragma: no cover
    app()
