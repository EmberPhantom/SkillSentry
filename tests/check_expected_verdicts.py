#!/usr/bin/env python3
"""Validate SkillSentry's fixture corpus and report expectations.

The module is both a pytest helper (``check_static`` / ``check_full``) and a
standalone SARIF/JSON acceptance checker:

    python tests/check_expected_verdicts.py results.sarif
    python tests/check_expected_verdicts.py results.sarif --allow-static

The full-sandbox checks are skipped when Docker or the configured sandbox image
is unavailable.  They are never turned into a passing static result.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_PATH = ROOT / "tests" / "expected_verdicts.json"
FIXTURES = ROOT / "fixtures"


@dataclass(frozen=True)
class CheckResult:
    skill: str
    status: str
    detail: str = ""


def _expected() -> dict[str, dict[str, Any]]:
    payload = json.loads(EXPECTED_PATH.read_text(encoding="utf-8"))
    skills = payload.get("skills")
    if not isinstance(skills, dict):
        raise RuntimeError(f"{EXPECTED_PATH}: missing skills mapping")
    return skills


def _scan_one(name: str, expected: dict[str, Any], *, sandbox: bool) -> CheckResult:
    from skillsentry.core.cache import SQLiteStore
    from skillsentry.core.config import SkillsEntryConfig
    from skillsentry.core.contracts import ScanOptions
    from skillsentry.core.engine import ScanEngine
    from skillsentry.core.models.mock import MockGemma

    with tempfile.TemporaryDirectory(prefix="skillsentry-fixture-") as temp:
        store = SQLiteStore(Path(temp) / "scan.sqlite")
        engine = ScanEngine(SkillsEntryConfig(), store=store, model=MockGemma())
        try:
            roots = {root.name: root for root in engine.discover(FIXTURES)}
            root = roots.get(name)
            if root is None:
                return CheckResult(name, "FAIL", "fixture package was not discovered")
            outcome = engine.scan(
                root,
                options=ScanOptions(
                    sandbox=sandbox,
                    backend="demo",
                    no_cache=True,
                    timeout_s=60,
                ),
            )
        except Exception as exc:  # pragma: no cover - exercised by broken environments
            return CheckResult(name, "FAIL", f"scan raised {type(exc).__name__}: {exc}")
        finally:
            engine.close()
            store.close()

    verdict = outcome.verdict
    if verdict.verdict.value != expected["verdict"]:
        return CheckResult(
            name,
            "FAIL",
            f"expected {expected['verdict']}, got {verdict.verdict.value} "
            f"(risk {verdict.risk_score})",
        )
    risk = verdict.risk_score
    if "min_risk" in expected and risk < int(expected["min_risk"]):
        return CheckResult(name, "FAIL", f"risk {risk} < {expected['min_risk']}")
    if "max_risk" in expected and risk > int(expected["max_risk"]):
        return CheckResult(name, "FAIL", f"risk {risk} > {expected['max_risk']}")

    if sandbox:
        e2e = expected.get("e2e")
        if isinstance(e2e, dict):
            full_min = e2e.get("min_risk")
            if isinstance(full_min, int) and risk < full_min:
                return CheckResult(name, "FAIL", f"full-scan risk {risk} < {full_min}")
            active = verdict.active_defense
            if e2e.get("active_defense") and not (
                active is not None and active.triggered
            ):
                return CheckResult(
                    name,
                    "FAIL",
                    "Poisoned Well did not trigger in full-scan mode",
                )
            channel = e2e.get("exfil_channel")
            if channel and (
                active is None
                or active.exfil_channel is None
                or str(active.exfil_channel.value) != channel
            ):
                actual = None if active is None else active.exfil_channel
                return CheckResult(
                    name,
                    "FAIL",
                    f"expected exfil channel {channel}, got {actual!r}",
                )
            if e2e.get("evasion") and not (
                active is not None and active.sandbox_evasion_detected
            ):
                return CheckResult(name, "FAIL", "sandbox evasion was not detected")
    return CheckResult(name, "PASS", f"{verdict.verdict.value} risk={risk}")


def check_static() -> list[CheckResult]:
    """Run every fixture through the real engine with the deterministic model."""

    return [
        _scan_one(name, expected, sandbox=False)
        for name, expected in _expected().items()
        if expected.get("static", True)
    ]


def docker_prerequisites() -> tuple[bool, str]:
    """Return whether a usable Docker daemon and sandbox image are available."""

    try:
        import docker  # type: ignore[import-untyped]
    except Exception as exc:  # pragma: no cover - depends on the host
        return False, f"docker SDK unavailable: {exc}"

    try:
        client = docker.from_env()
        client.ping()
        from skillsentry.core.config import SkillsEntryConfig

        image = SkillsEntryConfig().sandbox.base_image
        client.images.get(image)
    except Exception as exc:  # pragma: no cover - depends on the host
        return False, f"Docker/sandbox image unavailable: {exc}"
    finally:
        try:
            client.close()
        except Exception:
            pass
    return True, "ready"


def check_full() -> list[CheckResult]:
    """Run the Docker-dependent fixtures when the sandbox prerequisites exist."""

    ready, reason = docker_prerequisites()
    if not ready:
        return [CheckResult("*", "SKIP", reason)]

    results: list[CheckResult] = []
    for name, expected in _expected().items():
        e2e = expected.get("e2e")
        if not isinstance(e2e, dict):
            continue
        results.append(_scan_one(name, expected, sandbox=True))
    return results


def _rows(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, dict) and isinstance(payload.get("runs"), list):
        rows: list[dict[str, Any]] = []
        for run in payload["runs"]:
            props = run.get("properties") if isinstance(run, dict) else None
            if not isinstance(props, dict):
                continue
            active = props.get("activeDefense")
            rows.append(
                {
                    "skill": props.get("skill"),
                    "verdict": props.get("verdict"),
                    "risk": props.get("riskScore"),
                    "active_defense": active if isinstance(active, dict) else None,
                }
            )
        return rows
    if isinstance(payload, list):
        items = payload
    elif isinstance(payload, dict) and isinstance(payload.get("skills"), list):
        items = payload["skills"]
    else:
        raise SystemExit("report must be SARIF, a JSON verdict, or a JSON list of verdicts")

    rows = []
    for item in items:
        if not isinstance(item, dict):
            continue
        active = item.get("activeDefense")
        rows.append(
            {
                "skill": item.get("skill"),
                "verdict": item.get("verdict"),
                "risk": item.get("riskScore"),
                "active_defense": active if isinstance(active, dict) else None,
            }
        )
    return rows


def _check_row(
    name: str,
    expected: dict[str, Any],
    row: dict[str, Any],
    *,
    allow_static: bool,
) -> list[str]:
    errors: list[str] = []
    expected_verdict = expected.get("verdict")
    if row.get("verdict") != expected_verdict:
        errors.append(f"{name}: expected verdict {expected_verdict!r}, got {row.get('verdict')!r}")

    risk = row.get("risk")
    if not isinstance(risk, int):
        errors.append(f"{name}: missing integer risk score")
        risk = -1
    if "min_risk" in expected and risk < int(expected["min_risk"]):
        errors.append(f"{name}: risk {risk} < required {expected['min_risk']}")
    if "max_risk" in expected and risk > int(expected["max_risk"]):
        errors.append(f"{name}: risk {risk} > allowed {expected['max_risk']}")

    e2e = expected.get("e2e")
    if isinstance(e2e, dict) and not allow_static:
        active = row.get("active_defense")
        if e2e.get("min_risk") is not None and risk < int(e2e["min_risk"]):
            errors.append(f"{name}: full-scan risk {risk} < required {e2e['min_risk']}")
        if e2e.get("active_defense") and not (
            isinstance(active, dict) and active.get("triggered")
        ):
            errors.append(f"{name}: Poisoned Well did not trigger in full-scan mode")
        channel = e2e.get("exfil_channel")
        if channel and isinstance(active, dict) and active.get("exfil_channel") != channel:
            errors.append(
                f"{name}: expected exfil channel {channel}, got "
                f"{active.get('exfil_channel')!r}"
            )
        if e2e.get("evasion") and not (
            isinstance(active, dict) and active.get("sandbox_evasion_detected")
        ):
            errors.append(f"{name}: sandbox evasion was not detected")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path, help="SARIF or JSON report")
    parser.add_argument(
        "--allow-static",
        action="store_true",
        help="Do not enforce full-scan (Docker/Poisoned Well) requirements.",
    )
    args = parser.parse_args(argv)

    expected = _expected()
    payload = json.loads(args.report.read_text(encoding="utf-8"))
    rows = _rows(payload)
    by_name = {row["skill"]: row for row in rows if row.get("skill")}
    errors: list[str] = []
    for name, spec in expected.items():
        row = by_name.get(name)
        if row is None:
            errors.append(f"{name}: missing from report")
            continue
        errors.extend(_check_row(name, spec, row, allow_static=args.allow_static))

    if errors:
        for error in errors:
            print(f"FAIL: {error}", file=sys.stderr)
        return 1
    mode = "static" if args.allow_static else "full"
    print(f"OK: {len(expected)} fixtures matched expected verdicts ({mode} mode)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
