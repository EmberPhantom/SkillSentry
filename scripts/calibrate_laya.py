"""Calibrate Laya's capability threshold and temperature against the labelled corpus.

Needs a working Laya install (``pip install "skillsentry[laya]"``) and a
checkpoint.  Any case that cannot be scored aborts the run, so a partial corpus
never produces a calibration file.  ``review`` cases are reported but excluded
from fitting.  The report separates the held-out result from the final fit.

Exit status is 1 when the final fit still misses a malicious case.

Example:
    python scripts/calibrate_laya.py --version cal-2026-10-28 \
        --out calibration.json --report calibration-report.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from skillsentry.core.config import DecisionSettings
from skillsentry.core.decisions import DecisionResult, LayaDecisionClient, semantic_questions
from skillsentry.core.decisions.calibration import (
    CalibrationError,
    CorpusRecord,
    fit_calibration,
    write_calibration,
)
from skillsentry.core.decisions.questions import CAPABILITY_QUESTIONS
from skillsentry.core.parser import parse_skill
from skillsentry.core.semantic import scan_anchors
from skillsentry.core.semantic.laya_analyzer import build_decision_state

REPO = Path(__file__).resolve().parent.parent
DEFAULT_LABELS = REPO / "tests" / "fixtures" / "decisions" / "labels.json"


def record_from_result(case: dict[str, Any], result: DecisionResult) -> CorpusRecord:
    """Turn one backend result into a corpus record; abstentions are omitted."""

    raw = {
        qid: float(answer.noul)
        for qid in CAPABILITY_QUESTIONS
        if (answer := result.answers.get(qid)) is not None
        and not answer.abstention
        and answer.noul is not None
    }
    truths = case.get("capabilities")
    return CorpusRecord(
        case_id=case["id"],
        label=case["label"],
        capabilities=frozenset(truths) if truths is not None else None,
        raw=raw,
    )


def run_corpus(
    client: LayaDecisionClient,
    manifest: dict[str, Any],
    *,
    root: Path,
    timeout_s: float,
) -> tuple[list[CorpusRecord], str]:
    """Score every case; return the records and the checkpoint that answered."""

    records: list[CorpusRecord] = []
    checkpoint = ""
    for case in manifest["cases"]:
        package = parse_skill(root / case["path"])
        state, *_ = build_decision_state(package, scan_anchors(package))
        try:
            result = client.decide(state, semantic_questions(), timeout_s=timeout_s)
        except Exception as exc:  # abort: a partial corpus must not calibrate
            raise CalibrationError(f"case {case['id']} could not be scored: {exc}") from exc
        checkpoint = result.checkpoint
        records.append(record_from_result(case, result))
    return records, checkpoint


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--labels", type=Path, default=DEFAULT_LABELS)
    parser.add_argument("--out", type=Path, required=True, help="calibration JSON to write")
    parser.add_argument("--report", type=Path, help="calibration report JSON to write")
    parser.add_argument("--version", required=True, help="calibration version label")
    parser.add_argument("--checkpoint", default="english")
    parser.add_argument("--device", default="auto")
    parser.add_argument("--timeout", type=float, default=600.0)
    args = parser.parse_args(argv)

    manifest = json.loads(args.labels.read_text(encoding="utf-8"))
    settings = DecisionSettings(
        checkpoint=args.checkpoint,
        device=args.device,
        timeout_s=args.timeout,
    )
    client = LayaDecisionClient(settings)
    try:
        records, checkpoint = run_corpus(client, manifest, root=REPO, timeout_s=settings.timeout_s)
        calibration, report = fit_calibration(records, version=args.version, checkpoint=checkpoint)
    except CalibrationError as exc:
        print(f"calibration aborted: {exc}", file=sys.stderr)
        return 2
    finally:
        client.close()

    write_calibration(args.out, calibration)
    if args.report is not None:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    final = report["final"]
    print(
        f"threshold={calibration.capability_threshold} temperature={calibration.temperature} "
        f"final false_negatives={final['false_negatives']}/{final['malicious_cases']} "
        f"benign_flagged={final['benign_flagged']} -> {args.out}"
    )
    held = report["held_out"]
    if held is not None:
        print(
            f"held-out false_negatives={held['false_negatives']}/{held['malicious_cases']} "
            f"benign_flagged={held['benign_flagged']}/{held['cases'] - held['malicious_cases']}"
        )
    return 0 if final["false_negatives"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
