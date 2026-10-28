"""Versioned calibration for typed decision thresholds.

A calibration file records the capability threshold chosen from a labelled
corpus, the checkpoint it was fitted against, and the error counts that
justified it.  Thresholds are never assumed; without a file the provisional
``CAPABILITY_THRESHOLD`` applies and the report says ``uncalibrated``.

Temperature scaling works on the logit of each reported probability.  The
adapter exposes probabilities rather than raw logits, and ``logit(p)`` recovers
the same ordering and scale, so fitting ``T`` on those values is temperature
scaling in the usual sense.  Only the ``noul`` question type is calibrated here,
because every capability question is ``noul``.
"""

from __future__ import annotations

import json
import math
from collections.abc import Iterable, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

SCHEMA = "skillsentry.decision-calibration/v1"
_EPS = 1e-6
_TEMPERATURE_GRID = [round(0.05 * 1.05**step, 6) for step in range(0, 120)]


class CalibrationError(ValueError):
    """A calibration file is missing required fields or is malformed."""


@dataclass(frozen=True)
class Calibration:
    version: str
    checkpoint: str
    capability_threshold: float
    evaluated_cases: int
    malicious_cases: int
    false_negatives: int
    benign_flagged: int
    temperature: float = 1.0
    expected_calibration_error: float | None = None

    @property
    def label(self) -> str:
        return self.version or "uncalibrated"


def fit_capability_threshold(
    scored_cases: Iterable[tuple[float, bool]],
) -> tuple[float, int, int]:
    """Fit one threshold from ``(max_capability_probability, is_malicious)`` pairs.

    The threshold is the lowest malicious score, so no malicious case is missed
    on the fitted corpus.  Returns ``(threshold, false_negatives, benign_flagged)``.
    A corpus with no malicious cases cannot be fitted and raises.
    """

    cases = list(scored_cases)
    malicious = [score for score, is_malicious in cases if is_malicious]
    benign = [score for score, is_malicious in cases if not is_malicious]
    if not malicious:
        raise CalibrationError("calibration needs at least one malicious case")
    # Round down, never to nearest: a rounded-up threshold would miss a malicious case
    # that the fit itself saw.
    threshold = max(math.floor(min(malicious) * 10_000) / 10_000, 0.0001)
    false_negatives = sum(1 for score in malicious if score < threshold)
    benign_flagged = sum(1 for score in benign if score >= threshold)
    return threshold, false_negatives, benign_flagged


def _clamp(probability: float) -> float:
    return min(1.0 - _EPS, max(_EPS, float(probability)))


def calibrate_probability(probability: float, temperature: float) -> float:
    """Return ``sigmoid(logit(p) / T)``; ``T = 1`` leaves ``p`` unchanged."""

    if temperature <= 0:
        raise CalibrationError("temperature must be positive")
    p = _clamp(probability)
    logit = math.log(p / (1.0 - p))
    return _clamp(1.0 / (1.0 + math.exp(-logit / temperature)))


def fit_temperature(samples: Iterable[tuple[float, bool]]) -> float:
    """Fit ``T`` by minimising negative log-likelihood over a fixed grid.

    ``samples`` are ``(raw_probability, is_positive)`` pairs for one question
    type.  The grid is deterministic, so refitting the same corpus gives the same
    temperature.  With no samples the identity temperature ``1.0`` is returned.
    """

    pairs = list(samples)
    if not pairs:
        return 1.0

    def negative_log_likelihood(temperature: float) -> float:
        total = 0.0
        for probability, positive in pairs:
            q = calibrate_probability(probability, temperature)
            total -= math.log(q if positive else 1.0 - q)
        return total

    return min(_TEMPERATURE_GRID, key=negative_log_likelihood)


def expected_calibration_error(
    samples: Sequence[tuple[float, bool]],
    *,
    bins: int = 10,
) -> float:
    """Expected calibration error over ``bins`` equal-width probability bins."""

    if not samples:
        return 0.0
    buckets: list[list[tuple[float, bool]]] = [[] for _ in range(bins)]
    for probability, positive in samples:
        index = min(bins - 1, int(_clamp(probability) * bins))
        buckets[index].append((probability, positive))
    total = len(samples)
    error = 0.0
    for bucket in buckets:
        if not bucket:
            continue
        confidence = sum(p for p, _ in bucket) / len(bucket)
        accuracy = sum(1 for _, positive in bucket if positive) / len(bucket)
        error += abs(confidence - accuracy) * len(bucket) / total
    return round(error, 4)


def split_held_out(
    items: Sequence[Any],
    *,
    every: int = 4,
) -> tuple[list[Any], list[Any]]:
    """Deterministic ``(fit, held_out)`` split: every ``every``-th item is held out."""

    if every < 2:
        raise CalibrationError("held-out split needs every >= 2")
    fit = [item for index, item in enumerate(items) if index % every != 0]
    held_out = [item for index, item in enumerate(items) if index % every == 0]
    return fit, held_out


def load_calibration(path: str | Path | None) -> Calibration | None:
    """Return the calibration at ``path``, or ``None`` when no path is configured."""

    if path is None or not str(path).strip():
        return None
    target = Path(path)
    try:
        raw = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CalibrationError(f"cannot read calibration {target}: {exc}") from exc
    if not isinstance(raw, dict) or raw.get("schema") != SCHEMA:
        raise CalibrationError(f"{target} is not a {SCHEMA} file")
    try:
        threshold = float(raw["capability_threshold"])
    except (KeyError, TypeError, ValueError) as exc:
        raise CalibrationError("calibration is missing a numeric capability_threshold") from exc
    if not 0.0 < threshold <= 1.0:
        raise CalibrationError("capability_threshold must be in (0, 1]")
    try:
        temperature = float(raw.get("temperature", 1.0))
    except (TypeError, ValueError) as exc:
        raise CalibrationError("temperature must be a number") from exc
    if temperature <= 0:
        raise CalibrationError("temperature must be positive")
    ece = raw.get("expected_calibration_error")
    return Calibration(
        version=str(raw.get("version") or ""),
        checkpoint=str(raw.get("checkpoint") or ""),
        capability_threshold=threshold,
        evaluated_cases=int(raw.get("evaluated_cases", 0)),
        malicious_cases=int(raw.get("malicious_cases", 0)),
        false_negatives=int(raw.get("false_negatives", 0)),
        benign_flagged=int(raw.get("benign_flagged", 0)),
        temperature=temperature,
        expected_calibration_error=float(ece) if ece is not None else None,
    )


def write_calibration(path: str | Path, calibration: Calibration) -> None:
    """Write ``calibration`` as a schema-tagged JSON file."""

    payload: dict[str, Any] = {"schema": SCHEMA, **asdict(calibration)}
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


__all__ = [
    "SCHEMA",
    "Calibration",
    "CalibrationError",
    "CorpusRecord",
    "calibrate_probability",
    "expected_calibration_error",
    "fit_calibration",
    "fit_capability_threshold",
    "fit_temperature",
    "load_calibration",
    "split_held_out",
    "write_calibration",
]


@dataclass(frozen=True)
class CorpusRecord:
    """One scored corpus case.

    ``capabilities`` is the set of capability truths, or ``None`` when the case
    has none recorded (shipped fixtures).  ``raw`` maps capability question IDs to
    the backend's raw ``noul`` probabilities.
    """

    case_id: str
    label: str
    capabilities: frozenset[str] | None
    raw: dict[str, float]


def _case_score(record: CorpusRecord, temperature: float) -> float:
    return max(
        (calibrate_probability(probability, temperature) for probability in record.raw.values()),
        default=0.0,
    )


def _capability_pairs(
    records: Sequence[CorpusRecord],
    temperature: float | None = None,
) -> list[tuple[float, bool]]:
    pairs: list[tuple[float, bool]] = []
    for record in records:
        if record.capabilities is None:
            continue
        for question_id, probability in record.raw.items():
            value = (
                probability
                if temperature is None
                else calibrate_probability(probability, temperature)
            )
            pairs.append((value, question_id in record.capabilities))
    return pairs


def _evaluate(
    records: Sequence[CorpusRecord],
    threshold: float,
    temperature: float,
) -> dict[str, Any]:
    malicious = [r for r in records if r.label == "malicious"]
    benign = [r for r in records if r.label == "benign"]
    scores = {r.case_id: _case_score(r, temperature) for r in records}
    return {
        "cases": len(records),
        "malicious_cases": len(malicious),
        "false_negatives": sum(1 for r in malicious if scores[r.case_id] < threshold),
        "benign_flagged": sum(1 for r in benign if scores[r.case_id] >= threshold),
        "expected_calibration_error": expected_calibration_error(
            _capability_pairs(records, temperature)
        ),
    }


def fit_calibration(
    records: Sequence[CorpusRecord],
    *,
    version: str,
    checkpoint: str,
    every: int = 4,
) -> tuple[Calibration, dict[str, Any]]:
    """Fit temperature and threshold, then report on a held-out split.

    ``review`` cases are excluded from fitting and listed in the report.  The
    procedure fits on the non-held-out cases, evaluates on the held-out cases,
    and then refits on every fitting case for the file that gets written.  The
    report carries both the held-out result and the final fit so the difference
    is visible.
    """

    fitting = [r for r in records if r.label != "review"]
    review = [r.case_id for r in records if r.label == "review"]
    if not any(r.label == "malicious" for r in fitting):
        raise CalibrationError("calibration needs at least one malicious case")

    fit_set, held_out = split_held_out(fitting, every=every)
    temperature_fit = fit_temperature(_capability_pairs(fit_set))
    threshold_fit, _, _ = fit_capability_threshold(
        [(_case_score(r, temperature_fit), r.label == "malicious") for r in fit_set]
    )
    held_out_metrics = _evaluate(held_out, threshold_fit, temperature_fit) if held_out else None

    temperature = fit_temperature(_capability_pairs(fitting))
    threshold, false_negatives, benign_flagged = fit_capability_threshold(
        [(_case_score(r, temperature), r.label == "malicious") for r in fitting]
    )
    final = _evaluate(fitting, threshold, temperature)
    calibration = Calibration(
        version=version,
        checkpoint=checkpoint,
        capability_threshold=threshold,
        evaluated_cases=len(fitting),
        malicious_cases=final["malicious_cases"],
        false_negatives=false_negatives,
        benign_flagged=benign_flagged,
        temperature=temperature,
        expected_calibration_error=final["expected_calibration_error"],
    )
    report: dict[str, Any] = {
        "schema": "skillsentry.decision-calibration-report/v1",
        "version": version,
        "checkpoint": checkpoint,
        "review_cases_excluded": review,
        "fit_cases": len(fit_set),
        "held_out_cases": len(held_out),
        "temperature_on_fit_split": temperature_fit,
        "threshold_on_fit_split": threshold_fit,
        "held_out": held_out_metrics,
        "final": {**final, "temperature": temperature, "threshold": threshold},
    }
    return calibration, report
