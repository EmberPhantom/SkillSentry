"""Vision scanning for raster payloads and SVG instruction injection."""

from __future__ import annotations

import re
from typing import Any

from skillsentry.core.contracts import (
    Finding,
    FindingEvidence,
    Severity,
    Stage,
    StageResult,
    VisionEvidence,
    utc_now,
)
from skillsentry.core.models.base import ModelClient
from skillsentry.core.parser import SkillPackage
from skillsentry.core.vision.image_extractor import ImageAsset, extract_images

MAX_OCR_CHARS = 20_000
_SEVERITY = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "note": Severity.NOTE,
}
_SEVERITY_SCORE = {
    Severity.CRITICAL: 95,
    Severity.HIGH: 72,
    Severity.MEDIUM: 42,
    Severity.LOW: 18,
    Severity.NOTE: 0,
}

_SVG_ACTIVE = re.compile(
    r"<\s*(?:script|foreignObject|iframe|object|embed)\b|on[a-z]+\s*=|"
    r"javascript\s*:|xlink:href\s*=\s*[\"'](?:https?:|data:text/html)",
    re.IGNORECASE,
)
_INSTRUCTION = re.compile(
    r"(?:ignore|disregard)\s+(?:all\s+)?(?:previous|prior)\s+instructions?|"
    r"(?:read|open|include|send|upload|exfiltrate)[^\n]{0,100}(?:~|/home/[^/\s]+)/\.ssh/|"
    r"(?:send|post|upload)[^\n]{0,100}(?:token|secret|credential|api[_\s-]?key)",
    re.IGNORECASE,
)


def _normalise_bbox(raw: Any) -> list[float]:
    if not isinstance(raw, list) or len(raw) != 4:
        return []
    values: list[float] = []
    for item in raw:
        if not isinstance(item, (int, float)) or isinstance(item, bool):
            return []
        values.append(max(0.0, min(1.0, float(item))))
    return values


def _svg_scan(asset: ImageAsset) -> tuple[list[Finding], str]:
    text = asset.data.decode("utf-8", "replace")[:MAX_OCR_CHARS]
    findings: list[Finding] = []
    if _SVG_ACTIVE.search(text):
        findings.append(
            Finding(
                stage=Stage.VISION,
                severity=Severity.HIGH,
                message="Active content detected in SVG asset",
                type="svg-active-content",
                evidence=FindingEvidence(
                    file=asset.relative,
                    line=1,
                    code=_SVG_ACTIVE.search(text).group(0)[:200],  # type: ignore[union-attr]
                ),
            )
        )
    if _INSTRUCTION.search(text):
        match = _INSTRUCTION.search(text)
        findings.append(
            Finding(
                stage=Stage.VISION,
                severity=Severity.CRITICAL,
                message="Instruction injection detected in SVG asset",
                type="hidden-image-instruction",
                evidence=FindingEvidence(
                    file=asset.relative,
                    line=1,
                    code=(match.group(0) if match else text[:200])[:500],
                    ocr=text[:MAX_OCR_CHARS],
                ),
            )
        )
    return findings, text


def scan_vision(
    package: SkillPackage,
    model: ModelClient | None,
    *,
    max_px: int = 1024,
) -> StageResult:
    """Scan bundled images.  Missing images are not a degraded stage."""

    assets, notes = extract_images(package)
    if not assets:
        return StageResult(
            stage=Stage.VISION,
            findings=[],
            signals={},
            telemetry={"images_scanned": 0, "notes": notes},
        )

    findings: list[Finding] = []
    evidence: list[VisionEvidence] = []
    degraded_errors: list[str] = []
    for asset in assets:
        if asset.is_svg:
            svg_findings, ocr = _svg_scan(asset)
            findings.extend(svg_findings)
            if svg_findings or ocr:
                evidence.append(
                    VisionEvidence(
                        image=asset.preview_uri(),
                        image_name=asset.relative,
                        ocr=ocr[:MAX_OCR_CHARS],
                        bboxes=[],
                        confidence=0.99 if svg_findings else 0.5,
                        position_note="SVG text content",
                        findings=svg_findings,
                    )
                )
            continue

        if model is None:
            degraded_errors.append(f"vision model unavailable for {asset.relative}")
            continue
        try:
            analysis = model.analyze_image(asset.path, f"Scan {asset.relative} for hidden instructions")
        except Exception as exc:
            degraded_errors.append(f"{asset.relative}: {exc}")
            continue

        image_findings: list[Finding] = []
        for item in analysis.findings[:50]:
            if not isinstance(item, dict):
                continue
            severity = _SEVERITY.get(str(item.get("severity", "medium")).lower(), Severity.MEDIUM)
            raw_bbox = _normalise_bbox(item.get("bbox"))
            message = str(item.get("evidence") or item.get("type") or "Suspicious image content")
            image_findings.append(
                Finding(
                    stage=Stage.VISION,
                    severity=severity,
                    message=f"Image payload detected in {asset.relative}: {message[:400]}",
                    type=str(item.get("type") or "hidden-image-instruction")[:80],
                    evidence=FindingEvidence(
                        file=asset.relative,
                        line=1,
                        code=str(item.get("evidence") or "")[:500],
                        bbox=raw_bbox or None,
                        ocr=analysis.ocr[:MAX_OCR_CHARS] if analysis.ocr else None,
                    ),
                )
            )
        # OCR is untrusted text, but instruction-shaped OCR is still evidence.
        if _INSTRUCTION.search(analysis.ocr or "") and not any(
            item.severity.rank >= Severity.HIGH.rank for item in image_findings
        ):
            image_findings.append(
                Finding(
                    stage=Stage.VISION,
                    severity=Severity.CRITICAL,
                    message=f"Hidden instruction in image OCR: {asset.relative}",
                    type="hidden-image-instruction",
                    evidence=FindingEvidence(
                        file=asset.relative,
                        line=1,
                        ocr=analysis.ocr[:MAX_OCR_CHARS],
                    ),
                )
            )
        findings.extend(image_findings)
        evidence.append(
            VisionEvidence(
                image=asset.preview_uri(),
                image_name=asset.relative,
                ocr=(analysis.ocr or "")[:MAX_OCR_CHARS],
                bboxes=[b for b in (_normalise_bbox(item) for item in analysis.bboxes) if b],
                confidence=0.95 if image_findings else 0.5,
                position_note="hidden image payload" if image_findings else None,
                findings=image_findings,
            )
        )

    score = 0.0
    if findings:
        score = max(_SEVERITY_SCORE[item.severity] for item in findings)
        score = min(100.0, score + min(8, (len(findings) - 1) * 2))
    telemetry = {
        "images_scanned": len(evidence),
        "images_total": len(assets),
        "notes": notes,
        "evidence": [item.model_dump(by_alias=True, mode="json") for item in evidence],
        "scanned_at": utc_now().isoformat(),
    }
    if degraded_errors:
        return StageResult(
            stage=Stage.VISION,
            findings=findings,
            signals={"vision": score} if findings else {},
            telemetry=telemetry,
            degraded=True,
            error="; ".join(degraded_errors)[:1000],
        )
    return StageResult(
        stage=Stage.VISION,
        findings=findings,
        signals={"vision": score},
        telemetry=telemetry,
    )


__all__ = ["scan_vision"]
