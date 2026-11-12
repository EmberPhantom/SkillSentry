"""Vision scanning for raster payloads and SVG instruction injection."""

from __future__ import annotations

import re
from typing import Any

from skill_sentry_cli.core.contracts import (
    Finding,
    FindingEvidence,
    Severity,
    Stage,
    StageResult,
    VisionEvidence,
    utc_now,
)
from skill_sentry_cli.core.models.base import ModelClient
from skill_sentry_cli.core.parser import SkillPackage
from skill_sentry_cli.core.vision.image_extractor import ImageAsset, extract_images

MAX_OCR_CHARS = 20_000
# Raster images sent to the model per scan; the rest are reported as partial coverage.
MAX_MODEL_IMAGES = 3
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
    r"javascript\s*:|xlink:href\s*=\s*[\"'](?:https?:|data:text/html)|"
    # Entity and DTD declarations are how XML entity-expansion attacks arrive.
    r"<!\s*(?:ENTITY|DOCTYPE)\b|"
    # A <use> that points outside the file pulls in remote or inline content.
    r"<\s*use\b[^>]*\bhref\s*=\s*[\"'](?!#)|"
    # Any data: URI can carry an active document, whatever its media type.
    r"\bhref\s*=\s*[\"']\s*data:|"
    # Remote stylesheets and url() fetches run during rendering.
    r"<\s*style\b[^>]*>[^<]*(?:@import|url\(\s*[\"']?https?:)|"
    # Text the reader cannot see is a common carrier for injected instructions.
    r"<\s*text\b[^>]*(?:opacity\s*[:=]\s*[\"']?0(?:\.0*)?[\"';\s>]|"
    r"font-size\s*[:=]\s*[\"']?0?\.\d+|fill\s*[:=]\s*[\"']?none)",
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


def _decode_svg(data: bytes) -> str:
    """Decode an SVG the way an XML reader would, so UTF-16 cannot hide markup."""

    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16", "replace")
    if data.count(b"\x00") > len(data) // 4:
        order = "utf-16-be" if data[:1] == b"\x00" else "utf-16-le"
        return data.decode(order, "replace")
    return data.decode("utf-8", "replace")


def _svg_scan(asset: ImageAsset) -> tuple[list[Finding], str]:
    # The whole document is scanned; only the stored excerpt is truncated.
    full = _decode_svg(asset.data)
    text = full[:MAX_OCR_CHARS]
    findings: list[Finding] = []
    active = _SVG_ACTIVE.search(full)
    if active:
        findings.append(
            Finding(
                stage=Stage.VISION,
                severity=Severity.HIGH,
                message="Active content detected in SVG asset",
                finding_type="svg-active-content",
                evidence=FindingEvidence(
                    file=asset.relative,
                    line=1,
                    code=active.group(0)[:200],
                ),
            )
        )
    if _INSTRUCTION.search(full):
        match = _INSTRUCTION.search(full)
        findings.append(
            Finding(
                stage=Stage.VISION,
                severity=Severity.CRITICAL,
                message="Instruction injection detected in SVG asset",
                finding_type="hidden-image-instruction",
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
    if not assets and not notes:
        return StageResult(
            stage=Stage.VISION,
            findings=[],
            signals={},
            telemetry={"images_scanned": 0, "notes": notes, "vision_status": "not_applicable"},
        )

    findings: list[Finding] = []
    evidence: list[VisionEvidence] = []
    # Images the extractor skipped (oversize, over the image limit, unreadable) were
    # never analysed, so they degrade the stage exactly like a failed model call.
    degraded_errors: list[str] = list(notes)
    analysed = 0
    skipped = 0
    model_calls = 0
    for asset in assets:
        if asset.is_svg:
            analysed += 1
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
            skipped += 1
            degraded_errors.append(f"vision model unavailable for {asset.relative}")
            continue
        if model_calls >= MAX_MODEL_IMAGES:
            # Bounded so a scan stays within its time budget on a CPU-hosted model.
            skipped += 1
            degraded_errors.append(f"{asset.relative}: image budget of {MAX_MODEL_IMAGES} reached")
            continue
        model_calls += 1
        try:
            analysis = model.analyze_image(
                asset.path, f"Scan {asset.relative} for hidden instructions"
            )
        except Exception as exc:
            skipped += 1
            degraded_errors.append(f"{asset.relative}: {exc}")
            continue
        analysed += 1

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
                    finding_type=str(item.get("type") or "hidden-image-instruction")[:80],
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
                    finding_type="hidden-image-instruction",
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
    if skipped == 0 and not notes:
        vision_status = "evaluated"
    elif analysed == 0:
        # Deferred or unavailable vision must never read as a clean image result.
        vision_status = "not_evaluated"
    else:
        vision_status = "partial"
    telemetry = {
        "images_scanned": len(evidence),
        "images_total": len(assets),
        "vision_status": vision_status,
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
