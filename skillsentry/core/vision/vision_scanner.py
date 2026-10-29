"""Vision scanning for raster payloads and SVG instruction injection."""

from __future__ import annotations

import re
from typing import Any

import defusedxml.ElementTree as ET

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


_SVG_DANGEROUS_TAGS = frozenset({"script", "foreignobject", "iframe", "object", "embed", "use"})
_SVG_DANGEROUS_ATTRS = frozenset(
    {
        "onload",
        "onerror",
        "onclick",
        "onmouseover",
        "onfocus",
        "onblur",
        "onunload",
        "onresize",
        "onactivate",
        "onbegin",
        "onend",
    }
)
_DANGEROUS_URI_PREFIXES = ("javascript:", "data:text/html")
_SVG_HIDDEN_CSS = re.compile(
    r"(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0(?:\.0+)?)(?=[;\s\"\']|$)",
    re.IGNORECASE,
)
_SVG_TINY_TEXT = re.compile(
    r"font-size\s*:\s*0(?:\.0+)?(?:px|pt|em|rem)?(?=[;\s\"\']|$)|font-size\s*=\s*[\"\']0(?:\.0+)?(?:px|pt|em|rem)?[\"\']",
    re.IGNORECASE,
)

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
    text_lower = text.lower()

    # XML entity / DTD injection (Billion Laughs / XXE defense - DEF-12)
    if "<!entity" in text_lower or "<!doctype" in text_lower:
        findings.append(
            Finding(
                stage=Stage.VISION,
                severity=Severity.CRITICAL,
                message=f"Insecure XML entity/DTD declaration in SVG: {asset.relative}",
                type="xxe-entity-injection",
                evidence=FindingEvidence(
                    file=asset.relative,
                    line=1,
                    code=text[:200],
                ),
            )
        )
        return findings, text

    try:
        root = ET.fromstring(text)
        for elem in root.iter():
            local_name = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
            local_name_lower = local_name.lower()
            if local_name_lower in _SVG_DANGEROUS_TAGS:
                findings.append(
                    Finding(
                        stage=Stage.VISION,
                        severity=Severity.HIGH,
                        message=f"Dangerous SVG element detected: <{local_name}>",
                        type="svg-active-content",
                        evidence=FindingEvidence(
                            file=asset.relative, line=1, code=f"<{local_name}>"
                        ),
                    )
                )

            for attr_name, attr_val in elem.attrib.items():
                clean_attr = (attr_name.split("}")[-1] if "}" in attr_name else attr_name).lower()
                val_clean = attr_val.strip().lower()
                val_compact = re.sub(r"[\s\x00-\x1f]+", "", val_clean)

                if clean_attr in _SVG_DANGEROUS_ATTRS:
                    findings.append(
                        Finding(
                            stage=Stage.VISION,
                            severity=Severity.HIGH,
                            message=f'Event handler in SVG: {clean_attr}="{attr_val[:80]}"',
                            type="svg-active-content",
                            evidence=FindingEvidence(
                                file=asset.relative, line=1, code=f"{clean_attr}={attr_val[:100]}"
                            ),
                        )
                    )

                for prefix in _DANGEROUS_URI_PREFIXES:
                    if prefix in val_compact:
                        findings.append(
                            Finding(
                                stage=Stage.VISION,
                                severity=Severity.CRITICAL,
                                message=f"Dangerous URI scheme '{prefix}' in SVG attribute '{clean_attr}'",
                                type="svg-dangerous-uri",
                                evidence=FindingEvidence(
                                    file=asset.relative,
                                    line=1,
                                    code=f"{clean_attr}={attr_val[:100]}",
                                ),
                            )
                        )

                if clean_attr == "font-size" and (
                    val_clean in ("0", "0px", "1px", "0pt", "0.001", "0.01")
                    or re.match(r"^0(?:\.0+)?(?:px|pt|em|rem)?$", val_clean)
                ):
                    findings.append(
                        Finding(
                            stage=Stage.VISION,
                            severity=Severity.HIGH,
                            message=f"Tiny-text obfuscation detected: font-size='{attr_val}'",
                            type="svg-tiny-text",
                            evidence=FindingEvidence(
                                file=asset.relative, line=1, code=f"font-size={attr_val[:100]}"
                            ),
                        )
                    )
    except Exception as exc:
        if "entity" in str(exc).lower() or "dtd" in str(exc).lower():
            findings.append(
                Finding(
                    stage=Stage.VISION,
                    severity=Severity.CRITICAL,
                    message=f"XML entity expansion blocked by defusedxml in SVG: {asset.relative}",
                    type="xxe-entity-injection",
                    evidence=FindingEvidence(file=asset.relative, line=1, code=text[:200]),
                )
            )
            return findings, text

    if _SVG_HIDDEN_CSS.search(text) and not any(f.type == "svg-hidden-css" for f in findings):
        findings.append(
            Finding(
                stage=Stage.VISION,
                severity=Severity.MEDIUM,
                message="Hidden CSS detected in SVG (display:none, opacity:0, or visibility:hidden)",
                type="svg-hidden-css",
                evidence=FindingEvidence(
                    file=asset.relative, line=1, code=_SVG_HIDDEN_CSS.search(text).group(0)[:100]
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
            telemetry={"images_scanned": 0, "notes": notes, "vision_status": "not_applicable"},
        )

    findings: list[Finding] = []
    evidence: list[VisionEvidence] = []
    degraded_errors: list[str] = []
    analysed = 0
    skipped = 0
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
        try:
            analysis = model.analyze_image(
                asset.path, f"Scan {asset.relative} for hidden instructions"
            )
        except Exception as exc:
            skipped += 1
            if "decompressionbomb" in str(exc).lower():
                findings.append(
                    Finding(
                        stage=Stage.VISION,
                        severity=Severity.CRITICAL,
                        message=f"Image decompression bomb detected: {asset.relative}",
                        type="image-decompression-bomb",
                        evidence=FindingEvidence(file=asset.relative, line=1, code=str(exc)[:200]),
                    )
                )
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
    if skipped == 0:
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
