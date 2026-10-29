"""
Vision Scanner (Stage 3).

Coordinates Gemma 4 Vision OCR via the Model Client interface (I2),
extracts bounding boxes for Gemma's Eye View, performs dual SVG scan
(XML text + rendered raster), and classifies hidden injection payloads.

CL-D2-5 · REQ-VIS-02/03 · Source: developer-2/03-functional-specifications.md Cap F.
"""

from __future__ import annotations

import json
import logging
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Optional

from skillsentry_dev2.contracts import (
    Finding,
    ModelClient,
    ModelUnavailableError,
    PackageManifest,
    StageResult,
)
from skillsentry_dev2.core.semantic.prompts import VISION_PROMPT
from skillsentry_dev2.core.vision.image_extractor import extract_image_assets

logger = logging.getLogger(__name__)


# ── SVG Static XML Analysis ────────────────────────────────────────────

_SVG_DANGEROUS_TAGS = {"script", "foreignobject", "iframe"}
_SVG_DANGEROUS_ATTRS = {"onload", "onclick", "onerror", "onmouseover"}
_SVG_HIDDEN_CSS = re.compile(
    r"(?:display\s*:\s*none|opacity\s*:\s*0(?:\.0+)?|visibility\s*:\s*hidden)",
    re.IGNORECASE,
)


def _scan_svg_static(svg_path: str, rel_path: str) -> list[Finding]:
    """Parse SVG as XML and detect dangerous elements/attributes.

    Returns findings for script tags, event handlers, foreignObject,
    and CSS obfuscation patterns.
    """
    findings: list[Finding] = []

    try:
        content = Path(svg_path).read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        findings.append(Finding(
            stage="vision",
            severity="high",
            message=f"Cannot read SVG file: {e}",
            file=rel_path,
        ))
        return findings

    # Check for XML Entity / DTD injection (Billion Laughs / XXE defense — DEF-12)
    content_lower = content.lower()
    if "<!entity" in content_lower or "<!doctype" in content_lower:
        findings.append(Finding(
            stage="vision",
            severity="critical",
            message=f"Insecure XML entity/DTD declaration in SVG: {rel_path}",
            file=rel_path,
            evidence_json={"pattern": "xxe_dtd_injection"},
        ))
        return findings

    try:
        root = ET.fromstring(content)
    except ET.ParseError:
        # Treat as text and do regex scanning
        for tag_name in _SVG_DANGEROUS_TAGS:
            if f"<{tag_name}" in content.lower():
                findings.append(Finding(
                    stage="vision",
                    severity="high",
                    message=f"Dangerous SVG element detected: <{tag_name}>",
                    file=rel_path,
                ))
        return findings

    # Walk tree
    for elem in root.iter():
        # Strip namespace
        local_name = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag

        # Check dangerous tags
        if local_name.lower() in _SVG_DANGEROUS_TAGS:
            findings.append(Finding(
                stage="vision",
                severity="high",
                message=f"Dangerous SVG element: <{local_name}>",
                file=rel_path,
                evidence_json={"element": local_name},
            ))

        # Check dangerous attributes
        for attr_name in elem.attrib:
            clean_attr = attr_name.split("}")[-1] if "}" in attr_name else attr_name
            if clean_attr.lower() in _SVG_DANGEROUS_ATTRS:
                findings.append(Finding(
                    stage="vision",
                    severity="high",
                    message=f"Event handler in SVG: {clean_attr}=\"{elem.attrib[attr_name][:80]}\"",
                    file=rel_path,
                    evidence_json={
                        "attribute": clean_attr,
                        "value": elem.attrib[attr_name][:200],
                    },
                ))

    # Check for hidden CSS in style elements and attributes
    if _SVG_HIDDEN_CSS.search(content):
        findings.append(Finding(
            stage="vision",
            severity="medium",
            message="Hidden CSS detected in SVG (display:none, opacity:0, or visibility:hidden)",
            file=rel_path,
        ))

    return findings


# ── Vision Model Analysis ──────────────────────────────────────────────

def _analyze_image_with_model(
    image_path: str,
    rel_path: str,
    model_client: ModelClient,
    has_suspicious_regions: bool,
    contrast_ratio: float,
) -> tuple[list[Finding], bool]:
    """Submit an image to the vision model for OCR and injection detection.

    Returns (findings, degraded).
    """
    findings: list[Finding] = []
    is_degraded = False

    try:
        response = model_client.analyze_image(
            image_path=image_path,
            prompt=VISION_PROMPT,
        )
    except ModelUnavailableError:
        findings.append(Finding(
            stage="vision",
            severity="note",
            message=f"Vision model unavailable for image: {rel_path}",
            file=rel_path,
        ))
        return findings, True
    except Exception as e:
        findings.append(Finding(
            stage="vision",
            severity="note",
            message=f"Vision analysis error on {rel_path}: {e}",
            file=rel_path,
        ))
        return findings, True

    if not isinstance(response, dict):
        return findings, True

    # Extract OCR and injection results
    has_hidden_text = bool(response.get("has_hidden_text", False))
    ocr_text = str(response.get("ocr_text", ""))
    is_injection = bool(response.get("is_injection", False))
    injection_type = str(response.get("injection_type", "none"))
    bboxes = response.get("bboxes", [])
    try:
        confidence = float(response.get("confidence", 0.5))
    except (ValueError, TypeError):
        confidence = 0.5

    if is_injection and ocr_text:
        # Build evidence with INT-3 bounding box contract
        bbox_list = []
        if bboxes and isinstance(bboxes, list):
            for bb in bboxes:
                if isinstance(bb, dict):
                    try:
                        bbox_list.append([
                            float(bb.get("x", 0.0)),
                            float(bb.get("y", 0.0)),
                            float(bb.get("w", 0.0)),
                            float(bb.get("h", 0.0)),
                        ])
                    except (ValueError, TypeError):
                        bbox_list.append([0.0, 0.0, 1.0, 1.0])

        findings.append(Finding(
            stage="vision",
            severity="critical",
            message=f"Hidden prompt injection detected in image '{rel_path}'",
            file=rel_path,
            evidence_json={
                "ocr": ocr_text[:500],
                "bbox": bbox_list[0] if bbox_list else [0.0, 0.0, 1.0, 1.0],
                "view_modes": ["Normal", "Contrast", "GemmasEye"],
                "contrast_ratio": round(float(contrast_ratio), 3),
                "confidence": round(confidence, 3),
                "injection_type": injection_type,
            },
        ))
    elif has_hidden_text and ocr_text:
        findings.append(Finding(
            stage="vision",
            severity="medium",
            message=f"Hidden text detected in image '{rel_path}': {ocr_text[:100]}",
            file=rel_path,
            evidence_json={
                "ocr": ocr_text[:500],
                "bbox": [0.0, 0.0, 1.0, 1.0],
                "view_modes": ["Normal", "Contrast", "GemmasEye"],
                "contrast_ratio": round(float(contrast_ratio), 3),
                "confidence": round(confidence, 3),
            },
        ))

    return findings, is_degraded


# ── Public API ──────────────────────────────────────────────────────────

def scan_visual_assets(
    manifest: PackageManifest,
    model_client: Optional[ModelClient],
    package_root: str | Path,
) -> StageResult:
    """Scan all visual assets in a skill package for hidden payloads.

    Args:
        manifest: Parsed PackageManifest from Stage 1.
        model_client: I2 model client (real or MockGemma). None if unavailable.
        package_root: Absolute path to the skill package root.

    Returns:
        StageResult with stage='vision' and findings.
    """
    all_findings: list[Finding] = []
    signals: dict[str, float] = {"vision_risk": 0.0, "vision": 0.0}
    stage_degraded = False

    if not manifest.assets:
        all_findings.append(Finding(
            stage="vision",
            severity="note",
            message="No visual assets found in package",
        ))
        return StageResult(
            stage="vision",
            findings=all_findings,
            signals=signals,
            telemetry={"image_count": 0},
        )

    # Extract and preprocess images
    prepared_images, extract_findings = extract_image_assets(
        manifest.assets, package_root,
    )
    all_findings.extend(extract_findings)
    if any(f.severity == "critical" and "bomb" in f.message.lower() for f in extract_findings):
        stage_degraded = True

    if not prepared_images:
        all_findings.append(Finding(
            stage="vision",
            severity="note",
            message="No scannable images found in package assets",
        ))
        return StageResult(
            stage="vision",
            findings=all_findings,
            signals=signals,
            telemetry={"image_count": 0},
        )

    # Process each image
    for img_info in prepared_images:
        rel_path = img_info["relative_path"]

        if img_info["is_svg"]:
            # SVG dual-scan: static XML analysis
            svg_findings = _scan_svg_static(img_info["path"], rel_path)
            all_findings.extend(svg_findings)

            # SVG vision model scan (rendered raster) — requires model
            if model_client is not None:
                model_findings, model_degraded = _analyze_image_with_model(
                    img_info["path"], rel_path, model_client,
                    img_info["has_suspicious_regions"],
                    img_info["contrast_ratio"],
                )
                if model_degraded:
                    stage_degraded = True
                # Deduplicate with static findings
                existing_msgs = {f.message for f in svg_findings}
                for mf in model_findings:
                    if mf.message not in existing_msgs:
                        all_findings.append(mf)
            else:
                stage_degraded = True
        else:
            # Raster image: model analysis
            if model_client is not None:
                model_findings, model_degraded = _analyze_image_with_model(
                    img_info["path"], rel_path, model_client,
                    img_info["has_suspicious_regions"],
                    img_info["contrast_ratio"],
                )
                if model_degraded:
                    stage_degraded = True
                all_findings.extend(model_findings)
            else:
                stage_degraded = True

    # Compute vision risk signal
    critical_findings = [f for f in all_findings if f.severity == "critical"]
    high_findings = [f for f in all_findings if f.severity == "high"]
    medium_findings = [f for f in all_findings if f.severity == "medium"]

    vision_risk = min(100.0, (
        len(critical_findings) * 40.0
        + len(high_findings) * 25.0
        + len(medium_findings) * 10.0
    ))
    signals["vision_risk"] = vision_risk
    signals["vision"] = vision_risk

    return StageResult(
        stage="vision",
        findings=all_findings,
        signals=signals,
        degraded=stage_degraded,
        telemetry={"image_count": len(prepared_images)},
    )

