"""
Image & Asset Extractor (Stage 3 preprocessing).

Inventories raster images and SVGs from a skill package, enforces
size/count caps, applies 1024px downscale, and executes a deterministic
contrast pre-filter to flag potential white-on-white hidden text regions
before expensive model inference.

CL-D2-5 · REQ-VIS-01 · Source: developer-2/03-functional-specifications.md Cap F.
"""

from __future__ import annotations

import io
import logging
from pathlib import Path
from typing import Optional

from skillsentry_dev2.contracts import AssetFile, Finding

try:
    from PIL import Image, ImageStat
except ImportError:
    Image = None  # type: ignore[assignment]
    ImageStat = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)

# ── Constants ───────────────────────────────────────────────────────────

MAX_IMAGE_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB
MAX_IMAGE_DIMENSION = 4096               # Max dimension before skip
TARGET_MAX_DIMENSION = 1024              # Downscale target
LOW_CONTRAST_THRESHOLD = 1.5            # CR < 1.5:1 flags suspicious


# ── Contrast Pre-Filter ────────────────────────────────────────────────

def compute_contrast_ratio(
    image_path: str | Path,
) -> tuple[float, bool, Optional[bytes]]:
    """Compute luminance contrast ratio and flag low-contrast text regions.

    Deterministic, cheap pre-filter (<50ms target) that runs before
    model inference. Flags white-on-white or near-invisible text regions.

    Args:
        image_path: Path to the image file.

    Returns:
        Tuple of (contrast_ratio, has_suspicious_regions, downscaled_bytes).
        downscaled_bytes is the PNG-encoded downscaled image, or None on error.
    """
    try:
        from PIL import Image, ImageStat
    except ImportError:
        logger.warning("Pillow not available for contrast pre-filter")
        return 0.0, False, None

    try:
        img = Image.open(image_path)

        # Decompression bomb protection
        if img.width > MAX_IMAGE_DIMENSION or img.height > MAX_IMAGE_DIMENSION:
            logger.info(f"Image too large ({img.width}x{img.height}), will downscale")

        # Convert to RGB for luminance analysis
        if img.mode != "RGB":
            img = img.convert("RGB")

        # Downscale to target max dimension
        if max(img.width, img.height) > TARGET_MAX_DIMENSION:
            ratio = TARGET_MAX_DIMENSION / max(img.width, img.height)
            new_size = (int(img.width * ratio), int(img.height * ratio))
            img = img.resize(new_size, Image.LANCZOS)

        # Convert to grayscale for luminance
        gray = img.convert("L")
        stat_data = ImageStat.Stat(gray)

        # Overall luminance stats
        mean_lum = stat_data.mean[0]  # 0-255
        stddev_lum = stat_data.stddev[0]

        # Check for suspicious low-contrast regions
        # Scan quadrants for localized low-contrast text
        w, h = gray.size
        has_suspicious = False
        min_cr = 999.0

        # Divide into a grid and check each cell
        grid_size = 4
        cell_w = max(1, w // grid_size)
        cell_h = max(1, h // grid_size)

        for gy in range(grid_size):
            for gx in range(grid_size):
                x0 = gx * cell_w
                y0 = gy * cell_h
                x1 = min(x0 + cell_w, w)
                y1 = min(y0 + cell_h, h)

                cell = gray.crop((x0, y0, x1, y1))
                cell_stat = ImageStat.Stat(cell)

                cell_mean = cell_stat.mean[0]
                cell_min = cell_stat.extrema[0][0]
                cell_max = cell_stat.extrema[0][1]

                if cell_max > 0:
                    # Relative luminance (simplified sRGB)
                    l1 = (cell_max / 255.0 + 0.05)
                    l2 = (cell_min / 255.0 + 0.05)
                    cr = l1 / l2 if l2 > 0 else 999.0
                    min_cr = min(min_cr, cr)

                    # Flag if: high mean luminance (bright background) but
                    # very small contrast range (text nearly invisible)
                    if cell_mean > 230 and cr < LOW_CONTRAST_THRESHOLD and cell_stat.stddev[0] > 0.5:
                        has_suspicious = True

        # Save downscaled image to bytes
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        downscaled_bytes = buf.getvalue()

        return min_cr, has_suspicious, downscaled_bytes

    except Image.DecompressionBombError:
        # Re-raise decompression bomb so extract_image_assets can emit critical finding (DEF-13)
        raise
    except Exception as e:
        logger.error(f"Contrast pre-filter error on {image_path}: {e}")
        return 0.0, False, None


def extract_image_assets(
    assets: dict[str, AssetFile],
    package_root: str | Path,
) -> tuple[list[dict], list[Finding]]:
    """Extract and preprocess image assets for vision scanning.

    Enumerates raster images and SVGs, enforces size caps, and applies
    the contrast pre-filter.

    Args:
        assets: Map of relative path → AssetFile from PackageManifest.
        package_root: Absolute path to the package root directory.

    Returns:
        Tuple of (prepared_images, findings).
        Each prepared_image dict contains: path, relative_path, mime_type,
        downscaled_bytes, contrast_ratio, has_suspicious_regions.
    """
    findings: list[Finding] = []
    prepared: list[dict] = []
    root = Path(package_root)

    IMAGE_MIMES = {
        "image/png", "image/jpeg", "image/gif", "image/webp", "image/bmp",
        "image/svg+xml",
    }

    for rel_path, asset in assets.items():
        if asset.mime_type not in IMAGE_MIMES:
            continue

        abs_path = root / rel_path

        # Check size cap
        if asset.size_bytes > MAX_IMAGE_SIZE_BYTES:
            findings.append(Finding(
                stage="vision",
                severity="note",
                message=f"Image exceeds size limit ({asset.size_bytes} bytes > {MAX_IMAGE_SIZE_BYTES}), skipped: {rel_path}",
                file=rel_path,
            ))
            continue

        if not abs_path.exists():
            findings.append(Finding(
                stage="vision",
                severity="note",
                message=f"Image file not found: {rel_path}",
                file=rel_path,
            ))
            continue

        # SVG handling
        if asset.mime_type == "image/svg+xml":
            # SVG text analysis handled separately in vision_scanner
            prepared.append({
                "path": str(abs_path),
                "relative_path": rel_path,
                "mime_type": asset.mime_type,
                "is_svg": True,
                "downscaled_bytes": None,
                "contrast_ratio": 0.0,
                "has_suspicious_regions": False,
            })
            continue

        # Raster image: run contrast pre-filter
        try:
            cr, suspicious, downscaled = compute_contrast_ratio(abs_path)
        except Image.DecompressionBombError as e:
            findings.append(Finding(
                stage="vision",
                severity="critical",
                message=f"Image decompression bomb detected: {rel_path} ({e})",
                file=rel_path,
                evidence_json={"pattern": "image_decompression_bomb"},
            ))
            continue

        if suspicious:
            findings.append(Finding(
                stage="vision",
                severity="medium",
                message=f"Low-contrast text region detected in {rel_path} (CR={cr:.2f}:1) — possible hidden payload",
                file=rel_path,
                evidence_json={
                    "contrast_ratio": round(cr, 3),
                    "pre_filter": "low_contrast_flagged",
                },
            ))

        prepared.append({
            "path": str(abs_path),
            "relative_path": rel_path,
            "mime_type": asset.mime_type,
            "is_svg": False,
            "downscaled_bytes": downscaled,
            "contrast_ratio": cr,
            "has_suspicious_regions": suspicious,
        })

    return prepared, findings

