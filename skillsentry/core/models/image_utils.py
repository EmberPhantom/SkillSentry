"""Image loading and downscaling shared by local and cloud model clients."""

from __future__ import annotations

import base64
import io
from pathlib import Path

MAX_IMAGE_BYTES = 20 * 1024 * 1024
MAX_IMAGE_PIXELS = 40_000_000

_MIME_BY_FORMAT = {
    "JPEG": "image/jpeg",
    "JPG": "image/jpeg",
    "PNG": "image/png",
    "WEBP": "image/webp",
}


class ImagePreparationError(ValueError):
    """The image cannot be sent to a model (unsupported, corrupt, too large)."""


def load_image_for_model(path: str | Path, *, max_px: int = 1024) -> tuple[str, str]:
    """Return ``(mime_type, base64_data)`` for a raster image.

    The image is re-encoded, which strips metadata and bounds the payload size.
    Animated GIFs use the first frame; non-web formats are converted to PNG.
    SVG and other vector formats are intentionally rejected here: Dev 2's
    vision pipeline renders SVG to a raster image and scans its text separately.
    """

    if max_px < 64:
        raise ImagePreparationError("max_px must be at least 64")
    source = Path(path)
    try:
        raw = source.read_bytes()
    except OSError as exc:
        raise ImagePreparationError(f"could not read image: {source}") from exc
    if len(raw) > MAX_IMAGE_BYTES:
        raise ImagePreparationError(f"image exceeds {MAX_IMAGE_BYTES} bytes")

    try:
        from PIL import Image, ImageOps, UnidentifiedImageError
    except ImportError as exc:  # pragma: no cover - Pillow is a hard dependency
        raise ImagePreparationError("Pillow is required for image analysis") from exc

    try:
        with Image.open(io.BytesIO(raw)) as opened:
            image_format = (opened.format or "").upper()
            if image_format == "SVG":
                raise ImagePreparationError("SVG must be rendered before model analysis")
            if opened.width * opened.height > MAX_IMAGE_PIXELS:
                raise ImagePreparationError(
                    f"image exceeds {MAX_IMAGE_PIXELS} pixels before downscaling"
                )
            opened.seek(0)
            image = ImageOps.exif_transpose(opened)
            if image.mode not in {"RGB", "RGBA", "L"}:
                image = image.convert("RGBA" if "A" in image.getbands() else "RGB")
            if max(image.size) > max_px:
                image.thumbnail((max_px, max_px), Image.Resampling.LANCZOS)

            if image_format in {"JPEG", "JPG"}:
                mime = "image/jpeg"
                output_format = "JPEG"
                if image.mode != "RGB":
                    image = image.convert("RGB")
                save_kwargs = {"quality": 85, "optimize": True}
            elif image_format == "WEBP":
                mime = "image/webp"
                output_format = "WEBP"
                save_kwargs = {"quality": 85, "method": 4}
            else:
                # PNG is the safe common denominator for GIF/BMP/TIFF and
                # preserves alpha for transparent logos.
                mime = "image/png"
                output_format = "PNG"
                save_kwargs = {"optimize": True}

            output = io.BytesIO()
            image.save(output, format=output_format, **save_kwargs)
            payload = output.getvalue()
    except ImagePreparationError:
        raise
    except (
        OSError,
        UnidentifiedImageError,
        ValueError,
        SyntaxError,
        Image.DecompressionBombError,
    ) as exc:
        raise ImagePreparationError(f"could not decode image: {source}") from exc

    if not payload:
        raise ImagePreparationError(f"image encoded to an empty payload: {source}")
    return mime, base64.b64encode(payload).decode("ascii")


def image_mime_from_format(image_format: str | None) -> str:
    """Map a PIL format name to a supported model MIME type."""

    return _MIME_BY_FORMAT.get((image_format or "").upper(), "image/png")


__all__ = [
    "MAX_IMAGE_BYTES",
    "MAX_IMAGE_PIXELS",
    "ImagePreparationError",
    "image_mime_from_format",
    "load_image_for_model",
]
