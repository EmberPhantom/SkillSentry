"""Bounded image discovery and safe preview construction for vision analysis."""

from __future__ import annotations

import base64
import mimetypes
from dataclasses import dataclass
from pathlib import Path

from skill_sentry_cli.core.parser import SkillPackage
from skill_sentry_cli.core.parser.skill_parser import IMAGE_SUFFIXES

MAX_IMAGES = 20
MAX_IMAGE_BYTES = 20 * 1024 * 1024
MAX_PREVIEW_BYTES = 2 * 1024 * 1024


@dataclass(frozen=True)
class ImageAsset:
    path: Path
    relative: str
    suffix: str
    size: int
    data: bytes
    mime: str

    @property
    def is_svg(self) -> bool:
        return self.suffix == ".svg"

    def preview_uri(self) -> str:
        payload = self.data
        if len(payload) > MAX_PREVIEW_BYTES:
            # The API schema needs a displayable string.  Do not inline
            # arbitrarily large blobs into a verdict; give the UI a stable
            # relative reference instead.
            return f"skill-file:{self.relative}"
        encoded = base64.b64encode(payload).decode("ascii")
        return f"data:{self.mime};base64,{encoded}"


def extract_images(package: SkillPackage) -> tuple[list[ImageAsset], list[str]]:
    """Return image assets (bounded) and human-readable skip notes."""

    assets: list[ImageAsset] = []
    notes: list[str] = []
    for path in package.files:
        if len(assets) >= MAX_IMAGES:
            notes.append(f"image limit reached ({MAX_IMAGES}); remaining images not scanned")
            break
        suffix = path.suffix.lower()
        if suffix not in IMAGE_SUFFIXES:
            continue
        try:
            size = path.stat().st_size
        except OSError as exc:
            notes.append(f"could not stat {path.name}: {exc}")
            continue
        if size > MAX_IMAGE_BYTES:
            notes.append(f"{path.name} exceeds 20 MiB and was not scanned")
            continue
        try:
            data = path.read_bytes()
        except OSError as exc:
            notes.append(f"could not read {path.name}: {exc}")
            continue
        mime = mimetypes.guess_type(path.name)[0] or (
            "image/svg+xml" if suffix == ".svg" else "application/octet-stream"
        )
        assets.append(
            ImageAsset(
                path=path,
                relative=path.relative_to(package.root).as_posix(),
                suffix=suffix,
                size=size,
                data=data,
                mime=mime,
            )
        )
    return assets, notes


__all__ = [
    "IMAGE_SUFFIXES",
    "MAX_IMAGES",
    "MAX_IMAGE_BYTES",
    "ImageAsset",
    "extract_images",
]
