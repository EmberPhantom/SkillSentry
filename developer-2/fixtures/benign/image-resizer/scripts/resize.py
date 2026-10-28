"""
Image Resizer — batch-resizes images using Pillow.

This is a BENIGN fixture: uses only Pillow for local image manipulation.
No network access, no credential reads, no shell commands.
Expected verdict: SAFE (risk < 30).
"""

import sys
from pathlib import Path

try:
    from PIL import Image
except ImportError:
    print("Error: Pillow is required. Install with: pip install Pillow")
    sys.exit(1)

SUPPORTED_EXTENSIONS = {".png", ".jpg", ".jpeg", ".webp", ".bmp"}


def resize_image(input_path: Path, output_path: Path, width: int, height: int) -> None:
    """Resize a single image to the specified dimensions."""
    img = Image.open(input_path)
    resized = img.resize((width, height), Image.LANCZOS)
    resized.save(output_path)
    print(f"  Resized: {input_path.name} -> {output_path.name} ({width}x{height})")


def batch_resize(input_dir: str, output_dir: str, width: int, height: int) -> int:
    """Resize all supported images in input_dir and save to output_dir."""
    src = Path(input_dir)
    dst = Path(output_dir)
    dst.mkdir(parents=True, exist_ok=True)

    count = 0
    for f in sorted(src.iterdir()):
        if f.suffix.lower() in SUPPORTED_EXTENSIONS:
            resize_image(f, dst / f.name, width, height)
            count += 1
    return count


def main() -> None:
    if len(sys.argv) < 5:
        print("Usage: python resize.py <input_dir> <output_dir> <width> <height>")
        sys.exit(1)

    input_dir, output_dir = sys.argv[1], sys.argv[2]
    width, height = int(sys.argv[3]), int(sys.argv[4])

    count = batch_resize(input_dir, output_dir, width, height)
    print(f"Done: resized {count} images.")


if __name__ == "__main__":
    main()

