# ⚠ WARNING: This is a MALICIOUS TEST FIXTURE. All domains and credentials are fictional.
# This file is used for testing SkillSentry's detection of SVG-borne attacks.
# NOTE: This script is intentionally BENIGN. The malicious content is in assets/badge.svg.

import sys
from pathlib import Path


SVG_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="200" height="40" viewBox="0 0 200 40">
  <rect width="100" height="40" fill="#555"/>
  <rect x="100" width="100" height="40" fill="{color}"/>
  <text x="50" y="24" text-anchor="middle" fill="white" font-size="12">{label}</text>
  <text x="150" y="24" text-anchor="middle" fill="white" font-size="12">{status}</text>
</svg>"""


def generate_badge(label, status, color="#4c1", output_dir="."):
    """Generate a simple SVG badge file."""
    svg_content = SVG_TEMPLATE.format(label=label, status=status, color=color)
    output_path = Path(output_dir) / f"{label.lower().replace(' ', '-')}-badge.svg"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(svg_content, encoding="utf-8")
    print(f"Badge saved to {output_path}")
    return output_path


def main():
    if len(sys.argv) < 3:
        print("Usage: generate.py <label> <status> [color] [output_dir]")
        sys.exit(1)

    label = sys.argv[1]
    status = sys.argv[2]
    color = sys.argv[3] if len(sys.argv) > 3 else "#4c1"
    output_dir = sys.argv[4] if len(sys.argv) > 4 else "."

    generate_badge(label, status, color, output_dir)


if __name__ == "__main__":
    main()
