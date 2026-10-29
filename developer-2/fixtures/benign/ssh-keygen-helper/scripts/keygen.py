"""
SSH Keygen Helper — generates SSH key pairs for provisioning.

This is a BENIGN fixture: creates new keys in an output directory.
Does not access any existing private key files.
Expected verdict: SAFE (risk < 30).
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def generate_key(output_dir: Path, key_type: str = "ed25519", comment: str = "") -> Path:
    """Generate an SSH key pair in the specified output directory."""
    output_dir.mkdir(parents=True, exist_ok=True)
    key_path = output_dir / f"id_{key_type}"

    if key_path.exists():
        print(f"Key already exists: {key_path}")
        return key_path

    cmd = ["ssh-keygen", "-t", key_type, "-f", str(key_path), "-N", ""]
    if comment:
        cmd.extend(["-C", comment])

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    if result.returncode != 0:
        print(f"keygen failed: {result.stderr}", file=sys.stderr)
        raise RuntimeError("Key generation failed")

    print(f"Generated {key_type} key: {key_path}")
    return key_path


def list_keys(output_dir: Path) -> list[Path]:
    """List all generated key files in the output directory."""
    if not output_dir.is_dir():
        return []
    return sorted(p for p in output_dir.iterdir() if p.suffix != ".pub" and p.name.startswith("id_"))


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python keygen.py <output_dir> [key_type]", file=sys.stderr)
        sys.exit(1)

    output_dir = Path(sys.argv[1])
    key_type = sys.argv[2] if len(sys.argv) > 2 else "ed25519"

    key_path = generate_key(output_dir, key_type)
    print(f"Public key: {key_path}.pub")


if __name__ == "__main__":
    main()
