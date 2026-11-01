"""The installer's pinned version must match the package version it installs."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_install_script_pins_the_package_version():
    version_py = (ROOT / "skill_sentry_cli" / "core" / "version.py").read_text(encoding="utf-8")
    package_version = re.search(r'__version__ = "([^"]+)"', version_py).group(1)
    installer = (ROOT / "install.sh").read_text(encoding="utf-8")
    pinned = re.search(r'^VERSION="([^"]+)"', installer, re.M).group(1)
    assert pinned == package_version
