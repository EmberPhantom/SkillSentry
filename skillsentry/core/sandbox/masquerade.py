"""Masquerade configuration, shim source, and verification helpers.

The shim hides ``/.dockerenv`` and redirects fake ``/proc`` views while logging
canary reads and sandbox probes.  A failed verification is an **engine error**:
the runner must not continue and must never emit a clean verdict.
"""

from __future__ import annotations

import base64
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ASSET_DIR = Path(__file__).resolve().parent / "assets"
MASQUERADE_SOURCE_PATH = ASSET_DIR / "masquerade.c"
RUN_SCRIPT_PATH = ASSET_DIR / "run_skill.sh"
DOCKERFILE_PATH = ASSET_DIR / "Dockerfile.sandbox"

SHIM_PATH = "/opt/skillsentry/masquerade.so"
SHIM_LOG_PATH = "/tmp/skillsentry/events.jsonl"
FAKE_CGROUP_PATH = "/tmp/skillsentry/cgroup"
FAKE_MOUNTINFO_PATH = "/tmp/skillsentry/mountinfo"
DOCKERENV_PATH = "/.dockerenv"
CGROUP_PATH = "/proc/1/cgroup"
MOUNTINFO_PATH = "/proc/self/mountinfo"

FAKE_CGROUP_CONTENT = "0::/\n"
FAKE_MOUNTINFO_CONTENT = (
    "1 0 0:1 / / ext4 rw,relatime 0 0\n"
    "2 1 0:2 / /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n"
    "3 1 0:3 / /sys sysfs ro,nosuid,nodev,noexec,relatime 0 0\n"
    "4 1 0:4 / /tmp tmpfs rw,nosuid,nodev,noexec,relatime 0 0\n"
    "5 1 0:5 / /home/sandbox tmpfs rw,nosuid,nodev,noexec,relatime 0 0\n"
)


class MasqueradeUnavailable(RuntimeError):
    """The shim cannot be built or is absent from the image."""


class MasqueradeError(RuntimeError):
    """The shim is present but its hides/redirects did not verify."""


@dataclass(frozen=True)
class MasqueradeConfig:
    shim_path: str = SHIM_PATH
    require_shim: bool = True
    dockerenv_source: str = "/dev/null"
    dockerenv_target: str = DOCKERENV_PATH
    # Docker's --tmpfs cannot target a file, and /proc/1/cgroup is a file.
    # The runner writes these fake files per scan and bind-mounts them
    # read-only; the shim additionally redirects /proc/self/* lookups.
    cgroup_host_path: str | None = None
    mountinfo_host_path: str | None = None

    def environment(self) -> dict[str, str]:
        return {"LD_PRELOAD": self.shim_path}

    def volumes(self) -> dict[str, dict[str, str]]:
        volumes = {
            self.dockerenv_source: {
                "bind": self.dockerenv_target,
                "mode": "ro",
            }
        }
        if self.cgroup_host_path:
            volumes[self.cgroup_host_path] = {"bind": CGROUP_PATH, "mode": "ro"}
        if self.mountinfo_host_path:
            volumes[self.mountinfo_host_path] = {
                "bind": "/proc/1/mountinfo",
                "mode": "ro",
            }
        return volumes

    def tmpfs(self) -> dict[str, str]:
        # Kept as an extension point for callers that need a directory tmpfs.
        return {}


@dataclass(frozen=True)
class MasqueradeCheck:
    dockerenv_hidden: bool
    cgroup_fake: bool
    mountinfo_clean: bool
    shim_present: bool
    errors: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return not self.errors

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "dockerenvHidden": self.dockerenv_hidden,
            "cgroupFake": self.cgroup_fake,
            "mountinfoClean": self.mountinfo_clean,
            "shimPresent": self.shim_present,
            "errors": list(self.errors),
        }


def source_text() -> str:
    return MASQUERADE_SOURCE_PATH.read_text(encoding="utf-8")


def run_script_text() -> str:
    return RUN_SCRIPT_PATH.read_text(encoding="utf-8")


def compile_shim(
    *,
    source: str | Path | None = None,
    output: str | Path | None = None,
    compiler: str | None = None,
) -> Path:
    """Compile the shim with a local gcc (development/CI packaging helper)."""

    gcc = compiler or shutil.which("gcc")
    if not gcc:
        raise MasqueradeUnavailable("gcc is unavailable; use the sandbox Docker image")
    source_path = Path(source or MASQUERADE_SOURCE_PATH)
    output_path = Path(output or (ASSET_DIR / "masquerade.so"))
    output_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        completed = subprocess.run(
            [
                gcc,
                "-shared",
                "-fPIC",
                "-O2",
                "-Wall",
                "-Wextra",
                "-o",
                str(output_path),
                str(source_path),
                "-ldl",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise MasqueradeUnavailable(f"could not run gcc: {exc}") from exc
    if completed.returncode != 0:
        raise MasqueradeUnavailable(
            f"gcc failed ({completed.returncode}): {completed.stderr.strip()}"
        )
    return output_path


def _decode_b64(value: str) -> str:
    try:
        return base64.b64decode(value.encode("ascii"), validate=False).decode(
            "utf-8", errors="replace"
        )
    except (ValueError, UnicodeError):
        return ""


def verify_outputs(
    *,
    dockerenv_exists: bool,
    cgroup: str,
    mountinfo: str,
    shim_present: bool,
    require_shim: bool = True,
) -> MasqueradeCheck:
    errors: list[str] = []
    dockerenv_hidden = not dockerenv_exists
    if not dockerenv_hidden:
        errors.append("/.dockerenv is visible to the skill")

    lowered_cgroup = cgroup.lower()
    cgroup_fake = bool(cgroup.strip()) and not any(
        marker in lowered_cgroup for marker in ("docker", "containerd", "kubepods")
    )
    if not cgroup_fake:
        errors.append("/proc/1/cgroup still exposes container markers")

    lowered_mountinfo = mountinfo.lower()
    mountinfo_clean = not any(
        marker in lowered_mountinfo
        for marker in ("docker", "containerd", "overlay", "kubepods", "skillsentry")
    )
    if not mountinfo_clean:
        errors.append("/proc/self/mountinfo still exposes container markers")

    if require_shim and not shim_present:
        errors.append("masquerade shim is missing from the sandbox image")

    return MasqueradeCheck(
        dockerenv_hidden=dockerenv_hidden,
        cgroup_fake=cgroup_fake,
        mountinfo_clean=mountinfo_clean,
        shim_present=shim_present,
        errors=tuple(errors),
    )


def verification_script(shim_path: str = SHIM_PATH) -> str:
    """POSIX shell probe used by :func:`verify_container`."""

    return f"""
if [ -e {DOCKERENV_PATH} ]; then d=present; else d=absent; fi
if [ -f {shim_path} ]; then s=present; else s=missing; fi
c=$(base64 < {CGROUP_PATH} 2>/dev/null | tr -d '\\n')
m=$(base64 < {MOUNTINFO_PATH} 2>/dev/null | tr -d '\\n')
printf 'SKILLSENTRY_DOCKERENV=%s\\n' "$d"
printf 'SKILLSENTRY_SHIM=%s\\n' "$s"
printf 'SKILLSENTRY_CGROUP=%s\\n' "$c"
printf 'SKILLSENTRY_MOUNTINFO=%s\\n' "$m"
""".strip()


def parse_verification_output(
    text: str | bytes,
    *,
    require_shim: bool = True,
) -> MasqueradeCheck:
    if isinstance(text, bytes):
        text = text.decode("utf-8", errors="replace")
    values: dict[str, str] = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key.startswith("SKILLSENTRY_"):
            values[key] = value.strip()
    return verify_outputs(
        dockerenv_exists=values.get("SKILLSENTRY_DOCKERENV") != "absent",
        cgroup=_decode_b64(values.get("SKILLSENTRY_CGROUP", "")),
        mountinfo=_decode_b64(values.get("SKILLSENTRY_MOUNTINFO", "")),
        shim_present=values.get("SKILLSENTRY_SHIM") == "present",
        require_shim=require_shim,
    )


def verify_container(
    container: Any,
    *,
    config: MasqueradeConfig | None = None,
    user: str = "65534:65534",
) -> MasqueradeCheck:
    """Run the verification probe in a started container."""

    config = config or MasqueradeConfig()
    result = container.exec_run(
        ["/bin/sh", "-c", verification_script(config.shim_path)],
        user=user,
        environment=config.environment(),
    )
    if isinstance(result.output, bytes):
        output = result.output.decode("utf-8", errors="replace")
    else:
        output = str(result.output or "")
    if result.exit_code not in (0, None):
        return MasqueradeCheck(
            dockerenv_hidden=False,
            cgroup_fake=False,
            mountinfo_clean=False,
            shim_present=False,
            errors=(f"masquerade probe exited {result.exit_code}: {output.strip()}",),
        )
    return parse_verification_output(output, require_shim=config.require_shim)


def require_masquerade(check: MasqueradeCheck) -> None:
    if not check.ok:
        raise MasqueradeError("; ".join(check.errors))
