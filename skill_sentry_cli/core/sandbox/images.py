"""Container image references used by the sandbox and its sinkhole sidecar.

The sidecar's base image is pinned by digest, the same digest the sandbox
Dockerfile uses (``assets/Dockerfile.sandbox``). Read it from this module
only. A tag such as ``python:3.11-slim`` moves when the upstream image is
rebuilt, so a sidecar pulled by tag can change between scans.

The published sandbox image lives in ``skill_sentry_cli/data/sandbox_image.json``,
which the release workflow overwrites with ``repository`` and ``digest``. Keep the
sidecar reference here, not in that file.
"""

from __future__ import annotations

SIDECAR_BASE_IMAGE = (
    "python:3.11-slim@sha256:07d4824036af339fa1b6ef769cc99d9c10a141769538b52b3b597c84f7a7b535"
)

__all__ = ["SIDECAR_BASE_IMAGE"]
