"""Demo server: ``python -m skillsentry.server.demo_mode --port 8000``.

Serves every endpoint from docs/05-api-reference.md §5.2 with canned data from
the 7-skill store.  No Docker, model, or database required.
"""

from __future__ import annotations

import argparse

import uvicorn
from fastapi import FastAPI

from skillsentry.server.app import create_app
from skillsentry.server.demo_backend import DemoBackend


def create_demo_app(*, speed: float | None = None) -> FastAPI:
    return create_app(DemoBackend(speed=speed))


app = create_demo_app()


def main() -> None:
    parser = argparse.ArgumentParser(description="SkillSentry demo server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument(
        "--speed",
        type=float,
        default=1.0,
        help="WS replay speed multiplier (0 disables delays; used by tests)",
    )
    args = parser.parse_args()
    uvicorn.run(create_demo_app(speed=args.speed), host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
