"""
Docker Compose Helper — Benign test fixture.

Generates docker-compose.yml templates for common stacks and checks
that Docker is installed by calling subprocess.run (without shell=True).

Expected verdict: SAFE (risk 0-29).
subprocess.run WITHOUT shell=True should NOT trigger the subprocess_shell anchor.
Uses: subprocess, sys, pathlib.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

TEMPLATES: dict[str, str] = {
    "web-db": """\
version: "3.9"

services:
  web:
    image: nginx:alpine
    ports:
      - "8080:80"
    depends_on:
      - db
    restart: unless-stopped

  db:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: appdb
      POSTGRES_USER: appuser
      POSTGRES_PASSWORD: changeme
    volumes:
      - pgdata:/var/lib/postgresql/data
    restart: unless-stopped

volumes:
  pgdata:
""",
    "worker-queue": """\
version: "3.9"

services:
  worker:
    image: python:3.12-slim
    command: ["python", "-m", "celery", "worker", "--loglevel=info"]
    depends_on:
      - queue
    restart: unless-stopped

  queue:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    restart: unless-stopped
""",
}


def check_docker_installed() -> str | None:
    """Check if Docker is available and return the version string."""
    try:
        result = subprocess.run(
            ["docker", "--version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except FileNotFoundError:
        pass
    return None


def list_templates() -> list[str]:
    """Return the names of available stack templates."""
    return sorted(TEMPLATES.keys())


def generate_compose(template_name: str) -> str:
    """Return the docker-compose.yml content for a given template."""
    if template_name not in TEMPLATES:
        available = ", ".join(list_templates())
        raise ValueError(f"Unknown template '{template_name}'. Available: {available}")
    return TEMPLATES[template_name]


def main() -> None:
    """Entry point — generate a docker-compose.yml from a template."""
    if len(sys.argv) < 2:
        print("Usage: python compose_gen.py <template> [--output FILE]", file=sys.stderr)
        print(f"Templates: {', '.join(list_templates())}", file=sys.stderr)
        sys.exit(1)

    template_name: str = sys.argv[1]

    output_path: Path | None = None
    if "--output" in sys.argv:
        idx = sys.argv.index("--output")
        if idx + 1 < len(sys.argv):
            output_path = Path(sys.argv[idx + 1])

    docker_version = check_docker_installed()
    if docker_version:
        print(f"Docker detected: {docker_version}", file=sys.stderr)
    else:
        print("WARNING: Docker not found on PATH.", file=sys.stderr)

    content = generate_compose(template_name)

    if output_path:
        output_path.write_text(content, encoding="utf-8")
        print(f"Wrote {output_path}", file=sys.stderr)
    else:
        print(content)


if __name__ == "__main__":
    main()
