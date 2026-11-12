# SkillSentry server image.
#
# Stage 1 builds the dashboard into skill_sentry_cli/ui/dist.  Stage 2 installs the
# Python package and runs the server as a non-root user.
#
# The sandbox needs a Docker engine.  Mounting /var/run/docker.sock gives this
# container root-equivalent control of the host, so the socket is NOT mounted by
# default.  Without it, sandbox stages report themselves as degraded.
#
# Base images are pinned by index digest.  To refresh them, run:
#   docker buildx imagetools inspect node:24-slim
#   docker buildx imagetools inspect python:3.12-slim
# and replace the digests below.  Dependabot's docker updates open the pull requests.

FROM node:24-slim@sha256:c86ecead9e55a5210ac1727de38a4ca840bf03dcaf34dc9749addbf383b1920c AS ui
WORKDIR /src
COPY ui ./ui
RUN mkdir -p skill_sentry_cli/ui \
 && cd ui \
 && npm ci --no-audit --no-fund \
 && npm run build

FROM python:3.12-slim@sha256:b18b261e1b4974b4f321451ad5251ded85abb22c2b8b262da527dda1d031ab30 AS app
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1
WORKDIR /app
COPY pyproject.toml README.md LICENSE requirements-runtime.txt ./
COPY packaging ./packaging
COPY skill_sentry_cli ./skill_sentry_cli
COPY --from=ui /src/skill_sentry_cli/ui/dist ./skill_sentry_cli/ui/dist
# Dependencies come from the hash-locked file; the project itself is installed without resolving.
RUN pip install --require-hashes -r requirements-runtime.txt \
 && pip install --no-deps . \
 && useradd --system --uid 10001 --home-dir /home/skillsentry skillsentry \
 && mkdir -p /home/skillsentry && chown skillsentry /home/skillsentry
USER skillsentry
ENV HOME=/home/skillsentry \
    SKILLSENTRY_CONTAINER=1
EXPOSE 8000
# /meta is a cheap, dependency-free route, so the container is healthy when the server
# answers, even when Docker or Ollama are not reachable from inside it.  The check uses
# the Python standard library because the slim image has no curl.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/meta', timeout=4)"
# Bind to all interfaces inside the container; publish the port only on loopback
# on the host (for example -p 127.0.0.1:8000:8000).
ENTRYPOINT ["skill-sentry-cli"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8000"]
