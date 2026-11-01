# SkillSentry server image.
#
# Stage 1 builds the dashboard into skill_sentry_cli/ui/dist.  Stage 2 installs the
# Python package and runs the server as a non-root user.
#
# The sandbox needs a Docker engine.  Mounting /var/run/docker.sock gives this
# container root-equivalent control of the host, so the socket is NOT mounted by
# default.  Without it, sandbox stages report themselves as degraded.

FROM node:24-slim AS ui
WORKDIR /src
COPY ui ./ui
RUN mkdir -p skill_sentry_cli/ui \
 && cd ui \
 && npm ci --no-audit --no-fund \
 && npm run build

FROM python:3.12-slim AS app
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY skill_sentry_cli ./skill_sentry_cli
COPY --from=ui /src/skill_sentry_cli/ui/dist ./skill_sentry_cli/ui/dist
RUN pip install . \
 && useradd --system --uid 10001 --home-dir /home/skillsentry skillsentry \
 && mkdir -p /home/skillsentry && chown skillsentry /home/skillsentry
USER skillsentry
ENV HOME=/home/skillsentry
EXPOSE 8000
# Bind to all interfaces inside the container; publish the port only on loopback
# on the host (for example -p 127.0.0.1:8000:8000).
ENTRYPOINT ["skill-sentry-cli"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8000"]
