"""FastAPI application factory."""

from __future__ import annotations

import logging
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from skill_sentry_cli.core.contracts import ErrorDetail, ErrorResponse
from skill_sentry_cli.core.version import __version__
from skill_sentry_cli.server.backend import ScanBackend
from skill_sentry_cli.server.errors import ApiError
from skill_sentry_cli.server.live_backend import LiveBackend
from skill_sentry_cli.server.routes import router
from skill_sentry_cli.server.security import (
    TokenAuthMiddleware,
    TrustedHostMiddleware,
    allowed_hostnames_from_env,
)

logger = logging.getLogger(__name__)

_DEV_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:4173",
    "http://127.0.0.1:4173",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
]


# First path segments that belong to the JSON API (see server/routes.py).
_API_PREFIXES = frozenset({"scan", "scans", "skills", "cache", "health", "meta", "api"})


def _default_ui_dist() -> Path:
    """Dashboard build: shipped inside the package, with the repo build as a dev fallback."""

    packaged = Path(__file__).resolve().parent.parent / "ui" / "dist"
    if (packaged / "index.html").is_file():
        return packaged
    return Path.cwd() / "ui" / "dist"


def _validation_message(exc: RequestValidationError) -> str:
    """One readable line per problem, e.g. ``body.path: Field required``."""

    parts: list[str] = []
    for error in exc.errors():
        location = ".".join(str(part) for part in error.get("loc", ()))
        message = str(error.get("msg", "invalid value"))
        parts.append(f"{location}: {message}" if location else message)
    return "; ".join(parts[:10]) or "request failed validation"


def create_app(
    backend: ScanBackend | None = None,
    *,
    static_dir: str | Path | None = None,
    bind_host: str | None = None,
    token: str | None = None,
) -> FastAPI:
    """Build the API.

    ``bind_host`` is the address the server listens on. A specific address is added to
    the accepted Host names; wildcard and loopback binds accept only loopback names
    (plus ``SKILLSENTRY_ALLOWED_HOSTS``).

    ``token``, when set, is required as a bearer token on every API route except
    ``/health`` and ``/meta``, and on the WebSocket. It is never logged.
    """

    backend = backend or LiveBackend()
    app = FastAPI(
        title="SkillSentry",
        version=__version__,
        description="Context-aware firewall for the Agent Skill supply chain.",
    )
    app.state.backend = backend
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_DEV_ORIGINS,
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    if token:
        app.add_middleware(TokenAuthMiddleware, token=token)
    # Outermost: refuse foreign Host and Origin values before any route runs.
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=allowed_hostnames_from_env(bind_host),
        allowed_origins=_DEV_ORIGINS,
    )

    @app.exception_handler(ApiError)
    async def _api_error(_: Request, exc: ApiError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content=exc.to_response().model_dump(by_alias=True, mode="json"),
        )

    @app.exception_handler(Exception)
    async def _unexpected_error(_: Request, exc: Exception) -> JSONResponse:
        # Never a bare "Internal Server Error": the client gets the same JSON shape as every
        # other error. The detail goes to the server log, not to the client.
        logger.exception("unhandled error in the API", exc_info=exc)
        response = ErrorResponse(
            error=ErrorDetail(
                code="internal_error",
                message="the server hit an unexpected error; see the server log",
                degraded=False,
            )
        )
        return JSONResponse(
            status_code=500,
            content=response.model_dump(by_alias=True, mode="json"),
        )

    @app.exception_handler(RequestValidationError)
    async def _validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
        response = ErrorResponse(
            error=ErrorDetail(
                code="schema_violation",
                message=_validation_message(exc),
                degraded=False,
            )
        )
        return JSONResponse(
            status_code=422,
            content=response.model_dump(by_alias=True, mode="json"),
        )

    app.include_router(router)
    # The same routes under /api, so an API client and the dashboard's own files cannot be
    # confused. The unprefixed routes stay, because the dashboard and existing clients use them.
    app.include_router(router, prefix="/api", include_in_schema=False)

    ui_dist = Path(static_dir) if static_dir is not None else _default_ui_dist()
    ui_index = ui_dist / "index.html"

    @app.get("/", include_in_schema=False)
    async def index():
        if ui_index.is_file():
            return FileResponse(ui_index)
        return {
            "name": "SkillSentry",
            "version": __version__,
            "docs": "/docs",
            "meta": "/meta",
        }

    if ui_index.is_file():
        # SPA fallback: serve built assets, otherwise index.html.  API routes
        # are registered above and therefore take precedence.
        if (ui_dist / "assets").is_dir():
            app.mount("/assets", StaticFiles(directory=ui_dist / "assets"), name="assets")

        @app.get("/{full_path:path}", include_in_schema=False)
        async def spa(full_path: str):
            # An API-shaped path that matched no route is an error, not a page.
            if full_path.split("/", 1)[0] in _API_PREFIXES:
                response = ErrorResponse(
                    error=ErrorDetail(
                        code="not_found",
                        message=f"no API route at /{full_path}",
                        degraded=False,
                    )
                )
                return JSONResponse(
                    status_code=404,
                    content=response.model_dump(by_alias=True, mode="json"),
                )
            candidate = (ui_dist / full_path).resolve()
            if candidate.is_file() and candidate.is_relative_to(ui_dist.resolve()):
                return FileResponse(candidate)
            return FileResponse(ui_index)

    return app


__all__ = ["create_app"]
