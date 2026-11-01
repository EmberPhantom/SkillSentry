"""API error model (docs/05-api-reference.md §5.8)."""

from __future__ import annotations

from uuid import UUID

from skill_sentry_cli.core.contracts import ErrorDetail, ErrorResponse, Stage


class ApiError(Exception):
    """A structured HTTP error rendered as ``{"error": {...}}``."""

    def __init__(
        self,
        status_code: int,
        code: str,
        message: str,
        *,
        stage: Stage | None = None,
        degraded: bool = False,
        scan_id: UUID | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.stage = stage
        self.degraded = degraded
        self.scan_id = scan_id

    def to_response(self) -> ErrorResponse:
        return ErrorResponse(
            error=ErrorDetail(
                code=self.code,
                message=self.message,
                stage=self.stage,
                degraded=self.degraded,
                scan_id=self.scan_id,
            )
        )


def not_found(code: str, message: str) -> ApiError:
    return ApiError(404, code, message)


def bad_request(code: str, message: str) -> ApiError:
    return ApiError(400, code, message)
