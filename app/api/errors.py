"""Error responses in the OpenAI envelope.

One handler converts every failure, so the API layer never guesses how to
serialise an error and no code path can invent its own shape.

Three rules govern the bodies (docs/07-openai-compatible-api.md):

1. Block responses state category and request ID only — never the score, the
   matched rule, or the offending text. Anything more turns the gateway into a
   tuning oracle an attacker can iterate against (threat T-13).
2. Upstream response bodies are never reflected; they can contain the reflected
   prompt or provider internals.
3. Unhandled exceptions return a generic message. Stack traces are logged
   server-side only.
"""

from __future__ import annotations

from typing import Any

import structlog
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.exceptions import FirewallError

logger = structlog.get_logger(__name__)


def error_body(
    message: str,
    error_type: str,
    *,
    code: str | None = None,
    request_id: str | None = None,
) -> dict[str, Any]:
    error: dict[str, Any] = {"message": message, "type": error_type}
    if code is not None:
        error["code"] = code
    if request_id is not None:
        error["request_id"] = request_id
    return {"error": error}


def _request_id(request: Request) -> str | None:
    value = request.scope.get("state", {}).get("request_id")
    return value if isinstance(value, str) else None


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(FirewallError)
    async def _firewall_error(request: Request, exc: FirewallError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content=error_body(
                # `safe_message`, not `message`: subclasses that must never leak
                # their detail to a client override it with a fixed string.
                exc.safe_message,
                exc.error_type,
                code=exc.code,
                request_id=_request_id(request),
            ),
        )

    @app.exception_handler(RequestValidationError)
    async def _validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        # Field locations and messages only. Pydantic's `input` field echoes the
        # submitted value, which for this service is prompt content.
        details = [
            {"loc": list(err.get("loc", ())), "msg": err.get("msg", "invalid")}
            for err in exc.errors()
        ]
        return JSONResponse(
            status_code=400,
            content=error_body(
                "Request failed validation.",
                "invalid_request_error",
                request_id=_request_id(request),
            )
            | {"detail": details},
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        mapping = {
            404: "not_found_error",
            405: "method_not_allowed",
            413: "request_too_large",
        }
        return JSONResponse(
            status_code=exc.status_code,
            content=error_body(
                str(exc.detail),
                mapping.get(exc.status_code, "api_error"),
                request_id=_request_id(request),
            ),
        )

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("unhandled_exception", error_kind=type(exc).__name__)
        return JSONResponse(
            status_code=500,
            content=error_body(
                "Internal server error.",
                "internal_error",
                request_id=_request_id(request),
            ),
        )
