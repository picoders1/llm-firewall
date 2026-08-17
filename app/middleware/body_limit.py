"""Request body size limit.

Enforced two ways, because either alone is insufficient:

* **`Content-Length` pre-check** rejects the common case before a single byte of
  body is read.
* **Streaming byte count** covers a chunked request, which has no
  `Content-Length` at all. Without it, `Transfer-Encoding: chunked` is a trivial
  bypass of the first check — and an unbounded body is a memory-exhaustion vector
  (threat T-16).

The limit is on the raw HTTP body. `max_inspect_chars` is a separate, smaller
bound on how much text each detector examines.
"""

from __future__ import annotations

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.exceptions import RequestTooLarge


class BodyLimitMiddleware:
    """Rejects bodies larger than `max_request_bytes`.

    This middleware sits *outside* the application's exception handlers, so a
    raised exception here would surface as a 500. The pre-check therefore writes
    its own response; the streaming check raises, because that code runs inside
    the handler stack (the app awaits `receive`) where the handlers do apply.
    """

    def __init__(self, app: ASGIApp, *, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    def _too_large(self, scope: Scope) -> JSONResponse:
        request_id = scope.get("state", {}).get("request_id")
        return JSONResponse(
            status_code=413,
            content={
                "error": {
                    "message": f"Request body exceeds the {self.max_bytes} byte limit.",
                    "type": "request_too_large",
                    "request_id": request_id,
                }
            },
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        for name, value in scope.get("headers", ()):
            if name == b"content-length":
                try:
                    declared = int(value)
                except ValueError:
                    await self._too_large(scope)(scope, receive, send)
                    return
                if declared > self.max_bytes:
                    # Rejected before a single byte of body is read.
                    await self._too_large(scope)(scope, receive, send)
                    return
                break

        received = 0

        async def counting_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    # Raised mid-read so a chunked body cannot grow unbounded.
                    # The handler's FirewallError branch turns it into a 413.
                    raise RequestTooLarge(f"Request body exceeds the {self.max_bytes} byte limit.")
            return message

        await self.app(scope, counting_receive, send)
