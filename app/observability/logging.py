"""Structured logging with content redaction enforced at the sink.

The uncomfortable property of this product: a firewall that inspects prompts is a
system that has all the prompts. The naive implementation — log everything, you
will want it for debugging — turns the security control into the largest store of
sensitive text in the architecture.

Redaction is therefore a **structlog processor at the sink**, not a rule each call
site follows. A future contributor writing ``logger.info("blocked", prompt=text)``
produces a harmless line; enforced per call site, that same line is a leak that
passes review because it looks like debugging.

See docs/10-security-model.md.
"""

from __future__ import annotations

import logging
import sys
from collections.abc import MutableMapping
from contextvars import ContextVar
from typing import Any

import structlog

from app.config.settings import ContentLogging, LogFormat, Settings
from app.core.ids import content_hash

# Keys whose values are, or may contain, inspected content. Redacted according to
# the configured content-logging mode before any renderer sees them.
CONTENT_KEYS: frozenset[str] = frozenset(
    {
        "content",
        "prompt",
        "prompts",
        "completion",
        "completions",
        "message",
        "messages",
        "text",
        "raw_text",
        "normalized_text",
        "matched",
        "match",
        "span_text",
        "decoded",
        "body",
        "response_text",
    }
)

# Keys that must never be emitted under any mode, at any log level.
SECRET_KEYS: frozenset[str] = frozenset(
    {
        "api_key",
        "apikey",
        "authorization",
        "password",
        "secret",
        "token",
        "database_url",
        "upstream_api_key",
        "credentials",
    }
)

REDACTED = "<redacted>"

_request_id: ContextVar[str | None] = ContextVar("request_id", default=None)


def bind_request_id(request_id: str) -> None:
    """Bind the correlation ID for the current async context.

    A contextvar rather than a parameter threaded through every signature: the
    alternative is a `request_id` argument on every internal API, which people
    eventually stop passing.
    """
    _request_id.set(request_id)


def get_request_id() -> str | None:
    return _request_id.get()


def reset_request_id() -> None:
    _request_id.set(None)


def add_request_id(
    _logger: Any, _method: str, event_dict: MutableMapping[str, Any]
) -> MutableMapping[str, Any]:
    request_id = _request_id.get()
    if request_id is not None:
        event_dict.setdefault("request_id", request_id)
    return event_dict


def make_content_redactor(mode: ContentLogging) -> Any:
    """Build the processor that enforces the content-logging policy.

    ``none`` drops content keys entirely, ``hash`` replaces them with a truncated
    fingerprint plus length, ``full`` passes them through (local debugging only —
    :meth:`Settings.effective_content_logging` refuses it in production).
    """

    def redact(
        _logger: Any, _method: str, event_dict: MutableMapping[str, Any]
    ) -> MutableMapping[str, Any]:
        for key in list(event_dict):
            lowered = key.lower()

            if lowered in SECRET_KEYS or any(hint in lowered for hint in ("secret", "password")):
                event_dict[key] = REDACTED
                continue

            if lowered not in CONTENT_KEYS:
                continue

            if mode is ContentLogging.FULL:
                continue

            value = event_dict.pop(key)
            if mode is ContentLogging.HASH and value is not None:
                text = value if isinstance(value, str) else repr(value)
                event_dict[f"{key}_hash"] = content_hash(text)
                event_dict[f"{key}_length"] = len(text)

        return event_dict

    return redact


def configure_logging(settings: Settings) -> None:
    """Configure structlog and the stdlib logging bridge.

    Output goes to stdout as JSON by default; containers do not manage log files,
    the platform does.
    """
    mode = settings.effective_content_logging()

    shared: list[Any] = [
        structlog.contextvars.merge_contextvars,
        add_request_id,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        # Redaction runs last, immediately before rendering, so nothing added by
        # an earlier processor can slip past it.
        make_content_redactor(mode),
    ]

    renderer: Any = (
        structlog.processors.JSONRenderer()
        if settings.log_format is LogFormat.JSON
        else structlog.dev.ConsoleRenderer(colors=sys.stdout.isatty())
    )

    structlog.configure(
        processors=[*shared, renderer],
        wrapper_class=structlog.make_filtering_bound_logger(
            logging.getLevelNamesMapping()[settings.log_level]
        ),
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )

    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=logging.getLevelNamesMapping()[settings.log_level],
        force=True,
    )
