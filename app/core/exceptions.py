"""Application exception hierarchy.

Every exception carries an `error_type` that maps directly onto the OpenAI error
envelope so the API layer never has to guess how to serialise a failure.
"""

from __future__ import annotations

from typing import ClassVar


class FirewallError(Exception):
    """Base class for all errors raised by the gateway.

    `message` is for operators and goes to logs. `client_message`, when a subclass
    defines it, is what the client receives *instead* — a fixed string that no
    call site can influence. That distinction exists so a guarantee like "upstream
    response text is never reflected to the client" is enforced by the type rather
    than by every future `raise` site remembering it.
    """

    error_type: ClassVar[str] = "firewall_error"
    status_code: ClassVar[int] = 500
    client_message: ClassVar[str | None] = None

    def __init__(self, message: str, *, code: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.code = code

    @property
    def safe_message(self) -> str:
        """What may be returned to the client."""
        return self.client_message or self.message


class ConfigurationError(FirewallError):
    """Invalid or unsafe configuration; raised at startup, never per-request."""

    error_type: ClassVar[str] = "configuration_error"


class DetectorError(FirewallError):
    """A detector raised while inspecting text."""

    error_type: ClassVar[str] = "detector_error"
    status_code: ClassVar[int] = 503

    def __init__(self, detector: str, message: str) -> None:
        super().__init__(message, code=detector)
        self.detector = detector


class DetectorTimeout(DetectorError):
    """A detector exceeded its configured timeout budget."""

    error_type: ClassVar[str] = "detector_timeout"


class UpstreamError(FirewallError):
    """The upstream LLM was unreachable, timed out, or returned an error.

    Upstream response bodies are never echoed to the client: they may contain
    provider-internal details or reflected prompt content.
    """

    error_type: ClassVar[str] = "upstream_error"
    status_code: ClassVar[int] = 502
    client_message: ClassVar[str | None] = "The upstream model is unavailable."


class UpstreamTimeout(UpstreamError):
    error_type: ClassVar[str] = "upstream_timeout"
    status_code: ClassVar[int] = 504
    client_message: ClassVar[str | None] = "The upstream model timed out."


class RequestTooLarge(FirewallError):
    error_type: ClassVar[str] = "request_too_large"
    status_code: ClassVar[int] = 413


class UnsupportedFeature(FirewallError):
    """A well-formed request asks for something the gateway cannot inspect yet."""

    error_type: ClassVar[str] = "unsupported_feature"
    status_code: ClassVar[int] = 400


class InvalidRequest(FirewallError):
    """A malformed or schema-violating request.

    Carries a fixed message rather than the validator's, because pydantic's error
    text echoes the submitted value — which for this service is prompt content
    (docs/10-security-model.md). Field locations are safe to return; values are
    not.
    """

    error_type: ClassVar[str] = "invalid_request_error"
    status_code: ClassVar[int] = 400


class NotImplementedYet(FirewallError):
    """A documented endpoint that a later phase will implement.

    Returned instead of a plausible-looking success. A security gateway that
    appears to work while inspecting nothing is worse than one that says so.
    """

    error_type: ClassVar[str] = "not_implemented"
    status_code: ClassVar[int] = 501


class SecurityBlock(FirewallError):
    """The policy engine returned BLOCK for this request or response."""

    error_type: ClassVar[str] = "security_block"
    status_code: ClassVar[int] = 403

    def __init__(self, message: str, *, category: str, detector: str | None = None) -> None:
        super().__init__(message, code=category)
        self.category = category
        self.detector = detector
