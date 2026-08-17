"""Core domain types shared by detectors, the policy engine and the gateway.

These types are the contract between layers. Detectors produce `DetectionResult`;
the policy engine consumes them and produces a `PolicyDecision`. Neither layer
imports the other.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator


class Action(StrEnum):
    """Business action chosen by the policy engine.

    Ordered by severity in `ACTION_PRECEDENCE`; the engine always selects the
    most severe action requested by any triggering detector.
    """

    ALLOW = "allow"
    WARN = "warn"
    REDACT = "redact"
    BLOCK = "block"


ACTION_PRECEDENCE: dict[Action, int] = {
    Action.ALLOW: 0,
    Action.WARN: 1,
    Action.REDACT: 2,
    Action.BLOCK: 3,
}


class Category(StrEnum):
    """What a detector claims to have found."""

    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    PII = "pii"
    OUTPUT_POLICY = "output_policy"
    DETECTOR_FAILURE = "detector_failure"


class Direction(StrEnum):
    """Which side of the proxy the text came from."""

    INPUT = "input"
    OUTPUT = "output"


class ErrorPolicy(StrEnum):
    """What to do when a detector times out or raises.

    `FAIL_CLOSED` converts the failure into a BLOCK. It is the default for
    security-critical detectors: a firewall that silently stops inspecting is
    worse than one that is loudly unavailable. See docs/adr/ADR-007.
    """

    FAIL_CLOSED = "fail_closed"
    FAIL_OPEN = "fail_open"


class Role(StrEnum):
    """OpenAI chat roles the gateway understands."""

    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"
    DEVELOPER = "developer"


class TextSpan(BaseModel):
    """A half-open `[start, end)` character range in the text a detector saw.

    Spans are relative to `DetectionContext.raw_text` so that redaction can be
    applied to the original message without re-running normalisation.
    """

    model_config = ConfigDict(frozen=True)

    start: int = Field(ge=0)
    end: int = Field(ge=0)
    label: str
    replacement: str | None = None

    @model_validator(mode="after")
    def _check_ordering(self) -> Self:
        # An inverted span silently corrupts redaction (it would splice text
        # rather than replace it), so it is rejected at construction.
        if self.end < self.start:
            raise ValueError(f"span end ({self.end}) precedes start ({self.start})")
        return self

    def __len__(self) -> int:
        return self.end - self.start

    def overlaps(self, other: TextSpan) -> bool:
        return self.start < other.end and other.start < self.end


class DecodedSegment(BaseModel):
    """A payload that was encoded inside the raw text and has been decoded.

    Attackers hide instructions in base64/hex to slip past detectors that only
    read literal text. Surfacing the decoded form lets every detector inspect it
    without each one re-implementing decoding.
    """

    model_config = ConfigDict(frozen=True)

    encoding: str
    span: TextSpan
    decoded: str


class DetectionContext(BaseModel):
    """Everything a detector is given about one piece of text.

    Carries both `raw_text` and `normalized_text`: normalisation defeats
    homoglyph and zero-width evasion, but redaction spans and audit records must
    refer to the original bytes the client sent.

    `normalized_offsets` is what makes those two facts compatible — it maps each
    normalised character back to its source index, so a detector may match on the
    folded text and still emit a span that is exact against `raw_text`. Without
    it, evasion resistance and correct redaction are mutually exclusive
    (docs/adr/ADR-010-normalization-strategy.md).
    """

    model_config = ConfigDict(frozen=True)

    request_id: str
    direction: Direction
    role: Role
    message_index: int = 0
    part_index: int = 0
    raw_text: str
    normalized_text: str
    normalized_offsets: tuple[int, ...] = ()
    decoded_segments: tuple[DecodedSegment, ...] = ()
    truncated: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _offsets_match_normalized_text(self) -> Self:
        if self.normalized_offsets and len(self.normalized_offsets) != len(self.normalized_text):
            raise ValueError(
                "normalized_offsets desynchronised from normalized_text "
                f"({len(self.normalized_offsets)} offsets, {len(self.normalized_text)} chars)"
            )
        return self

    def source_span(self, start: int, end: int, label: str) -> TextSpan | None:
        """Map a half-open span in normalised space back to `raw_text`.

        Returns None when the span is empty, out of range, or when no offset map
        is present — callers must treat a missing span as "no redactable
        location", never as "redact from zero".
        """
        offsets = self.normalized_offsets
        if not offsets or start < 0 or end > len(offsets) or start >= end:
            return None
        return TextSpan(start=offsets[start], end=offsets[end - 1] + 1, label=label)


class DetectionResult(BaseModel):
    """A detector's finding. Deliberately carries no business action.

    `score` is detector-defined and only comparable against that detector's own
    configured threshold. Scores from different detectors are NOT comparable and
    are not calibrated probabilities unless the detector documents otherwise.
    """

    model_config = ConfigDict(frozen=True)

    detector: str
    detected: bool
    score: float = Field(ge=0.0, le=1.0)
    category: Category
    reasons: tuple[str, ...] = ()
    spans: tuple[TextSpan, ...] = ()
    metadata: dict[str, Any] = Field(default_factory=dict)
    latency_ms: float = Field(default=0.0, ge=0.0)
    errored: bool = False
    error_kind: str | None = None


class PolicyDecision(BaseModel):
    """The single authoritative outcome for one inspected direction.

    Self-describing on purpose: the policy engine is pure and cannot log, so the
    decision must carry its own reasoning for the caller to persist. See
    docs/06-policy-engine.md.
    """

    model_config = ConfigDict(frozen=True)

    action: Action
    direction: Direction
    category: Category | None = None
    triggering_detector: str | None = None
    reasons: tuple[str, ...] = ()
    results: tuple[DetectionResult, ...] = ()
    redaction_spans: tuple[TextSpan, ...] = ()

    @property
    def blocked(self) -> bool:
        return self.action is Action.BLOCK
