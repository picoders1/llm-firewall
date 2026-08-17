"""Core domain types shared by detectors, the policy engine and the gateway.

These types are the contract between layers. Detectors produce `DetectionResult`;
the policy engine consumes them and produces a `PolicyDecision`. Neither layer
imports the other.
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


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


class Provenance(StrEnum):
    """Where a piece of text actually came from.

    Deliberately **not** the same thing as :class:`Role`, which is only what the
    wire said. A RAG application concatenates a retrieved document into a `user`
    turn, so `role=user, provenance=EXTERNAL` is the normal case and the one the
    gateway could not previously express (ADR-017).

    `EXTERNAL` collapses retrieved documents, web pages, email bodies, files,
    database records and API results: they share the property that decides
    treatment — they originated outside the trust boundary — and no policy in the
    threat model distinguishes them. The finer detail lives in
    `DetectionContext.source_kind`, which is recorded and never consulted.
    """

    SYSTEM_CONFIG = "system_config"
    USER_INPUT = "user_input"
    MODEL_OUTPUT = "model_output"
    TOOL_RESULT = "tool_result"
    EXTERNAL = "external"
    UNKNOWN = "unknown"


class TrustLevel(StrEnum):
    """How much the origin of a piece of text is worth.

    **Assigned by the gateway, never accepted from a caller.** Provenance is not
    trust: a `TOOL_RESULT` from an internal service is `DERIVED`, the same result
    from a tool that fetched a URL is `UNTRUSTED`, and only the adapter that
    invoked it knows which.
    """

    OPERATOR = "operator"
    PRINCIPAL = "principal"
    DERIVED = "derived"
    UNTRUSTED = "untrusted"
    UNKNOWN = "unknown"


TRUST_PRECEDENCE: dict[TrustLevel, int] = {
    TrustLevel.UNTRUSTED: 0,
    TrustLevel.UNKNOWN: 1,
    TrustLevel.DERIVED: 2,
    TrustLevel.PRINCIPAL: 3,
    TrustLevel.OPERATOR: 4,
}
"""Ordering used to adjudicate claims: a caller may only ever lower trust.

`UNKNOWN` sits above `UNTRUSTED` and below `DERIVED` because the three states are
"we do not know", "we know it came from outside", and "we know our own component
produced it" — ignorance is worth less than knowledge of an internal origin and
more than knowledge of an external one.

This is **not** a statement about policy strictness. That `UNKNOWN` leaves policy
unchanged (ADR-017's tighten-only rule) is a property of the Phase C overlay, not
a position in this ordering. Phase A/B applies no policy effect at all, so the two
cannot currently be confused — but they are distinct and a future reader should
not collapse them.
"""


SOURCE_REF_MAX_CHARS = 64
SOURCE_KIND_MAX_CHARS = 32
_SOURCE_REF_ALLOWED = re.compile(r"^[A-Za-z0-9._:-]+$")
_SOURCE_KIND_ALLOWED = re.compile(r"^[a-z0-9_]+$")


def source_ref_problem(value: str) -> str | None:
    """Why `value` is unacceptable as a `source_ref`, or None if it is fine.

    `source_ref` is a **correlation handle, not a locator**. A URL or a file path
    leaks internal structure and sometimes credentials into audit records and
    traces (docs/10-security-model.md), so the permitted charset excludes `/`,
    `@`, `?`, `=`, `\\` and whitespace — which rules out URLs, paths, query
    strings and userinfo without needing to recognise each form.

    Deliberately permissive about what *is* an identifier: `doc_8814`,
    `kb-2291`, `connector:acme:42` and `sha256.ab12cd` all pass. The goal is to
    prevent accidental leakage, not to make correlation inconvenient.
    """
    if not value:
        return "must not be empty"
    if len(value) > SOURCE_REF_MAX_CHARS:
        return f"exceeds {SOURCE_REF_MAX_CHARS} characters ({len(value)})"
    if ".." in value:
        return "must not contain '..' (path traversal)"
    if not _SOURCE_REF_ALLOWED.match(value):
        return (
            "must match [A-Za-z0-9._:-]+ — it is an opaque handle, not a URL, "
            "path, or credential-bearing string"
        )
    return None


def source_kind_problem(value: str) -> str | None:
    """Why `value` is unacceptable as a `source_kind`, or None if it is fine.

    Constrained despite being purely descriptive, because it is a
    caller-supplied string and therefore must never become a metrics label:
    unbounded cardinality is a denial of service against the metrics backend
    reachable by any client (docs/10-security-model.md).
    """
    if not value:
        return "must not be empty"
    if len(value) > SOURCE_KIND_MAX_CHARS:
        return f"exceeds {SOURCE_KIND_MAX_CHARS} characters ({len(value)})"
    if not _SOURCE_KIND_ALLOWED.match(value):
        return "must match [a-z0-9_]+ (lowercase snake case)"
    return None


def sanitise_source_ref(value: object) -> str | None:
    """Lenient counterpart to the strict model validator, for wire input.

    Returns None for anything unusable rather than raising. A malformed
    correlation handle must not fail a request (ADR-017 §12).
    """
    if not isinstance(value, str):
        return None
    return None if source_ref_problem(value) else value


def sanitise_source_kind(value: object) -> str | None:
    """Lenient counterpart to the strict model validator, for wire input."""
    if not isinstance(value, str):
        return None
    return None if source_kind_problem(value) else value


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

    # --- provenance (ADR-017) ------------------------------------------------
    # Default `UNKNOWN` rather than a guess: a request that says nothing about
    # origin must not be silently treated as trusted, and must behave exactly as
    # it did before provenance existed.
    provenance: Provenance = Provenance.UNKNOWN
    trust: TrustLevel = TrustLevel.UNKNOWN
    # Opaque correlation handle — never a locator. See `sanitise_source_ref`.
    source_ref: str | None = None
    # Descriptive only. **No policy rule may key on this** (ADR-017 §2).
    source_kind: str | None = None

    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("source_ref")
    @classmethod
    def _source_ref_is_opaque(cls, value: str | None) -> str | None:
        """Strict invariant for internal construction.

        Wire input never reaches this validator directly: `sanitise_source_ref`
        drops a bad claim before a context is built, because a metadata defect
        must not turn into a failed request. Reaching here with a bad value is a
        programming error and should raise.
        """
        if value is None:
            return None
        problem = source_ref_problem(value)
        if problem:
            raise ValueError(f"source_ref {problem}")
        return value

    @field_validator("source_kind")
    @classmethod
    def _source_kind_is_a_plain_descriptor(cls, value: str | None) -> str | None:
        if value is None:
            return None
        problem = source_kind_problem(value)
        if problem:
            raise ValueError(f"source_kind {problem}")
        return value

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


class ProvenanceContext(BaseModel):
    """The origin facts the policy engine is allowed to see.

    Deliberately **not** the whole `DetectionContext`. Handing the engine a
    context would give it `raw_text`, which breaks the property that makes its
    truth table exhaustively testable and puts prompt content one attribute
    access away from a decision path that must never log it (ADR-003, ADR-017).

    Two fields, both bounded enums, both derived by the gateway.
    """

    model_config = ConfigDict(frozen=True)

    provenance: Provenance = Provenance.UNKNOWN
    trust: TrustLevel = TrustLevel.UNKNOWN

    @classmethod
    def from_context(cls, ctx: DetectionContext) -> ProvenanceContext:
        """Project a detection context down to only what policy may consider."""
        return cls(provenance=ctx.provenance, trust=ctx.trust)


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
