"""The application-level audit contract.

Deliberately independent of storage: the same objects are emitted as structured
logs and persisted to PostgreSQL, and Phase 5's queued writer will consume them
unchanged.

**What may never appear in these models** (docs/10-security-model.md, ADR-012):
raw prompts, raw completions, matched PII values, API keys, `Authorization`
headers. The models carry decisions, scores, categories, latencies, counts and
truncated content *hashes*. That constraint is structural — there is no field to
put content in — and it is asserted by `tests/security/test_audit_privacy.py`.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.core.types import Action, Category, Direction


def _now() -> datetime:
    return datetime.now(UTC)


class DetectorOutcome(BaseModel):
    """One detector's contribution to one inspected text.

    Records the score *and the threshold in force at decision time*, without
    which a historical decision cannot be interpreted after the policy changes —
    and which is what makes retrospective threshold tuning possible.
    """

    model_config = ConfigDict(frozen=True)

    detector: str
    direction: Direction
    category: Category
    detected: bool
    score: float
    threshold: float
    latency_ms: float
    errored: bool = False
    error_kind: str | None = None
    # Rule identifiers only, never matched text.
    reasons: tuple[str, ...] = ()


class SecurityEvent(BaseModel):
    """A notable security outcome: a block, a redaction, a warning or a failure.

    Emitted only for non-ALLOW outcomes and for failures; benign traffic produces
    a request trace but no security event, so the security table stays a record of
    things that happened rather than a copy of the access log.
    """

    model_config = ConfigDict(frozen=True)

    request_id: str
    created_at: datetime = Field(default_factory=_now)
    event_type: str  # block | redact | warn | detector_failure | upstream_failure
    direction: Direction
    category: Category | None = None
    detector: str | None = None
    score: float | None = None
    severity: int = 5
    # Truncated SHA-256 of the inspected text. Turns "is someone probing us with
    # the same payload" into a GROUP BY without storing a single prompt — while
    # proving sameness, not secrecy (docs/10-security-model.md).
    content_hash: str | None = None
    content_length: int | None = None
    # Bounded and label-only: entity types and counts, rule ids, span offsets.
    details: dict[str, Any] = Field(default_factory=dict)


class RequestTrace(BaseModel):
    """One row per request that reaches the gateway, including rejected ones."""

    model_config = ConfigDict(frozen=True)

    request_id: str
    created_at: datetime = Field(default_factory=_now)
    model: str | None = None
    upstream_host: str | None = None
    status_code: int
    # None when the request failed before or during policy evaluation (malformed
    # body, unsupported feature, upstream error). Recording ALLOW there would
    # claim a policy examined the request and permitted it, which is false — and
    # an audit trail that is confidently wrong is worse than one that is absent.
    decision: Action | None = None
    block_category: Category | None = None
    policy_version: str

    # Latency accounting. `gateway_latency_ms` excludes upstream time by
    # construction — it is the figure a future overhead claim must rest on.
    gateway_latency_ms: float
    upstream_latency_ms: float | None = None
    detector_latency_ms: float = 0.0
    normalization_latency_ms: float = 0.0
    policy_latency_ms: float = 0.0

    # The security invariant, recorded rather than inferred: a blocked request
    # must never have reached the model.
    upstream_called: bool = False

    input_chars: int = 0
    output_chars: int = 0
    inspected_messages: int = 0
    truncated: bool = False

    detector_outcomes: tuple[DetectorOutcome, ...] = ()
    events: tuple[SecurityEvent, ...] = ()
