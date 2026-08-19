"""The OpenAI-compatible chat-completions path — the vertical security slice.

Sequencing is the whole point of this module, and it is deliberately thin: every
step delegates, and nothing here decides anything by itself.

    validate → extract → normalise → input detectors → policy
      ├─ BLOCK  → 403, upstream NEVER called
      ├─ REDACT → rewrite the outgoing body, then forward
      └─ ALLOW / WARN → forward
    → upstream → output detectors → policy
      ├─ BLOCK  → 403 (the completion is discarded)
      └─ REDACT → rewrite the response body
    → audit event → response

Two invariants this file is responsible for:

1. **A blocked request never reaches the upstream.** Structurally guaranteed:
   the upstream call site is inside the non-blocking branch, and the audit row
   records `upstream_called` so the invariant is auditable rather than assumed.
2. **Policy decides, not this handler.** The handler executes a
   `PolicyDecision`; it never inspects a score or a threshold.
"""

from __future__ import annotations

from typing import Any

import structlog
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from app.core.exceptions import (
    FirewallError,
    InvalidRequest,
    NotImplementedYet,
    UnsupportedFeature,
)
from app.core.ids import content_hash
from app.core.types import (
    Action,
    Category,
    DetectionContext,
    Direction,
    PolicyDecision,
    ProvenanceContext,
)
from app.gateway.openai_schema import (
    ChatCompletionRequest,
    response_texts,
    set_response_text,
)
from app.gateway.translate import (
    build_contexts,
    build_output_context,
    redact_request,
)
from app.models.events import DetectorOutcome, RequestTrace, SecurityEvent
from app.observability.metrics import record_trace
from app.observability.timing import RequestTimings
from app.policy import engine
from app.policy.redaction import apply_redactions, redaction_summary

logger = structlog.get_logger(__name__)

ROUTE_CHAT = "/v1/chat/completions"

router = APIRouter(prefix="/v1", tags=["gateway"])

SEVERITY = {Action.BLOCK: 8, Action.REDACT: 5, Action.WARN: 3, Action.ALLOW: 1}


class _Accumulator:
    """Collects everything the audit record needs as the request progresses."""

    def __init__(self, request_id: str, policy_version: str, caller_id: str | None) -> None:
        self.request_id = request_id
        self.policy_version = policy_version
        # WHICH application called, never HOW it proved it. The identity is set
        # by `CallerAuthMiddleware` from configuration; there is no code path
        # from the presented credential to here (ADR-024 §20).
        self.caller_id = caller_id
        self.outcomes: list[DetectorOutcome] = []
        self.events: list[SecurityEvent] = []
        self.upstream_called = False
        self.inspected_messages = 0
        self.truncated = False

    def add_results(self, ctx: DetectionContext, decision: PolicyDecision, policy: Any) -> None:
        for result in decision.results:
            entry = policy.for_detector(ctx.direction, result.detector)
            self.outcomes.append(
                DetectorOutcome(
                    detector=result.detector,
                    direction=ctx.direction,
                    category=result.category,
                    detected=result.detected,
                    score=result.score,
                    threshold=entry.threshold if entry else 0.0,
                    latency_ms=result.latency_ms,
                    errored=result.errored,
                    error_kind=result.error_kind,
                    reasons=result.reasons,
                    provenance=ctx.provenance,
                    trust=ctx.trust,
                )
            )

    def add_event(
        self, ctx: DetectionContext, decision: PolicyDecision, details: dict[str, Any]
    ) -> None:
        if decision.action is Action.ALLOW:
            return
        self.events.append(
            SecurityEvent(
                request_id=self.request_id,
                event_type=decision.action.value
                if decision.category is not Category.DETECTOR_FAILURE
                else "detector_failure",
                direction=ctx.direction,
                category=decision.category,
                detector=decision.triggering_detector,
                score=max((r.score for r in decision.results), default=None),
                severity=SEVERITY[decision.action],
                # Fingerprint, never content.
                content_hash=content_hash(ctx.raw_text),
                content_length=len(ctx.raw_text),
                provenance=ctx.provenance,
                trust=ctx.trust,
                details=details,
            )
        )


def _block_response(request_id: str, decision: PolicyDecision, status_code: int) -> JSONResponse:
    """The documented block envelope.

    Category and request ID only — never the score, the rule, or the offending
    text. Returning more turns the gateway into a tuning oracle an attacker can
    iterate against (threat T-13); the detail lives in the audit trail, where the
    operator can retrieve it by request ID.
    """
    category = decision.category.value if decision.category else "security_policy"
    if decision.category is Category.DETECTOR_FAILURE:
        message = (
            "The security gateway could not complete inspection and failed closed. "
            "This is a gateway availability problem, not a policy violation."
        )
        error_type = "detector_failure"
    else:
        message = "Request blocked by security policy."
        error_type = "security_block"
    return JSONResponse(
        status_code=status_code,
        content={
            "error": {
                "message": message,
                "type": error_type,
                "code": category,
                "request_id": request_id,
                "decision": decision.action.value,
            }
        },
    )


@router.post("/chat/completions", summary="OpenAI-compatible chat completions")
async def chat_completions(request: Request) -> JSONResponse:
    state = request.app.state
    config = state.config
    policy = config.policy
    settings = config.settings
    timings = RequestTimings()
    request_id = request.scope.get("state", {}).get("request_id", "unknown")
    caller = request.scope.get("state", {}).get("caller")
    acc = _Accumulator(request_id, config.policy_version, getattr(caller, "caller_id", None))

    status_code = 200
    decision_for_trace: PolicyDecision | None = None
    upstream_latency: float | None = None
    output_chars = 0

    try:
        # --- 1. Validate ---------------------------------------------------
        try:
            raw_body = await request.json()
        except ValueError as exc:
            raise InvalidRequest("Request body is not valid JSON.") from exc
        if not isinstance(raw_body, dict):
            raise InvalidRequest("Request body must be a JSON object.")
        try:
            parsed = ChatCompletionRequest.model_validate(raw_body)
        except ValidationError as exc:
            # Field locations only. Pydantic's rendered message embeds the
            # submitted value, and letting it reach the generic 500 handler would
            # write prompt content into a logged traceback.
            fields = sorted({".".join(str(p) for p in e.get("loc", ())) for e in exc.errors()})
            raise InvalidRequest(
                f"Request failed validation for: {', '.join(fields) or 'body'}"
            ) from None

        if parsed.stream:
            # Refused, not faked. A firewall that streams bytes it has not
            # inspected provides no guarantee (ADR-004).
            raise UnsupportedFeature(
                "Streaming is not supported yet: responses cannot be inspected "
                "incrementally without weakening the guarantee. See "
                "docs/03-request-response-flow.md."
            )

        # --- 2. Extract + normalise ----------------------------------------
        with timings.measure("normalization_ms"):
            contexts = build_contexts(
                parsed,
                policy,
                request_id=request_id,
                trust_inline_claims=settings.trust_inline_provenance_claims,
            )
        acc.inspected_messages = len(contexts)
        acc.truncated = any(ctx.truncated for ctx in contexts)
        input_chars = sum(len(ctx.raw_text) for ctx in contexts)

        # --- 3. Input detection + policy, per inspectable part -------------
        outgoing: dict[str, Any] = raw_body
        worst = Action.ALLOW
        blocking: PolicyDecision | None = None

        for ctx in contexts:
            with timings.measure("detector_ms"):
                results = await state.pipeline.run(Direction.INPUT, ctx)
            with timings.measure("policy_ms"):
                decision = engine.evaluate(
                    results, policy, Direction.INPUT, ProvenanceContext.from_context(ctx)
                )

            acc.add_results(ctx, decision, policy)
            acc.add_event(
                ctx,
                decision,
                {
                    "message_index": ctx.message_index,
                    "role": ctx.role.value,
                    "reasons": list(decision.reasons),
                    "redactions": redaction_summary(decision.redaction_spans),
                },
            )

            if engine.is_more_severe(decision.action, worst):
                worst = decision.action
            if decision.action is Action.BLOCK and blocking is None:
                blocking = decision
            elif decision.action is Action.REDACT and decision.redaction_spans:
                redact_request(outgoing, ctx, decision.redaction_spans, policy.redaction.template)

        # --- 4. Block before the upstream is ever contacted ----------------
        if blocking is not None:
            decision_for_trace = blocking
            status_code = 503 if blocking.category is Category.DETECTOR_FAILURE else 403
            return _block_response(request_id, blocking, status_code)

        # --- 5. Upstream ----------------------------------------------------
        acc.upstream_called = True
        result = await state.upstream.chat_completions(outgoing)
        timings.upstream_ms = result.latency_ms
        upstream_latency = result.latency_ms
        body = result.body

        # --- 6. Output inspection ------------------------------------------
        output_worst = Action.ALLOW
        output_blocking: PolicyDecision | None = None

        for choice_index, text in response_texts(body):
            output_chars += len(text)
            out_ctx = build_output_context(
                text, policy, request_id=request_id, choice_index=choice_index
            )
            with timings.measure("output_detector_ms"):
                results = await state.pipeline.run(Direction.OUTPUT, out_ctx)
            with timings.measure("policy_ms"):
                decision = engine.evaluate(
                    results, policy, Direction.OUTPUT, ProvenanceContext.from_context(out_ctx)
                )

            acc.add_results(out_ctx, decision, policy)
            acc.add_event(
                out_ctx,
                decision,
                {
                    "choice_index": choice_index,
                    "reasons": list(decision.reasons),
                    "redactions": redaction_summary(decision.redaction_spans),
                },
            )

            if engine.is_more_severe(decision.action, output_worst):
                output_worst = decision.action
            if decision.action is Action.BLOCK and output_blocking is None:
                output_blocking = decision
            elif decision.action is Action.REDACT and decision.redaction_spans:
                set_response_text(
                    body,
                    choice_index,
                    apply_redactions(
                        text, decision.redaction_spans, template=policy.redaction.template
                    ),
                )

        if output_blocking is not None:
            # Containment, not prevention: the completion was produced and paid
            # for, and is discarded rather than returned.
            decision_for_trace = output_blocking
            status_code = 403
            return _block_response(request_id, output_blocking, 403)

        final = output_worst if engine.is_more_severe(output_worst, worst) else worst
        decision_for_trace = PolicyDecision(action=final, direction=Direction.OUTPUT)
        headers = {"X-Firewall-Decision": final.value}
        if settings.expose_timing_headers:
            timings.finish()
            headers["X-Firewall-Gateway-Ms"] = f"{timings.gateway_overhead_ms:.3f}"
            headers["X-Firewall-Upstream-Ms"] = f"{timings.upstream_ms:.3f}"

        return JSONResponse(status_code=200, content=body, headers=headers)

    except FirewallError as exc:
        # Every typed failure — upstream error, malformed request, unsupported
        # feature, audit refusal — records the status it will actually produce.
        # Without this the audit row reports 200 for a request that failed, which
        # makes the trail worse than absent: confidently wrong.
        status_code = exc.status_code
        raise
    except Exception:
        status_code = 500
        raise
    finally:
        timings.finish()
        await _persist(
            state,
            acc,
            parsed_model=locals().get("parsed"),
            status_code=status_code,
            decision=decision_for_trace,
            timings=timings,
            upstream_latency=upstream_latency,
            input_chars=locals().get("input_chars", 0),
            output_chars=output_chars,
        )


async def _persist(
    state: Any,
    acc: _Accumulator,
    *,
    parsed_model: ChatCompletionRequest | None,
    status_code: int,
    decision: PolicyDecision | None,
    timings: RequestTimings,
    upstream_latency: float | None,
    input_chars: int,
    output_chars: int,
) -> None:
    """Write the audit record. Never raises into the request path unless
    `require_audit` is configured (ADR-012)."""
    trace = RequestTrace(
        request_id=acc.request_id,
        model=parsed_model.model if parsed_model else None,
        upstream_host=getattr(state.upstream, "host", None),
        caller_id=acc.caller_id,
        status_code=status_code,
        decision=decision.action if decision else None,
        block_category=decision.category if decision and decision.blocked else None,
        policy_version=acc.policy_version,
        gateway_latency_ms=timings.gateway_overhead_ms,
        upstream_latency_ms=upstream_latency,
        detector_latency_ms=timings.detector_ms + timings.output_detector_ms,
        normalization_latency_ms=timings.normalization_ms,
        policy_latency_ms=timings.policy_ms,
        upstream_called=acc.upstream_called,
        input_chars=input_chars,
        output_chars=output_chars,
        inspected_messages=acc.inspected_messages,
        truncated=acc.truncated,
        detector_outcomes=tuple(acc.outcomes),
        events=tuple(acc.events),
    )

    # One call site for both sinks: metrics and audit are emitted from the same
    # assembled trace, so a discrepancy between the dashboard and the audit table
    # cannot come from two code paths disagreeing.
    metrics = getattr(state, "metrics", None)
    if metrics is not None:
        record_trace(metrics, trace, route=ROUTE_CHAT)

    logger.info(
        "request_decided",
        decision=trace.decision.value if trace.decision else "not_evaluated",
        category=trace.block_category.value if trace.block_category else None,
        status_code=status_code,
        upstream_called=trace.upstream_called,
        inspected_messages=trace.inspected_messages,
        **timings.as_dict(),
    )

    with timings.measure("audit_ms"):
        await state.audit.record(trace)


@router.get("/models", summary="Proxied model list (Phase 1)")
async def models() -> None:
    raise NotImplementedYet("Model listing is not implemented yet (Phase 1).")


__all__ = ["ValidationError", "router"]
