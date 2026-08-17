"""Turning an OpenAI request into inspectable units, and writing redactions back.

Two security-relevant decisions live here.

**Which messages are inspected.** Governed by `inspect_roles`, default
`[user, tool]`. `tool` is the indirect-injection surface: retrieved documents and
tool output are attacker-controlled in any RAG or agent system and arrive with the
same syntactic status as the user's own words. `system` is trusted *by
configuration*, not by assumption (docs/03-request-response-flow.md).

**One context per message part.** Redaction spans are offsets into one specific
string. Merging spans across messages would corrupt content, so each inspectable
part becomes its own `DetectionContext` and its own policy decision.
"""

from __future__ import annotations

from typing import Any

from app.config.policy import PolicyConfig
from app.core.normalize import decode_embedded, normalize
from app.core.provenance import assign, derive_from_role
from app.core.types import DetectionContext, Direction, Role, TextSpan
from app.gateway.openai_schema import ChatCompletionRequest, ContentPart
from app.policy.redaction import apply_redactions


def _message_parts(content: str | list[ContentPart] | None) -> list[tuple[int, str]]:
    """Text parts of a message, with their part index."""
    if isinstance(content, str):
        return [(0, content)] if content else []
    if isinstance(content, list):
        return [
            (index, part.text)
            for index, part in enumerate(content)
            if part.text and part.type in {"text", "input_text"}
        ]
    return []


def _message_part_extras(
    content: str | list[ContentPart] | None, part_index: int
) -> dict[str, Any] | None:
    """Extras declared on one content part, if the message uses the parts form."""
    if not isinstance(content, list) or part_index >= len(content):
        return None
    return content[part_index].model_extra


def build_contexts(
    request: ChatCompletionRequest,
    policy: PolicyConfig,
    *,
    request_id: str,
    trust_inline_claims: bool = False,
) -> list[DetectionContext]:
    """Build one `DetectionContext` per inspectable text part.

    `trust_inline_claims` defaults to False, which is the whole security posture
    of Phase B: with it off, nothing a caller sends can influence provenance or
    trust, and every context's assignment is derived from the wire role alone.
    """
    contexts: list[DetectionContext] = []
    limits = policy.limits

    for message_index, message in enumerate(request.messages[: limits.max_messages]):
        try:
            role = Role(message.role)
            role_recognised = True
        except ValueError:
            # An unknown role is not silently trusted: it is inspected, because
            # "we did not recognise it" is not a reason to skip inspection.
            #
            # It is coerced to USER *for inspection routing only*. Its origin is
            # genuinely unknown, so provenance and trust must not inherit
            # PRINCIPAL from this coercion — hence the separate flag (ADR-017).
            role = Role.USER
            role_recognised = False
        if role not in policy.inspect_roles:
            continue

        for part_index, text in _message_parts(message.content):
            truncated = len(text) > limits.max_inspect_chars
            body = text[: limits.max_inspect_chars] if truncated else text
            # Provenance is assigned BEFORE normalisation and never re-derived
            # from the text. It attaches to the whole part, so the
            # `normalized_offsets` invariant gains nothing to desynchronise.
            assignment = assign(
                role,
                role_recognised=role_recognised,
                message_extras=message.model_extra,
                part_extras=_message_part_extras(message.content, part_index),
                trust_inline_claims=trust_inline_claims,
            )
            folded = normalize(body)
            contexts.append(
                DetectionContext(
                    request_id=request_id,
                    direction=Direction.INPUT,
                    role=role,
                    message_index=message_index,
                    part_index=part_index,
                    raw_text=body,
                    normalized_text=folded.text,
                    normalized_offsets=folded.offsets,
                    decoded_segments=decode_embedded(body, max_segments=limits.base64_segments),
                    truncated=truncated,
                    provenance=assignment.provenance,
                    trust=assignment.trust,
                    source_ref=assignment.source_ref,
                    source_kind=assignment.source_kind,
                )
            )
    return contexts


def build_output_context(
    text: str,
    policy: PolicyConfig,
    *,
    request_id: str,
    choice_index: int,
) -> DetectionContext:
    limits = policy.limits
    truncated = len(text) > limits.max_inspect_chars
    body = text[: limits.max_inspect_chars] if truncated else text
    folded = normalize(body)
    # The model produced this text; there is no caller claim to consider on the
    # output path at all.
    assignment = derive_from_role(Role.ASSISTANT)
    return DetectionContext(
        request_id=request_id,
        direction=Direction.OUTPUT,
        role=Role.ASSISTANT,
        message_index=choice_index,
        provenance=assignment.provenance,
        trust=assignment.trust,
        raw_text=body,
        normalized_text=folded.text,
        normalized_offsets=folded.offsets,
        decoded_segments=decode_embedded(body, max_segments=limits.base64_segments),
        truncated=truncated,
    )


def redact_request(
    payload: dict[str, Any],
    ctx: DetectionContext,
    spans: tuple[TextSpan, ...],
    template: str,
) -> None:
    """Apply redactions to one message part of the outgoing request body, in place.

    Operates on the raw payload rather than the parsed model so that provider
    fields the gateway does not model survive untouched.
    """
    if not spans:
        return
    messages = payload.get("messages")
    if not isinstance(messages, list) or ctx.message_index >= len(messages):
        return
    message = messages[ctx.message_index]
    if not isinstance(message, dict):
        return

    content = message.get("content")
    if isinstance(content, str):
        # Truncated inspection means the tail was never inspected; redacting only
        # the inspected prefix keeps the rest byte-identical.
        message["content"] = (
            apply_redactions(content[: len(ctx.raw_text)], spans, template=template)
            + content[len(ctx.raw_text) :]
        )
        return

    if isinstance(content, list) and ctx.part_index < len(content):
        part = content[ctx.part_index]
        if isinstance(part, dict) and isinstance(part.get("text"), str):
            part["text"] = apply_redactions(part["text"], spans, template=template)
