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


def build_contexts(
    request: ChatCompletionRequest,
    policy: PolicyConfig,
    *,
    request_id: str,
) -> list[DetectionContext]:
    """Build one `DetectionContext` per inspectable text part."""
    contexts: list[DetectionContext] = []
    limits = policy.limits

    for message_index, message in enumerate(request.messages[: limits.max_messages]):
        try:
            role = Role(message.role)
        except ValueError:
            # An unknown role is not silently trusted: it is inspected, because
            # "we did not recognise it" is not a reason to skip inspection.
            role = Role.USER
        if role not in policy.inspect_roles:
            continue

        for part_index, text in _message_parts(message.content):
            truncated = len(text) > limits.max_inspect_chars
            body = text[: limits.max_inspect_chars] if truncated else text
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
    return DetectionContext(
        request_id=request_id,
        direction=Direction.OUTPUT,
        role=Role.ASSISTANT,
        message_index=choice_index,
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
