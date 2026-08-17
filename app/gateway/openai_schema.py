"""The OpenAI chat-completions subset the gateway validates.

Only the fields the gateway *acts on* are validated: `model`, `messages`,
`stream`. Everything else is preserved and forwarded unchanged
(`extra="allow"`), because a proxy that drops what it does not understand
silently changes request semantics and produces bugs that look like model
regressions (docs/07-openai-compatible-api.md).
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class ContentPart(BaseModel):
    """One part of a multi-part message."""

    model_config = ConfigDict(extra="allow")

    type: str
    text: str | None = None


class ChatMessage(BaseModel):
    model_config = ConfigDict(extra="allow")

    role: str
    # str | parts | null — `null` is legal for an assistant message carrying only
    # tool_calls.
    content: str | list[ContentPart] | None = None
    name: str | None = None
    tool_call_id: str | None = None


class ChatCompletionRequest(BaseModel):
    model_config = ConfigDict(extra="allow")

    model: str
    messages: list[ChatMessage] = Field(min_length=1)
    stream: bool | None = None


class Usage(BaseModel):
    model_config = ConfigDict(extra="allow")

    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    total_tokens: int | None = None


class ResponseMessage(BaseModel):
    model_config = ConfigDict(extra="allow")

    role: str = "assistant"
    content: str | None = None


class Choice(BaseModel):
    model_config = ConfigDict(extra="allow")

    index: int = 0
    message: ResponseMessage
    finish_reason: str | None = None


class ChatCompletionResponse(BaseModel):
    """Parsed only for inspection. The body forwarded to the client is the
    upstream's own JSON with redactions applied, never a re-serialisation of this
    model — that would silently drop provider fields we do not model."""

    model_config = ConfigDict(extra="allow")

    id: str | None = None
    object: Literal["chat.completion"] | str = "chat.completion"
    model: str | None = None
    choices: list[Choice] = Field(default_factory=list)
    usage: Usage | None = None


def response_texts(body: dict[str, Any]) -> list[tuple[int, str]]:
    """Extract `(choice_index, text)` for every assistant message in a response.

    Every choice is inspected, not only the first — `n > 1` returning an
    uninspected second completion is a real and commonly-missed gap.
    """
    texts: list[tuple[int, str]] = []
    choices = body.get("choices")
    if not isinstance(choices, list):
        return texts
    for position, choice in enumerate(choices):
        if not isinstance(choice, dict):
            continue
        message = choice.get("message")
        if not isinstance(message, dict):
            continue
        content = message.get("content")
        if isinstance(content, str) and content:
            index = choice.get("index")
            texts.append((index if isinstance(index, int) else position, content))
    return texts


def set_response_text(body: dict[str, Any], choice_index: int, text: str) -> None:
    """Write redacted text back into the upstream body in place."""
    choices = body.get("choices")
    if not isinstance(choices, list):
        return
    for position, choice in enumerate(choices):
        if not isinstance(choice, dict):
            continue
        index = choice.get("index")
        if (index if isinstance(index, int) else position) != choice_index:
            continue
        message = choice.get("message")
        if isinstance(message, dict):
            message["content"] = text
        return
