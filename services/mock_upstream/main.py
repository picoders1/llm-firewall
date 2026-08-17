"""A controllable OpenAI-compatible mock upstream.

Deliberately **not a model**. It does no generation and makes no claim to. It is a
controllable mirror that lets the gateway be tested and measured as a gateway
(docs/adr/ADR-009-mock-upstream.md).

Four needs it satisfies that no real endpoint can satisfy together:

1. `docker compose up` works with no API key, no account and no egress.
2. Tests are deterministic — "the response was redacted" needs a known response.
3. Latency benchmarks isolate gateway overhead. A real model's variance is one to
   three orders of magnitude larger than the effect being measured, so
   `MOCK_LATENCY_MS` provides a fixed, configurable delay instead.
4. Output-inspection tests need a PII-bearing response on demand, without asking
   a real model to emit PII.

It also exposes `GET /__stats`, a call counter. That endpoint exists for one
security invariant: **a blocked request must never reach the upstream**, and
asserting a 403 status code does not prove it. The test asserts the counter did
not move (docs/16-testing-strategy.md §17).

This service is intentionally standalone — it imports nothing from `app`. A test
double that imports the system under test is not a test double.
"""

from __future__ import annotations

import asyncio
import os
import time
import uuid
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI(title="Mock OpenAI-compatible upstream", version="0.1.0")

LATENCY_MS = float(os.environ.get("MOCK_LATENCY_MS", "0"))

# Marker phrases that select a behaviour. Explicit triggers rather than clever
# inference, so a test's intent is readable from its fixture.
TRIGGER_PII = "__return_pii__"
TRIGGER_ERROR = "__return_500__"
TRIGGER_SLOW = "__slow__"
TRIGGER_MALFORMED = "__return_malformed__"
TRIGGER_HUGE = "__return_huge__"

# Synthetic only: example.com, a reserved-range number, and the standard
# Luhn-valid test card. No real PII exists anywhere in this repository.
PII_RESPONSE = (
    "Sure. You can reach the account holder at alice@example.com "
    "or on +1-555-0142. The card on file is 4111 1111 1111 1111."
)

_stats: dict[str, int] = {"chat_completions": 0, "models": 0}


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "mock-upstream"}


@app.get("/__stats")
async def stats() -> dict[str, int]:
    """Observable call counter — the upstream-invariant assertion point."""
    return dict(_stats)


@app.post("/__stats/reset")
async def reset_stats() -> dict[str, int]:
    for key in _stats:
        _stats[key] = 0
    return dict(_stats)


@app.get("/v1/models")
async def models() -> dict[str, Any]:
    _stats["models"] += 1
    return {
        "object": "list",
        "data": [{"id": "mock-model", "object": "model", "owned_by": "mock"}],
    }


def _extract_text(payload: dict[str, Any]) -> str:
    parts: list[str] = []
    for message in payload.get("messages", []):
        if not isinstance(message, dict):
            continue
        content = message.get("content")
        if isinstance(content, str):
            parts.append(content)
        elif isinstance(content, list):
            parts.extend(
                part.get("text", "")
                for part in content
                if isinstance(part, dict) and isinstance(part.get("text"), str)
            )
    return "\n".join(parts)


@app.post("/v1/chat/completions")
async def chat_completions(request: Request) -> JSONResponse:
    _stats["chat_completions"] += 1

    payload = await request.json()
    text = _extract_text(payload)

    if TRIGGER_ERROR in text:
        return JSONResponse(status_code=500, content={"error": {"message": "mock upstream error"}})

    if TRIGGER_MALFORMED in text:
        # Valid HTTP, invalid contract: proves the gateway fails safe rather than
        # propagating whatever the provider sent.
        return JSONResponse(status_code=200, content=["not", "an", "object"])

    if TRIGGER_SLOW in text:
        await asyncio.sleep(float(os.environ.get("MOCK_SLOW_S", "5")))

    if LATENCY_MS:
        await asyncio.sleep(LATENCY_MS / 1000.0)

    if TRIGGER_PII in text:
        content = PII_RESPONSE
    elif TRIGGER_HUGE in text:
        content = "x" * 200_000
    else:
        # Deterministic and derived from the request: the same input always
        # produces the same output, which is what makes assertions possible.
        content = f"Mock completion for: {text[:200]}" if text else "Mock completion."

    prompt_tokens = max(1, len(text) // 4)
    completion_tokens = max(1, len(content) // 4)

    return JSONResponse(
        status_code=200,
        content={
            "id": f"chatcmpl-mock-{uuid.uuid4().hex[:12]}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": payload.get("model", "mock-model"),
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": content},
                    "finish_reason": "stop",
                }
            ],
            "usage": {
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens": prompt_tokens + completion_tokens,
            },
        },
    )
