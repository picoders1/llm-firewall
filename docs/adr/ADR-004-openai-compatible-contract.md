# ADR-004: OpenAI-Compatible Contract, and Deferring Streaming

**Status:** Accepted
**Date:** 2026-08-17
**Phase:** 0 (contract), Phase 6 (streaming)

## Context

The entire adoption argument for this product is one line:

```python
client = OpenAI(base_url="http://localhost:8000/v1", api_key=...)
```

If integration requires an SDK, a wrapper, or an application change, it competes with every
other security tool for engineering time and loses. Speaking the OpenAI HTTP contract makes
the gateway adoptable by an application team in a config change, and — because vLLM, Ollama,
Together, Groq, OpenRouter and most self-hosted servers implement the same contract — makes
the upstream swappable without provider lock-in.

The complication: the contract includes streaming, and streaming is in genuine tension with
output inspection.

## Decision

**Implement a documented subset of the OpenAI HTTP contract**, and be explicit about the
boundary.

| Endpoint | Status |
|---|---|
| `POST /v1/chat/completions` (non-streaming) | Phase 0/1 |
| `GET /v1/models` | Phase 1 — proxied from upstream |
| `POST /v1/chat/completions` (`stream: true`) | **`400 unsupported_feature`** until Phase 6 |
| `POST /v1/completions` (legacy) | Not planned; document it |
| `POST /v1/embeddings` | Phase 7 if justified — different threat surface |
| Assistants / files / fine-tuning | Out of scope |

**Request handling:** validate the fields we act on (`model`, `messages`, `stream`); preserve
and forward unknown fields rather than dropping them, so a provider feature we have not heard
of does not silently break. Passing through what we do not understand is the correct default
for a proxy — the alternative is a gateway that quietly changes request semantics.

**Response handling:** the upstream response is returned as-is except for applied redactions.
`usage` is never rewritten, even when content is redacted: it reports what the upstream
actually billed, and adjusting it would be falsifying an accounting record.

**Error envelope** — the OpenAI shape, so existing client error handling works unchanged:

```json
{
  "error": {
    "message": "Request blocked by security policy.",
    "type": "security_block",
    "code": "prompt_injection",
    "request_id": "..."
  }
}
```

Block responses state category and request ID only — never the score, matched rule, or
offending text (threat T-13).

**Streaming is refused, not faked.** `400` with a message pointing to the documented
limitation.

## Why streaming is refused rather than approximated

Once a token is on the client socket it cannot be recalled. The three available strategies
and their real costs are analysed in
[output-inspection.md](../03-request-response-flow.md):

* **Buffer everything** — full inspection, zero streaming benefit. Honest but pointless.
* **Sliding window with bounded lookahead** — partial inspection, quantifiable TTFT cost,
  findings that straddle the window boundary are missed.
* **Emit immediately, kill the stream on detection** — the sensitive prefix has already
  left. This is what most "streaming-capable" guardrails do, and advertising it as inspected
  streaming is a false security claim.

Phase 6 will implement the sliding window, publish its measured TTFT cost, record
`leaked_prefix_tokens` on every stream-block event, and state in the API documentation that
streaming inspection is strictly weaker than non-streaming inspection — with the difference
measured on the same evaluation dataset.

Until that exists, `400` is the answer that does not lie.

## Alternatives considered

| Alternative | Rejected because |
|---|---|
| **A custom, cleaner API** | Better shaped for the domain, adopted by nobody. Every integration becomes an application change. |
| **Silently buffer streaming requests and return a single response** | The client asked for SSE and would receive a non-streaming body — a protocol violation that surfaces as a confusing client bug rather than a clear error. |
| **Pass streaming through uninspected** | The gateway would then advertise protection it does not provide on the code path most production chat applications use. This is the worst option available and is the one most commonly shipped. |
| **Support only streaming, buffered internally** | Sacrifices TTFT for everyone to serve one use case. |
| **Full OpenAI surface (assistants, files, embeddings)** | Enormous surface, mostly irrelevant to the threat model. Endpoints exist to be inspected, not to look complete. |
| **Provider-specific adapters (Anthropic, Bedrock, Vertex native formats)** | Real value, wrong phase. The OpenAI contract already reaches most self-hosted and hosted endpoints; native adapters are Phase 7 if demand justifies the translation-layer maintenance. |

## Consequences

### Positive
* Adoption is a base-URL change; existing SDKs, retries and error handling keep working.
* The upstream is swappable — mock, Ollama, vLLM, or a hosted provider — with one env var,
  which is exactly what makes the Phase 4 benchmark design possible (ADR-009).
* Passing unknown fields through means provider feature velocity does not break us.

### Negative / accepted costs
* **No streaming until Phase 6.** This is the largest functional gap, and for interactive
  chat applications it is a blocker. Stated in the README rather than buried.
* Non-streaming forces the full completion to be generated before the client sees anything;
  for long completions the user-visible latency is materially worse.
* Implementing someone else's contract means tracking its changes.
* Compatibility is a subset, so a client using an unimplemented endpoint gets a 404 from us
  where the provider would have answered. The supported surface is documented explicitly for
  this reason.

### Revisit when
Phase 6, when the sliding-window design has a measured TTFT cost and a measured detection
delta against non-streaming inspection.

## Verification

* `tests/api/test_chat_completions.py` — happy path against the mock upstream; unknown
  fields survive the round trip.
* `tests/api/test_streaming_rejected.py` — `stream: true` → `400`, correct error envelope.
* `tests/security/test_block_response.py` — a block response contains no score, rule name or
  prompt fragment.
* An unmodified `openai` Python SDK client can call the gateway (integration test, Phase 1).
