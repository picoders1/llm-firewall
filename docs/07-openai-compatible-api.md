# 07 — OpenAI-Compatible API Contract

Decision record: [ADR-004](adr/ADR-004-openai-compatible-contract.md).

## Goal

```python
from openai import OpenAI

client = OpenAI(base_url="http://localhost:8000/v1", api_key="...")
client.chat.completions.create(model="gpt-4o-mini", messages=[...])
```

An existing application changes one line and gains inspection, policy and audit. If
integration needs an SDK or a wrapper, the product competes for engineering time and loses.

**Compatibility is claimed only where it has been tested.** Until the Phase 1 SDK integration
test passes, this document describes an *intended* contract.

## Supported surface

| Endpoint | Phase | State |
|---|---|---|
| `POST /v1/chat/completions` (non-streaming) | 0/1 | Planned |
| `GET /v1/models` | 1 | Planned — proxied, short-cached |
| `GET /health` | 0 | Liveness, no dependencies |
| `GET /ready` | 0 | Readiness, dependency-checked |
| `GET /metrics` | 0 | Prometheus |
| `POST /v1/chat/completions` (`stream: true`) | 6 | **`400 unsupported_feature`** |
| `POST /v1/completions` (legacy) | — | Not planned |
| `POST /v1/embeddings` | 7 | Conditional — different threat surface |
| Assistants, files, fine-tuning, batches | — | Out of scope |

Unimplemented endpoints return `404` with the OpenAI error envelope. The supported surface is
documented explicitly so a client is never surprised by a silent behavioural difference.

## Request handling

**Validated** (the fields the gateway acts on): `model`, `messages`, `stream`.

**Preserved and forwarded unchanged**: `temperature`, `top_p`, `n`, `stop`, `max_tokens`,
`tools`, `tool_choice`, `response_format`, `seed`, `logit_bias`, `user`, and **any field the
gateway does not recognise**.

Pass-through of unknown fields is deliberate. Provider feature velocity is high; a proxy that
drops what it does not understand silently changes request semantics and produces bugs that
look like model regressions. The gateway validates what it inspects and forwards the rest.

### Message content

Both content forms are handled:

```jsonc
{"role": "user", "content": "text"}                                    // string
{"role": "user", "content": [{"type": "text", "text": "..."},          // multi-part
                             {"type": "image_url", "image_url": {...}}]}
```

Text parts are extracted and inspected. Non-text parts are **counted and recorded but not
inspected** — a documented Phase 0 limitation, not a silent gap
([09-threat-model.md](09-threat-model.md), non-text modalities are out of scope).

### Which messages are inspected

Governed by `inspect_roles`, default `[user, tool]`. Rationale and the full role table are in
[03-request-response-flow.md](03-request-response-flow.md). The short version: `tool` is where
indirect injection arrives, and `system` is trusted by configuration rather than by assumption.

## Response handling

The upstream response is returned as-is except for applied redactions.

* Every choice is inspected when `n > 1`, not only the first.
* `usage` is **never rewritten**, even when content is redacted. It reports what the upstream
  actually billed; adjusting it would falsify an accounting record.
* Added response headers: `X-Request-ID`, and `X-Firewall-Decision` (`allow` / `warn` /
  `redact`) so a client can detect modified content without parsing the body.

## Error contract

The OpenAI error envelope, so existing client error handling keeps working:

```json
{
  "error": {
    "message": "Request blocked by security policy.",
    "type": "security_block",
    "code": "prompt_injection",
    "request_id": "3f9c1e7a8b2d4f60"
  }
}
```

| Condition | Status | `type` |
|---|---|---|
| Malformed body / schema violation | 400 | `invalid_request_error` |
| `stream: true` | 400 | `unsupported_feature` |
| Missing or unrecognised caller credential | 401 | `invalid_request_error` / code `invalid_api_key` |
| Per-caller rate or concurrency ceiling | 429 | `rate_limit_exceeded`, with `Retry-After` |
| Blocked by policy | 403 | `security_block` |
| Unknown endpoint | 404 | `not_found_error` |
| Body over `max_request_bytes` | 413 | `request_too_large` |
| Upstream rate limit | 429 | passthrough with `Retry-After` — distinguishable from the gateway's own limit by `type` |
| Upstream unreachable / 5xx | 502 | `upstream_error` |
| Detector failure, fail-closed | 503 | `detector_failure` |
| Upstream read timeout | 504 | `upstream_timeout` |

Four rules govern error bodies:

1. **Block responses state category and request ID only** — never the score, the matched rule,
   or the offending text. Anything more turns the gateway into a tuning oracle the attacker
   can iterate against (threat T-13). The detail goes to the audit trail, retrievable by
   request ID.
2. **Upstream response bodies are never reflected.** They can contain the reflected prompt or
   provider internals.
3. **Unhandled exceptions return a generic message.** Stack traces are logged server-side
   only.
4. **A 401 does not say *why*.** "No credential", "wrong credential" and "revoked
   credential" produce byte-identical bodies apart from the request ID; the distinction goes
   to `firewall_caller_auth_failures_total{reason}` and the log. Telling them apart on the
   wire turns the gateway into an oracle for enumerating which keys exist
   ([ADR-024](adr/ADR-024-llm-caller-authentication.md)).

Note the deliberate distinction between `403` (you are being blocked) and `503` (we cannot
inspect right now). A client's retry logic should treat these differently, and merging them
would hide detector outages behind apparent attack traffic.

## Upstream configuration

```bash
FIREWALL_UPSTREAM_BASE_URL=http://localhost:8081/v1   # default: bundled mock
FIREWALL_UPSTREAM_API_KEY=                            # SecretStr; empty for the mock
FIREWALL_UPSTREAM_CONNECT_TIMEOUT_S=5
FIREWALL_UPSTREAM_READ_TIMEOUT_S=60
```

Any endpoint speaking the contract works: OpenAI, vLLM, Ollama (`/v1`), Groq, Together,
OpenRouter, or an internal service. The gateway does **not** route between providers or
rewrite model names — that is a different product (LiteLLM), and conflating routing with
security would double the surface of both.

Client `Authorization` headers are **not** forwarded. The gateway holds its own upstream
credential; passing client keys through would make the gateway a credential relay and defeat
the point of terminating the connection.

## Streaming

`stream: true` → `400 unsupported_feature`.

This is a refusal, not a gap. Once a token is on the client socket it cannot be recalled, and
the three available strategies each cost something real — analysed in
[03-request-response-flow.md](03-request-response-flow.md). The common industry choice (emit
immediately, terminate the stream on detection) leaks the sensitive prefix and is frequently
advertised as inspected streaming. Shipping that would be a false security claim, which this
project treats as worse than a missing feature.

**Phase 6 commitment.** Sliding-window inspection with bounded lookahead, shipping only with:
measured TTFT cost, `leaked_prefix_tokens` recorded on every stream-block event, and a
published detection delta against non-streaming inspection on the same dataset.

## Request identity

`X-Request-ID` is reused if the client supplies a valid one, otherwise generated. Client
values are **untrusted input**: bounded to 128 characters, `[A-Za-z0-9-_:.]` only, so a header
containing a newline cannot forge records in the security log (FR-051).

Echoed on every response, including errors, and used as the correlation key across logs,
metrics, spans and audit rows.

## Compatibility limitations (stated, not hidden)

| Limitation | Phase |
|---|---|
| No streaming | 6 |
| Non-text content parts not inspected | — (out of scope) |
| No provider routing or model aliasing | — (out of scope) |
| Client `Authorization` not forwarded | by design |
| No `/v1/completions`, assistants, files, batches | — |
| Compatibility asserted only where tested | Phase 1 SDK test |

## Verification

| Property | Test |
|---|---|
| Unmodified OpenAI SDK works end to end | `tests/integration/test_openai_sdk.py` (Phase 1) |
| Unknown fields survive the round trip | `tests/api/test_passthrough.py` |
| `stream: true` → 400 with correct envelope | `tests/api/test_streaming_rejected.py` |
| Every error condition maps to the documented status and type | `tests/api/test_error_envelope.py` |
| Block response contains no score, rule or prompt fragment | `tests/security/test_block_response.py` |
| Upstream body never reflected | `tests/security/test_upstream_leak.py` |
| `n > 1` — all choices inspected | `tests/api/test_multi_choice.py` (Phase 1) |
| Malicious `X-Request-ID` rejected | `tests/security/test_log_injection.py` |
