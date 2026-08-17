# 04 — Component Design

Module-by-module design: what each package owns, its public surface, its dependencies, and
its failure modes. This is the document an implementer works from.

Layering rules and the dependency direction are in
[02-system-architecture.md](02-system-architecture.md).

---

## `app/core` — domain vocabulary

**Owns:** the types every other layer speaks. No I/O, no framework imports, no logging.

| Module | Contents |
|---|---|
| `types.py` | `Action`, `Category`, `Direction`, `ErrorPolicy`, `Role`, `TextSpan`, `DecodedSegment`, `DetectionContext`, `DetectionResult`, `PolicyDecision` |
| `normalize.py` | `normalize(text) -> Normalized` (index-preserving), `decode_embedded(text)` |
| `ids.py` | `new_request_id()`, `content_hash()`, `is_valid_request_id()` |
| `exceptions.py` | Exception hierarchy, each carrying `error_type` + `status_code` |

**Design notes**

* All models are frozen Pydantic models. Detection results flow through three layers and are
  written to an audit record; mutation in transit would make the audit record a lie.
* `TextSpan` offsets are always relative to `raw_text`, never to normalised text — see
  [ADR-010](adr/ADR-010-normalization-strategy.md).
* Exceptions carry their own HTTP mapping so the API layer never guesses.

**Failure modes:** none — pure functions and data. Normalisation is bounded by
`max_inspect_chars` upstream of it.

---

## `app/config` — two configuration systems

**Owns:** settings from environment, policy from YAML, and the wall between them
([ADR-011](adr/ADR-011-configuration-model.md)).

| Module | Contents |
|---|---|
| `settings.py` | `Settings(BaseSettings)`, prefix `FIREWALL_`, `SecretStr` secrets, `effective_content_logging()` |
| `policy.py` | `PolicyConfig`, `DetectorPolicy`, validators |
| `loader.py` | Environment overlay precedence, `policy_version` hash, effective-config startup log |

**Validators that must exist** (each is a startup failure, never a runtime surprise):

* secret-shaped key anywhere in policy YAML (`*_key`, `*secret*`, `*token*`, `*password*`)
* threshold outside `[0, 1]`
* unknown detector name or unknown action
* `action: redact` on a detector that cannot emit spans
* `inspect_roles` containing an unknown role

**Failure modes:** invalid configuration → process does not start. `/ready` reports the reason
if the process starts but policy is later found unusable.

---

## `app/detectors` — the pluggable layer

**Owns:** detection. Full design in
[05-detector-architecture.md](05-detector-architecture.md).

| Module | Contents |
|---|---|
| `base.py` | `Detector` protocol; `SyncDetectorAdapter` (bounded thread offload) |
| `guarded.py` | `GuardedDetector` — timeout, error capture, latency measurement |
| `registry.py` | name → factory; instances built from `PolicyConfig` at startup |
| `pipeline.py` | `DetectorPipeline.run(direction, contexts)` — concurrent fan-out |
| `rules.py` | Shared rule engine: named weighted patterns, noisy-OR scoring, bounded matching |
| `injection/heuristic.py` | 10 weighted rules; **uncalibrated score, declared as such** |
| `jailbreak/heuristic.py` | 8 rules; distinct category and semantics from injection |
| `pii/regex.py` | Structured identifiers with spans, Luhn/mod-97 validation, overlap resolution |
| `stub.py` | `output.stub` — registered, wired, `detected=False` until Phase 3 |

**Public surface:** `build_detectors(policy, settings) -> DetectorPipeline`. Everything else is
internal.

**Failure modes:** every failure becomes `DetectionResult(errored=True)`; nothing propagates.
Conversion to an action happens in the policy engine, not here.

---

## `app/policy` — the only component that decides

**Owns:** `(results, config) → PolicyDecision`, and the mechanics of redaction.

| Module | Contents |
|---|---|
| `engine.py` | `evaluate(results, config, direction) -> PolicyDecision` — pure |
| `redaction.py` | `apply(text, spans) -> str`; overlapping-span merge; labelled tokens |

**Constraint:** `engine.py` imports nothing from `detectors`, `gateway`, `database`, `logging`
or `time`. Enforced by test. This is what makes the truth-table test possible
([06-policy-engine.md](06-policy-engine.md)).

**Failure modes:** none by construction. A malformed `DetectionResult` cannot exist — Pydantic
validated at the boundary.

---

## `app/gateway` — upstream and contract

| Module | Contents |
|---|---|
| `openai_schema.py` | Request/response models for the supported subset; unknown fields preserved |
| `translate.py` | `extract_inspectable(request, policy) -> list[DetectionContext]`; role filter, char budget, truncation flag; and the inverse, applying redactions back into the body |
| `upstream.py` | `UpstreamClient` — pooled `httpx.AsyncClient`, timeout budget, error mapping |

**Design notes**

* One client for the process lifetime, created in lifespan. A client per request is the most
  common latency bug in Python proxies.
* Upstream response bodies are **never** reflected to the client — they can contain the
  reflected prompt or provider internals.
* `translate.py` is where the `tool`-role decision lives; it is the indirect-injection surface
  and the reason the role filter is configuration rather than a constant.

**Failure modes:** connect error → `502`; read timeout → `504`; upstream 4xx → status
preserved, body dropped; upstream 5xx → `502`.

---

## `app/api` + `app/middleware` — the edge

| Module | Contents |
|---|---|
| `middleware/request_id.py` | Bind contextvar; validate untrusted client header |
| `middleware/body_limit.py` | `413` on `Content-Length` **and** during streamed read. The pre-check writes its own response because this middleware sits outside the app's exception handlers; the streaming check raises, because that code runs inside them |
| `middleware/timing.py` | Monotonic total-time measurement |
| `middleware/headers.py` | `nosniff`, `no-store`, `no-referrer` |
| `api/errors.py` | `FirewallError` → OpenAI error envelope; generic message for unhandled |
| `api/health.py` / `ready.py` / `metrics.py` | Liveness / readiness with per-check breakdown / Prometheus |
| `api/v1/chat.py` | The orchestration handler |
| `main.py` | App factory + lifespan |

**Middleware order (outermost first):** request-id → body-limit → timing → headers →
exception-handler. Request-id is outermost so that *every* failure, including a `413`, is
correlated.

**`api/v1/chat.py` is the only place the full pipeline is sequenced.** It is deliberately thin
— validate, extract, normalise, detect, decide, forward, detect, decide, record, respond —
with each step delegating. If it grows logic of its own, that logic belongs in a layer.

**Lifespan responsibilities:** load settings → load and validate policy → build detectors →
`warmup()` all detectors → create HTTP client → create DB engine → mark ready. Reverse on
shutdown, with in-flight requests drained.

---

## `app/observability`

| Module | Contents |
|---|---|
| `logging.py` | structlog config; `request_id` contextvar processor; **content-redaction processor at the sink** |
| `metrics.py` | The metric catalogue with domain-appropriate histogram buckets |
| `tracing.py` | OTel span helpers behind `tracing_enabled`; no exporter until Phase 5 |

The redaction processor is the single enforcement point for the no-prompt-logging property
([10-security-model.md](10-security-model.md)). A future `logger.info("blocked", prompt=text)`
must be harmless.

---

## `app/database` + `app/models`

| Module | Contents |
|---|---|
| `models/events.py` | `SecurityEvent` — the event contract, independent of storage |
| `database/models.py` | SQLAlchemy 2.0 async models for the six tables |
| `database/session.py` | Async engine, session factory, statement timeout |
| `database/repository.py` | `AuditRepository.record(trace, results, decision, event)` |

**The repository interface exists in Phase 0 for one reason:** Phase 5 replaces synchronous
writes with a bounded queue and background writer, and no caller should change
([ADR-012](adr/ADR-012-persistence-and-retention.md)).

**Failure modes:** write failure logs at ERROR, increments
`firewall_audit_write_failures_total`, and does **not** fail the request unless
`require_audit=true`.

---

## `services/mock_upstream` — separate service

Deliberately outside `app/`. FastAPI + Uvicorn only, its own Dockerfile, no shared code — a
test double that imports the system under test is not a test double
([ADR-009](adr/ADR-009-mock-upstream.md)).

Behaviour triggers (marker phrases in the request): PII-bearing response, 5xx, slow response,
oversized response. `MOCK_LATENCY_MS` provides the fixed delay that makes benchmark conditions
valid.

---

## `eval/` — evaluation harness

| Module | Contents |
|---|---|
| `datasets/registry.yaml` | source, licence, redistributable, checksum |
| `datasets/splits.py` | `sha256(sample_id) % 100` bucketing |
| `runners/in_process.py` | Detection quality — detectors + policy directly |
| `runners/http.py` | Latency/throughput — drives a running gateway |
| `metrics/classification.py` | Confusion matrix, precision/recall/F1/FPR/FNR, Wilson intervals |
| `metrics/latency.py` | Percentiles, throughput, saturation |
| `metrics/report.py` | JSON + Markdown; **refuses to emit without metadata** |

Imports `app.detectors` and `app.policy`; **never** `app.api` or `app.database`. The harness
evaluates the detection stack, not the web server.

---

## Cross-cutting: object lifetimes

| Object | Lifetime | Why it matters |
|---|---|---|
| `Settings` | Process (cached) | Re-reading env per request is waste and a config-drift bug |
| `PolicyConfig` | Process (hot-reload in Phase 6) | `policy_version` must be stable within a request |
| Detector instances | Process, warmed at startup | Model loading is 1–3 s; never on the request path |
| `httpx.AsyncClient` | Process | Connection reuse is a first-order latency effect |
| DB engine/pool | Process | |
| `DetectionContext`, results, decision | Request | Frozen; safe to pass across layers |

**No request-scoped state outside the process** (NFR-017) — instances stay interchangeable.

## Cross-cutting: what must never appear where

| Never | Where | Enforced by |
|---|---|---|
| `Action` | `app/detectors/**` | import test |
| `app.detectors` import | `app/policy/**` | import test |
| Prompt content | logs, spans, audit columns | sink processor + canary test + schema |
| Secret values | logs, spans, errors, audit | `SecretStr` + test |
| Blocking call | any `async def` on the request path | ruff `ASYNC` + review |
| Upstream response body | client error responses | test |

---

## Provenance-aware detection — Phases A+B+C implemented

[ADR-017](adr/ADR-017-provenance-aware-detection-context.md). **Implemented:**
`app/core/provenance.py`, the four `DetectionContext` fields, assignment in
`build_contexts`, `consumes_provenance` on the detector protocol,
`ProvenanceContext` as `evaluate()`'s fourth argument, and the monotone `by_trust`
overlay with load-time rejection of any loosening.

**The shipped policy configures no overlay**, so provenance remains inert in the
default configuration and every decision is what it was before. Enabling an
escalation is a reviewable policy edit — see the commented example in
`config/policies/default.yaml`.

### Where provenance enters, and where it is discarded today

```
                    ┌─────────────────────────────────────────────┐
   external world   │  user typing   retrieved doc   tool result  │
                    │       │             │              │        │
                    │       │        web page / email / file      │
                    └───────┼─────────────┼──────────────┼────────┘
                            ▼             ▼              ▼
                    ┌─────────────────────────────────────────────┐
                    │  application / retriever / tool adapter     │  ← knows the true origin
                    │  (inside the trust boundary)                │
                    └───────────────────────┬─────────────────────┘
                                            │  optional claim
  ══════════════════════════ gateway trust boundary ══════════════════════════
                                            ▼
                    ┌─────────────────────────────────────────────┐
                    │  app/api/v1/chat.py      ingress            │
                    ├─────────────────────────────────────────────┤
                    │  app/gateway/translate.py                   │
                    │    ┌───────────────────────────────────┐    │
                    │    │ SOURCE CLASSIFICATION  (Phase B)  │    │  ◀── authoritative point
                    │    │  claim honoured only if trusted   │    │
                    │    │  else derive from role            │    │
                    │    └───────────────┬───────────────────┘    │
                    │                    ▼                        │
                    │      message-part extraction                │  one part → one context
                    │                    ▼                        │
                    │      app/core/normalize.py                  │  text + offsets
                    └───────────────────────┬─────────────────────┘
                                            ▼
                    ┌─────────────────────────────────────────────┐
                    │  DetectionContext  (frozen)                 │
                    │    raw_text, normalized_text, offsets       │
                    │    role, message_index, part_index          │
                    │    provenance, trust, source_ref (Phase A)  │
                    └───────────────────────┬─────────────────────┘
                                            ▼
                    ┌─────────────────────────────────────────────┐
                    │  detectors    consumes_provenance = T/F     │  all ship False
                    └───────────────────────┬─────────────────────┘
                                            ▼
                                    DetectionResult
                                            ▼
                    ┌─────────────────────────────────────────────┐
                    │  app/policy/engine.py   evaluate(           │
                    │      results, config, direction,            │
                    │      ProvenanceContext | None )             │  still pure
                    └───────────────────────┬─────────────────────┘
                                            ▼
                              ALLOW / WARN / REDACT / BLOCK
```

`ProvenanceContext` carries `(provenance, trust)` **only** — not the whole context.
Handing the policy engine `raw_text` would break the property that makes its truth
table exhaustively testable, and would put prompt content one attribute access from
a decision path that must never log it.

### Test plan — all rows implemented

Every row below exists and passes.

| Area | Test | Asserts |
|---|---|---|
| Assignment | `test_provenance_assigned_at_ingress` | Every context from `build_contexts` has a non-null provenance and trust |
| Assignment | `test_role_derivation_table` | Each role maps to the ADR-017 default pair; `tool` → `UNTRUSTED` |
| Assignment | `test_unrecognised_role_is_unknown_not_trusted` | Unknown role → `UNKNOWN`/`UNKNOWN`, still inspected |
| **Spoofing** | `test_inline_claim_ignored_by_default` | A body field `x-firewall-provenance: system_config` does **not** raise trust |
| **Spoofing** | `test_claim_may_lower_trust_never_raise` | `role=system` + claim `EXTERNAL` → `UNTRUSTED`; `role=tool` + claim `SYSTEM_CONFIG` → still `UNTRUSTED` |
| **Spoofing** | `test_claim_honoured_only_on_trusted_channel` | Same claim, config off vs on, different result |
| Propagation | `test_provenance_survives_part_extraction` | Per-part provenance preserved across a multi-part message |
| Normalisation | `test_provenance_survives_normalisation` | Provenance unchanged and `normalized_offsets` invariant still holds |
| Mixed | `test_split_parts_keep_distinct_provenance` | Two parts, two provenances, two decisions |
| Mixed | `test_flattened_part_degrades_to_lowest_trust` | user+external in one string → `UNTRUSTED` |
| Compatibility | `test_legacy_detectors_run_unchanged` | `consumes_provenance=False` detectors produce byte-identical results to today |
| Compatibility | `test_request_without_provenance_reproduces_current_decisions` | Golden-file comparison against pre-change decisions |
| Policy | `test_overlay_may_only_tighten` | A `by_trust` overlay raising a threshold is **rejected at config load** |
| Policy | `test_overlay_tightening_applies` | Same detector score, `UNTRUSTED` vs `UNKNOWN`, more severe action for the former |
| Policy | `test_policy_engine_remains_pure` | `evaluate` has no I/O; same inputs → same decision |
| Policy | `test_provenance_effect_appears_in_reasons` | Any provenance-driven tightening is visible in `PolicyDecision.reasons`, never hidden |
| Failure | `test_malformed_claim_does_not_reject_the_request` | Bad enum / oversized `source_ref` → counter incremented, request proceeds |
| Observability | `test_provenance_never_used_as_unbounded_metric_label` | `source_kind`/`source_ref` absent from metric labels |
| Privacy | `test_source_ref_is_not_a_url_or_path` | Validation rejects `://`, leading `/`, and >64 chars |
| Privacy | `test_no_source_content_in_audit_or_logs` | Extends the existing log-leak canary to the new fields |
