# Architecture Overview

## Problem

An application that calls an LLM has no natural place to enforce security. Detection logic
ends up duplicated in every service, coupled to one provider's SDK, untested, and
unmeasured. Meanwhile the interesting attacks — prompt injection arriving through retrieved
documents, PII leaking outward in a completion — cross the boundary between the
application and the model, which is precisely where nobody is looking.

**LLM Firewall** puts a single inspected boundary there. It speaks the OpenAI HTTP contract,
so adoption is one configuration change:

```python
client = OpenAI(base_url="http://localhost:8000/v1", api_key=...)
```

Every request and response then passes through detection, a policy decision, and an audit
record, with no application code change.

## System context

```
┌──────────────┐   OpenAI-compatible HTTP    ┌───────────────┐   OpenAI-compatible HTTP   ┌──────────────┐
│ Application  │ ──────────────────────────► │ LLM Firewall  │ ─────────────────────────► │  Upstream    │
│ (OpenAI SDK) │ ◄────────────────────────── │   (gateway)   │ ◄───────────────────────── │  LLM         │
└──────────────┘        response /           └───────┬───────┘         completion         └──────────────┘
                        403 security_block           │                              (mock · vLLM · Ollama ·
                                                     │                               hosted provider)
                                          ┌──────────▼──────────┐
                                          │ PostgreSQL          │  security events, traces,
                                          │ (audit + eval)      │  detector results, eval runs
                                          └─────────────────────┘
```

The evaluation harness is deliberately **outside** this picture. It drives the same
detectors and the same policy engine, but through its own runner, never through production
traffic. See [ADR-006](adr/ADR-006-evaluation-methodology.md).

## Internal decomposition

```
                        HTTP request
                             │
┌────────────────────────────▼─────────────────────────────────────────┐
│ app/middleware      request-id · body-size limit · timing ·          │
│                     security headers · error envelope                │
├──────────────────────────────────────────────────────────────────────┤
│ app/api             /health  /ready  /metrics  /v1/chat/completions  │
│                     /v1/models                                       │
├──────────────────────────────────────────────────────────────────────┤
│ app/gateway         OpenAI schema · message extraction ·             │
│                     UpstreamClient (pooled httpx, timeouts)          │
├──────────────────────────────────────────────────────────────────────┤
│ app/core            normalisation · DetectionContext · domain types  │
├──────────────────────────────────────────────────────────────────────┤
│ app/detectors       Detector protocol · GuardedDetector ·            │
│                     registry · pipeline                              │
│                     injection/ · jailbreak/ · pii/ · output/         │
├──────────────────────────────────────────────────────────────────────┤
│ app/policy          PolicyEngine (pure) · redaction                  │
├──────────────────────────────────────────────────────────────────────┤
│ app/observability   structlog · Prometheus · OTel spans              │
│ app/database        SQLAlchemy async · repositories · Alembic        │
│ app/config          Settings (env) · PolicyConfig (YAML)             │
└──────────────────────────────────────────────────────────────────────┘
```

## Layering rules

Dependencies point **downward only**. These are enforced by review and by import-linting in
CI (Phase 1).

| Layer | May import | Must never import |
|---|---|---|
| `core` | stdlib, pydantic | anything else in `app` |
| `policy` | `core`, `config` | `detectors`, `gateway`, `api`, `database` |
| `detectors` | `core`, `config` | `policy`, `gateway`, `api`, `database` |
| `gateway` | `core`, `config` | `api`, `policy` |
| `database` | `core`, `models`, `config` | `api`, `detectors`, `policy` |
| `api` | everything | — |

Two consequences worth stating explicitly:

* **`policy` cannot import `detectors`.** The engine consumes `DetectionResult` values and
  has no idea what produced them. This is what makes the whole decision surface testable
  from synthetic results with no models loaded.
* **`detectors` cannot import `policy`.** A detector physically cannot return an action.

## Component responsibilities

### `app/core`
Domain vocabulary: `Action`, `Category`, `Direction`, `DetectionContext`, `DetectionResult`,
`PolicyDecision`, `TextSpan`. Plus normalisation and content fingerprinting. No I/O, no
framework imports.

### `app/config`
Two distinct configuration systems that are never mixed
([ADR-011](adr/ADR-011-configuration-model.md)):
* `Settings` — deployment and secrets, from environment variables only.
* `PolicyConfig` — declarative security policy, from YAML, structurally forbidden from
  containing secrets.

### `app/detectors`
The pluggable detection layer ([ADR-002](adr/ADR-002-detector-plugin-architecture.md)).
A detector answers one question about one piece of text and returns evidence. It never
decides, never logs content, never talks to the database.

### `app/policy`
The only component that decides ([ADR-003](adr/ADR-003-policy-engine-design.md)).
A pure function of `(results, config) → PolicyDecision`. No clock, no I/O, no logging —
which is why it can be exhaustively unit-tested as a truth table.

### `app/gateway`
Speaks OpenAI ([ADR-004](adr/ADR-004-openai-compatible-contract.md)). Owns the pooled
`httpx.AsyncClient`, timeout budget, and the mapping of upstream failures into a safe error
envelope. Upstream response bodies are never reflected to the client.

### `app/observability`
Structured logs, Prometheus metrics, OpenTelemetry spans
([ADR-008](adr/ADR-008-observability-and-privacy.md)). Content redaction is enforced
here, at the sink, not at each call site.

### `app/database`
Audit persistence and evaluation storage
([ADR-012](adr/ADR-012-persistence-and-retention.md)). Schema is designed so that raw
prompt text has nowhere to go.

### `services/mock_upstream`
A separate, deliberately tiny OpenAI-compatible service
([ADR-009](adr/ADR-009-mock-upstream.md)). It makes `docker compose up` work with no API
key and no egress, makes tests deterministic, and — because it can be told to inject a
fixed latency — is what allows gateway overhead to be isolated from model latency in
benchmarks.

## Request lifecycle (summary)

Detailed in [request-flow.md](03-request-response-flow.md).

```
validate → extract inspectable messages → normalise → input detectors (concurrent, guarded)
   → policy → BLOCK? ─yes→ 403 + security event
                └─no→ apply redactions → upstream → output detectors → policy
                        → BLOCK? ─yes→ 403 + event
                              └─no→ apply redactions → 200 + event
```

## Concurrency model

The process is a single-threaded asyncio event loop per worker.

* All I/O (upstream HTTP, PostgreSQL) is async.
* Detectors are declared `async`, but real ML detectors (Phase 2) are synchronous,
  CPU-bound and hold the GIL. They subclass `SyncDetectorAdapter`, which dispatches to a
  bounded worker thread pool via `anyio.to_thread.run_sync`. Establishing this in Phase 0
  means Phase 2 cannot accidentally stall the loop for every concurrent request.
* Detectors within one direction run concurrently under `asyncio.gather`; the wall-clock
  cost of the detection stage is the slowest detector, not the sum.
* Audit writes are behind a repository interface so they can move off the request path
  (bounded queue + background writer) in Phase 5 without changing any caller.

## What is deliberately absent

No message bus, no microservice split, no plugin-discovery-by-entry-point, no rules DSL, no
caching layer. Each of those solves a problem this system does not yet have. The detector
registry is a dictionary; if the project ever needs third-party detector packages, that is
a small, contained change.
