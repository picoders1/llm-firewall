# ADR-009: Ship a Mock Upstream Service

**Status:** Accepted
**Date:** 2026-08-17
**Phase:** 0

## Context

A proxy needs something to proxy to. Four separate needs collide here:

1. **`docker compose up` must work for a stranger** — with no API key, no account, no GPU,
   and no network egress.
2. **Tests must be deterministic.** Assertions like "the response was redacted" require a
   known response. A real model returns something different every time.
3. **Latency benchmarks must isolate gateway overhead.** A real model's latency varies by
   seconds, load and token count — one to three orders of magnitude larger than the effect
   being measured. Benchmarking through it measures the provider.
4. **Output-inspection tests need a response containing PII**, on demand, without asking a
   real model to emit PII.

No available upstream satisfies all four. A hosted provider fails 1, 2 and 3. A local Ollama
model fails 2 and 3 and needs a multi-gigabyte download and a GPU.

## Decision

**Ship `services/mock_upstream/` — a small, separate OpenAI-compatible FastAPI service — as
part of the default Compose stack.**

| Property | Behaviour |
|---|---|
| Endpoints | `POST /v1/chat/completions`, `GET /v1/models`, `GET /health` |
| Responses | Deterministic and derived from the request, in the exact OpenAI response shape including `usage` |
| Latency injection | `MOCK_LATENCY_MS` — fixed, configurable delay. **This is the property that makes benchmark conditions valid** |
| Behaviour triggers | Marker phrases in the request produce a PII-bearing response, an error status, a slow response, or an oversized response |
| Dependencies | FastAPI + Uvicorn only; its own slim Dockerfile |
| Isolation | A separate service over HTTP, not an in-process stub — the gateway's real HTTP client, serialisation and connection pooling are exercised |

It is **not** a model. It does no generation and makes no claim to. It is a controllable
mirror that lets the gateway be tested and measured as a gateway.

Real providers remain fully supported: `FIREWALL_UPSTREAM_BASE_URL` and
`FIREWALL_UPSTREAM_API_KEY` point at OpenAI, vLLM, Ollama, Groq or anything else speaking the
contract. The mock is the default, not the only option.

## Alternatives considered

| Alternative | Rejected because |
|---|---|
| **Require a real API key for development** | Anyone evaluating the repository needs an account and a budget before `docker compose up` does anything. Tests become non-deterministic, slow and expensive; CI cannot run them at all. And a security product whose test suite ships prompts to a third party is a bad look on its own terms. |
| **Ollama with a small local model in Compose** | Multi-gigabyte download, GPU pressure (4 GB VRAM on the target machine), still non-deterministic, and still unusable for overhead measurement because generation latency swamps the signal. Remains available as an optional Compose profile for realistic demos. |
| **In-process stub / monkeypatched httpx** | Used for unit tests and correct there, but it bypasses serialisation, the connection pool and real network timing — so it cannot validate the parts of the gateway most likely to be wrong, and it cannot support the compose experience at all. Both exist; they serve different layers. |
| **`respx` mocking everywhere** | Same limitation. Excellent for unit and API tests, useless for integration and benchmarking. |
| **Record/replay real provider responses (VCR-style)** | Realistic fixtures, and the cassettes would contain real completions — a data-handling problem — plus no latency control and constant re-recording. |

## Consequences

### Positive
* `git clone && docker compose up && curl` works in under a minute, with no account.
* Tests are deterministic, fast, free, and produce zero egress.
* **Benchmark conditions A–D are meaningful** — with `MOCK_LATENCY_MS=0` the gateway's own
  cost is the entire signal, and with a realistic value the user-visible impact is
  measurable. This is what turns "overhead" from an assertion into a measurement.
* Failure-path testing is easy: timeouts, 5xx and oversized responses on demand, which are
  otherwise hard to provoke against a real provider.
* No API key exists in the development path, so none can leak from it.

### Negative / accepted costs
* A second service to build, maintain and keep OpenAI-compatible as the contract evolves.
* **A mock can drift from real provider behaviour**, and tests that pass against it can fail
  against a real endpoint. Mitigated by a Phase 1 integration test against a real
  OpenAI-compatible endpoint (opt-in, credential-gated, excluded from default CI) — the mock
  is the default, not the only thing ever tested.
* Its determinism means it cannot surface problems that only appear with real generated text
  (unusual Unicode, very long completions, unexpected tool-call shapes). Partly addressed by
  the behaviour triggers.
* Adds a container to the default stack — accepted, since the alternative is a stack that
  does not run at all without credentials.

### Revisit when
The optional Ollama profile becomes the more useful default for demos; or contract drift
against real providers starts causing escaped bugs, which would argue for running the
contract test suite against a real endpoint on a schedule.

## Verification

* `docker compose up` followed by a `curl` to `/v1/chat/completions` returns a completion with
  no credentials configured.
* `tests/integration/test_end_to_end.py` — allow, block and redact paths through the real
  containerised mock.
* `tests/integration/test_upstream_failures.py` — trigger-driven 5xx and timeout produce
  `502`/`504` with no upstream body reflected.
* A benchmark run with `MOCK_LATENCY_MS=0` and `=800` produces overhead figures that differ
  by less than the measurement noise — the check that the mock's delay is not being counted
  as gateway cost.
