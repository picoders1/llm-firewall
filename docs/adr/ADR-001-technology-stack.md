# ADR-001: Technology Stack and Packaging

**Status:** Accepted
**Date:** 2026-08-17
**Phase:** 0

## Context

The gateway sits on the latency path of every LLM call in an application. It must be
async-first, must speak the OpenAI HTTP contract exactly, must host Python ML models later,
and must be reproducible enough that a stranger can rebuild the exact environment a
benchmark was measured on.

Constraints observed on the target machine: Ubuntu 24.04, Python 3.12.3, Docker 29.7 with
Compose v5.4, 16 cores, 31 GB RAM, RTX 3050 (4 GB). Host ports 5432 and 3000 are already in
use. Poetry is installed but broken (`ModuleNotFoundError: poetry`); `uv` was not present.

## Decision

**Runtime:** Python 3.12 · FastAPI · Uvicorn · Pydantic v2 · pydantic-settings ·
httpx (async, pooled) · structlog · SQLAlchemy 2.0 async + asyncpg · Alembic ·
prometheus-client · PyYAML · anyio. Twelve runtime packages.

**Packaging:** PEP 621 `pyproject.toml`, hatchling backend, **`uv`** for resolution and
locking, `uv.lock` committed. Heavy stacks are optional extras and are **not** in the
default install:

| Extra | Contents | Needed from |
|---|---|---|
| `ml` | transformers, onnxruntime | Phase 2 |
| `pii` | presidio-analyzer, presidio-anonymizer, spacy | Phase 2 |
| `eval` | pandas, scikit-learn | Phase 4 |
| `dev` | pytest, ruff, mypy, respx, pip-audit | always, in dev |

**Quality tooling:** ruff (lint + format, including bandit `S` rules) · mypy `--strict` on
`app/` · pytest with marker-segmented suites.

**Datastore:** PostgreSQL 16. Container port mapped to host **5434** because 5432 is taken.

## Alternatives considered

| Alternative | Rejected because |
|---|---|
| **Go / Rust gateway** | Genuinely better for a pure proxy — lower latency, real parallelism, no GIL. Rejected because the detectors are Python ML models; a Go gateway would need an RPC hop to a Python model server, adding a network round trip to the exact path being optimised, plus a second deployment unit. Revisit if detection ever moves fully to ONNX/Rust inference. |
| **LiteLLM as the proxy base** | Excellent multi-provider routing, but it owns the request path and inverts the dependency: we would be writing plugins inside someone else's proxy and inherit their release cadence for a security control. Also brings a large dependency surface. Our OpenAI-compat scope is a subset, not a routing product. |
| **Envoy / NGINX + WASM filter** | Right answer at very large scale. Wrong answer for a system whose detectors are Python models; the operational complexity is unjustified before there is traffic to justify it. |
| **Poetry** | Broken on this machine, and slower. Repairing it buys nothing over `uv`. |
| **pip + requirements.txt** | Weakest lock semantics of the options; `uv` costs one `pipx install`. |
| **Flask / Django** | Not async-first. Wrong shape for a latency-sensitive proxy. |
| **SQLite** | Fine for tests, and used there. Wrong for concurrent audit writes and a schema meant to outlive one process. |
| **MongoDB** | The audit data is relational, the queries are analytical, and retention is a `DELETE ... WHERE`. Postgres is the boring correct answer. |
| **Kafka for the event stream** | Solves a scale problem this system does not have. Postgres first; the repository interface makes a queue a later, contained change. |

## Consequences

### Positive
* Async end to end; no blocking I/O on the request path by construction.
* Pydantic v2 gives request validation and configuration validation from one type system,
  and the OpenAI contract is expressible directly as models.
* `uv` makes CI and Docker builds fast, and `uv.lock` makes "the environment the benchmark
  ran on" a checkable artefact rather than a claim.
* Optional extras keep the default image small: an operator who never enables Presidio does
  not carry spaCy, and a CVE in a stack we do not use is not in our image.

### Negative / accepted costs
* **The GIL.** Python parallelism is bounded; CPU-bound detectors need thread offload
  (ADR-002) and, eventually, more worker processes rather than more threads. This is the
  main scalability ceiling and it is accepted knowingly.
* Python's per-request overhead is higher than a compiled proxy's. Phase 4 will quantify
  it rather than assume it is acceptable.
* `uv` is young relative to pip. It is a build-time tool only — nothing in the runtime image
  depends on it — so the blast radius of that risk is a CI change.
* Optional extras mean four install configurations, and CI must exercise more than the
  default one.

### Revisit when
Measured gateway overhead exceeds the acceptable budget after profiling; or detection moves
entirely to non-Python inference; or single-process throughput becomes the binding
constraint in production.

## Verification

```bash
uv lock --check          # lockfile current
uv sync --extra dev
uv run ruff check . && uv run mypy app
docker compose config    # postgres published on 5434
```
