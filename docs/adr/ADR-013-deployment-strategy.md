# ADR-013: Deployment Strategy — Compose First, Kubernetes Conditionally

**Status:** Accepted
**Date:** 2026-08-17
**Phase:** 0 (local), Phase 7 (production)

## Context

The gateway is a stateless HTTP service in front of every LLM call an application makes. That
position sets the deployment requirements: it must be trivially runnable for evaluation, and
it must be horizontally scalable and boringly operable in production.

There is also a portfolio-specific failure mode worth naming. Kubernetes manifests written
before anything runs locally are decoration, and an experienced reviewer reads them as
inexperience rather than sophistication (PM-7 in [20-risk-register.md](../20-risk-register.md)).
The temptation to add infrastructure that signals seriousness is exactly what makes a project
look unserious.

Constraints from the reference machine: host ports 5432, 5433 and 3000 are already occupied, and the
GPU is a 4 GB laptop part.

## Decision

**Docker Compose is the reference deployment. Kubernetes is Phase 7 and conditional on there
being something to deploy to.**

### Local (Phase 0)

Three services, and nothing else:

| Service | Host port | Notes |
|---|---|---|
| `firewall-api` | 8000 | The gateway |
| `mock-upstream` | 8081 | Zero-credential, zero-egress upstream ([ADR-009](ADR-009-mock-upstream.md)) |
| `postgres` | **5434** | 5432 (host PostgreSQL) and 5433 (unrelated container) are both occupied |

Langfuse, Grafana and the Streamlit dashboard join **in Phase 5**, not on day one — a
seven-container stack that takes ten minutes to start is friction that gets paid on every
single development iteration, in exchange for components nothing yet uses. Langfuse will bind
host **3001**.

Compose posture: healthchecks with `depends_on: service_healthy`, named volume for Postgres,
non-root, `read_only: true` with tmpfs for `/tmp`, `cap_drop: [ALL]`,
`no-new-privileges:true`, and explicit memory limits.

### Image

Multi-stage on a **digest-pinned** `python:3.12-slim`. Builder installs from `uv.lock` into a
venv; the runtime stage copies only the venv, so no compiler or build header ships. Non-root
`app` user, `HEALTHCHECK` on `/health`, `.dockerignore` excluding `.env`, `.git` and tests.

Heavy ML extras are **not** in the default image ([ADR-001](ADR-001-technology-stack.md)) —
an operator who does not enable Presidio does not carry spaCy, and a CVE in an unused stack is
not in our attack surface.

### Production shape

Stateless replicas behind an ingress that owns TLS, authentication and (until Phase 6) rate
limiting. Postgres is the only state. Probes: `/health` for liveness, **`/ready` for traffic**
— readiness waits for detector warm-up, so an instance whose models have not loaded never
receives a request it would have to block.

Migrations run as a **separate step** under a separate role, never on application startup: N
replicas starting together would race, and a failed migration would become a crash loop
instead of a clear failure.

### Obligations the gateway cannot enforce

Stated in [17-deployment-architecture.md](../17-deployment-architecture.md) as a checklist.
The load-bearing one: **the upstream must be unreachable from the application** (threat T-14).
If the app can call the model directly, this gateway is advisory. A NetworkPolicy, security
group or egress proxy enforces it; the gateway cannot.

### Sizing

**Deferred to Phase 4.** Publishing a sizing recommendation before measuring per-request CPU
cost, detector latency and memory-per-worker would be exactly the unbacked claim this project
refuses to make.

## Alternatives considered

| Alternative | Rejected because |
|---|---|
| **Kubernetes from Phase 0** | Manifests before a working local stack invert the order of validation, and nothing exists to deploy. It also makes the contribution loop require a cluster. |
| **Full observability stack in the Phase 0 Compose file** | Langfuse + Grafana + Prometheus + dashboard before any of them has data to show. Slow starts on every iteration, for components Phase 0 does not use. |
| **Single container running Postgres + app** | Simpler `docker run`, and it conflates lifecycles, prevents independent scaling, and teaches a deployment shape nobody should copy. |
| **Serverless (Lambda/Cloud Run)** | Attractive for a stateless proxy, and cold starts are fatal for a service that must load ML models to become ready. Revisit only if detection moves to a remote inference service. |
| **Requiring a real provider key to run locally** | Blocks evaluation behind an account and a budget, and makes tests non-deterministic ([ADR-009](ADR-009-mock-upstream.md)). |
| **Helm chart up front** | Templating one deployment is overhead without a second. Only if the manifests prove repetitive. |

## Consequences

### Positive
* `git clone && docker compose up && curl` works in under a minute with no account — the
  single most important property for anyone evaluating the repository.
* The development loop stays fast because the default stack is three containers.
* Container hardening is present from Phase 0 rather than retrofitted.
* Deferring Kubernetes keeps the repository honest about what has actually been run.

### Negative / accepted costs
* **No production deployment exists**, so operational claims are limited to what Compose
  demonstrates. Stated rather than obscured.
* Compose is not a production orchestrator; the gap between local and production remains
  documentation until Phase 7.
* Deferring sizing means "how many replicas do I need" has no answer yet.
* Adding Langfuse in Phase 5 means the Compose file changes shape mid-project.

### Revisit when
There is a real target environment to deploy to; or a phase requires an orchestrator feature
(autoscaling on a measured metric, rolling upgrades under load) that Compose cannot express.

## Verification

* `docker compose config` validates; `docker compose up` on a clean machine reaches
  `/health` 200 with no credentials — `tests/integration/test_end_to_end.py`.
* Container posture (non-root, read-only root filesystem, dropped capabilities) —
  `tests/integration/test_container.py`.
* Image contains no compiler, no `.env`, no tests — build inspection in CI.
* Postgres is published on 5434 and the host's own 5432 service is untouched.
