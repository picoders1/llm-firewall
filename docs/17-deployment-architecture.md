# Deployment Architecture

Local development first, production second — deliberately in that order. A design that cannot
be run locally by a stranger in one command is not ready to be deployed anywhere
(NFR-012 in [01-requirements.md](01-requirements.md)).

* **Part 1 — Local environment.** Docker Compose, configuration, everyday commands.
* **Part 2 — Production.** Topology, obligations, sizing, migrations, rollout, Kubernetes.

---

## Part 1 — Local development environment


### Prerequisites

| Tool | Version | Notes |
|---|---|---|
| Python | 3.12+ | 3.12.3 verified on the reference machine |
| uv | 0.12+ | `pipx install uv` |
| Docker | 24+ | 29.7.2 verified |
| Docker Compose | v2+ | v5.4.0 verified |
| git | 2.40+ | |

Poetry is not used — it was broken on the reference machine and `uv` is faster
([ADR-001](adr/ADR-001-technology-stack.md)).

### Host port note

The reference machine already has services on **5432** (a local PostgreSQL) and **3000**.
Compose therefore publishes:

| Service | Container port | Host port |
|---|---|---|
| firewall-api | 8000 | 8000 |
| mock-upstream | 8081 | 8081 |
| postgres | 5432 | **5434** |
| Langfuse (Phase 5) | 3000 | **3001** |

Your existing local PostgreSQL is untouched. Connect to the project database with
`psql -h localhost -p 5434`.

### Quick start

```bash
git clone <repo> && cd llm-firewall
cp .env.example .env          # defaults work; no credentials required
docker compose up -d --build
curl localhost:8000/health
curl localhost:8000/ready
```

The default stack uses the bundled mock upstream
([ADR-009](adr/ADR-009-mock-upstream.md)), so this works with **no API key and no network
egress**.

### Local (non-container) development

```bash
uv sync --extra dev                       # creates .venv from uv.lock
docker compose up -d postgres mock-upstream
uv run alembic upgrade head
uv run uvicorn app.main:app --reload --port 8000
```

Add extras as phases land: `--extra ml`, `--extra pii`, `--extra eval`.

### Configuration

Two systems, deliberately separate
([ADR-011](adr/ADR-011-configuration-model.md)):

* **`.env` / environment** — secrets and deployment values, prefix `FIREWALL_`.
* **`config/policies/default.yaml`** — security policy. **Secrets here are rejected at
  startup**, by a validator.

Precedence: environment variable > `config/environments/<env>.yaml` > built-in default.

Common variables:

```bash
FIREWALL_ENVIRONMENT=development
FIREWALL_LOG_LEVEL=INFO
FIREWALL_CONTENT_LOGGING=none          # none | hash | full ('full' is refused in production)
FIREWALL_UPSTREAM_BASE_URL=http://localhost:8081/v1
FIREWALL_UPSTREAM_API_KEY=             # empty for the mock
FIREWALL_DATABASE_URL=postgresql+asyncpg://firewall:firewall@localhost:5434/firewall
FIREWALL_POLICY_FILE=config/policies/default.yaml
```

### Pointing at a real provider

```bash
FIREWALL_UPSTREAM_BASE_URL=https://api.openai.com/v1
FIREWALL_UPSTREAM_API_KEY=sk-...
```

Any OpenAI-compatible endpoint works — vLLM, Ollama (`http://localhost:11434/v1`), Groq,
Together, OpenRouter. Note that real prompts then leave your machine; the mock exists so that
day-to-day development does not require this.

### Using the gateway from an application

```python
from openai import OpenAI

client = OpenAI(base_url="http://localhost:8000/v1", api_key="unused-by-mock")
client.chat.completions.create(
    model="mock",
    messages=[{"role": "user", "content": "Hello"}],
)
```

`stream=True` returns `400` — a documented limitation, not a bug
([ADR-004](adr/ADR-004-openai-compatible-contract.md)).

### Everyday commands

```bash
uv run pytest -m "unit or api"          # fast loop, no containers
uv run pytest -m security               # security-critical suite
uv run pytest -m integration            # needs postgres + mock upstream
uv run ruff check . && uv run ruff format .
uv run mypy app services
uv run alembic revision --autogenerate -m "..."   # always review the generated file
docker compose logs -f firewall-api
```

### Pre-commit

```bash
uv run pre-commit install
```

Runs ruff, ruff-format and gitleaks. The secret scan is the one that matters — this
repository must never accumulate a credential in its history.

### Troubleshooting

| Symptom | Cause |
|---|---|
| `/ready` returns 503 | Check the per-check breakdown in the body: policy invalid, detector warm-up failed, or database unreachable |
| Every request returns 503 `detector_failure` | Fail-closed is working as designed ([ADR-007](adr/ADR-007-detector-failure-semantics.md)) — a detector is broken. Check `firewall_detector_errors_total` and the logs |
| Port 5432 conflict | Expected; the project uses 5434 |
| Alembic sees no changes | Ensure the model module is imported in `migrations/env.py` |
| Logs show no prompt content | Working as designed. `FIREWALL_CONTENT_LOGGING=full` in development only ([logging.md](10-security-model.md)) |

---

## Part 2 — Production deployment


**Status: placeholders only.** No production deployment exists, no credentials are stored in
this repository, and no sizing guidance can be given until Phase 4 produces measurements.
This document records the intended shape and the obligations that come with it.

### Deployment model

The gateway is a stateless HTTP service. State lives in PostgreSQL; instances are
interchangeable and scale horizontally (NFR-017).

```
        ingress (TLS, authn/z, rate limiting)
                       │
        ┌──────────────┼──────────────┐
        ▼              ▼              ▼
   firewall-api   firewall-api   firewall-api      ← stateless, /ready-gated
        └──────────────┼──────────────┘
                       ▼
                  PostgreSQL                        ← audit
                       │
                  upstream LLM                      ← reachable ONLY from these pods (T-14)
```

### Non-negotiable obligations

These are the difference between a deployed gateway and a decorative one.

1. **The upstream must be unreachable from the application.** If the app can call the model
   directly, the firewall is advisory (threat T-14). Enforce with a NetworkPolicy, security
   group, or egress proxy — the gateway cannot enforce this itself.
2. **TLS terminates at or before the gateway.**
3. **Rate limiting at the ingress** until Phase 6 (threat T-18).
4. **`FIREWALL_ENVIRONMENT=production`** — this is what refuses `full` content logging.
5. **`/ready`, not `/health`, wired to the load balancer.** `/health` is liveness only;
   routing on it sends traffic to instances whose detectors have not loaded.
6. **Secrets from the platform's secret manager**, injected as environment variables. Never
   `.env` files, never image layers, never policy YAML (which rejects them structurally).
7. **Alerts on `firewall_detector_errors_total` and `firewall_audit_write_failures_total`.**
   Both are silent security degradations.
8. **Least-privilege database role** — no `DROP`; migrations under a separate role.

### Configuration surface

```bash
FIREWALL_ENVIRONMENT=production
FIREWALL_LOG_LEVEL=INFO
FIREWALL_CONTENT_LOGGING=none
FIREWALL_UPSTREAM_BASE_URL=<provider or internal vLLM>
FIREWALL_UPSTREAM_API_KEY=<from secret manager>
FIREWALL_DATABASE_URL=<from secret manager>
FIREWALL_POLICY_FILE=/etc/firewall/policy.yaml     # mounted read-only
FIREWALL_TRACING_ENABLED=false                     # opt-in only
```

Policy is mounted read-only from a ConfigMap or equivalent. A policy change is a
security-relevant change and should go through review, which is why it is a file in git
rather than a runtime setting
([ADR-011](adr/ADR-011-configuration-model.md)).

### Container posture

Per [hardening.md](10-security-model.md): non-root, read-only root filesystem with a
tmpfs for `/tmp`, `cap_drop: ALL`, `no-new-privileges`, digest-pinned base image, resource
limits set.

Memory limits matter more once Phase 2 lands: a transformer detector holds its model
resident, so the limit must accommodate model size × worker count, and an under-limit
deployment will OOM during warm-up rather than under load — which at least fails visibly at
`/ready`.

### Sizing

**Unknown. Pending Phase 4 benchmarks.**

Sizing requires measured per-request CPU cost, detector latency, memory per worker with
models loaded, and the concurrency knee. Publishing a recommendation before measuring it
would be exactly the kind of unbacked claim this project refuses to make. Phase 4 produces
the numbers; this section gets rewritten with citations then.

Known shape of the answer without numbers: CPU-bound at the detector, GIL-limited per process
([ADR-001](adr/ADR-001-technology-stack.md)), so scaling is more workers/pods rather than
more threads, and worker count interacts with the detector thread pool.

### Migrations

Alembic, run as a separate step (init container or pipeline stage) under a role that may
alter schema. Never on application startup: N replicas starting simultaneously would race,
and a failed migration would become a crash loop instead of a clear failure.

Rollback: every revision has a working `downgrade`, and destructive migrations are split into
expand/contract steps across releases so a rollback does not lose the audit trail.

### Rollout

Rolling update gated on `/ready`. Because `/ready` waits for detector warm-up, rollout is
naturally slower than a plain proxy's — that is correct, not a problem to tune away.

Policy changes and code changes should be separate deployments. A rollout that changes both
makes "which change caused the block-rate spike" unanswerable, and block-rate spikes are the
most common post-deploy incident in this product category.

### Kubernetes

Manifests are Phase 7, **and only if justified**. Local Docker Compose must work first
(NFR-012). When written, they will include: Deployment, Service, liveness/readiness probes
wired correctly, PodDisruptionBudget, HorizontalPodAutoscaler with a metric derived from
Phase 4 measurements, resource requests/limits, and a NetworkPolicy enforcing obligation 1.

### CD

The CI pipeline builds, tests and scans; it does not deploy, and holds no credentials
([ci.md](18-ci-cd-strategy.md)). A deployment pipeline belongs to the operator's environment. Intended
shape: build → scan → sign → publish → migrate → rolling update gated on `/ready`.
