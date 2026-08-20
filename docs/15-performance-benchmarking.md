# Performance Benchmarking

## The claim we are trying to earn

> "The gateway adds X ms at p95."

That sentence is worthless unless three things are pinned down: what "adds" means, what it
was measured against, and on what machine. Most published guardrail latency numbers fail all
three. This document defines the measurement so that ours can be checked.

**Current status: measured 2026-08-19 (Phase 15).** Runs are in
[`eval/results/performance/`](../eval/results/performance/), each with its machine metadata,
git commit and raw per-request timings. Figures in `compose.prod.yaml` and `compose.edge.yaml`
remain **development defaults** — this benchmark characterised cost, it did not size limits
(R-67).

**Headline, and its conditions.** On a 12th-gen i7 laptop, mock upstream at 0 ms,
concurrency 1, 265-byte request: gateway span p50 **2.27 ms**, of which detection 0.99 ms,
normalisation 0.29 ms, policy 0.09 ms. The synchronous audit write adds a further
**10.5 ms p50** that the span excludes by construction. A 16 KB request costs
**32.0 ms p50** in-span, because normalisation and detection scale with length.

## Definition of overhead

```
total_client_latency = gateway_overhead + upstream_latency
gateway_overhead     = total_client_latency − measured_upstream_latency
```

where `measured_upstream_latency` is the wall-clock of the `httpx` call inside the handler.
This is recorded per request in production (`firewall_gateway_overhead_seconds`), not only
in a benchmark rig — a benchmark-only number is unfalsifiable in the environment that
matters.

`gateway_overhead` decomposes into:

| Component | Expected magnitude | Measured by |
|---|---|---|
| HTTP parse, validation, routing | small | span |
| Normalisation | scales with input length | span |
| Detection stage | `max` of concurrent detector latencies | per-detector histogram |
| Policy evaluation | negligible (pure function, no I/O) | span |
| Redaction | only on redact paths | span |
| Audit write | 0 on the request path once Phase 5 lands; non-zero in Phase 0 | span |

## Experimental design

Four conditions, identical harness, identical machine, run interleaved rather than
sequentially so that thermal drift and background load affect all conditions equally:

| # | Condition | Isolates |
|---|---|---|
| **A** | Client → mock upstream, gateway bypassed | Floor: the mock and the network stack |
| **B** | Client → gateway (all detectors disabled) → mock upstream | Proxy cost alone: parsing, validation, connection reuse |
| **C** | Client → gateway (detectors enabled) → mock upstream | **The headline: C − A is total overhead; C − B is detection cost** |
| **D** | Detector called directly, no HTTP | Pure detector cost, for per-detector budgeting |
| **F** | Client → gateway (detectors enabled, **audit disabled**) → mock | Added in Phase 15. Without it, C − B conflates detection with a synchronous database write. F − B is detection; C − F is persistence |
| **E** | Client → HTTPS edge → gateway → mock | Added in Phase 15. The deployment path of ADR-026/ADR-028, which did not exist when this document was written |

The **mock upstream is what makes this valid** ([ADR-009](adr/ADR-009-mock-upstream.md)).
A real model's latency variance (seconds, load-dependent, token-dependent) is one to three
orders of magnitude larger than the effect being measured; benchmarking overhead through a
real provider measures the provider. The mock returns a fixed-size response after a
configured fixed delay, so the signal is not buried.

Both a `MOCK_LATENCY_MS=0` configuration (maximum sensitivity to gateway cost) and a
realistic one (e.g. 800 ms, representative user experience) are run. The first tells you
what the gateway costs; the second tells you whether anyone would notice.

## Protocol

| Parameter | Value |
|---|---|
| Warm-up | ≥100 requests, discarded — JIT, connection pool, page cache, model warm-up |
| Measured iterations | ≥1 000 per condition (the harness refuses to emit latency metrics below the configured minimum) |
| Concurrency levels | 1, 4, 16, 64 — reported separately, never averaged together |
| Payload sizes | short (~50 tokens), medium (~500), long (~4 000) — normalisation and detection scale with length |
| Repetitions | 3 independent runs; report median of medians and inter-run spread |
| Clock | `time.perf_counter()` (monotonic) |
| Client | Async client, connection reuse on — otherwise TCP/TLS setup dominates |

## Reported statistics

p50, p90, p95, p99, max, mean, standard deviation, and **n**, per condition, per concurrency
level, per payload size.

* **p99 and max are reported and never dropped.** A tail that is 40× the median is a
  timeout-and-retry storm waiting to happen, and reporting only p50/p95 hides exactly that.
* **Mean is reported alongside, never instead of, percentiles.**
* **Throughput** is measured as sustained requests/second at each concurrency level *with
  its error rate*. Throughput without an error rate is a measure of how fast a server can
  fail.
* **Saturation behaviour** is described qualitatively: where latency starts climbing
  non-linearly is more actionable than the peak number.

## Required metadata (every report)

```
CPU model, physical + logical cores, base/boost clock, governor
RAM total, GPU model + VRAM + driver, storage class
OS + kernel, container runtime, Python version + build
git commit + dirty flag, dependency versions
gateway worker count, detector thread-pool size, thresholds, policy_version
mock upstream configured latency and response size
concurrency, payload size, iteration count, warm-up count
```

Without this block a latency number is folklore. The harness collects it automatically via
`scripts/capture_machine_metadata.py` and refuses to write a report without it.

## Known measurement pitfalls (and how this design avoids them)

| Pitfall | Why it inflates or deflates results | Mitigation |
|---|---|---|
| No warm-up | First-request model load lands in the sample | 100 discarded requests |
| Client is the bottleneck | You measure the load generator | Report client CPU; verify with condition A |
| New connection per request | TCP setup dominates gateway cost | Connection reuse, stated |
| Averaging across concurrency | Hides the saturation knee | Reported separately |
| Benchmarking on a laptop under thermal throttling | Late samples are slower than early ones | Interleave conditions; report inter-run spread; note the machine class |
| Measuring through a real LLM | Provider variance swamps the effect | Mock upstream with fixed latency |
| Reporting p50 only | Hides the tail that causes incidents | p99 and max mandatory |
| Detectors not warmed | Model load counted as detection | `warmup()` at startup, verified via `/ready` |

The laptop caveat is real for this project: the development machine is a laptop-class CPU
with a 4 GB GPU. Absolute figures from it characterise **relative overhead**, and reports
say so rather than presenting them as production capacity.

## What will and will not be claimed

**Will be claimed, once measured:** gateway overhead distribution under stated conditions;
per-detector latency; throughput at each concurrency level with error rates; the marginal
cost of enabling each detector.

**Will not be claimed:** a single headline number without its conditions; production
capacity extrapolated from a laptop; overhead measured through a real provider; any figure
not backed by a committed report.

## Reproducing

```bash
MOCK_LATENCY_MS=0 docker compose -f compose.yaml -f compose.bench.yaml up -d --build

uv run python -m eval.runners.benchmark --label main-matrix \
    --conditions A,B,F,C \
    --concurrency 1,4,16,64 \
    --payload short,medium,long \
    --iterations 1000 --warmup 100 --repeats 1

uv run python -m eval.runners.report eval/results/performance/<run-id>
```

Output: `eval/results/performance/<run-id>/` — `manifest.json`, `workload.json`,
`raw_results.jsonl`, `summary.json` and the derived CSVs, including the machine metadata and
the raw per-request timings needed to recompute every statistic independently. The harness
**refuses to write into an existing directory**: a benchmark whose history can be edited
proves whatever was run last.

`compose.bench.yaml` adds the two containers conditions B and F need — a gateway running
`config/policies/benchmark-passthrough.yaml` (every detector disabled) and one with audit
persistence off. Both are measuring instruments; `tests/security/test_benchmark_isolation.py`
asserts neither can become the production configuration.

### Two overhead definitions, and why the report carries both

This document defines `gateway_overhead = total_client_latency − upstream_latency`. The
gateway separately reports its own in-handler span as `x-firewall-gateway-ms`. **They are not
the same number**, and Phase 15 measured the difference: the span starts after ASGI and
middleware and stops before the response is serialised — and, critically, before the audit
write. On this machine the gap is ~5 ms for a bare proxy and ~15 ms with audit persistence on.

Both are computed **per request** from paired samples, never by subtracting two percentiles
from different distributions.

### Measurement limits observed

* **Concurrency 16 and 64 are floor-limited by the harness.** Condition A — no gateway at all
  — degrades from 4 ms p50 at concurrency 1 to 206 ms at 64 on this laptop. Client-observed
  figures above concurrency 4 measure the mock and the loopback; the server-measured span
  stays valid because it is measured inside the gateway.
* **Run-to-run spread**, two identical back-to-back runs: p50 within ±4 % at concurrency 1,
  up to 11 % at concurrency 4. Reported rather than thresholded — no stability bound has been
  established.
