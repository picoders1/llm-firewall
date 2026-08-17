# Performance Benchmarking

## The claim we are trying to earn

> "The gateway adds X ms at p95."

That sentence is worthless unless three things are pinned down: what "adds" means, what it
was measured against, and on what machine. Most published guardrail latency numbers fail all
three. This document defines the measurement so that ours can be checked.

**Current status: no benchmark has been run. Every latency and throughput figure in this
repository reads `pending benchmark execution`.**

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
docker compose up -d
uv run python -m eval.runners.benchmark \
    --conditions A,B,C,D \
    --concurrency 1,4,16,64 \
    --payload short,medium,long \
    --iterations 1000 --warmup 100 --repeats 3 \
    --report eval/reports/
```

Output: `eval/reports/bench-<run_id>.{json,md}`, including the machine metadata block and
the raw per-request timings needed to recompute every statistic independently.
