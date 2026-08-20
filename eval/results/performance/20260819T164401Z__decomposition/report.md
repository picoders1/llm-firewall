# Gateway performance — cost decomposition

**Run:** `20260819T164401Z__decomposition` · protocol `docs/15-performance-benchmarking.md`
**Conditions:** A (mock only) · B (gateway, detectors off, audit off) · F (detectors on,
audit off) · C (detectors on, audit on)
**Upstream:** mock at `MOCK_LATENCY_MS=0` · **n** = 1 000 measured per cell, 100 warm-up
discarded · concurrency 1 and 4 · payloads short (265 B) / medium (2 065 B) / long (16 065 B)

Every number below is a **measured value under the conditions stated**, not a target and not
a capacity claim. See `manifest.json` for the machine, the git commit and the policy version.

## Server-measured gateway overhead, p50 (ms)

`x-firewall-gateway-ms` — the in-handler span, excluding the upstream call.

| payload | conc | B proxy | F +detection | C +audit | detection | audit |
|---|---|---|---|---|---|---|
| short | 1 | 0.939 | 1.845 | 2.269 | **0.907** | 0.424 |
| short | 4 | 0.419 | 4.787 | 5.484 | **4.368** | 0.697 |
| medium | 1 | 2.171 | 5.583 | 5.907 | **3.412** | 0.324 |
| medium | 4 | 1.136 | 8.816 | 11.191 | **7.680** | 2.375 |
| long | 1 | 12.143 | 20.005 | 32.525 | **7.862** | 12.520 |
| long | 4 | 6.596 | 43.998 | 48.181 | **37.402** | 4.184 |

## Per-stage breakdown, concurrency 1 (from the audit trail, n = 500 each)

| input | normalisation | detectors | policy | gateway span p50 | p95 |
|---|---|---|---|---|---|
| 0.2 KB | 0.293 | 0.985 | 0.094 | 2.150 | 3.157 |
| 2 KB | 1.599 | 3.233 | 0.089 | 5.731 | 8.478 |
| 16 KB | 11.659 | 19.438 | 0.085 | 32.019 | 44.408 |

Policy evaluation is **0.09 ms regardless of input size** — it is a pure function over
detector results, exactly as docs/15 predicted. Normalisation and detection both scale
roughly linearly with input length and together account for 60–97 % of the span.

## The finding: the instrumented span is not what a caller waits for

`client_latency − (gateway_overhead_ms + upstream_ms)`, p50 (ms):

| condition | short | medium | long |
|---|---|---|---|
| B (no detectors, no audit) | 5.10 | 4.94 | 5.50 |
| F (detectors, no audit) | 4.97 | 5.30 | 3.86 |
| **C (detectors + audit)** | **15.88** | **15.65** | **15.06** |

B and F agree, so detection is fully accounted for by the span. **C does not**, by a flat
~10 ms — and the cause is the synchronous audit write, which
`timings.finish()` excludes from `total_ms` by construction.

Measured directly after correcting the instrumentation ordering (n = 150, short payload):

| | p50 | p95 |
|---|---|---|
| `detector_ms` | 0.517 | 0.754 |
| `gateway_overhead_ms` | 1.745 | 2.233 |
| **`audit_ms`** | **10.517** | **14.377** |

The audit write costs **six times the entire rest of the gateway's measured overhead**, and
until this run every instrument reported it as `0.000`: the log line emitted `audit_ms`
*before* the measurement block that populates it. That ordering is fixed; the exclusion from
`gateway_overhead_ms` is not, because it is deliberate — the write is off the security
decision path (ADR-012). The consequence is recorded as **R-77**.

## Baseline floor

A loopback round trip on this machine costs ~4 ms p50 to *either* service — the mock's
`/health` (3.99 ms) and the gateway's `/health` (3.56 ms) are indistinguishable. Any
end-to-end figure here contains that floor twice for a proxied call, and it is the harness
and the kernel, not the gateway.

## Bottleneck

**The synchronous audit write**, at ~10 ms p50, dominates. After it, text processing
(normalisation + detection) scaling with input length. Policy evaluation is free. Proxying
itself costs ~1 ms for a small body and ~12 ms for a 16 KB one.

An async audit writer is already listed as outstanding work in
`docs/19-implementation-roadmap.md`. This run is the first measurement that says what it
would be worth.
