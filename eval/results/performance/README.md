# Gateway performance benchmarks

Immutable run directories, one per invocation of
`python -m eval.runners.benchmark`. **Nothing here is ever overwritten** — the
harness refuses to write into an existing directory, because a benchmark whose
history can be edited is a benchmark that proves whatever was run last.

Protocol: [`docs/15-performance-benchmarking.md`](../../../docs/15-performance-benchmarking.md).

## Phase 15 runs (2026-08-19)

| Run | What it establishes |
|---|---|
| `main-matrix` | A/B/C × {short, medium, long} × concurrency {1, 4, 16, 64}, n = 1 000/cell |
| `decomposition` | Adds condition F (detectors on, audit off) to split detection from persistence |
| `stage-breakdown-c1` | Per-stage timings at concurrency 1, from the audit trail |
| `upstream-{0,50,200}ms` | Gateway overhead is independent of upstream latency |
| `consistency-run{1,2}` | Two identical runs, back to back — the run-to-run spread |
| `edge-vs-direct` | The TLS edge hop, measured against the same gateway process |

The headline results and their limits are in
[`decomposition/report.md`](20260819T164401Z__decomposition/report.md).

## Files in a run

| File | Contents |
|---|---|
| `manifest.json` | machine, git commit, policy version, protocol parameters, endpoints |
| `workload.json` | the exact payload definitions, frozen with the results |
| `raw_results.jsonl` | one line per measured request — every statistic is recomputable |
| `summary.json` | per-cell statistics |
| `latency_by_configuration.csv` | both overhead definitions, side by side |
| `throughput_by_concurrency.csv` | throughput against concurrency |

## Reading these numbers honestly

**They are measurements on one laptop, not capacity.** Every figure carries a
machine, a payload, a concurrency and an upstream condition, and means nothing
without them.

**Concurrency 16 and 64 are floor-limited by the harness, not by the gateway.**
Condition A — the client talking to the mock with no gateway at all — degrades
from 4 ms p50 at concurrency 1 to 206 ms at 64 on this machine. Above
concurrency 4 the client-observed numbers measure the mock and the loopback.
The *server-measured* overhead stays valid there, because it is measured inside
the gateway.

**A blocked request is a success.** Workload W4 expects `403`; counting it as an
error would make the security path look like an outage.
