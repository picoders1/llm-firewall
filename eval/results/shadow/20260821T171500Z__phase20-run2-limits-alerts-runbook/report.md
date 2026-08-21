# Phase 20 — Run 2: limits, alerts, runbook

Protocol: [ADR-034](../../../docs/adr/ADR-034-shadow-traffic-validation.md).
Baseline: **`v1.0.0-rc1`** at `76d6fadc60492c32a628ff673297317cef4383ec` — unchanged by this run.

| | |
|---|---|
| Date | 2026-08-21, ~17:00–17:20 UTC |
| Stack | `compose.yaml` + `compose.edge.yaml` + `compose.observability.yaml` |
| Gateway | host `:8005` → container `:8000`; edge `:8089`; Prometheus `:9091` |
| Machine | reference dev machine (16 cores / 31 GiB) — **loopback, not production capacity** |
| Limits under test | edge `limit_req 5r/s burst=10`, `limit_conn 20`; app `FIREWALL_MAX_CONCURRENT_REQUESTS=64` |
| Policy | heuristics 0.85/block, transformer disabled/warn, overlays 0 — verified unchanged |

## M3 — Capacity and development-default limits

### Edge rate limit — **behaves exactly as documented**

Workload: 60 requests issued concurrently to `http://localhost:8089/v1/chat/completions`.

| Offered | 200 | 429 | Upstream calls |
|---|---|---|---|
| 60 | **11** | **49** | **11** |

`limit_req` at 5 r/s with `burst=10` predicts 11 admitted (burst + one refill).
Observed exactly 11. **Upstream calls equal admitted requests**: the 49 refused
never reached the model.

### In-process admission control — **exact and deterministic**

First attempt with 300 requests at parallelism 200 produced **zero** rejections:
each request completes in ~11 ms, so in-flight never approached 64. The ceiling is
not reachable with fast responses — recorded because it explains why an untuned
load test would wrongly report the limit as untested.

Re-run with the mock upstream at `MOCK_LATENCY_MS=1500` (its documented knob;
restored to 0 afterwards):

| Offered concurrent | 200 | 503 | `concurrency_rejections_total` | Upstream calls |
|---|---|---|---|---|
| 120 | **64** | **56** | 0 → **56** | **64** |

Admitted exactly the configured ceiling, refused exactly the remainder, counter
matched the refusals exactly, and **the 56 rejected requests produced no upstream
call**. The development default of 64 behaves deterministically.

**No limit was changed.** Whether 64 is the right number for a real deployment is
not answerable from a loopback test (R-67 remains open).

### Not exercised

`limit_conn 20` (edge) — the rate limiter refuses before the connection ceiling is
reachable with short requests. Caller rate limit — `FIREWALL_CALLER_RATE_LIMIT_PER_MINUTE`
is `0` (disabled) in this stack, so there is nothing to exercise.

## M4 — Alert validation

**A real defect, found only because the condition was real.**

`FirewallConcurrencyRejections` (`sum(increase(firewall_concurrency_rejections_total[5m])) > 0`)
**did not fire** on the 56 rejections that had just occurred:

```
app:        firewall_concurrency_rejections_total{scope="gateway"} 56.0
prometheus: series present, value 56
            samples in 10m: 5, distinct values: ['56']
            sum(increase(...[5m])) = 0        ← alert cannot fire
```

The counter is **labelled**, so the series does not exist until the first
rejection — it springs into existence *at* 56 with no prior zero to rise from, and
`increase()` over a flat series is 0.

Confirmed by a second burst: 56 → 92 gave `increase[5m] = 39.2`, which would fire.
**The alert misses the first occurrence of the condition it exists to catch and
only fires on the second.**

Same shape, same expression form, therefore also affected:

| Alert | Counter | Affected |
|---|---|---|
| `FirewallConcurrencyRejections` | `firewall_concurrency_rejections_total{scope}` | **yes — demonstrated** |
| `FirewallDetectorErrorsPresent` | `firewall_detector_errors_total{detector,error_kind}` | **yes — same form, not separately demonstrated** |
| `FirewallRetentionSweepsFailing` | `firewall_retention_sweeps_total{outcome}` | **yes — same form, not separately demonstrated** |
| `FirewallAuditEventsDropped` | `firewall_audit_events_dropped_total` (**unlabelled**) | **no** — exists at 0 from process start |

The promtool unit tests did not catch this because every input series they define
starts at 0, i.e. they model a series that already exists. That is a test-fidelity
gap, not a rule-syntax gap.

### Alert-by-alert status

| Alert | Result |
|---|---|
| `FirewallHTTPSEnforcementDisabled` | **FIRING** on the real condition (dev stack does not enforce HTTPS) |
| `FirewallRetentionDisabled` | **FIRING** on the real condition (retention off by default) |
| `FirewallGatewayOverheadHigh` | **PENDING** on real load during the slow-upstream test |
| `FirewallConcurrencyRejections` | **DID NOT FIRE on first occurrence** — defect above |
| `FirewallDetectorErrorsPresent`, `FirewallDetectorErrorRateHigh` | **not exercised** — needs an induced detector failure; no fault-injection hook exists |
| `FirewallUpstreamErrorsHigh` | **not exercised** — needs sustained upstream 5xx; the mock has no error-injection knob |
| `FirewallAuditEventsDropped`, `FirewallAuditQueueSaturating` | **not exercised** — need `queue_drop` mode plus a stalled database |
| `FirewallAuditWriteFailing` | **not exercised** — needs 10 min of continuous DB failure |
| `FirewallRetentionStalled`, `FirewallRetentionSweepsFailing`, `FirewallAuditBacklogExceedsRetention` | **not exercised** — need retention enabled and a multi-hour window |
| `FirewallBlockRateStepChange` | **not exercised** — compares against `offset 1d`; needs >24 h of history |
| `FirewallCallerAuthFailureSpike`, `FirewallOperatorAuthDenialSpike` | **not exercised** — need the boundaries enforcing, which the dev stack disables |

**3 of 16 observed firing/pending on real conditions; 1 demonstrated defective;
12 not exercised**, each with the dependency named.

### Incidental documentation defect

`firewall_audit_queue_capacity` reads **0.0** in `sync` mode, not absent —
an unlabelled Prometheus gauge exists from process start. ADR-031 and the rule
comment both claim the series is *absent*. Behaviour is still correct
(`0/0` = NaN, no alert) but the stated mechanism is wrong.

## M5 — Runbook dry run

| Entry | Executable | Result |
|---|---|---|
| `FirewallConcurrencyRejections` | yes | **Worked.** Metrics present; `admission_rejected` log lines = 92, matching the counter exactly; `admission_control` startup line present |
| `FirewallRetentionDisabled` | partly | Metrics and log line present, `firewall_audit_retention_period_seconds` correct (2.592e6 / 1.5552e7). **`uv run python scripts/purge_audit.py` fails as written** |
| `FirewallHTTPSEnforcementDisabled` | yes | **Worked.** Gauge at 0 and `https_not_enforced` startup warning both present |

**Runbook gap found.** The documented command

```
uv run python scripts/purge_audit.py
```

returns `No audit database is configured` unless `FIREWALL_DATABASE_URL` is
exported. The runbook does not say so. With the variable supplied it works and
reports the 30-day / 180-day cutoffs correctly.

## M6 — Security invariants, continuously

| Invariant | Result |
|---|---|
| Blocked requests never reach upstream | injection → 403, upstream delta **0** |
| Rate-limited requests never reach upstream | 49 refused at the edge, upstream = 11 = admitted |
| Admission-rejected requests never reach upstream | 56 refused, upstream = 64 = admitted |
| Audit coverage | 441 traces for this session's served requests |
| Transformer disabled / warn | verified |
| Production policy unchanged | `config/`, `app/`, `deploy/`, `compose.prod.yaml` byte-identical to HEAD |
| Hold-outs unread | harness refused `holdout/v3` by path, verified this run |

**No invariant failed.**

## Reproducibility

```bash
docker compose -f compose.yaml -f compose.edge.yaml -f compose.observability.yaml up -d --wait
# edge rate limit
seq 1 60 | xargs -P 60 -I{} curl -s -o /dev/null -w "%{http_code}\n" \
  -X POST http://localhost:8089/v1/chat/completions -H 'content-type: application/json' \
  -d '{"model":"mock-model","messages":[{"role":"user","content":"what is 2+2"}]}'
# admission ceiling (needs slow upstream: MOCK_LATENCY_MS=1500 via an override, then restore)
seq 1 120 | xargs -P 120 -I{} curl -s -o /dev/null -w "%{http_code}\n" --max-time 30 \
  -X POST http://localhost:8005/v1/chat/completions -H 'content-type: application/json' \
  -d '{"model":"mock-model","messages":[{"role":"user","content":"what is 2+2"}]}'
```

## Limitations

Loopback only; no production capacity claim. Twelve of sixteen alerts unexercised.
The runbook dry run is a rehearsal on a healthy stack, not an incident.
