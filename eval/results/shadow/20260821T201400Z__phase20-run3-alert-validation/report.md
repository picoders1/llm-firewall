# Phase 20 — Run 3: real-stack alert validation

Protocol: [ADR-035](../../../../docs/adr/ADR-035-fault-injection-and-alert-validation.md),
pre-registered in phase 0, amended in phase 0b on measured evidence, seam
re-designed and verified in phase 0c.
Baseline: **`v1.0.0-rc1`** at `76d6fadc60492c32a628ff673297317cef4383ec` — unchanged by this run.

| | |
|---|---|
| Date | 2026-08-21, 20:14–22:16 UTC |
| Stack | `compose.yaml` + `compose.fault.yaml` + `compose.observability.yaml` |
| Gateway | fault project `llm-firewall-fault`, host `:8006`; mock `:8082`; Postgres `:5435`; Prometheus `:9091` |
| Machine | reference dev machine, 16 cores / 31 GiB — **loopback, not production capacity** |
| Corpus | `eval/datasets/finetune/dev/cases.jsonl`, sha256 `07a1e685aed81cdc…`, 808 cases |
| Driver seed | `20260822` (recorded in every run; fault selection is exact-count, not Bernoulli) |
| Policy | heuristics 0.85/block, transformer disabled/warn, overlays 0 — **verified unchanged** |
| Hold-outs | **not read**. `eval/datasets/**` unmodified |

## What "validated" means here

An alert is validated **only** when the real condition was produced through the
real stack and the shipped Prometheus rule reached the state the rule requires.
Neither a green `promtool` case nor an incrementing counter counts. Every
transition below carries the timestamps Prometheus recorded.

## Result: 15 of 16 validated

| # | Alert | `for:` | PENDING | FIRING | Trigger |
|---|---|---|---|---|---|
| 6 | `FirewallDetectorErrorsPresent` | — | — | **20:14:24** | one marker request at 20:14:15 |
| 10 | `FirewallRetentionSweepsFailing` | — | — | **20:15:38** | `stop postgres` at 20:14:57 |
| 1 | `FirewallAuditEventsDropped` | — | — | **≤20:20:59** | `pause postgres` + 20 req/s, `queue_drop` |
| 12 | `FirewallAuditQueueSaturating` | 10m | 20:19:38 | **20:29:52** | same run; depth pinned at 5000/5000 |
| 11 | `FirewallAuditBacklogExceedsRetention` | 30m | 20:31:08 | **21:01:14** | 5,000 rows backdated 10 days, 1-row sweep budget |
| 5 | `FirewallDetectorErrorRateHigh` | 10m | 20:42:24 | **20:52:52** | 5% `detector-error`, 5 req/s |
| 8 | `FirewallUpstreamErrorsHigh` | 10m | 20:59:24 | **21:09:30** | 30% `__return_500__`, 5 req/s |
| 16 | `FirewallGatewayOverheadHigh` | 15m | 21:21:00 | **21:36:03** | 10% `detector-slow`, p95 ≈ 170 ms |
| 14 | `FirewallCallerAuthFailureSpike` | 10m | 21:38:00 | **21:48:59** | 2 invalid bearers/s |
| 15 | `FirewallOperatorAuthDenialSpike` | 10m | 21:38:00 | **21:48:59** | 1 unauthenticated console GET/s |
| 2 | `FirewallAuditWriteFailing` | 10m | 22:05:13 | **22:15:42** | `sync` + `stop postgres`, 2 req/s — **after fixing R-111** |
| 3 | `FirewallHTTPSEnforcementDisabled` | 5m | 20:14:13 | **firing** | dev stack does not enforce HTTPS (re-confirms Run 2) |
| 4 | `FirewallRetentionDisabled` | 30m | — | Run 2 | retention off by default |
| 13 | `FirewallConcurrencyRejections` | 5m | — | post-R-104 | 56 rejections on a virgin process |
| 9 | `FirewallRetentionStalled` | 15m | 01:05:30 | **01:20:30** | one success 22:04:48, then 613 consecutive failed sweeps |
| **7** | `FirewallBlockRateStepChange` | 30m | — | **EXTERNALLY UNVERIFIED** | not attempted — see below |

Every alert that fired also **resolved** when its condition ended. None stuck.

## The R-104 fix, proven twice more on genuine first occurrences

#6 and #10 were the two remaining alerts carrying the R-104 newness clause, and
each is exercisable **once per virgin TSDB**. Both were driven on a Prometheus
started with `--renew-anon-volumes`, with the target series confirmed absent
beforehand. At the moment each fired:

```
#6   sum by (detector, error_kind) (increase(...[30m]))  =  0     <- original expression: cannot fire
     newness clause  (> 0 unless ... offset 30m)         =  1     <- what actually fired it

#10  sum(increase(...{outcome="failed"}[1h]))            =  0     <- original expression: cannot fire
     newness clause  (> 0 unless ... offset 1h)          =  1     <- what actually fired it
```

All three R-104 alerts (#13, #6, #10) have now been proven on real first
occurrences. Without the fix, none of them would have fired.

## R-107, exercised for the first time

`FirewallUpstreamErrorsHigh` had a permanently empty numerator until R-107.
Under 30% induced upstream failures the counter moved and the alert fired:

```
firewall_upstream_errors_total{kind="5xx"}                    720
firewall_upstream_latency_seconds_count{outcome="ok"}      18,673
```

**Denominator note, worth recording:** the ratio settled at **0.20**, not the
0.30 fault fraction, because `firewall_requests_total` counts blocked requests
and a blocked request can never reach the upstream. The achievable ratio is
capped by the allow rate. Still 2× the 0.10 threshold.

## R-111 — a critical alert that could never fire, found by driving it

**This run found a defect of exactly R-107's shape, and it is the most important
thing in this report.**

Driving #2 against a stopped database produced **660 `audit_write_failed` ERROR
log lines in five minutes** while `firewall_audit_write_failures_total` read
**0.0** throughout. Cause, established by inspection:

* `Metrics.record_audit_failure()` existed and was exported;
* `PostgresAuditRepository.record()` logged the failure and held **no metrics
  reference at all**;
* `record_audit_failure` had **zero call sites in the entire repository**.

ADR-012 fixed this contract in Phase 0 — *"the write failure is logged at ERROR
and increments `firewall_audit_write_failures_total`, which is an alerting
metric"*. The metric, the rule (`FirewallAuditWriteFailing`, severity
**critical**) and the runbook entry all existed. The increment did not. The alert
was dead in **both** write modes, including the `queue_drop` mode
`compose.prod.yaml` ships.

A critical alert whose numerator cannot move is worse than no alert, because the
silence reads as health.

**Fixed** by passing metrics into `PostgresAuditRepository` and counting in the
failure branch — the same pattern `QueuedAuditRepository` already used. Verified
live: 5 requests with the database down → counter `5.0`, where the same 5
requests previously left it at `0.0`. Six regression tests added
(`tests/unit/test_audit_failure_accounting.py`), covering both write modes, one
increment per failed record, no increment on success, and the ADR-012 property
that the request still succeeds.

### Post-commit confirmation

R-111 is committed at **`3114fb9`**. Against image `3f62e57a2835`, built from that
commit, in an isolated throwaway container with an unreachable database:

```
12 requests: 8 benign -> 8 x 200 ; 4 injection -> 4 x 403 ; 5xx: 0
firewall_audit_write_failures_total : 0 -> 12   (exactly one per request)
firewall_requests_total             : allow/2xx 8.0, block/4xx 4.0
detector runs : injection 12, jailbreak 12, pii input 12, pii OUTPUT 8
no detector-error, upstream-error, drop, rejection or auth-failure movement
```

`pii.regex` ran 8 times on output against 12 on input — only allowed requests reach
output inspection, confirming the requests took the real path.

**This is a dependency check, not a re-execution of the #2 alert transition.** The
PENDING -> FIRING observation below remains the single observation of that alert
firing, and it was made against pre-commit code; the confirmation establishes only
that the committed code behaves as the code that produced it.

### The validating run (pre-commit)

The validating run drove **1,600 requests at 2.001 req/s for 800 s with the
database stopped**:

```
status codes : 200 x 1139, 403 x 461, and NO 5xx
latency      : p50 7.1 ms, p95 9.1 ms, p99 12.3 ms
firewall_audit_write_failures_total : 1771
```

Every request was served and decided correctly while the audit trail was
unavailable — ADR-012's deliberate exception to fail-closed, holding under a real
outage — and the counter tracked the loss instead of staying silent.

## R-109 — the queue-depth hypothesis, partially confirmed

ADR-035 §4 registered a prediction: the depth gauge has one call site, at the end
of each drained item, so under a stall it may freeze during exactly the condition
#12 detects. Measured during the stall:

```
20:16:17 depth=0      20:17:07 depth=1084    20:18:22 depth=2295
20:19:12 depth=3506   20:20:59 depth=4717    21:21:29 depth=5000
```

The gauge **advances in ~60-second steps against a 15-second scrape interval**,
so four consecutive scrapes report the same stale value. It is not frozen — #12
still fired correctly — but it lags reality by up to a minute, and the first
update took ~50 s rather than the 5 s command timeout would suggest. Recorded as
**partially confirmed**: the alert works; the gauge is coarser than its scrape.

## Incidental confirmations

* **ADR-029's "drop, don't block" holds under load.** The saturation run served
  **19,200 requests at 20.001 req/s with zero 5xx** while the audit queue was
  full and discarding every record. p50 4.3 ms throughout.
* **ADR-012's availability trade-off holds.** With the database stopped in `sync`
  mode, requests returned 200 and decisions stayed correct; only the record was
  lost.
* **Fixture B's latency marker is input-only**, confirming the phase 0b
  correction: `firewall_detector_latency_seconds{direction="output"}` totalled
  0.000124 s over 8 marker requests.
* **The driver's rate control is exact**: 5.016 req/s requested 5.000; 20.001
  req/s requested 20.000. Fault delivery was exact in every run (e.g. 200 of 200,
  1200 of 1200).

## #7 `FirewallBlockRateStepChange` — EXTERNALLY UNVERIFIED

Not attempted, as pre-registered. It requires **all** of: ≥48 h Prometheus
retention (the shipped overlay sets 24 h, shorter than the `offset 1d` lookback
needs), ≥25.5 h of continuous scraped history, two traffic regimes ~24 h apart,
and a ≥10 percentage-point block-rate difference. Synthesising samples or
shortening the offset was explicitly refused.

## #9 `FirewallRetentionStalled` — completed

```
last successful sweep        22:04:48Z
consecutive failed sweeps       613
threshold 10800 s crossed    01:04:48Z
PENDING (first sample)       01:05:30Z
FIRING  (first sample)       01:20:30Z   = threshold + the registered 15 m hold
```

The 10800 s threshold and the 15 m hold were **preserved, not shortened**, and the
condition came from the registered mechanism (`stop postgres` and leave it).

**Recorded honestly:** the soak began as a **by-product** of the #2 test leaving the
database stopped, rather than as a separately initiated #9 run. The mechanism,
sequence and durations match ADR-035 §8 exactly, so the registered criteria are met
on their own terms — but the way the condition arose is stated rather than tidied
away, because a reader reconstructing this run would otherwise find a three-hour gap
with no explanation.

## Runbook walk — five entries against genuinely firing conditions

ADR-034 §5 registers: *"Walk the evidence-gathering commands of a representative
subset against a live stack and record, per entry: exercised / worked / missing /
unverified."*

Run 2 walked three entries **on a healthy stack**. This walk was performed
2026-08-22 03:20–03:22 UTC with five alerts genuinely firing, which is the
difference that produced the finding below. Endpoint and compose flags were
substituted for the fault project (`:8006`, `-f compose.yaml -f compose.fault.yaml
-f compose.observability.yaml`); the runbook targets the default stack, so that is
operator context rather than a defect.

| Entry | Command | Result |
|---|---|---|
| **#2** `FirewallAuditWriteFailing` | `logs \| jq 'select(.event=="audit_write_failed")'` | **WORKED** — 358 events in 30 m, each carrying `error_kind` and **no exception text**, exactly as the entry promises |
| | `curl /ready \| jq '.checks[] \| select(.name\|startswith("database"))'` | **WORKED** — `{"passed":false,"detail":"unreachable","requirement":"advisory"}`, and `/ready` still returned **200**. ADR-027's classification behaving correctly under a real outage: an audit outage is not a traffic outage |
| | `docker compose exec postgres pg_isready` | **WORKED as a diagnostic** — *"service postgres is not running"*, the correct diagnosis |
| **#10** `FirewallRetentionSweepsFailing` | `logs \| jq 'select(.event=="retention_sweep_failed")'` | **WORKED** — 240 in the 2 h window, `error_kind` only |
| | `metrics \| grep retention_sweeps_total` | **WORKED** — `success 1.0`, `failed 633.0` |
| **#9** `FirewallRetentionStalled` | `metrics \| grep retention_(last_success\|sweeps_total\|enabled)\|oldest_row_age` | **WORKED** — all four metric families present |
| | `logs \| jq 'select(.event\|startswith("retention_"))'` | **WORKED** — 633 `retention_sweep_failed`, 1 `retention_sweep`, 1 `retention_budget_exhausted` |
| | `uv run python scripts/purge_audit.py` | **FAILED — see R-112** |
| **#11** `FirewallAuditBacklogExceedsRetention` | `metrics \| grep oldest_row_age\|retention_period\|rows_deleted` | **WORKED** — oldest `869662 s` against a period of `86400 s`, over the 1.5x bound; `rows_deleted 1` |
| | `logs \| jq 'select(.event=="retention_budget_exhausted")'` | **WORKED** — the documented diagnosis line is present verbatim |
| | `uv run python scripts/purge_audit.py` | **FAILED** — same as #9; not re-run |
| **#3** `FirewallHTTPSEnforcementDisabled` | `metrics \| grep firewall_https_enforced` | **WORKED** — `0.0` |
| | `logs \| jq 'select(.event=="startup")'` | **WORKED** — `{"environment":"development","https_enforced":false,"trusted_proxies":[]}` |
| | `logs \| jq 'select(.event=="https_not_enforced")'` | **WORKED** — the startup warning names the reason |

**13 commands walked: 11 worked, 2 failed** (the same command in two entries).

### R-112 — `purge_audit.py` stack-traces when the database is unreachable

The runbook sends an operator to `purge_audit.py` from the **retention-stalled** and
**backlog** entries — which are precisely the situations where the database is most
likely to be down. With the documented prerequisite supplied and the database
unreachable:

```
exit code    : 1
stdout       : 0 lines
stderr       : 129 lines, beginning "Traceback (most recent call last):"
               and ending  "ConnectionRefusedError: [Errno 111] Connect call failed"
operator-facing message before the traceback: none
```

Contrast the path R-105 already fixed — no database *configured* — which still exits
cleanly with *"No audit database is configured … Nothing to purge."* The
**configured-but-unreachable** path was never exercised, because Run 2 walked the
runbook on a healthy stack. **Not fixed in this run**; recorded as R-112.

### Note on stray traffic during the run

Two `until` waiter loops left over from the alert-driving phase were still running
~7 h later (their grep patterns never matched the rules API's JSON field ordering).
One POSTed a benign request every 5 s to the fault gateway, which is the source of
the 358 `audit_write_failed` events observed above. Both were stopped at 03:22.
**No evidence is contaminated:** the loop does not touch retention, so #9's gauge and
sweep counters are independent of it, and #2's criterion is `rate > 0` rather than a
counter value — #2 fired at 22:15:42, hours earlier. Its only effect was to keep #2's
condition true, which is why these logs were available to walk against.

## Limitations

Loopback only; no capacity claim. **Every threshold remains an unvalidated
development default** — firing on a condition built to fire it says nothing about
whether 1%, 10%, 0.2/s or 100 ms suits real traffic. **R-67 and R-88 are not
narrowed by this run.** The fault fixtures are opt-in, absent from the production
image, and asserted so by `tests/security/test_fault_fixtures_are_not_production.py`.

## Reproducibility

```bash
docker compose -f compose.yaml -f compose.fault.yaml -f compose.observability.yaml \
  up -d --renew-anon-volumes --wait postgres mock-upstream
docker compose -f compose.yaml -f compose.fault.yaml run --rm firewall-api alembic upgrade head
docker compose -f compose.yaml -f compose.fault.yaml -f compose.observability.yaml \
  up -d --renew-anon-volumes --wait

# #6 — one marker request on a virgin TSDB
curl -X POST localhost:8006/v1/chat/completions -H 'content-type: application/json' \
  -d '{"model":"mock-model","messages":[{"role":"user","content":"FAULT-DETECTOR-ERROR-3f9a1c"}]}'

# #5 — sustained detector errors
uv run python eval/runners/shadow.py eval/datasets/finetune/dev/cases.jsonl \
  --base-url http://localhost:8006 --duration-s 800 --rate 5 \
  --fault-marker detector-error --fault-fraction 0.05 --seed 20260822
```

Migrations must run **before** the gateway starts: the retention scheduler sweeps
at startup, and a pre-migration sweep fails for a reason unrelated to #10 and
would contaminate its newness clause (ADR-035 phase 0b, finding 5).
