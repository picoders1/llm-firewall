# ADR-035: Fault Injection and Real-Stack Alert Validation (Phase 20, Run 3)

**Status:** **Pre-registered, AMENDED by measured Phase 1 evidence (Phase 0b, 2026-08-22).**
Phase 1 built the fixtures and verified them in isolation. **No alert has been validated; Run 3 has not been executed.**
One registered design detail was **refuted by measurement** and is corrected in [Amendment — Phase 1 measured evidence](#amendment--2026-08-22-phase-1-measured-evidence). The original text is preserved unchanged so the correction is legible as a correction.
Phase 0c pre-registers the replacement detector-error seam that Phase 0b left open: see [Amendment — Phase 0c](#amendment--2026-08-22-phase-0c-the-replacement-detector-error-seam).
**Date:** 2026-08-22 (pre-registration) · amended 2026-08-22 (Phase 0b, Phase 0c)
**Phase:** 20, run 3
**Registers:** the remainder of [ADR-034](ADR-034-shadow-traffic-validation.md) §4 (alert validation) and §5 (runbook dry run)
**Baseline:** `v1.0.0-rc1` at `76d6fadc60492c32a628ff673297317cef4383ec`, plus the two post-RC hardening commits `3adc8eb` (R-104/R-105/R-106) and `72f2be7` (R-107)

## Reading this document

**Everything below is a plan.** Every table entry describing an alert transition
is a *design expectation*, written before execution, so that the result cannot be
chosen after seeing it. Nothing here is evidence.

Two kinds of number appear, and they are kept apart deliberately:

* **Measured, pre-execution** — timings taken from the real registry and the real
  `re` module on the reference machine on 2026-08-22, used to *choose* the fixture
  parameters. These are design inputs. They say nothing about any alert.
* **Expected** — what the design predicts Run 3 will observe. Unconfirmed by
  definition.

* **Measured, Phase 1** — added by the Phase 0b amendment. Observations taken from
  the *built fixtures on a running fault stack*, before any alert validation. These
  are evidence about the **fixtures**, never about an alert.

When Run 3 executes, its results go in `eval/results/shadow/<run-id>/report.md` and
the execution-status table at the foot of this document. **This document is not
edited to make a prediction come true.**

> ### ⚠ Amended — read the amendment before acting on §3, §5, §6 or §10
>
> Phase 1 measured the built fixture and **refuted one registered expectation**:
> the 24 × `x` marker does *not* produce a detector timeout, because
> `asyncio.wait_for` neither preempts nor **reports** CPU-bound synchronous
> detector work. Fixture B therefore **cannot** validate **#5** or **#6**; it
> **can** still drive **#16**.
>
> Nothing in the original text below has been deleted or softened. The sections it
> affects carry an inline pointer, and the full correction — with the measurements
> that forced it — is in
> [Amendment — Phase 1 measured evidence](#amendment--2026-08-22-phase-1-measured-evidence).

## Context

[ADR-034](ADR-034-shadow-traffic-validation.md) pre-registered Phase 20 and its
§4 said what alert validation means: *"Drive the conditions each rule describes and
observe Prometheus transition `pending` → `firing`… What is unproven is that a
**real** condition produces the series the rule expects."*

Runs 1 and 2 executed the corpus and capacity measurements. Alert validation
finished **partial: 3 of 16 observed on real conditions, 12 unexercised**, and the
one condition that *was* driven end to end found a defect no synthetic test could
have found — R-104, three alerts unable to fire on the first occurrence of the
condition they exist to catch. That is the whole argument for this run:

> **`promtool test rules` is rule-level validation, not alert validation.**
> It proves an expression computes what its author intended over series the author
> also wrote. Every input series in the promtool suite starts at 0 — that is, it
> models a series that *already exists*. Real labelled counters do not exist until
> their first event. The suite was green throughout, all 16 rules, while three
> alerts could not fire. Only a real condition through the real stack distinguishes
> "the rule is correct" from "the rule works".

Run 2 also recorded that `FirewallUpstreamErrorsHigh` was unexercisable because
*"the mock has no error-injection knob"*. **That was wrong**, and this ADR corrects
the record: `services/mock_upstream/main.py` has shipped `__return_500__`,
`__return_malformed__`, `__return_huge__` and `__slow__` since Phase 0, alongside
`MOCK_LATENCY_MS` and `MOCK_SLOW_S`. The real obstacle was **R-107** — the alert's
numerator never incremented for any real upstream failure. R-107 is fixed at
`72f2be7` and unit-tested; **its >10% for 10m condition remains externally
unverified**, and exercising it is a Run 3 objective. No upstream fixture needs
building.

## 1. Purpose

Run 3 exists to **externally validate the remaining locally-validatable Phase 20
alerts** — to drive each registered condition through the real stack, at real
rates, and observe the real rule reach its required state.

It is not an experiment with a hypothesis to confirm. It succeeds as a validation
exercise if it produces, per alert, either an observed transition with its
timestamps or an explicit record of why the condition could not be produced.

Three things it deliberately does **not** attempt:

* **It does not calibrate.** Every value chosen below is chosen for margin over a
  registered threshold. Firing on a condition built to fire it says nothing about
  whether that threshold suits real traffic. R-67 and R-88 stay open whatever
  happens.
* **It does not change protection.** No detector threshold, no policy, no alert
  expression, no `for:` duration, no severity, no label.
* **It does not touch RC1.**

## 2. Current alert status

Sixteen rules in `deploy/alerts/firewall.rules.yaml`, numbered here in file order
and used consistently throughout this document.

### Already validated on real conditions — 3

| # | Alert | Evidence |
|---|---|---|
| 3 | `FirewallHTTPSEnforcementDisabled` | Run 2 — FIRING; the development stack genuinely does not enforce HTTPS |
| 4 | `FirewallRetentionDisabled` | Run 2 — FIRING; retention genuinely ships off |
| 13 | `FirewallConcurrencyRejections` | Post-R-104, on a virgin process and a renewed Prometheus volume: a first-ever burst of 56 rejections gave `increase[5m] = 0` (the old expression would not have fired) while the new clause read 56, and the alert went PENDING then FIRING |

These are **not** re-run. They are recorded as done.

### Remaining, locally validatable — 11

**#1** `FirewallAuditEventsDropped` · **#2** `FirewallAuditWriteFailing` ·
**#5** `FirewallDetectorErrorRateHigh` · **#6** `FirewallDetectorErrorsPresent` ·
**#8** `FirewallUpstreamErrorsHigh` · **#10** `FirewallRetentionSweepsFailing` ·
**#11** `FirewallAuditBacklogExceedsRetention` · **#12** `FirewallAuditQueueSaturating` ·
**#14** `FirewallCallerAuthFailureSpike` · **#15** `FirewallOperatorAuthDenialSpike` ·
**#16** `FirewallGatewayOverheadHigh`

> **Amended (Phase 0b).** **#5** and **#6** remain outstanding and remain locally
> validatable *in principle*, but **Fixture B as designed cannot exercise the metric
> they need** — `firewall_detector_errors_total` is never emitted by the registered
> seam. They are blocked on a new, separately pre-registered detector-error seam.
> See the amendment.

**#6 and #10 carry a significance beyond themselves.** They are the two remaining
R-104 newness clauses. #13 is the only one exercised against a genuinely
lazily-created series; these are the last two opportunities, and each is available
exactly once per virgin Prometheus volume.

### External-only — 1

**#7** `FirewallBlockRateStepChange` — see §7. **Not attempted in Run 3.**

### Long soak, optional — 1

**#9** `FirewallRetentionStalled` — see §8. Mechanically simple, ~3 h 20 m of
wall clock, no shortcut that preserves the registered threshold.

## 3. Fixture B — deterministic detector fault injection

### Why the obvious seams do not work

Four candidate seams were tested against the implementation before this design was
chosen. All four are eliminated, three of them by measurement.

**Measured, pre-execution.** The three enabled detectors, driven through the real
registry at and below the shipped `limits.max_inspect_chars = 100000`:

| Detector | 1 k chars | 10 k | 100 k |
|---|---|---|---|
| `injection.heuristic` | 0.17 ms | 1.22 ms | **12.54 ms** |
| `jailbreak.heuristic` | 0.15 ms | 1.35 ms | **13.24 ms** |
| `pii.regex` | 0.11 ms | 0.89 ms | **8.75 ms** |

* **A large payload cannot cause a timeout.** Cost is linear and `max_inspect_chars`
  bounds it at ~13 ms against a 250 ms budget — a 19× margin. This is a *positive*
  finding about the shipped detectors and it closes the simplest seam.
* **`timeout_ms: 1` does not work.** `DetectorPolicy.timeout_ms` is
  `Field(default=250, gt=0, le=60_000)`, so 0 is rejected; and the three enabled
  detectors are `BaseDetector` subclasses whose `detect()` never awaits, so the
  coroutine runs to completion in one step and `asyncio.wait_for` has no suspension
  point at which to fire. Whether it times out becomes a race with task scheduling —
  **non-deterministic**, which disqualifies it for a pre-registered protocol.
* **`injection.transformer` with a bad `model_path` is a *startup* failure.**
  `warmup()` raises `ConfigurationError` and the process refuses to start, by
  design (ADR-021). It produces no `firewall_detector_errors_total` sample at all.
* **`output.stub` has no error path.**

That leaves exactly one seam reachable without application code: `pii.regex`
`options.custom_patterns`, which compiles operator-supplied regexes and catches
only `re.error` before skipping the entry.

### Design

A **dedicated fault-injection policy**, `config/policies/fault-injection.yaml`: a
copy of `default.yaml` with one addition and nothing else changed.

```yaml
  pii:
    detector: pii.regex
    options:
      custom_patterns:
        - name: FAULT_INJECTION_MARKER
          pattern: "(x+x+)+y"
```

**Measured, pre-execution.** Backtracking cost of that pattern, clean
4×-per-2-characters scaling:

| Marker | Cost | Match | Registered use |
|---|---|---|---|
| 22 × `x` + `z` | **185.74 ms** | **None** | sub-timeout — drives **#16** without erroring |
| 24 × `x` + `z` | **770.38 ms** | **None** | 3.1× the 250 ms budget — deterministic **timeout** for **#5**, **#6** |
| ordinary text | **3.1 µs** | None | control — untouched |

Three properties make this usable as a pre-registered fixture:

* **It never matches.** `(x+x+)+y` against a run of `x` terminated by `z` fails
  after exhaustive backtracking. No span is found, so **no redaction occurs and no
  policy decision changes** — the fault is pure latency with zero effect on the
  security decision.
* **It is self-selecting and stateless.** The regex fails in microseconds on any
  text without a long `x` run, so ordinary corpus traffic in the same run is
  unaffected and the fault rate is exactly the driver's mix. No global switch, no
  per-process state, no reset step between requests.
* **It is deterministic at both lengths**, with the 3.1× and 0.74× margins above
  and below the 250 ms budget chosen so that neither outcome is a coin flip.

### Default-off, and never mounted by production

1. `config/policies/default.yaml` keeps `custom_patterns: []` — **unchanged, byte-identical to RC1.**
2. `compose.prod.yaml` is **standalone** (ADR-028) and mounts only the default
   policy. An overlay cannot add a mount to it.
3. The fault policy will be referenced by exactly one file, `compose.fault.yaml`,
   opt-in and never composed with production.
4. **A guard test is required, not optional** — `tests/security/test_fault_fixtures_are_not_production.py`,
   asserting (a) no policy file reachable from any production manifest declares a
   non-empty `custom_patterns`, and (b) `compose.fault.yaml` is unreferenced by
   `compose.prod.yaml`, `compose.prod-selftest.yaml` and the release workflow. This
   follows the project's rule that constraints are enforced by tests that attack the
   boundary rather than by convention.

**No production threshold or configuration changes.** The fault policy alters
`options.custom_patterns` and nothing else — same detectors, same 0.85 thresholds,
same actions, same `on_error` modes, same `timeout_ms`.

### R-108 — recorded as an observed concern, not a Run 3 result

> **SUPERSEDED IN PART by Phase 1 measurement.** The paragraph below states that
> *"the timeout is only recorded once control returns"*. **That is wrong.** The
> timeout is **never recorded at all**: the run is recorded as a *success* with a
> ~1.16 s latency against a 100 ms budget. R-108 is therefore materially worse than
> registered here, and it is now a **measured finding**, not a concern. The original
> wording is left standing so the error is visible; the corrected statement and its
> evidence are in the amendment.

**`timeout_ms` bounds observation, not impact.**

All three enabled detectors run **on the event loop**, not through
`SyncDetectorAdapter`'s bounded thread offload. `asyncio.wait_for` cannot preempt a
CPU-bound synchronous regex, so a 770 ms backtrack stalls the entire process for
770 ms and the timeout is only recorded once control returns. `GuardedDetector`
faithfully reports a timeout; what it cannot do is stop the work.

Ordinary traffic never reaches this — the measurements above show the shipped
detectors are linear and bounded by `max_inspect_chars`. But `custom_patterns` is
compiled with only `re.error` caught, and the code comment in
`app/detectors/pii/regex.py` already concedes *"Startup validation of custom
patterns is tracked as future work"*. That makes an operator-supplied regex the one
place in the system where detector cost is unbounded and the timeout guard is
decorative.

This was **observed while designing the fixture**, from the implementation and the
timings above. It is a property of shipped code, not of the fixture — the fixture
only makes it visible. It is registered here so that it is on the record before
execution, and it is **to be filed as R-108 in Phase 7** whether or not Run 3 runs.
It also constrains this design: the fault fraction is capped at 10% precisely so
the stall does not contaminate co-resident measurements (§9).

## 4. Fixture C — deterministic audit and database fault injection

### The architecture being faulted

`QueuedAuditRepository` (`app/database/repository.py`) is a bounded
`asyncio.Queue` sized by `FIREWALL_AUDIT_QUEUE_SIZE` (default 1000) with a single
`_drain_forever` writer; on `QueueFull` it increments `_dropped`, logs
`audit_event_dropped` and calls `record_audit_dropped()`. `Database` applies a
**5-second command timeout**. `RetentionScheduler` sweeps at startup and then every
`FIREWALL_RETENTION_INTERVAL_S` (default 3600), and `_observe()` — which sets
`firewall_audit_oldest_row_age_seconds` — runs **only after a non-dry-run sweep
succeeds**.

### `stop` and `pause` are different faults, and both are needed

| Fault | Effect | Serves |
|---|---|---|
| `docker compose stop postgres` | connection refused **immediately** — fast, repeated write failures | **#2**, **#10** |
| `docker compose pause postgres` | socket stays open, calls **hang** to the 5 s command timeout — the writer *stalls* at ~0.2 items/s | **#1**, **#12** |

Neither requires application code. Conflating them would make #1 and #12
unreachable: a refused connection fails fast and never fills the queue.

### Registered conditions

| Alert | Configuration | Fault | Expected onset |
|---|---|---|---|
| **#1** dropped | `FIREWALL_AUDIT_WRITE_MODE=queue_drop`, `FIREWALL_AUDIT_QUEUE_SIZE=200`, ≥10 req/s | `pause` | queue full in ~20 s; no `for:` |
| **#12** saturating | `queue_drop`, `FIREWALL_AUDIT_QUEUE_SIZE=5000`, ~20 req/s | `pause` | >50% at ~125 s; pinned at capacity thereafter; `for: 10m` |
| **#2** write failing | `FIREWALL_AUDIT_WRITE_MODE=sync`, ~2 req/s | `stop` | fast failures throughout; `for: 10m` |
| **#10** sweeps failing | `FIREWALL_RETENTION_ENABLED=true`, `FIREWALL_RETENTION_INTERVAL_S=30` | `stop` | first failure ≤30 s; no `for:` |
| **#11** backlog | `FIREWALL_RETENTION_ENABLED=true`, `FIREWALL_RETENTION_TRACE_DAYS=1`, `FIREWALL_RETENTION_MAX_ROWS_PER_SWEEP=1`, `FIREWALL_RETENTION_INTERVAL_S=30`, backdated rows | none | `for: 30m` |

**#11 needs the numerator to exist**, which means sweeps must **succeed** while
failing to keep up — a failing sweep raises before `_observe()` and never sets the
gauge. Hence a one-row budget against a seeded backlog: each sweep deletes one row,
exhausts its budget, and reports the oldest survivor. `FIREWALL_RETENTION_TRACE_DAYS=1`
is the `MINIMUM_RETENTION_DAYS` floor; **backdated audit rows** at `now() - 10 days`
then sit at ~8.6e5 s against a 1.5 × 8.64e4 = 1.3e5 s bound.

Label alignment checked against the implementation:
`firewall_audit_oldest_row_age_seconds` and `firewall_audit_retention_period_seconds`
both carry exactly `("table",)`, so the binary operation matches. Recorded because a
mismatch here would make #11 permanently unfireable while passing promtool.

### Prometheus recreation between newness-sensitive tests

`compose.observability.yaml` declares no named volume for `/prometheus`, so the
TSDB is **anonymous** and `--force-recreate` alone reuses it. For **#6** and
**#10** — the two remaining R-104 newness clauses — a series already present at the
offset is precisely what the second clause tests for, so a carried-over TSDB does
not merely add noise, **it silently invalidates the test**.

`--renew-anon-volumes` is therefore a **correctness requirement** for #6 and #10,
not hygiene. Registered as a mandatory step, not a recommendation.

### Data safety and teardown

Fixture C seeds and deletes audit rows, so it must not run against the development
volume:

* `compose.fault.yaml` gives PostgreSQL its own **named volume**
  (`firewall-fault-pgdata`), separate from development.
* Teardown is `docker compose -f compose.yaml -f compose.fault.yaml down -v`.
* **Nothing under `eval/datasets/` is written.** The frozen corpora and the hold-outs
  are read-only in this phase and the hold-outs are not read at all.
* `eval/results/**` is append-only — a new run directory, never an edit to an
  existing one.
* `scripts/seed_backdated_audit.py` will refuse to run unless the environment is
  not production and the target is the fault volume, and will be **dry-run unless
  given `--execute`**, matching `scripts/purge_audit.py`'s convention.
* After each condition: `unpause`/`start`, wait for `/ready`, and **re-assert the
  boundary invariants** (blocked → 403 with upstream delta 0; benign → 200 with
  delta 1) before the next condition begins.

### R-109 — a hypothesis to be confirmed or refuted, not assumed

`set_audit_queue_depth` has **exactly one call site**, at the end of each
`_drain_forever` iteration. During a stall the writer is blocked inside
`await self._inner.record(trace)`, so the gauge is not refreshed until that call
returns. With the 5 s command timeout it *should* refresh every ~5 s and the depth
curve *should* be visible — but if any path blocks longer than the scrape interval
without returning, the gauge freezes at its last value **during exactly the
condition #12 exists to detect**, and the system would jump silently from "quiet"
to `FirewallAuditEventsDropped`.

This is the same class of defect as R-104. It is registered **as a prediction**.
The depth series captured during #12 is what settles it. **If the gauge refreshes
normally, that is a refutation and must be reported as one** — a registered failure
mode must not later be presented as a discovery. To be filed as R-109 in Phase 7
with whichever outcome is observed.

## 5. Sustained-load driver

Seven alerts need a condition held at a controlled rate for 10–15 minutes:
**#2, #5, #8, #12, #14, #15, #16**.

**`eval/runners/shadow.py` will be extended. No third harness will be written.**
ADR-034 already refused a second one, and `eval/runners/benchmark.py` is the wrong
instrument: it is the Phase 15 fixed-grid latency experiment whose output backs
published performance claims, and adding a duration mode to it would put
load-generation code inside the measurement path those claims depend on.
`shadow.py` is already the Phase 20 deployment driver and already refuses hold-outs
by path.

### Registered flags

| Flag | Purpose |
|---|---|
| `--duration-s` | run until elapsed, cycling the corpus |
| `--rate` | target requests/second, token-bucket paced — **rate control, not max throughput**, so the ratio alerts have a known denominator |
| `--concurrency` | bounded in-flight, semaphore-limited as `benchmark.py` does |
| `--fault-fraction` | share of requests carrying a fault marker |
| `--fault-marker` | `upstream-500` (`__return_500__`) · `detector-timeout` (24 × `x`) · `detector-slow` (22 × `x`) |
| `--auth-failure-rate` | share of requests sent with a deliberately invalid bearer token (#14) |

### Registered guarantees

* **Seeded deterministic selection.** A seeded PRNG decides which requests carry a
  fault; the seed is recorded in the run artefact; corpus order is fixed. The same
  invocation reproduces the same fault pattern.
* **Observed counts, not assumed ones.** The driver reports `sent`, `faulted`, and
  a status-code histogram, so the *achieved* fault fraction is measured. A run whose
  achieved fraction misses its target is reported as such, not rounded to intent.
* **Existing one-shot behaviour remains the default.** Every new flag is optional;
  with none supplied `shadow.py` behaves exactly as it does today, so Run 1's
  invocation stays reproducible.
* **Hold-out protection is unchanged.** `FORBIDDEN = "holdout"` and the
  `load_cases` path check are untouched. No hold-out corpus is read in Run 3.

### Registered rates, with their margins

| Alert | Registered threshold | Planned load | Expected value | Margin |
|---|---|---|---|---|
| #8 | > 10% of **all** requests | 5 req/s, `--fault-fraction 0.30` | ≈ 0.30 | 3× |
| #5 | > 1% of detector runs | 5 req/s, `--fault-fraction 0.05` | **≈ 0.026** | **≈ 2.6×** |
| #16 | p95 > 100 ms | 5 req/s, `--fault-fraction 0.10` at 22 × `x` | ≥ 186 ms | ≥ 1.9× |
| #14 | > 0.2 /s per reason | 2 /s invalid bearer, one reason | ≈ 2 /s | 10× |
| #15 | > 0.1 /s per (class, reason) | 1 /s unauthenticated console GET | ≈ 1 /s | 10× |
| #2 | rate > 0 | 2 req/s, DB stopped | > 0 | — |
| #12 | depth/capacity > 0.5 | 20 req/s, DB paused | → 1.0 | 2× |

Two corrections the implementation forces, recorded so the registered numbers are
honest rather than tidy:

* **#5 is not `f`.** `pii.regex` runs on input *and* output, but a fail-closed
  input timeout returns 503 before output inspection. With fault fraction `f`,
  errors = `f` and runs = `f + 2(1−f)`, so the ratio is **`f/(2−f)`**. At `f = 0.05`
  that is **0.026**, not 0.05 — a 2.6× margin over the 1% threshold, not 5×. The
  threshold is cleared at any `f > 0.0198`.
* **#16's overhead is expected to roughly double.** The mock echoes `text[:200]`
  into the completion, so a 22 × `x` marker is re-scanned by `pii.regex` on the
  output path. Expected p95 is therefore ~2 × 186 ms. **To be measured, not
  assumed** — the registered success condition is only `p95 > 100 ms`.

> **Both bullets are corrected by Phase 1 measurement.**
>
> **#5's row and its `f/(2−f)` derivation are void**, because the premise — that the
> marker produces a detector *error* — is false. No fault fraction produces a
> non-zero numerator through this seam.
>
> **Phase 0c reinstates the derivation.** The arithmetic was correct; only its
> premise was false. The Phase 0c seam restores the premise, so `f/(2−f)` and the
> 2.6× margin stand again — see the Phase 0c amendment.
>
> **#16 does not double.** The marker is declared under `input.pii.options` only;
> the output `pii.regex` block carries no `custom_patterns`, and measured
> `firewall_detector_latency_seconds{direction="output"}` totalled **0.000124 s over
> 8 marker requests**. The cost is scanned once, on input. Measured end-to-end
> gateway latency was **~312 ms (22 × `x`)** and **~1201 ms (24 × `x`)**, both above
> the 100 ms threshold — but that is a *fixture* measurement, not a validated alert.

`FIREWALL_AUTH_FAILURES_PER_MINUTE` stays at its default `0` (off) for #14.
Enabling the throttle would convert some failures into 429s ahead of the credential
comparison and change the `reason` label mid-run, splitting the series the rule
aggregates by.

Both authentication boundaries need **environment only, no new code**:
`FIREWALL_CALLER_AUTH_MODE=api_key` with `FIREWALL_CALLER_API_KEYS` for #14
(`effective_caller_auth_mode` derives to `DISABLED` outside production, so it must
be set explicitly), and the existing `compose.console-auth.yaml` for #15.

## 6. Alert-by-alert validation matrix

`Y` = planned to be validatable end to end locally. **All transitions below are
expectations.**

> **Amended (Phase 0b): rows #5, #6 and #16 are superseded** by the table that
> follows this matrix. The matrix itself is left exactly as pre-registered.

| # | Alert | Metric | Trigger | Hold | Fixture / driver | Local | Expected evidence | Known limitation |
|---|---|---|---|---|---|---|---|---|
| 1 | `FirewallAuditEventsDropped` | `firewall_audit_events_dropped_total` | `queue_drop` + paused DB, ≥10 req/s | — | **C** | **Y** | counter > 0; `audit_event_dropped` log lines == counter; FIRING | unlabelled counter — newness clause not exercised here |
| 2 | `FirewallAuditWriteFailing` | `firewall_audit_write_failures_total` | `sync` + stopped DB, 2 req/s | 10m | **C** + driver | **Y** | `rate > 0` throughout; PENDING → FIRING at +10m; decisions still correct (ADR-012) | 13 min of wall clock |
| 3 | `FirewallHTTPSEnforcementDisabled` | `firewall_https_enforced` | dev stack default | 5m | — | **done** | FIRING (Run 2) | — |
| 4 | `FirewallRetentionDisabled` | `firewall_retention_enabled` | default off | 30m | — | **done** | FIRING (Run 2) | — |
| 5 | `FirewallDetectorErrorRateHigh` | `firewall_detector_errors_total` / `firewall_detector_latency_seconds_count` | 5% × 24-`x` marker, 12 min | 10m | **B** + driver | **Y** | ratio ≈ 0.026 by detector; PENDING → FIRING at +10m | ratio is `f/(2−f)`; threshold is an unvalidated default (R-88) |
| 6 | `FirewallDetectorErrorsPresent` | `firewall_detector_errors_total{detector,error_kind}` | **one** 24-`x` request | — | **B** | **Y** | series appears at 1; newness clause matches; FIRING within ~2 evaluations | **one shot per virgin TSDB** — R-104 clause |
| 7 | `FirewallBlockRateStepChange` | `firewall_requests_total{decision}` | ≥10 pp shift vs `offset 1d` | 30m | — | **N** | — | **EXTERNALLY UNVERIFIED — §7** |
| 8 | `FirewallUpstreamErrorsHigh` | `firewall_upstream_errors_total` | 30% `__return_500__`, 12 min | 10m | mock + driver | **Y** | ratio ≈ 0.30; PENDING → FIRING at +10m | **first exercise of the R-107 numerator**; threshold unvalidated |
| 9 | `FirewallRetentionStalled` | `firewall_retention_last_success_timestamp_seconds` | one success, then ≥3 h failing | 15m | **C** | **soak** | gauge frozen; `time() − gauge` > 10800; FIRING | **~3 h 20 m — §8** |
| 10 | `FirewallRetentionSweepsFailing` | `firewall_retention_sweeps_total{outcome="failed"}` | retention @30 s + stopped DB | — | **C** | **Y** | series appears; newness clause matches; FIRING | **one shot per virgin TSDB** — R-104 clause |
| 11 | `FirewallAuditBacklogExceedsRetention` | `firewall_audit_oldest_row_age_seconds` vs `..._retention_period_seconds` | 1 d period, 1 row/sweep, 10 d backlog | 30m | **C** + seeder | **Y** | age ≈ 8.6e5 s vs bound 1.3e5 s; FIRING at +30m | needs sweeps to *succeed* while not keeping up |
| 12 | `FirewallAuditQueueSaturating` | `firewall_audit_queue_depth` / `..._capacity` | queue 5000 @ 20 req/s, paused DB | 10m | **C** + driver | **Y** | depth curve; ratio → 1.0; FIRING at +10m | **settles R-109** — depth may not refresh during a stall |
| 13 | `FirewallConcurrencyRejections` | `firewall_concurrency_rejections_total` | 120 concurrent @ slow upstream | 5m | — | **done** | PENDING → FIRING, post-R-104 | — |
| 14 | `FirewallCallerAuthFailureSpike` | `firewall_caller_auth_failures_total` | 2/s invalid bearer, 12 min | 10m | env overlay + driver | **Y** | rate ≈ 2/s by reason; FIRING at +10m; `upstream.call_count` unchanged | throttle must stay off or the `reason` label splits |
| 15 | `FirewallOperatorAuthDenialSpike` | `firewall_auth_denials_total` | 1/s unauthenticated console GET, 12 min | 10m | `compose.console-auth.yaml` + driver | **Y** | rate ≈ 1/s by (access_class, reason); FIRING at +10m | — |
| 16 | `FirewallGatewayOverheadHigh` | `firewall_gateway_overhead_seconds` p95 by route | 10% × 22-`x` marker, 17 min | 15m | **B** + driver | **Y** | p95 > 100 ms; FIRING at +15m | marker re-scanned on output; must not run beside a latency measurement |

Planned total, running independent conditions concurrently where they do not
interfere: **≈ 75 minutes**, excluding #9.

### Amended rows after Phase 1 (supersedes the matrix above)

| # | Registered fixture | Measured outcome | Amended status |
|---|---|---|---|
| 5 | Fixture B, 5% × 24-`x`, `for: 10m` | **No `firewall_detector_errors_total` sample is produced.** 8 marker requests → 8 *successful* detector runs, 0 errors | **BLOCKED** — outstanding, locally validatable in principle, awaiting a new pre-registered detector-error seam |
| 6 | Fixture B, one 24-`x` request | Same. The series never comes into existence, so the R-104 newness clause cannot be exercised through this seam either | **BLOCKED** — as above. Still one shot per virgin TSDB *once a working seam exists* |
| 16 | Fixture B, 10% × 22-`x`, `for: 15m` | Marker cost confirmed on the real gateway: ~312 ms (22 × `x`), ~1201 ms (24 × `x`), scanned on **input only** | **UNCHANGED — Fixture B is sufficient.** The expectation that overhead doubles is withdrawn; the `p95 > 100 ms` condition is unaffected |

The other thirteen rows stand as pre-registered. **No alert has moved from
"planned" to "validated" — that requires a real Prometheus transition, which has
not been attempted.**

## 7. #7 `FirewallBlockRateStepChange` — EXTERNALLY UNVERIFIED

**Classification: EXTERNALLY UNVERIFIED. Not attempted in Run 3.**

The rule compares the block rate against the same 30-minute window one day earlier.
Producing that condition locally requires **all** of:

1. **≥ 48 h Prometheus retention.** `compose.observability.yaml` currently sets
   `--storage.tsdb.retention.time=24h`, which is **shorter than the `offset 1d`
   lookback needs** — even a sufficiently long soak would find the offset samples
   at or past the eviction edge. Raising this is a change to the validation
   harness, not to production (Prometheus is not part of the production topology,
   ADR-028), but it is a change and is named here rather than made silently.
2. **≥ 25.5 h of continuous scraped history** — `offset 1d` plus the `[30m]` window
   plus `for: 30m` — with the gateway up and scraped throughout.
3. **Two traffic regimes separated by approximately 24 h**, both above the 0.1 req/s
   floor the rule requires.
4. **A ≥ 10 percentage-point block-rate difference** between them.

Beyond cost, the rule is *designed* around a baseline nobody here has: it compares
against yesterday precisely because the correct block rate is a property of a
deployment's real traffic. A synthetic 25-hour soak would confirm arithmetic that
`promtool test rules` already confirms, and would say nothing about the threshold.

**Explicitly refused:** synthesising Prometheus samples, backfilling a TSDB, or
shortening the offset. Any of those would fabricate the evidence this ADR exists to
avoid fabricating.

The dependency is recorded so the alert can be validated by the first deployment
that has two days of real history — which is the correct place for it.

## 8. #9 `FirewallRetentionStalled` — long soak, optional

**Classification: locally validatable, but only as a ~3 h 20 m soak.**

The registered condition is `time() - min(firewall_retention_last_success_timestamp_seconds > 0) > 10800`
held `for: 15m`. The gauge is set by the process from its own successful sweeps, so
the sequence is:

1. **One successful retention observation** — retention enabled, database healthy,
   one sweep completes and sets the gauge.
2. **Then ≥ 3 h 15 m of continuous failure** — `docker compose stop postgres` and
   leave it. Every subsequent sweep fails, the gauge never advances, and
   `time() − gauge` crosses 10800 s at +3 h, after which the 15-minute hold elapses.

**The 10800 s threshold and the 15 m hold are preserved exactly.** No shortened
timing, no modified expression, no adjusted `for:`. There is no shortcut that leaves
the registered rule intact, and inventing one would validate a different alert from
the one that ships.

Mechanically simple and safe to run unattended. Registered as **optional** and
scheduled last (§10, Phase 5) so that a failure there costs nothing already banked.
If it is not run, it is recorded as *not produced, with the soak as its dependency* —
not as a limitation of the rule.

## 9. Pre-registered failure modes

Registered **before** execution so that none of them can later be presented as a
discovery.

* **A fixture that proves the metric rather than the alert.** If a marker request
  produces a detector error but the series never reaches Prometheus, or reaches it
  and the rule does not transition, **the alert is not validated**. The metric
  incrementing is not the criterion; the transition is. This is the exact failure
  R-104 was: green promtool, correct counter, alert that could not fire.
* **A stale Prometheus TSDB invalidates newness testing.** #6 and #10 are
  meaningless on a volume that already holds the series — a sample at the offset is
  what the second clause tests for. `--renew-anon-volumes` is mandatory before each,
  and each is available **once per virgin volume**. A run that forgets this produces
  a result that looks like a pass and is not one.
* **Detector CPU stall contaminates co-resident measurements.** Per R-108 the fault
  request stalls the whole event loop for its duration (~770 ms at 24 × `x`). Fault
  fraction is capped at 10%, and **#16 must never run beside a latency measurement**
  whose numbers would be attributed to the gateway.
* **A green firing does not prove threshold calibration.** Every registered value is
  chosen for margin over its threshold. Firing on a condition built to fire it says
  nothing about whether 1%, 10%, 0.2/s or 100 ms suits real traffic. **R-67 and
  R-88 remain open regardless of the outcome**, and no Run 3 result may be quoted as
  narrowing them.
* **R-109 must be confirmed or refuted, not assumed.** The queue-depth refresh
  hypothesis (§4) is a prediction. If the depth series refreshes normally during the
  #12 stall, that is a **refutation** and is to be reported as one, in the artefact
  and in the risk register.
* **The runbook walk is a rehearsal with a real fault, not an incident.** Fixture C
  makes the condition genuine, which is a strict improvement on Run 2's healthy
  stack. It still does not establish that a step works at 3am under pressure.
* **Loopback is not deployment capacity.** Inherited from ADR-034 and unchanged. No
  rate or latency figure from Run 3 is a capacity claim.

## 10. Execution order

Registered as the order of record. Each phase completes before the next begins.

> **Amended (Phase 0b).** Phase 1 is complete and its isolated-verification gate
> **failed on the detector-timeout half** — which is the gate working. A **Phase 0b**
> row is inserted below, and phases 3 and 4 lose #6 and #5 respectively until it
> closes. Phase 2 is unaffected.

| Phase | Content | Gate |
|---|---|---|
| **0** | **This document.** Pre-registration, reviewed and committed. | Nothing else starts until ADR-035 is committed |
| **1** | **Fixtures.** `config/policies/fault-injection.yaml`, `compose.fault.yaml`, `tests/security/test_fault_fixtures_are_not_production.py`, `scripts/seed_backdated_audit.py`. **Isolated verification first**: confirm against a running gateway that the 24-`x` marker produces `error_kind="timeout"` and the 22-`x` marker does **not**, before any alert is involved. Then full suite + `ruff` + `mypy` + `promtool check rules` + `promtool test rules`. | **Separate commit** |
| **2** | **Driver.** Extend `eval/runners/shadow.py`. Confirm achieved rate and fault fraction match the requested ones on a **60-second controlled dry run** before any timed condition. | **Separate commit** — the driver is measurement infrastructure and the fixtures are configuration; they land apart for the same reason R-104 and R-107 did |
| **3** | **#6 and #10 first, on a virgin Prometheus volume.** The last two untested R-104 newness clauses, and the only results a stale TSDB can invalidate. Then **#1**. | ~10 min |
| **4** | **Sustained alerts.** #8 and #5 (independent metrics, safe concurrently), then #16, #12, #2, #11, #14, #15. Restore and re-assert boundary invariants between conditions. | ~75 min |
| **5** | **Optional soak: #9.** Last, unattended. | ~3 h 20 m |
| **6** | **Runbook walk.** With each condition genuinely present, walk the corresponding entry and record exercised / worked / missing. **Interleaved with phase 4**, not batched — this is the only point at which the runbook is read against a genuinely broken stack. | — |
| **7** | **Evidence and ledgers.** Run report with transition timestamps; ADR-034 execution table; risk register (**R-108**, **R-109** filed with whichever outcome was observed); evidence ledger; `release-readiness.md`; ADR index. #7 recorded EXTERNALLY UNVERIFIED with its four dependencies; #9 recorded validated or deferred with its soak stated. | — |

### Amended order (Phase 0b)

| Phase | Content | Gate |
|---|---|---|
| **0** | Pre-registration. | **Done** |
| **1** | Fixtures + guard test + seed script. Isolated verification run; the detector-timeout half **failed and is recorded**, the overhead half and all of Fixture C **passed**. | **Ready for its own commit** |
| **0b** | **This amendment.** Reconcile the pre-registration with the measured evidence. | **No implementation.** Commit after review |
| **0c** | **Design a NEW deterministic detector-error seam for #5/#6.** | **A new deterministic detector-error seam must be designed, pre-registered, independently verified, and then implemented before #5/#6 execution.** Nothing about it is decided here — see the amendment |
| **2** | Driver (`eval/runners/shadow.py`). Unaffected by any of the above. | Separate commit |
| **3** | **#10 first, on a virgin Prometheus volume**, then **#1**. **#6 is removed from this phase** until 0c closes. | ~10 min |
| **4** | **#16, #12, #2, #11, #14, #15, #8.** **#5 is removed from this phase** until 0c closes. | ~75 min |
| **5–7** | Unchanged. | — |

## What Run 3 may not do

Inherited from ADR-034 §"What Phase 20 explicitly may not do", and extended:

* Change a detector threshold, enable the transformer, enable provenance overlays,
  or alter `config/policies/default.yaml`.
* Change **any** alert expression, threshold, label, severity or `for:` duration.
  An alert made easier to trigger is an alert that was not validated.
* Modify RC1 or move `v1.0.0-rc1`.
* Modify any production compose file or either Dockerfile.
* Synthesise Prometheus samples, backfill a TSDB, or hand-write a series.
* Read `eval/datasets/holdout/**`, or write anywhere under `eval/datasets/`.
* Retune a development-default limit on the strength of one synthetic run.

## Deliverables

* `config/policies/fault-injection.yaml`, `compose.fault.yaml`,
  `tests/security/test_fault_fixtures_are_not_production.py`,
  `scripts/seed_backdated_audit.py` — Fixtures B and C.
* An extended `eval/runners/shadow.py` — no new harness.
* `eval/results/shadow/<run-id>/report.md` — corpus checksums, machine metadata,
  per-alert transition timestamps, achieved-vs-requested fault fractions.
* Updates to `docs/20-risk-register.md`, `docs/22-evidence-and-claims.md`,
  `docs/runbook.md`, `docs/release-readiness.md`, ADR-034's execution table, and the
  ADR index — in phase 7, on evidence.

## Alternatives considered

| Alternative | Rejected because |
|---|---|
| **Trust `promtool test rules` and declare the alerts validated** | It was green on all 16 rules while three could not fire (R-104). It validates expressions against series its author wrote; every one of them starts at 0, which is the one thing a real labelled counter does not do. |
| **A test-only `fault.injector` detector in `app/detectors/`** | Puts test code in the production tree, mutates `_REGISTRY` (breaking the `registered_names()` freeze), and adds an environment variable that is itself a production risk. Larger blast radius than a policy file that production cannot mount. **OVERTURNED BY MEASUREMENT (Phase 0b):** this rejection assumed the policy-only route worked. It does not — see [Finding 3](#finding-3--5-and-6-are-reclassified-as-blocked). This is now the leading candidate for phase 0c and requires its own pre-registration; nothing is adopted here. |
| **`timeout_ms: 1` in a fault policy** | `gt=0` rejects 0, and the enabled detectors never await, so `wait_for` has no suspension point. Whether it fires is a scheduling race — non-deterministic, which disqualifies it for a pre-registered protocol. **Phase 0b: the reasoning was right and did not go far enough** — with no suspension point `wait_for` does not fire *at all*, at any budget, which is what Finding 1 measures. |
| **A 100 k-char payload to exhaust the detector budget** | Measured: ~13 ms at the `max_inspect_chars` cap against 250 ms. Cannot produce a timeout. |
| **`injection.transformer` with a bad `model_path`** | Fails at `warmup()`, so the process refuses to start. Produces no per-request error sample. |
| **Lower a threshold or shorten a `for:` to make an alert easier to fire** | Validates a rule that does not ship. |
| **Backfill Prometheus to reach `offset 1d` for #7** | Fabricated evidence, which is the one thing this project's evaluation discipline exists to prevent. |
| **A third load harness, or a duration mode inside `benchmark.py`** | ADR-034 already refused a second harness; `benchmark.py` backs published latency claims and must not gain load-generation code. |
| **Run everything against the development database volume** | Fixture C seeds and deletes audit rows. A disposable named volume costs one line and removes the risk entirely. |

## Consequences

### Positive

* The remaining eleven locally validatable alerts get **real-condition** evidence,
  which is the only kind that has ever found a defect in this rule set.
* The last two R-104 newness clauses (#6, #10) are exercised against genuinely
  lazily-created series — available once each, and not available at all after Run 3
  unless a fresh volume is used again.
* **R-107 is exercised** rather than merely unit-tested; #8's numerator gets its
  first real-traffic use.
* The runbook is walked against genuinely broken stacks instead of a healthy one.
* R-108 and R-109 are on the record **before** execution, so neither can be
  presented afterwards as a discovery.
* Nothing in the production configuration changes, so a green Run 3 says something
  about the shipped artefact rather than about a modified one.

### Negative / accepted costs

* **A ReDoS pattern enters the repository**, in a file named `fault-injection.yaml`
  with a header stating it must never be mounted by a production manifest, and
  behind a guard test. The alternative seams are measurably unavailable (§3), so the
  cost is accepted rather than avoided.
* **R-108 is exposed by using it.** The fixture demonstrates that an operator regex
  can stall the process. That is a property of shipped code and is recorded as a
  risk — but this document makes it publicly legible, which is a real cost.
* **#7 stays unvalidated**, and will until a deployment has two days of history.
* **#9 costs 3 h 20 m** or stays unvalidated. No shortcut preserves the registered
  threshold.
* **Fault fractions are capped at 10%** because of the event-loop stall, which
  bounds how aggressively the ratio alerts can be driven.
* **Run 3 narrows nothing about calibration.** R-67 and R-88 are untouched by every
  result it can produce.

### Revisit when

* A deployment accumulates ≥ 48 h of scraped history with real traffic — #7 becomes
  validatable, and the `offset 1d` thresholds become calibratable for the first time.
* `custom_patterns` gains startup validation (the fix R-108 implies) — Fixture B's
  seam closes and this ADR needs a successor seam, most likely the explicit
  test-only detector rejected above.
* Any alert expression, threshold or `for:` changes — the matrix in §6 is invalidated
  for that alert and its validation must be repeated.
* A real incident exercises an entry the phase-6 walk did not reach.

## Verification

This ADR is satisfied when, for **every** alert #1–#16, the Run 3 artefact contains
either:

* an observed transition, with the timestamps at which it entered `pending` and
  `firing`, the metric values that produced it, and the achieved fault fraction; or
* an explicit record of why the condition could not be produced, naming the
  dependency.

Additionally:

* `config/policies/default.yaml` and `deploy/alerts/firewall.rules.yaml` are
  **byte-identical** before and after Run 3.
* `tests/security/test_fault_fixtures_are_not_production.py` passes, and fails if
  the fault policy becomes reachable from a production manifest.
* The boundary invariants hold after every condition: blocked → 403 with upstream
  delta 0, benign → 200 with delta 1.
* No file under `eval/datasets/` is modified; no hold-out corpus is read.
* R-108 and R-109 appear in `docs/20-risk-register.md` with the outcome actually
  observed — including, for R-109, a refutation if that is what the depth series
  shows.

## Execution status

**RUN 3 NOT EXECUTED. NO ALERT HAS BEEN VALIDATED.** Phase 1 built the fixtures and
verified them in isolation; no Prometheus rule has been driven to `pending` or
`firing` by any of this work.

| # | Alert | Status |
|---|---|---|
| 1, 2, 8, 10, 11, 12, 14, 15, 16 | nine locally validatable | **PLANNED — not executed.** Fixtures built and verified in isolation |
| **5, 6** | detector-error alerts | **BLOCKED — no working seam.** Fixture B was measured and cannot emit `firewall_detector_errors_total`. Awaiting phase 0c |
| 3, 4, 13 | validated before Run 3 | Recorded in ADR-034 and the risk register; **not re-run** |
| 7 | `FirewallBlockRateStepChange` | **EXTERNALLY UNVERIFIED** — not attempted |
| 9 | `FirewallRetentionStalled` | **PLANNED, OPTIONAL** — ~3 h 20 m soak |

| Deliverable | Status |
|---|---|
| `config/policies/fault-injection.yaml` | **Built.** Marker cost confirmed on the real gateway |
| `compose.fault.yaml` | **Built.** Isolation and teardown confirmed |
| `tests/security/test_fault_fixtures_are_not_production.py` | **Built.** 21 tests, four negative controls |
| `scripts/seed_backdated_audit.py` | **Built.** Refusals and the #11 numerator confirmed |
| `eval/runners/shadow.py` extension | **Not started** (phase 2) |
| Detector-error seam for #5/#6 | **Not designed** (phase 0c) |

---

## Amendment — 2026-08-22: Phase 1 measured evidence

**Status of this amendment:** Phase 0b. It reconciles the pre-registration above
with what Phase 1 actually measured. **It implements nothing, designs no
replacement seam, and validates no alert.**

Everything above is left as written. A pre-registration that is quietly edited to
match its outcome is not a pre-registration, and the value of this record is
precisely that one of its expectations can be seen to have been wrong.

### What Phase 1 did

Built the four registered fixtures and ran §10's phase-1 gate: *"confirm against a
running gateway that the 24-`x` marker produces `error_kind="timeout"` and the
22-`x` marker does not, before any alert is involved."*

**That gate failed on its first half — which is the gate working.** It was placed
there to catch exactly this class of error before a validation run depended on it.

No Prometheus rule was driven. No alert reached `pending` or `firing`. Nothing
below is alert validation.

### Finding 1 — R-108 is a MEASURED finding, and it is worse than registered

§3 registered R-108 as *"`asyncio.wait_for` cannot preempt a CPU-bound synchronous
regex… the timeout is only recorded once control returns"*. The first clause is
right. **The second is wrong.**

Measured through the real gateway (`compose.yaml` + `compose.fault.yaml`, host
`:8006`), the fault policy bind-mounted, `input.pii.timeout_ms = 100`:

| Payload | HTTP | Latency | `firewall_detector_errors_total` |
|---|---|---|---|
| ordinary text | 200 | 39 ms | absent |
| 22 × `x` + `z` | 200 | 312 ms | absent — *as registered* |
| 24 × `x` + `z` | **200** | **1201 ms** | **absent — a timeout was expected** |
| 24 × `x` + `z`, five more | 200 ×5 | 818–899 ms | **still absent** |

After eight marker requests:

```
firewall_detector_latency_seconds_count{detector="pii.regex",direction="input"} 8.0
firewall_detector_latency_seconds_sum  {detector="pii.regex",direction="input"} 5.646605
firewall_detector_errors_total                                                 (absent)
```

Eight runs, **5.65 s of work, recorded as eight successes** against a 100 ms budget.

The mechanism, isolated from the application so the finding does not rest on
inference:

```
wait_for(coroutine doing 705 ms of synchronous regex, timeout=0.100)
    -> RETURNED NORMALLY after 705 ms. No TimeoutError. No error_kind.

wait_for(asyncio.sleep(1.0), timeout=0.100)
    -> TimeoutError after 100 ms. The guard works when the coroutine yields.
```

**Corrected statement of R-108.** For a detector whose `detect()` performs CPU work
without awaiting — which is **all three enabled detectors**, every one a
`BaseDetector` rather than a `SyncDetectorAdapter` — `timeout_ms`:

* does **not** bound the work;
* does **not** cancel it;
* does **not report that the budget was exceeded**.

The overrun is invisible in every metric except latency, and `GuardedDetector`'s
`on_error` semantics never engage, so a fail-closed detector does **not** fail
closed on a budget overrun. It is a latency event, not a fault event. `timeout_ms`
is a control only for detectors that suspend.

This is now **measured**, not observed-by-inspection. It is to be filed as **R-108**
in phase 7 with this evidence. **No fix is proposed here** — remedies touch
production code (`SyncDetectorAdapter` for the regex detectors, or startup
validation of `custom_patterns`, or both) and each needs its own decision record.

### Finding 2 — §5's #16 estimate was wrong; the corrected figure is measured

§5 predicted #16's overhead would *"roughly double"* because the mock echoes
`text[:200]` and `pii.regex` would rescan the marker on output.

**It does not.** The marker is declared under `input.pii.options.custom_patterns`
only; the `output.pii` block carries no `custom_patterns` at all. Measured over the
same eight requests:

```
firewall_detector_latency_seconds_sum{detector="pii.regex",direction="output"} 0.000124
```

124 microseconds total on the output path. The marker is scanned **once, on input**.

The registered success condition for #16 — `p95 > 100 ms` — is unaffected, and the
measured marker costs (~312 ms and ~1201 ms end to end) clear it with margin.

**#16 is NOT validated.** These are fixture measurements. Validation requires the
real rule to transition `pending` → `firing` over a 15-minute hold, which has not
been attempted.

### Finding 3 — #5 and #6 are reclassified as BLOCKED

Fixture B's policy-only custom-regex seam **cannot** validate
`FirewallDetectorErrorRateHigh` (#5) or `FirewallDetectorErrorsPresent` (#6),
because it produces no `firewall_detector_errors_total` sample at any fault
fraction. §5's `f/(2−f)` derivation is void along with its premise.

Both alerts remain **outstanding and locally validatable in principle**. What is
missing is a mechanism, not an opportunity.

**Registered requirement, and the gate on #5/#6:**

> **A new deterministic detector-error seam must be designed, pre-registered,
> independently verified, and then implemented before #5/#6 execution.**

> **Resolved by the Phase 0c amendment below.** The seam selected there is *not*
> the test-only detector anticipated in this paragraph — that candidate was
> re-examined and rejected as not implementable without production code changes.
> See [Amendment — Phase 0c](#amendment--2026-08-22-phase-0c-the-replacement-detector-error-seam).

Recorded as **phase 0c**. The leading candidate is a **test-only / fault-only
detector seam** — the alternative §"Alternatives considered" rejected on the
grounds that the policy-only route was available, which measurement has now
removed. **This amendment does not adopt it.** Nothing is committed to until a
successor pre-registration records:

* the exact seam and where its code lives;
* how it is made impossible to activate in a default or production configuration,
  and which test attacks that boundary;
* what it does to `registered_names()` and the existing registry-freeze tests;
* how a *single* error and a *sustained* error rate are each produced
  deterministically;
* independent verification that the error reaches
  `firewall_detector_errors_total` with the expected `detector` and `error_kind`
  labels, **before** any alert depends on it — the same gate that caught this.

Until that exists, **#6 leaves phase 3 and #5 leaves phase 4**. Neither is to be
attempted, and neither may be recorded as anything but blocked.

One consequence worth stating plainly: #6 is one of the two remaining R-104
newness clauses, and each is exercisable **once per virgin Prometheus TSDB**. The
delay costs nothing as long as the eventual run starts from a renewed volume.

### Finding 4 — the fault policy would have shipped in the production image

`deploy/docker/Dockerfile` contains:

```
COPY --chown=root:root config ./config
```

Unfiltered. Creating `config/policies/fault-injection.yaml` at the registered path
therefore places the fault policy **inside the production image**, leaving
production one `FIREWALL_POLICY_FILE` away from loading a policy whose purpose is
to stall a detector. §3's claim that production "cannot mount it" would have
degraded to "production has not set one environment variable".

**Control, and it is required, not optional:** the file is excluded from the build
context in `.dockerignore`, and `compose.fault.yaml` bind-mounts it at runtime
instead. The fixture is therefore opt-in **at the mount**, which no production
manifest can supply, rather than at a setting, which anything can.

Verified by building the image and listing the directory:

```
/app/config/policies/  ->  benchmark-passthrough.yaml, default.yaml
fault-injection.yaml   ->  ABSENT
```

**The Dockerfile is not modified**, and the production image is unchanged relative
to RC1, where the file did not exist. `.dockerignore` is a build-context control,
not a build instruction. The exclusion is asserted in both directions by
`tests/security/test_fault_fixtures_are_not_production.py`: the fault policy must
be excluded, and the exclusion must be surgical enough that `default.yaml` still
ships — a broader pattern would take the real policy out of the image and the
gateway would fail to start.

### Finding 5 — the fault stack's first retention sweep fails for the wrong reason

`RetentionScheduler` sweeps at startup. In the fault stack the container starts
before `alembic upgrade head` runs, so the first sweep finds no `request_traces`
table and fails. Observed:

```
firewall_retention_sweeps_total{outcome="failed"}  1.0
firewall_retention_sweeps_total{outcome="success"} 4.0
```

This is a **migration-ordering artefact of the fixture**, not the condition #10
describes.

**Registered for Run 3:** #10 `FirewallRetentionSweepsFailing` **must not** count
the startup sweep. Its validation begins from a **clean post-migration baseline** —
migrations applied, at least one sweep recorded `outcome="success"`, and the
counter's state noted — and only then is PostgreSQL deliberately stopped so
subsequent sweeps fail for the registered reason.

This matters more than it looks. #10 carries an R-104 newness clause, and that
clause tests whether a series that *did not exist one window ago* is caught. A
startup failure creates the series early and for an unrelated reason, which would
make a subsequent pass meaningless — the same shape of self-invalidation as a
stale TSDB (§9).

### Confirmed as registered — Fixture C and the disposable database

Measured, and unchanged by this amendment:

| Property | Evidence |
|---|---|
| Fault PostgreSQL uses its own volume | `llm-firewall-fault-postgres-1 -> firewall-fault-pgdata` |
| Development volume untouched | `llm-firewall-postgres-1 -> llm-firewall_postgres-data` |
| Teardown removes **only** the fault volume | after `down -v`: `firewall-fault-pgdata` removed, `llm-firewall_postgres-data` present, dev stack still running, dev `request_traces` **49,662 → 49,662** |
| Seed script refuses production | `FIREWALL_ENVIRONMENT=production` → refused, exit 2, even with `--execute` and a valid fault URL |
| Seed script refuses the development database | target `firewall` → refused, exit 2 |
| `--execute` is required | default invocation left the row count unchanged at 8 |
| #11's numerator is producible | after seeding, `firewall_audit_oldest_row_age_seconds{table="request_traces"}` reached **864099.65 s (10.00 days)** against a 129600 s bound, with the one-row sweep budget preserving the backlog |

The last row is a **fixture** measurement. #11 is not validated.

### What did not change

No application code, no `services/`, no alert rule, no threshold, no `for:`
duration, no label, no severity, no `config/policies/default.yaml`, no production
compose file, no Dockerfile, no `eval/runners/shadow.py`, no dataset, no evaluation
artefact, no ADR-034, no ledger, and not the RC1 tag. `deploy/alerts/*.yaml` and
`config/policies/default.yaml` are byte-identical to `HEAD`.

### Consequences of this amendment

**Positive.** The phase-1 gate did its job: a design error was caught by a
ten-minute isolated check instead of by a 75-minute validation run producing a
silently empty result. R-108 is upgraded from an inspection-time concern to a
measured property of shipped code, with a reproduction that does not depend on the
fixture. Nine of the eleven locally validatable alerts are unaffected, and Fixture
C is confirmed in every registered respect.

**Negative / accepted.** Two alerts are blocked on work not yet designed, and the
seam that unblocks them is the one this ADR rejected — so the rejection was wrong,
and the "Alternatives considered" entry for a test-only detector should be read as
overturned by evidence rather than as still standing. Run 3 now needs an extra
pre-registration cycle before it can be complete, and phase 1's own success
criteria are partly unmet, which is recorded rather than rounded up.

**Revisit when.** Phase 0c produces a verified detector-error seam — at which point
#5 and #6 rejoin phases 4 and 3 respectively, on a virgin TSDB. Or R-108 is fixed
in production code, which would change what a detector budget overrun *does* and
therefore what #5 and #6 are actually detecting; that fix needs its own ADR and
would invalidate the amended rows above.

---

## Amendment — 2026-08-22: Phase 0c, the replacement detector-error seam

**Status of this amendment:** Phase 0c pre-registration. **Nothing is implemented.**
No file named below has been created or modified by this amendment, no alert has
been attempted, and #5 and #6 remain blocked until the implementation and its
guard tests land.

Phase 0b left one thing open: *"A new deterministic detector-error seam must be
designed, pre-registered, independently verified, and then implemented before
#5/#6 execution."* This is that design. The seam has been **verified in isolation
before being written down**, because the Phase 1 failure was caused by
pre-registering an unverified mechanism.

### Why a search was necessary, and what it found

The registered seam failed for a specific reason: `GuardedDetector` records a
**timeout** only when `asyncio.wait_for` raises, and `wait_for` raises only if the
wrapped coroutine **suspends**. All three enabled detectors are `BaseDetector`
implementations whose `detect()` never awaits.

So the replacement cannot be another timeout. It must make `detect()` **raise**,
which `GuardedDetector` catches as `except Exception` and records as
`error_kind=type(exc).__name__`. `BaseDetector`'s own docstring contemplates
exactly this: *"genuine failures may raise and will be captured by
GuardedDetector."*

An inventory of every `raise` reachable inside `app/detectors/` found **four, all
of them `ConfigurationError`, all at startup** — three in
`TransformerInjectionDetector.warmup()` and one in `registry.create()`. **There is
no per-request raise site in any shipped detector.** That eliminates the "existing
per-request configuration failure path" candidate outright, by inspection rather
than by preference.

The seam therefore has to come from *data* that makes shipped code raise.

### Candidates evaluated

| # | Candidate | Verdict |
|---|---|---|
| 1 | **Test-only detector registered outside the production registry** | **Rejected — not implementable without production code changes.** `DetectorPipeline.from_policy` builds detectors solely through `registry.create()`, and `_REGISTRY` is a hard-coded module dict in `app/detectors/registry.py`. A detector reachable by a container must live inside the image, i.e. in `app/`; `tests/` is excluded from the build context. Registering one would also break the `set(registered_names()) <= {...}` subset assertions in five evaluation tests. Adding a registration hook is itself a production code change. Kept as the fallback **only** if the selected seam is invalidated |
| 2 | **An existing per-request configuration failure path** | **Rejected — none exists.** Every `raise` inside `app/detectors/` is a `ConfigurationError` at startup: three in `TransformerInjectionDetector.warmup()`, one in `registry.create()`. Established by inspecting all four sites, not by sampling |
| 3 | **An existing test fixture / adapter seam** | **Rejected for this purpose.** `tests/unit/test_guarded_detector.py`, `test_pipeline.py` and `test_slice_invariants.py` do define failing detector doubles, but they are test-local classes injected in-process. They cannot reach a containerised gateway that Prometheus scrapes, so they exercise the accounting path without producing a scrapeable sample |
| 4a | **`injection.transformer` with a broken checkpoint** | **Rejected.** Fails in `warmup()` — a startup failure, not a per-request one — and needs the `ml` extra, which is not installed in the image |
| 4b | **An unknown entity name in `options.entities`** | **Rejected.** `_resolve_rules` silently skips unknown labels (`if rule is not None`). No error at any time |
| 4c | **A `custom_patterns` regex that raises at match time** | **Rejected — depends on CPU/recursion limits**, i.e. exactly the timing-and-starvation class this seam must avoid, and it is the disproven approach in another costume |
| 4d | **Convert `pii.regex` to `SyncDetectorAdapter` so `wait_for` can fire** | **Rejected as a seam, retained as a finding.** It would work — `SyncDetectorAdapter.detect()` awaits a thread offload, so the timeout raises and *is* reported — but it is production runtime code and is arguably the fix for R-108. Changing production behaviour to make a test possible inverts the relationship. Recorded here because it is the most likely eventual remedy and it belongs in R-108's own decision record |
| **5** | **Out-of-range `custom_patterns[].confidence`** | **SELECTED.** Per-request, content-selected, deterministic, cheap, policy-only, and it exercises the real error-accounting path end to end |

### The selected seam

**A second `custom_patterns` entry on `input.pii` whose `confidence` is outside
the range `DetectionResult.score` permits.**

```yaml
      custom_patterns:
        - name: FAULT_DETECTOR_ERROR
          pattern: "FAULT-DETECTOR-ERROR-3f9a1c"   # a literal, not a backtracking regex
          confidence: 2.0                          # DetectionResult bounds score to [0.0, 1.0]
```

The chain, entirely in shipped code:

1. `RegexPiiDetector._resolve_rules` reads `float(custom.get("confidence", 0.85))`
   and **applies no bound**. `2.0` compiles and builds cleanly, so **startup is
   unaffected** — the failure is per request, which is what #5 and #6 need.
2. On a request **without** the marker, `finditer` finds nothing, `found` is empty,
   and `detect()` returns `score=0.0` normally. Ordinary traffic is untouched.
3. On a request **with** the marker, `_find` yields one span at confidence `2.0`,
   and `detect()` builds its result with
   `score=max(confidence for _, confidence in found)` → `2.0`.
4. `DetectionResult.score` is declared `Field(ge=0.0, le=1.0)`, so pydantic raises
   **`ValidationError` inside `detect()`**.
5. `GuardedDetector.detect`'s `except Exception` catches it, logs `detector_failed`,
   and returns `_failure(ctx, "ValidationError", started)` — `errored=True`,
   `error_kind="ValidationError"`, `reasons=("detector_error:ValidationError",)`.
6. `record_trace` → `record_detector(errored=True, error_kind="ValidationError")` →
   **`firewall_detector_errors_total{detector="pii.regex",error_kind="ValidationError"}`**,
   and the latency histogram is observed as well, so #5's ratio has both terms.
7. `input.pii` is `on_error: fail_closed`, so the policy engine converts the failure
   into a refusal — **HTTP 503 `detector_failure`**, and the upstream is never
   called.

This is the **real** error-accounting path, not a metric written by hand.

### Independent verification, performed before this was written down

Through the shipped `registry.create("pii.regex", …)` and the shipped
`GuardedDetector`, on the reference machine, 2026-08-22:

```
no marker : errored=False error_kind=None       detected=False
marker    : errored=True  error_kind='ValidationError' detected=False
            reasons=('detector_error:ValidationError',)

determinism: marker errored 50/50 ; clean errored 0/50

SHIPPED default policy + marker  : errored=False detected=False   <- inert
in-range confidence 0.9 + marker : errored=False detected=True score=0.9  <- no fault
```

The last two lines are the controls that matter. The marker is **inert under the
policy that ships**, and an **in-range** confidence with the same marker produces an
ordinary detection — so the fault comes from the out-of-range value, not from the
marker string.

**This is verification of the seam, not of an alert.** No Prometheus rule has been
driven.

### Why it is deterministic

It is a **content match on a literal string**. There is no timing, no scheduler
interaction, no CPU starvation, no race, and no dependence on load. The same input
produces the same outcome on every request and on every machine: 50/50 and 0/50
above, with no intermediate case possible — either the literal is present and
`score=2.0` is constructed, or it is absent and nothing happens.

It is also **cheap**, which the disproven seam was not. A literal pattern costs
microseconds, so the fault does not stall the event loop and cannot contaminate
co-resident measurements the way R-108's backtracking does. The measured
per-request cost of **74.4 ms** in the verification harness is **not representative**:
that harness ran under structlog's default console renderer, which formats a rich
traceback. The application configures `format_exc_info` + `JSONRenderer`
(`app/observability/logging.py`), which is far cheaper. **The real per-request cost
is to be measured during implementation, not assumed.**

### Expected labels and evidence

| | Expected |
|---|---|
| Metric | `firewall_detector_errors_total` |
| `detector` label | `pii.regex` |
| `error_kind` label | `ValidationError` |
| Denominator for #5 | `firewall_detector_latency_seconds_count{detector="pii.regex"}`, summed across both directions |
| HTTP status | **503**, body code `detector_failure` |
| Upstream calls | **0** for a faulted request — `on_error: fail_closed` refuses before the upstream call |
| `reasons` on the result | `("detector_error:ValidationError",)` |

### How #6 is triggered

`FirewallDetectorErrorsPresent` has **no `for:`** and carries an R-104 newness
clause. One single request containing the marker, on a **virgin Prometheus TSDB**,
creates `firewall_detector_errors_total{detector="pii.regex",error_kind="ValidationError"}`
at `1` where no series existed. `increase()` over that flat series is 0 — which is
the whole point — and the second clause (`> 0 unless … offset 30m`) is what must
match. The alert should reach `firing` within about two evaluation intervals.

**#6 needs no driver.** One `curl` is sufficient, so #6 is unblocked by this seam
alone and does **not** wait for Phase 2.

**One shot per virgin volume.** `--renew-anon-volumes` before the attempt is
mandatory, exactly as §4 requires.

### How #5 is sustained

`FirewallDetectorErrorRateHigh` needs
`errors / latency_count > 0.01` held for **10 minutes**, so it needs the Phase 2
driver: `--fault-marker detector-error --fault-fraction 0.05` at 5 req/s for ~12
minutes.

**§5's `f/(2−f)` derivation is reinstated.** Phase 0b voided it because its
*premise* — that the marker produces a detector error — was false. With this seam
the premise holds and the arithmetic is unchanged: a faulted request runs
`pii.regex` once (input only, because fail-closed refuses before output
inspection), a clean request runs it twice, so `errors = f` and
`runs = f + 2(1−f) = 2 − f`. At `f = 0.05` the ratio is **≈ 0.026**, a **2.6×**
margin over the 1% threshold, cleared at any `f > 0.0198`.

**#5 therefore remains blocked until Phase 2 lands**, for a scheduling reason
rather than a design one.

### Why it cannot activate in production

Four independent locks, the first three inherited from Fixture B and already
enforced:

1. **The file is in no image layer.** `config/policies/fault-injection.yaml` is
   excluded from the build context; verified by listing the built image.
2. **Only `compose.fault.yaml` mounts it**, and no production manifest or CI job
   references either the overlay or the policy.
3. **`config/policies/default.yaml` declares `custom_patterns: []`**, and the guard
   test fails if any production-reachable policy grows a non-empty one.
4. **New:** a guard test must additionally assert that **no production-reachable
   policy declares a `confidence` outside `[0.0, 1.0]`** — the specific value this
   seam depends on, checked directly rather than implied by lock 3.

Activation requires the mounted fault policy **and** the literal marker in the
request body. Neither is reachable from a production deployment.

### A production risk this seam exposes — to be filed as R-110

`custom_patterns[].confidence` is read as `float(...)` and **never bounded**, while
`DetectionResult.score` is bounded to `[0.0, 1.0]`. An operator who writes
`confidence: 95` intending `0.95` gets a policy that **starts cleanly** and then
returns **503 on every request that matches that pattern**, with `pii.regex` on
`fail_closed`. The failure is silent until traffic hits it, and it is a
configuration typo away.

This is the same shape as R-108: a validation gap in the `custom_patterns` seam
that `app/detectors/pii/regex.py` already flags as *"Startup validation of custom
patterns is tracked as future work."* It is a property of shipped code, found while
searching for a seam, and it is **to be filed as R-110 in phase 7**. **No fix is
proposed here** — it is production runtime code and needs its own decision record.

The tension is worth stating plainly: **this seam works because of a defect, and
fixing the defect closes the seam.** That is recorded below as the evidence that
would invalidate it, so nobody is surprised later.

### Required guard tests

To be added to `tests/security/test_fault_fixtures_are_not_production.py`:

* no production-reachable policy declares any `custom_patterns` **confidence**
  outside `[0.0, 1.0]`;
* the fault policy declares **exactly two** markers, and the error marker is a
  literal with no regex metacharacters — so it cannot become a second, accidental
  backtracking fault;
* the two markers do not match each other's payloads;
* the existing equality test is extended so the fault policy still differs from
  `default.yaml` by the `custom_patterns` key **and nothing else**.

### Required negative controls

Each must be shown to **fail** when the property is broken, per the discipline the
Phase 1 guard test already follows:

1. **In-range confidence** (`0.9`) with the marker → ordinary detection, `errored=False`.
   *Already demonstrated above.*
2. **Marker under the shipped default policy** → inert.
   *Already demonstrated above.*
3. **Clean traffic under the fault policy** → `errored=False`, and the error series
   stays absent.
4. **The overhead marker (`x`-run) must not produce a `ValidationError`**, and the
   error marker must not produce measurable backtracking latency — the two faults
   must stay separable, or #16 and #5 contaminate each other.
5. **No request content in logs.** `GuardedDetector` calls `logger.exception` with
   `ctx` in scope. The shipped configuration is `format_exc_info` + `JSONRenderer`,
   which emits a traceback string without locals — but this is a **new code path
   reaching that call**, so it must be asserted, not assumed, against the container's
   JSON output. If any part of `raw_text` appears, the seam is **withdrawn**.

### Expected metric and HTTP evidence

```
POST /v1/chat/completions  with the marker   -> 503, code "detector_failure"
POST /v1/chat/completions  without it        -> 200

firewall_detector_errors_total{detector="pii.regex",error_kind="ValidationError"}  N
firewall_detector_latency_seconds_count{detector="pii.regex",direction="input"}    >= N
mock upstream __stats delta for faulted requests                                    0
```

### Restoration procedure

The seam is stateless — no process state, no database state, no counter to reset.
Restoration is: stop sending the marker. To remove it entirely,
`docker compose -f compose.yaml -f compose.fault.yaml down -v` and bring the stack
up without the overlay. The development stack is unaffected throughout, on its own
project and its own volume.

Between conditions, the boundary invariants are re-asserted as §4 already requires:
blocked → 403 with upstream delta 0, benign → 200 with delta 1.

### Failure modes, pre-registered

* **The marker leaks into non-fault traffic.** The literal is deliberately
  distinctive; if a corpus sample contained it, the achieved fault fraction would
  exceed the requested one. The driver reports achieved counts, so this shows up as
  a discrepancy rather than as a quietly wrong denominator.
* **`ValidationError` is the wrong `error_kind` to expect.** If pydantic's exception
  type or name changes, the label changes with it. The label is read from the
  metric, never assumed, and the guard test asserts what is actually emitted.
* **The 503 changes the denominator.** A faulted request is refused before the
  upstream call and before output inspection, so it contributes one detector run
  rather than two. That is why the ratio is `f/(2−f)` and not `f`; a run that
  assumed `f` would report a margin 2× too large.
* **Logging cost at sustained rates.** Every faulted request formats a traceback.
  At `f = 0.05` and 5 req/s that is one every four seconds and immaterial, but the
  cost must be measured rather than assumed — the 74.4 ms figure above is a harness
  artefact, not a prediction.
* **A green #5 or #6 still proves the rule, not the threshold.** Unchanged from §9.

### What evidence would invalidate this seam

* **`custom_patterns[].confidence` gains validation** — at policy load, at detector
  build, or by clamping in `_resolve_rules`. This is the correct fix for R-110, it
  should happen, and it **closes this seam**. A successor pre-registration would
  then be required, and the leading candidate reverts to a test-only detector.
* **`DetectionResult.score` loses its `le=1.0` bound**, which would also silently
  weaken a real invariant.
* **The marker fails to produce `errored=True` through the containerised gateway**,
  as opposed to the in-process verification above.
* **Any request content appears in the logs** when the seam fires.

### Exact files that would change during Phase 0c implementation

| File | Change |
|---|---|
| `config/policies/fault-injection.yaml` | **Modify** — add the second `custom_patterns` entry. The `(x+x+)+y` overhead marker stays; the two are independent |
| `tests/security/test_fault_fixtures_are_not_production.py` | **Modify** — the four guard tests above, plus updating the existing equality assertion for two markers |
| `tests/unit/test_detector_error_seam.py` | **New** — the verification above, committed so it is permanent rather than a one-off: marker → `error_kind="ValidationError"`, clean → no error, in-range confidence → no error, default policy → inert |
| `docs/adr/ADR-035-…md` | **This amendment** |

`eval/runners/shadow.py` gains a `detector-error` marker **in Phase 2**, not here.

### Files that must remain untouched

`app/**` (in particular `app/detectors/pii/regex.py`, `app/detectors/guarded.py`,
`app/detectors/registry.py`, `app/core/types.py`, `app/observability/metrics.py`),
`services/**`, `deploy/alerts/**`, `config/policies/default.yaml`, `compose.yaml`,
`compose.prod.yaml`, `compose.prod-selftest.yaml`, `compose.edge.yaml`,
`compose.tls.yaml`, `compose.observability.yaml`, every Dockerfile,
`eval/datasets/**`, `eval/results/**`, `eval/runners/shadow.py`, ADR-034, the four
phase-7 ledgers, and the `v1.0.0-rc1` tag.

**No production runtime code changes.** The seam is configuration plus request
content, exercising shipped code paths unmodified.

### Amended status of #5 and #6

| # | Status after Phase 0c |
|---|---|
| 6 | **Unblocked by design; awaiting implementation.** Needs one marker request on a virgin TSDB. Does **not** depend on Phase 2 |
| 5 | **Unblocked by design; awaiting implementation and Phase 2.** Needs a sustained 5% fault fraction for a 10-minute hold |

Neither is validated. Neither may be recorded as anything but blocked until the
implementation, its guard tests and its negative controls are complete, and the
real Prometheus rule has transitioned.

### Implementation record — 2026-08-22 (phase 0c executed)

**Additive.** Nothing above is rewritten. This records what the implementation
measured against what it registered. **No alert was driven and Run 3 was not
executed.**

**Every registered expectation was met.** No contradiction was found, so no
further amendment is required.

#### Through the containerised gateway (`compose.yaml` + `compose.fault.yaml`, host `:8006`)

| Registered | Observed |
|---|---|
| HTTP **503**, code `detector_failure` | **503**, `"type":"detector_failure"`, `"decision":"block"` |
| Upstream calls for a faulted request: **0** | **0** — 10 marker requests, upstream delta 0 |
| `firewall_detector_errors_total{detector="pii.regex",error_kind="ValidationError"}` | **exactly that series**, absent before the first marker request, `1.0` after it |
| Denominator present | `firewall_detector_latency_seconds_count{detector="pii.regex",…}` observed for errored runs too |
| Clean request unaffected | **200**, upstream delta 1 |
| Deterministic | **10/10 marker → 503 + 10 errors; 10/10 clean → 200 + 0 errors** |

#### Negative controls, all four as registered

1. **In-range confidence (0.9), same marker** → `errored=False, detected=True, score=0.9`.
   The fault comes from the value, not the string.
2. **Marker under the shipped policy** → the *development* stack (`default.yaml`)
   answered **200** and its `firewall_detector_errors_total` stayed **absent**.
   Inert in production, demonstrated against a second running stack rather than
   argued.
3. **Clean traffic under the fault policy** → no error, series unchanged.
4. **Marker separability** → 5 requests carrying the `(x+x+)+y` latency marker
   added **0** detector errors. The two faults do not contaminate each other.

Three fixture-level negative controls were also run against the guard tests and
each failed loudly as intended: an out-of-range confidence on the *latency* marker
(3 failures), an out-of-range confidence in `default.yaml` (6 failures), and
bounding the seam's confidence to simulate the R-110 fix landing (5 failures,
including `test_the_seam_still_depends_on_an_unbounded_confidence`, which is the
registered invalidating evidence made executable).

#### Log safety — the control that could have withdrawn the seam

A faulted request carrying a unique canary phrase produced, across the whole
container log:

```
canary occurrences        : 0
marker occurrences        : 0
prompt-phrase occurrences : 0
```

The `detector_failed` record is JSON with keys
`detector, direction, error_kind, event, exception, level, request_id, timestamp`
— no content key — and its `exception` field is a 20-line
`traceback.format_exception` string containing **no locals and no `raw_text`**.
`app/observability/logging.py`'s `format_exc_info` + `JSONRenderer` chain behaves
as `GuardedDetector`'s docstring claims. **The seam is not withdrawn.**

#### `f/(2−f)` confirmed empirically

The reinstated derivation was measured rather than trusted. Final counter state
after the container run:

```
errors 12 · pii.regex input runs 28 · output runs 16  ->  12/44 = 0.2727
f = 12/28 = 0.4286   ->   f/(2-f) = 0.2727            ->  exact match
```

A faulted request runs `pii.regex` once and a clean one twice, exactly as
registered. #5's planned `f = 0.05` therefore predicts **0.0256**, a 2.6× margin.

#### The cost the pre-registration left open

Registered as *"to be measured during implementation, not assumed"*, against a
74.4 ms harness artefact. Measured under the application's own logging
configuration:

| | p50 | mean |
|---|---|---|
| Faulted request | **0.182 ms** | 0.186 ms |
| Clean request | 0.010 ms | — |

**400× cheaper than the harness figure**, which is why the pre-registration
refused to quote it. At #5's planned 5 req/s × 5% the logging cost is immaterial,
and unlike the disproven seam this fault does not stall the event loop at all.

#### Production isolation, re-verified after the fixture grew

The production image was rebuilt and inspected:

```
/app/config/policies/  ->  benchmark-passthrough.yaml, default.yaml
fault-injection.yaml   ->  ABSENT
"FAULT-DETECTOR-ERROR" anywhere under /app  ->  ABSENT
```

The marker string exists in no image layer, not merely in no loaded policy.

#### Restoration

`down -v` removed `firewall-fault-pgdata` and nothing else. The development stack
kept all five containers and its `request_traces` count was unchanged at
**49,663 → 49,663**. The seam is stateless: no counter to reset, no process state,
no database state.

#### Files changed

| File | Change |
|---|---|
| `config/policies/fault-injection.yaml` | Second `custom_patterns` entry. Still differs from `default.yaml` by that one key and nothing else |
| `tests/unit/test_detector_error_seam.py` | **New**, 11 tests |
| `tests/security/test_fault_fixtures_are_not_production.py` | 21 → 28 tests: confidence-range guards, marker separability, literal-marker check |
| `docs/adr/ADR-035-…md` | This record |

No production runtime code, no alert rule, no `default.yaml`, no Dockerfile, no
production compose file, no dataset. `eval/runners/shadow.py` untouched — the
`detector-error` marker reaches it in phase 2.

#### Status of #5 and #6 after this implementation

| # | Status |
|---|---|
| 6 | **Seam implemented and verified. NOT VALIDATED.** Needs one marker request on a virgin Prometheus TSDB and a real `firing` transition. Requires no driver, so it is ready the moment Run 3 phase 3 begins |
| 5 | **Seam implemented and verified. NOT VALIDATED.** Blocked on phase 2 for a sustained 5% fault fraction over a 10-minute hold |

The metric now exists and increments deterministically through the real stack.
**That is the mechanism working, not the alert firing.** Neither alert may be
recorded as validated until Prometheus transitions the registered rule.
