# ADR-029 — The audit write moves off the request path

**Status:** Accepted · **Date:** 2026-08-19 · **Resolves:** [OD-42](../21-open-decisions.md)
**Fulfils:** [ADR-012](ADR-012-persistence-and-retention.md) — "Writes move off the request path in Phase 5"
**Justified by:** [Phase 15 benchmark](../../eval/results/performance/)

---

## Context

OD-42 was framed as an open question. It was not quite one: **ADR-012 had already
decided this in Phase 0**, including the queue, the drop-on-full behaviour and
the metric name, and it registered the evidence that would justify building it:

> **Revisit when** […] Phase 4 measurements show synchronous writes are a
> material share of gateway overhead (accelerate the Phase 5 queue).

Phase 15 supplied that measurement. On the reference machine the synchronous
audit write costs **10.5 ms p50 / 14.4 ms p95**, against **1.7 ms p50** for the
entire rest of the gateway span — roughly **86 % of what a caller waits for** on
a small request. ADR-012's trigger has fired on its own terms.

So the work here was not to invent a design. It was to build the registered one
and subject it to the question ADR-012 could not answer in advance: **what should
happen when the queue cannot keep up?**

## The experiment

Three modes were implemented and measured against the same gateway, the same
payloads and the same mock upstream.

| | `sync` | `queue_drop` | `queue_block` |
|---|---|---|---|
| Client latency, 265 B, c=1, p50 | 22.19 ms | **13.34 ms** | 8.80 ms † |
| Healthy database, 500 requests | 500/500 written | **500/500 written** | — |
| Graceful shutdown, 300 requests | 300/300 | **300/300** | — |
| **SIGKILL after 300 requests** | **300/300** | **49/300** | — |
| **Stalled database, 120 requests** | served; records lost; latency paid per request | **served; 11 written, 109 dropped and counted** | **120 read timeouts — total outage** |

† Not a real advantage. Until the queue fills, drop and block are the same code
path; the difference is run-to-run noise, which Phase 15 measured at ±4–11 %.

## Decision

**Adopt the bounded queue with drop-on-full, exactly as ADR-012 registered it.**
It is the configuration of the reference production deployment
(`compose.prod.yaml`). The code default remains `sync`, so no existing
deployment changes behaviour by upgrading.

### Blocking was implemented, measured, and removed

Phase 15's closing note proposed blocking on a full queue "so saturation degrades
to today's behaviour rather than to silent data loss". **That was wrong, and the
experiment is what showed it.**

It does not degrade to today's behaviour. Synchronous writes against a stalled
database *fail*: the error is caught, logged, and the request proceeds
(`require_audit=false`). A blocking queue has nothing to fail against — it waits
for space that a stalled writer will never free. All 120 requests became read
timeouts. Blocking converts a database stall into a total gateway outage, which
is the same failure ADR-012 rejected an unbounded queue for, in a different
shape.

The mode has been deleted rather than left selectable. A configuration measured
to turn a degraded dependency into an outage is not an option to offer with a
warning.

### Drop dominates sync during an outage

This is the result that decides it. With a stalled database:

* `sync` loses the records anyway — the write fails — **and** pays a timeout on
  every request. The loss appears only as error log lines.
* `queue_drop` loses the records, serves every request at normal latency, and
  **counts the loss** in `firewall_audit_events_dropped_total`.

Same integrity outcome, better availability, and the failure is a number an
operator can alert on rather than a pattern in a log.

### `require_audit=true` forces `sync`, and the combination is refused

`require_audit` promises that a served request has a record. A queue is precisely
the removal of that promise. The application **refuses to start** with both
configured, rather than leaving a deployment believing it has a guarantee it does
not have.

---

## The cost, stated plainly

**A queued writer loses whatever is queued if the process is killed without
draining.** Measured: `sync` wrote 300/300 after a `SIGKILL`; `queue_drop` wrote
**49/300**. At ~10 ms per write, the queue holds roughly one write-latency's
worth of throughput at any moment — here, about 2.5 seconds of records.

A graceful stop loses nothing: the drain is bounded by
`FIREWALL_AUDIT_DRAIN_TIMEOUT_S` (5 s) and wrote 300/300. Bounded, because a
stuck database must not hold a rolling deploy open; what it abandons is logged
rather than discovered later as a hole.

This cost is **new information ADR-012 did not have**. It does not change the
decision — an ungraceful kill is the abnormal case, and the ordinary case saves
10 ms on every request — but it is why the code default stays `sync` and why a
deployment that cannot tolerate the window sets `sync` explicitly.

---

## Alternatives considered

| | Option | Why not |
|---|---|---|
| A | **Keep synchronous writes** | Costs 10.5 ms p50, 86 % of a small request's gateway latency, and during a database outage loses the records anyway while also paying the timeout. Retained as the default and as the `require_audit` implementation. |
| B | **Block on a full queue** | Implemented and measured. Turns a database stall into a total gateway outage. Removed. |
| C | **Unbounded queue** | ADR-012 rejected it in Phase 0 and the reasoning is unchanged: an unbounded queue in front of a failing database is an OOM kill wearing a buffer. |
| D | **Batch writes** | Would reduce per-record cost further, and adds a second dimension (batch size × flush interval) to a decision that is not yet limited by throughput. Reconsider if `firewall_audit_queue_depth` shows sustained backlog on a healthy database. |
| E | **Write-ahead to disk, replay on restart** | Closes the SIGKILL window properly. A meaningful amount of machinery — a log format, a replay path, corruption handling — for a window that a graceful stop already closes. Revisit if a deployment states that hard-kill loss is unacceptable *and* cannot use `sync`. |

---

## Consequences

**Gained.** ~10 ms off every request. A database stall costs audit records
instead of availability, and the loss is counted rather than inferred. The
metric ADR-012 named in Phase 0 now exists and has something to report.

**Cost.** A window between a request being served and its record being durable.
Zero on graceful shutdown, ~2.5 s of throughput on a hard kill.

**Not gained, stated plainly.**

* **No durability guarantee under `SIGKILL`** (R-80). `sync` is the answer for
  deployments that need one.
* **No batching**, so per-record write cost is unchanged — only its position
  relative to the response.
* **The measurements are one machine, one mock upstream, one payload profile.**
  They characterise the trade; they do not size a queue for anyone's traffic.
* **`firewall_audit_queue_depth` has no alert threshold** here, because no
  deployment traffic exists to derive one from.

---

## Verification

`tests/unit/test_audit_queue.py` (7) covers the semantics: `record` returns
without waiting for the write; a full queue drops and counts rather than waiting;
a failing sink does not kill the writer task; a graceful drain loses nothing; the
drain is bounded. `tests/security/test_audit_privacy.py` is unchanged and still
passes — the queue moves *when* a record is written, never *what*.

Reproducing the experiment:

```bash
MOCK_LATENCY_MS=0 docker compose -f compose.yaml -f compose.bench.yaml up -d --build
FIREWALL_AUDIT_WRITE_MODE=queue_drop docker compose up -d --force-recreate firewall-api
uv run python -m eval.runners.benchmark --label audit-queue-drop --conditions C \
    --concurrency 1,4 --payload short,medium --iterations 800 --warmup 100
```

The stall experiment pauses PostgreSQL (`docker pause`) with
`FIREWALL_AUDIT_QUEUE_SIZE=10` and compares served requests, written rows and
`firewall_audit_events_dropped_total`.
