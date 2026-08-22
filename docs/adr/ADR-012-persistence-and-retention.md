# ADR-012: Audit Persistence, Availability Trade-off, and Retention

**Status:** Accepted
**Date:** 2026-08-17
**Phase:** 0 (schema, synchronous writes), Phase 5 (async writer, retention job)

## Context

A security gateway that blocks a request and remembers nothing is not auditable. The audit
trail is what answers "what was blocked last Tuesday, by which detector, under which policy,
and has this payload been seen before".

Three hard questions come with it:

1. **What is stored?** Storing prompts makes the audit trail the most sensitive datastore in
   the architecture — the exact thing the product exists to protect.
2. **What happens when the database is down?** Fail the request (audit integrity) or serve it
   unaudited (availability)?
3. **Is writing on the request path acceptable?** Every millisecond in the handler is
   gateway overhead.

## Decision

### Store fingerprints, not content

There is **no column anywhere that can hold a full prompt or completion**. Audit tables store
hashes, lengths, categories, scores, thresholds, latencies and decisions. Schema in
[data-model.md](../11-data-model.md).

This is structural, not procedural: a future change that wants prompt text must add a column,
which is a visible migration and a reviewable decision rather than a one-line logging change.
The single exception, `security_events.content_preview`, is populated only under
`content_logging=full`, which is refused in production.

Recording `threshold` and `policy_version` alongside each result is what makes a historical
decision interpretable after the policy has changed — without them, old audit rows are
uninterpretable.

### Audit failure does not fail the request (default, configurable)

If the database is unreachable, the request **proceeds** and the decision still stands. The
write failure is logged at ERROR and increments
`firewall_audit_write_failures_total`, which is an alerting metric.

This is the one place the system deliberately does not fail closed, and the reasoning is
specific: the security *decision* is unaffected by a database outage — the detectors ran, the
policy was applied, the block or allow is correct. Only the record is lost. Turning a
Postgres outage into a total outage of the protected application trades a large availability
loss for a small integrity loss.

`require_audit=true` inverts this for deployments with a regulatory need for
guaranteed audit. It is a flag, not a fork, and it is off by default.

### Writes move off the request path in Phase 5

Phase 0 writes synchronously behind a repository interface. Phase 5 replaces the
implementation with a bounded in-process queue and a background writer:

```
handler ──► queue.put_nowait(event) ──► [bounded queue] ──► writer task ──► Postgres
                    │
                    └─ queue full: drop, count firewall_audit_events_dropped_total
```

Bounded and dropping, not unbounded and buffering: an unbounded queue in front of a failing
database converts a database outage into an out-of-memory kill. Dropping is visible in a
metric; an OOM is visible as an outage.

The repository interface exists in Phase 0 precisely so this change touches no caller.

### Retention

| Data | Default | Rationale |
|---|---|---|
| `request_traces`, `detector_results`, `policy_decisions` | 30 days | Tuning window |
| `security_events` | 180 days | Investigations begin long after the event |
| `content_preview` | Never in production | |
| Evaluation tables | Indefinite | Public benchmark data; reproducibility depends on history |

Enforced by a scheduled deletion job (Phase 5), not a runbook step. Configured values are
printed at startup.

### Least privilege

The application role holds `SELECT/INSERT/UPDATE` on audit tables and **no `DROP`**;
migrations run under a separate role. An application-level SQL flaw should not be able to
destroy the audit trail.

## Alternatives considered

| Alternative | Rejected because |
|---|---|
| **Store full prompts for investigation** | Creates a central store of exactly the sensitive content the product protects, with all the retention, access-control and breach consequences that follow. The hash gives repeat-payload correlation, which is the operationally useful part, at a fraction of the risk. |
| **Fail the request when the audit write fails** | Makes Postgres availability a hard dependency of every LLM call in the application. Available as `require_audit=true` for those who need it; wrong as a default. |
| **Async writes from Phase 0** | Premature. The synchronous write is measurable in Phase 4, so the optimisation can be justified by a number instead of an assumption — and the interface makes it cheap later. |
| **Unbounded in-memory queue** | Converts a database outage into an OOM kill. |
| **Write audit records to logs only** | Simple, and it makes "how many blocks by category last week" a log-aggregation problem, and repeat-payload correlation impractical. Structured logs are emitted *as well*, not instead. |
| **Kafka / event stream** | Correct at a scale this system has not reached. Postgres first; the repository interface keeps the door open. |
| **Append-only with cryptographic chaining** | Real tamper-evidence, real complexity. Deferred; T-21 records the residual risk honestly rather than pretending least-privilege is tamper-proofing. |

## Consequences

### Positive
* The audit trail is not a liability: no prompt content, so a compromise of it does not leak
  user data.
* Repeat-payload detection via `content_hash` without storing a single prompt.
* Threshold tuning is possible retrospectively, because scores from detectors that did *not*
  fire are recorded alongside the threshold in force.
* Database outages degrade auditing, not availability.
* `policy_version` makes historical decisions explainable.

### Negative / accepted costs
* **Investigating a specific incident is harder** without the prompt. An operator will
  sometimes have a hash and want the text, and will not have it. That is the accepted cost of
  not building a prompt warehouse, and it is stated in the README rather than discovered.
* Default configuration can lose audit records during a database outage (visible in a
  metric).
* Phase 0's synchronous write adds latency to the request path until Phase 5.
* Hashes prove sameness, not secrecy — a low-entropy prompt can be confirmed by an attacker
  who can guess and hash it ([logging.md](../10-security-model.md)).
* No cryptographic tamper-evidence.

### Revisit when
A deployment has a regulatory audit-integrity requirement (turn on `require_audit`, consider
chaining); or Phase 4 measurements show synchronous writes are a material share of gateway
overhead (accelerate the Phase 5 queue).

## Verification

* `tests/integration/test_audit_persistence.py` — a blocked request writes a trace, detector
  results, a policy decision and a security event, with the correct `policy_version`.
* `tests/unit/test_audit_failure_accounting.py` — with the database unreachable, the
  request still returns its correct decision and `firewall_audit_write_failures_total`
  increments, in both write modes.

  **Corrected 2026-08-21.** This line previously named
  `tests/integration/test_audit_failure.py`, **which was never written.** The
  verification this ADR relied on to hold its own Phase 0 promise did not exist, and
  the promise went unmet from Phase 0 until Run 3 drove the condition: the counter was
  exported and asserted *present* by a test, but nothing asserted it *moved*, and it
  never did (R-111). The file named above is the verification that now exists and does
  assert the increment.
* `tests/unit/test_no_content_columns.py` — asserts no audit model defines a
  content-bearing column beyond the gated `content_preview`.
* Migration review: every schema change is an Alembic revision; nothing is created by
  `create_all()` outside test fixtures.


---

## Amendment — 2026-08-19: the Phase 5 queue is built

This ADR registered a bounded queue with drop-on-full, named the metric
(`firewall_audit_events_dropped_total`), and set the condition for building it:
*"Phase 4 measurements show synchronous writes are a material share of gateway
overhead"*.

Phase 15 measured **10.5 ms p50** for the synchronous write against **1.7 ms** for
the rest of the gateway span. The trigger fired on this ADR's own terms, and
[ADR-029](ADR-029-audit-write-architecture.md) builds the design registered here.

**Nothing decided in this document changes.** The queue is bounded and drops;
dropping is counted; `require_audit=true` still means synchronous writes, and the
two settings together are now refused at startup rather than silently
contradicting each other.

One thing this ADR could not have known, added by ADR-029 rather than assumed:
the queue loses whatever is queued if the process is killed without draining —
measured at 49/300 records after a `SIGKILL`, against 300/300 for synchronous
writes. A graceful stop loses nothing. That is why the *code default* remains
`sync` and the queue is adopted in the reference production deployment
explicitly, rather than becoming everyone's behaviour on upgrade.

---

## Amendment — 2026-08-19: the retention job is built

This ADR set the periods (30 days of traces, 180 of security events), gave each a
reason, and said enforcement would be *"a scheduled `DELETE` in Phase 5, not a
manual process"*. Phase 5 built the schema and the console that reads it. Nothing
built the deletion, so until now every row ever written was still present — 55 MB
in 2.4 days on the reference development machine.

[ADR-030](ADR-030-audit-retention.md) builds the job. **The periods are unchanged**
and nothing decided here is revisited.

Two things this ADR could not have known, added by ADR-030 rather than assumed:

* `detector_results` is deleted by `ON DELETE CASCADE` from its trace rather than
  by age. It has no standalone `created_at` index, so an age-based sweep of the
  largest table in the schema would be a sequential scan; the cascade uses the
  foreign key's index instead.
* Deletion must be **batched**. `Database` applies a 5-second command timeout, so
  the single `DELETE` this ADR implies would time out against any real backlog,
  roll back, and delete nothing — while appearing to be enabled.

One thing decided here does change, and it is a loss. The least-privilege
paragraph above grants the application role `SELECT/INSERT/UPDATE` and no `DROP`,
so that an application-level SQL flaw could not destroy the audit trail. An
in-process retention sweeper needs `DELETE` on the three audit tables, which
weakens that protection. It is recorded as **R-82** and the alternative that would
preserve it — an external job holding its own credentials — is **OD-43**. The
grant split was in any case never implemented in a manifest: the application
connects as the table owner today.

