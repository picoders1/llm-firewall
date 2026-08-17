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
* `tests/integration/test_audit_failure.py` — with the database unreachable, the request
  still returns its correct decision and `firewall_audit_write_failures_total` increments.
* `tests/unit/test_no_content_columns.py` — asserts no audit model defines a
  content-bearing column beyond the gated `content_preview`.
* Migration review: every schema change is an Alembic revision; nothing is created by
  `create_all()` outside test fixtures.
