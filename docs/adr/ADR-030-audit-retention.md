# ADR-030: Audit Retention — the job that deletes

**Status:** Accepted
**Date:** 2026-08-19
**Phase:** 16
**Fulfils:** [ADR-012](ADR-012-persistence-and-retention.md) — "Enforced by a scheduled deletion job (Phase 5), not a runbook step"

## Context

ADR-012 decided retention in Phase 0. It fixed the periods (30 days of traces, 180
days of security events), gave each a reason, and said explicitly that enforcement
would be *"a scheduled `DELETE` in Phase 5, not a manual process"*. Phase 5 built
the schema and the console that reads it. **Nothing ever built the deletion.**

So every audit row this project has ever written is still there. On the reference
development machine, measured 2026-08-19:

| Table | Rows | Size |
|---|---|---|
| `detector_results` | 179,153 | 38 MB |
| `request_traces` | 45,095 | 17 MB |
| `security_events` | 535 | 464 kB |

The oldest row is dated 2026-08-17 — **55 MB in 2.4 days**, and not one byte of it
would ever have been removed by anything. That figure is development and Phase 15
benchmark traffic on one machine; it is **not** a production growth rate and is
not offered as one. What it establishes is only the shape of the problem: nothing
deletes, and the largest table is the one nobody looks at.

Three things have made this worse since Phase 5, all of them consequences of work
that was otherwise right:

* `request_traces` now carries `caller_id` ([ADR-024](ADR-024-llm-caller-authentication.md)),
  so rows are attributable to an application rather than anonymous.
* The console makes the trail readable by operators ([ADR-022](ADR-022-dashboard-frontend-architecture.md)).
* [ADR-029](ADR-029-audit-write-architecture.md) just made writes ~9 ms cheaper,
  which means more of them, faster, for longer.

An audit store that only grows is a privacy liability as much as a disk one, and it
is the one component in this system where doing nothing actively worsens the
position over time.

## Decision

Build the job ADR-012 registered. **The periods do not change** — this ADR
implements a decision, it does not revisit one.

### The policy

| Table | Period | Deletion | Reason |
|---|---|---|---|
| `request_traces` | 30 days | hard delete, by age | Operational tuning window. It is also the console's maximum query window (`MAX_WINDOW_HOURS = 24 * 30`), so retention never removes a row the console could still have displayed |
| `detector_results` | with its parent | hard delete, `ON DELETE CASCADE` | Meaningless without its trace; ~4 rows per trace, and the largest table in the schema |
| `security_events` | 180 days | hard delete, by age | Investigations begin long after the event. Denormalised precisely so it can outlive the traces |

No archival tier, no soft delete, no export-before-delete. Each was considered and
rejected below. `eval/results/**` is untouched and is not the same kind of thing:
it is versioned research evidence with pinned checksums, not an operational store,
and deleting from it destroys the record of a completed experiment.

### The only predicate is age

There is no parameter for a decision, a category, a detector or a caller, and no
CLI flag that adds one. This is the security-relevant property of the whole
feature: **a purge that can be aimed at particular rows is a supported mechanism
for erasing the evidence of a specific block** — a cleaner one than editing rows,
because it leaves a legitimate-looking gap rather than an anomaly.

`app/database/retention.py` builds row selection in exactly one function,
`_eligible_ids`, whose `WHERE` is `created_at < cutoff`. Everything else deletes by
primary key from the list that function returned.
`tests/security/test_retention_safety.py` compiles the statements against the
PostgreSQL dialect and asserts that no aimable column appears in the SQL at all,
and that the module contains exactly one `DELETE` whose id list has exactly one
origin. The property is asserted against the generated SQL, not against this
paragraph.

### Deletion is batched, and that is not a style preference

`Database` sets a 5-second command timeout on every connection. A single
`DELETE FROM request_traces WHERE created_at < …` against a real backlog would not
merely be slow — it would time out, roll back, and delete **nothing, permanently**.
Retention would appear to be enabled and running while the store grew unchecked.

Each batch (1,000 rows by default) is its own transaction. Consequences, all
intended: a cancelled sweep has committed everything it reported, partial progress
is the normal state rather than a failure, and no single transaction holds locks or
generates bloat proportional to the backlog.

Concurrent replicas each run a sweeper. Row selection uses `FOR UPDATE SKIP LOCKED`
so they divide the work instead of one blocking on the other's locks until the
5-second timeout kills it. The delete counts `rowcount`, not the length of the id
list, because with `SKIP LOCKED` another process can legitimately have removed a
row in between.

### The cutoff comes from PostgreSQL's clock

`created_at` is stamped by `server_default=now()`, so the cutoff is computed from
the same clock: one `SELECT now()` per sweep, then `now - interval` in Python. A
gateway whose own clock had drifted forward would otherwise delete rows that are
not old yet — the one failure mode of an age-based purge that is silent,
irreversible, and indistinguishable from correct operation.

### `detector_results` is deleted by cascade, not by age

It has no index on `created_at` alone — only `(detector, created_at)` — so an
age-based scan of the largest table in the schema would be sequential. It does not
need one: the foreign key is `ON DELETE CASCADE`, so deleting a trace removes its
detector rows through `ix_detector_results_trace_id`.

The cascade rows are **counted before each batch** so the metric reports what was
actually removed. That costs one indexed `count(*)` per batch, deliberately: the
child table is four times the volume, and a "rows deleted" metric that reported
only parents would understate the work by that factor and mislead exactly when
someone is trying to size a disk.

### Off by default; on in the reference production deployment

`FIREWALL_RETENTION_ENABLED=false` in code, `true` in `compose.prod.yaml`. The
reasoning is [ADR-029](ADR-029-audit-write-architecture.md)'s, applied to a more
consequential default: deletion is irreversible, and an upgrade must not begin
removing an operator's audit trail because a default moved underneath them.

Production is **not** refused when retention is off. That deserves a defence,
because this project does refuse to start on an unauthenticated console, an
unverifiable transport, and a `0.0.0.0/0` trusted range. The difference is that
those are open boundaries — a request gets through that should not have. An
un-purged audit store is a liability that accumulates, not a hole an attacker
walks through, and making deletion mandatory would mean the upgrade itself destroys
data for an operator who never asked for it. It is a **startup warning** naming
the consequence, and the periods are printed whether it is on or off, so no
deployment can quietly retain more than it intended.

### Safety floor and ordering

* No period below **1 day** (`MINIMUM_RETENTION_DAYS`). Zero would mean "delete
  everything on the next sweep", and a mistyped environment variable must not be
  recoverable only from a backup. Applied both in `Settings` and in
  `RetentionPolicy.from_settings`, because the CLI builds a policy without going
  through `Settings` and the floor must not depend on the route taken.
* `retention_event_days >= retention_trace_days`, refused at startup. The console's
  event-detail endpoint LEFT JOINs an event to its trace *because* events outlive
  traces, and documents null operational fields on an old event as normal.
  Inverting the order would make the longer-lived table the one that vanishes
  first, which nothing in the design expects.
* A per-table, per-sweep ceiling (50,000 rows) so a misconfiguration cannot empty
  the store in one pass unobserved. Reaching it is **logged**, never silent: a cap
  that quietly truncates reads as "retention is enforced" when it is only running
  behind.

### Scheduled in-process, at startup and then on an interval

There is no scheduler in this deployment ([OD-41](../21-open-decisions.md)) and
adding one to run a `DELETE` would be the largest piece of infrastructure in the
project. The sweeper is an `asyncio` task, off the request path.

It sweeps **at startup** and then every hour. At startup because a feature whose
first observable effect is an hour away is a feature nobody can verify they
enabled. Hourly rather than daily because a daily job inside a process that is
redeployed daily is a job that never runs.

A sweep that raises is caught, counted and logged — never allowed to escape, for
the same reason as the audit writer's drain loop: an exception would kill the task
and convert a transient database error into permanent, silent growth.

### Manual operation: dry run by default

`scripts/purge_audit.py` runs the same sweeper once. **`--execute` is required**,
because a deletion tool that runs when invoked with no arguments will eventually be
invoked with no arguments by someone who only wanted to see what it would do. It
reports per table: the period, the cutoff on the database clock, the rows that
would go, the cascade count, and the reason each period is what it is.

It has no flag to choose a period — the periods come from configuration so that
what the CLI does is what the scheduled sweep does, and a CLI that could delete on
its own terms would be a second, undocumented retention policy.

### Observability

| Metric | Type | Labels |
|---|---|---|
| `firewall_audit_rows_deleted_total` | counter | `table` |
| `firewall_retention_sweeps_total` | counter | `outcome` |
| `firewall_retention_last_success_timestamp_seconds` | gauge | — |
| `firewall_audit_oldest_row_age_seconds` | gauge | `table` |

The last one is the metric that matters, and it is not the delete counter. **A
counter can tick steadily while the backlog grows.** The age of the oldest
surviving row, compared against the configured period, is the only one of the four
that answers "is retention actually keeping up". It is reported for the two swept
tables only — `min(created_at)` on `detector_results` would be a sequential scan,
and a metric is not worth a full read of the largest table every hour.

`/ready` is deliberately **not** touched. A retention outage is not a readiness
condition: refusing traffic because deletion failed would trade a privacy and disk
problem for an availability outage, which is the same mistake
[ADR-027](ADR-027-readiness-contract.md) corrected for the audit store itself.

## Alternatives considered

| Alternative | Rejected because |
|---|---|
| **One `DELETE` per table per sweep** | The 5-second command timeout would roll it back against any real backlog, so retention would appear enabled and delete nothing. Batching is a correctness requirement here, not a tuning choice |
| **PostgreSQL native partitioning, drop old partitions** | Genuinely better at scale: `DROP PARTITION` is O(1) where `DELETE` is O(rows), with no bloat and no vacuum pressure. Rejected for *now* because it is a schema migration of the three busiest tables, it changes every index and the foreign key, and this store is 55 MB. Recorded as [OD-43](../21-open-decisions.md) with the volume that should trigger it rather than left as a vague "later" |
| **`pg_cron` / an external cron container** | Moves the policy out of the application that owns it and into a place where it can drift from `FIREWALL_RETENTION_*`. It also needs credentials with DELETE that the application would then not need — a real advantage, but it buys that by adding a component and a second copy of the policy |
| **Soft delete (`deleted_at`)** | Solves nothing this needs. The rows still occupy disk, still hold `caller_id`, and are still readable by anything with SQL access. It converts a deletion problem into a filtering problem, everywhere, forever |
| **Archive to object storage before deleting** | The archive inherits every property that made the audit store a liability, minus the access control the database provides, and nothing in this project has asked to read a 200-day-old trace. Deferred, not refused: [OD-43](../21-open-decisions.md) |
| **Delete the oldest N rows when a size threshold is crossed** | Retention by disk pressure rather than by policy. The period becomes an emergent property of traffic, so the same deployment retains 30 days on a quiet week and 3 on a busy one, and neither is what was documented |
| **Refuse to start in production without retention** | Consistent with the console, transport and trusted-proxy rules, and rejected above: unlike those, the failure is accumulation rather than an open boundary, and the refusal would make an upgrade destroy data nobody asked to have deleted |
| **`VACUUM FULL` after a sweep** | Takes an `ACCESS EXCLUSIVE` lock on the table — the audit store becomes unwritable for the duration. Autovacuum reclaims the space for reuse without it. A retention job that blocks the audit write is a worse problem than the one it solves |

## Consequences

### Positive

* ADR-012's retention decision is enforced by an artefact rather than described by
  a document, four phases after it was made.
* The oldest-row-age gauge makes "retention is silently not keeping up" an
  alertable condition instead of a discovery.
* Deleting a trace deletes its detector results by construction, so the child table
  cannot outlive its parent even if the sweeper is changed carelessly.
* Dry run means an operator can see the effect of a period before committing to it.

### Negative / accepted costs

* **The application role now needs `DELETE`.** ADR-012's least-privilege paragraph
  granted the app `SELECT/INSERT/UPDATE` and no `DROP`, on the reasoning that an
  application-level SQL flaw should not be able to destroy the audit trail. An
  in-process sweeper needs `DELETE` on the three audit tables, so that protection
  is genuinely weakened. Recorded as **R-82** rather than glossed. Mitigating
  facts, stated for what they are worth: the grant split was never implemented in
  any manifest (the app connects as the owner today), every statement here is
  parameterised, and no user input reaches the retention path. The alternative
  that preserves it — an external job with its own credentials — is OD-43.
* **Backups outlive retention.** A 30-day period in the database and a 90-day
  backup rotation means the data survives for 90 days. The gateway cannot enforce
  this and does not claim to; it is listed as a deployment obligation in
  [docs/10](../10-security-model.md).
* Deletion is irreversible and there is no undo. That is the point, and it is why
  the floor, the ceiling, the dry run and the required `--execute` all exist.
* A sweep competes with the request path for the connection pool (5 connections by
  default). One connection, in bounded batches, at most once an hour — but it is
  not free, and no measurement of its impact under load has been taken.
* Reaching the per-sweep ceiling means retention is running behind. It is logged,
  but nothing escalates automatically.

### Revisit when

The store reaches a volume where `DELETE` is no longer cheap — partitioning
(OD-43); a deployment needs the archive; or a regulatory requirement fixes a
retention period, at which point the period stops being a tuning knob and the
backup rotation has to be brought into the same policy.

## Verification

* `tests/integration/test_retention.py` — nine tests against real PostgreSQL:
  rows past the period go, rows at 29 days and at 30.001 days are correctly
  separated, the cascade removes and counts detector results, security events
  survive the trace period and go at their own, dry run deletes nothing, a second
  sweep deletes nothing, the per-sweep ceiling stops and reports, batching
  completes across batches, and the cutoff matches the database clock.
  Every fixture row is aged past the **default** periods and tagged, so the test
  never shortens a period — a retention test that did would delete the local
  development audit trail as a side effect, which is exactly the accident this
  feature must be trusted not to have.
* `tests/security/test_retention_safety.py` — the compiled SQL references no
  aimable column; selection is bounded, ordered and `SKIP LOCKED`; one `DELETE`
  with one id source; the sweeper has no filter parameter; the CLI requires
  `--execute` and offers no period or target flag; sweep logging carries counts
  and no row identity.
* `tests/unit/test_retention_policy.py` — the floor is refused from both routes,
  the ordering invariant holds, a failed sweep is counted and contained, the
  scheduler sweeps at startup, and **every table in the audit schema is either
  swept by age or cascaded from one**, so a table added later cannot escape
  retention by not being mentioned.
* Manually, against the running development stack: 10 traces + 40 detector rows +
  3 events aged past their periods were reported by the dry run, removed by
  `--execute`, and the 45,047 pre-existing traces and 179,241 detector rows were
  untouched — verified by count before and after.
