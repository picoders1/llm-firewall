# Incident Runbook

One section per alert in [`deploy/alerts/firewall.rules.yaml`](../deploy/alerts/firewall.rules.yaml),
and nothing else. `tests/unit/test_alert_rules.py` fails if a rule has no section
here or a section here names no rule — a page with no instructions and a procedure
nobody will ever be told to run are the two ways a runbook rots.

Each entry answers the same five questions: **what it means**, **what to look at**,
**what to do now**, **when to escalate**, **when it is over**.

---

## Before you use any of this

**Severity has two values and they are defined by response.**

| | Meaning |
|---|---|
| `critical` | Wake someone now. Security evidence is being lost, the protection is degraded, or the protected application is failing for its users. |
| `warning` | A ticket for the next working day. Something is wrong or drifting and nothing is on fire. |

There is no third level. A severity that means "look at it eventually" is a
severity that means nothing.

**Thresholds labelled `calibration: unvalidated` are development defaults.** This
project has no production traffic and has never tuned an alert against any. The
numbers are starting points chosen to be plausible, not measured (R-67). The first
week of real traffic should change most of them, and changing them is expected
maintenance rather than an admission of error.

**Counters are per process.** With N replicas, an unaggregated threshold is wrong
by a factor of N. Every expression in the rule file aggregates explicitly; if you
add one, do the same.

**`firewall_gateway_overhead_seconds` excludes the audit write** (R-77). What a
caller actually waits for is that number plus the audit latency — roughly 10 ms
synchronously, near zero when queued. Never quote it as end-to-end latency.

**Standard first look**, for every alert here:

```bash
curl -s localhost:8000/ready | jq                    # which checks are failing, and are they required
curl -s localhost:8000/metrics | grep ^firewall_     # the raw signal, unaggregated
docker compose logs --since 30m firewall-api | jq -c 'select(.level!="debug")'
curl -s localhost:8000/api/v1/overview?hours=6 | jq  # decisions, latency, failures over a window
```

`/metrics` is on the **internal** access class: reachable from
`FIREWALL_METRICS_NETWORKS`, and operator-authenticated otherwise. If a scrape is
401ing, that is configuration, not an incident (ADR-023).

---

## FirewallAuditEventsDropped

**`critical` · component: audit**

### What it means

The bounded audit queue filled and records were discarded. From the moment this
fires, requests are being served and decided correctly with **no audit row**, and
nothing else in the system records which ones. ADR-012 named this metric in Phase 0
for exactly this reason: dropping had to be visible.

It is not a database outage on its own — the queue fills because the writer cannot
keep up, which is usually a slow database rather than an absent one.

### What to look at

```bash
curl -s localhost:8000/metrics | grep -E 'audit_(events_dropped|queue_depth|queue_capacity|write_failures)'
docker compose logs --since 1h firewall-api | jq -c 'select(.event=="audit_event_dropped")' | wc -l
docker compose exec postgres psql -U firewall -d firewall -c \
  "select count(*), max(created_at) from request_traces;"
```

Compare the drop count against traffic in the same window. Queue depth at capacity
with no write failures means a slow database; depth at capacity *with* write
failures means an unreachable one and `FirewallAuditWriteFailing` should also be
firing.

### What to do now

1. If the database is slow rather than down, that is the fix — check its load,
   locks and disk before touching the gateway.
2. Raising `FIREWALL_AUDIT_QUEUE_SIZE` buys time proportional to the increase and
   nothing more. It is a legitimate stopgap and not a fix.
3. `FIREWALL_AUDIT_WRITE_MODE=sync` stops the dropping by putting the write back on
   the request path, which costs ~10 ms per request and makes a database stall a
   latency incident instead of a data-loss one. That is a deliberate trade, not an
   escalation — decide which you would rather have for the next hour.
4. Do **not** set `FIREWALL_REQUIRE_AUDIT=true` as a reaction. It is refused in
   combination with a queued writer and the process will not start (ADR-029).

### Escalate when

Drops continue after the database is healthy — that means the writer task itself is
wedged, and a process restart is the remedy. Escalate immediately, regardless of
volume, if the deployment has a compliance obligation to a complete audit trail:
those records are not recoverable.

### Resolved when

`increase(firewall_audit_events_dropped_total[5m])` is zero and queue depth has
returned to near zero. **Record the gap** — the drop count is the number of served
requests with no row, and it belongs in the incident record because nothing else
will ever show it.

---

## FirewallAuditWriteFailing

**`critical` · component: audit**

### What it means

Audit writes have failed continuously for ten minutes. Requests are still served
and their decisions are still correct — ADR-012 chose this deliberately, because
the detectors ran and the policy was applied; only the record is lost. What you
have is a security gateway that is working and cannot prove it.

A single transient failure does not fire this. If it fired, the database was down
for ten minutes, not one.

### What to look at

```bash
docker compose logs --since 30m firewall-api | jq -c 'select(.event=="audit_write_failed")' | tail
curl -s localhost:8000/ready | jq '.checks[] | select(.name|startswith("database"))'
docker compose exec postgres pg_isready -U firewall -d firewall
```

The failure log deliberately carries `error_kind` and **not** the exception text,
because that text can contain SQL parameters. For the real cause read the database's
own log.

### What to do now

1. Fix the database. Nothing on the gateway will help: it is behaving as designed.
2. Note that `/ready` stays **ready** through this when `require_audit=false`. That
   is correct and deliberate (ADR-027) — an audit outage must not empty the fleet
   and turn a record-keeping problem into a traffic outage. Do not "fix" readiness.
3. If the deployment runs `require_audit=true`, requests are being refused with
   `503 audit_unavailable` and this is a full outage. Treat it as one.

### Escalate when

The database is reachable and writes still fail — that is schema drift or a
permissions change, not an outage. Check the applied revision on `/ready` against
the one the code expects, and check that the application role still holds `DELETE`
and `INSERT` on the audit tables (R-82).

### Resolved when

The failure rate is zero for fifteen minutes. Records lost during the window are
gone; there is no backfill and pretending otherwise is worse than the gap.

---

## FirewallHTTPSEnforcementDisabled

**`critical` · component: transport**

### What it means

At least one process reports `firewall_https_enforced=0`, meaning it will accept a
request whose client hop was not TLS.

Be clear about what this can and cannot be. **Production refuses to start in this
state** (ADR-026). So this alert firing against a production scrape pool means one
of exactly three things, and none of them is "TLS broke":

1. A non-production instance is in the production scrape pool.
2. An instance is running with `FIREWALL_ENVIRONMENT` set to something other than
   `production`, and therefore skipped the refusal.
3. The startup check has been relaxed or removed.

It re-asserts a startup invariant rather than detecting a runtime failure — the same
honest limitation `/ready`'s security checks carry (R-71). Its value is that it
catches the third case, which is the one nothing else would catch.

### What to look at

```bash
curl -s localhost:8000/metrics | grep -E 'firewall_https_enforced|firewall_retention_enabled'
docker compose logs firewall-api | jq -c 'select(.event=="startup") | {environment, https_enforced, trusted_proxies}'
docker compose logs firewall-api | jq -c 'select(.event=="https_not_enforced")'
```

The `https_not_enforced` warning at startup names the reason.

### What to do now

1. Identify the instance from the `instance` label and check its
   `FIREWALL_ENVIRONMENT`. If it is not production, remove it from the scrape pool
   — the alert is right and the topology is wrong.
2. If it *is* production, the process should not have started. Stop routing traffic
   to it before diagnosing further: it will accept credentials over plaintext.
3. Check `FIREWALL_TRUSTED_PROXIES`. HTTPS enforcement needs a trusted proxy to
   assert `X-Forwarded-Proto`; with no trusted range the application refuses to
   enforce rather than pretending to (ADR-026).

### Escalate when

Immediately, if a production instance is serving with this at 0. Credentials have
potentially crossed a plaintext hop, and reading them cannot be un-done — key
rotation is the follow-up, not an optional extra.

### Resolved when

`min(firewall_https_enforced)` is 1 across the pool and you know which of the three
causes it was. "It went away after a restart" is not a diagnosis.

---

## FirewallRetentionDisabled

**`warning` · component: audit**

### What it means

At least one process has `FIREWALL_RETENTION_ENABLED=false`, so nothing is deleting
audit rows past their period. The store grows without bound, and every
`request_traces` row carries a caller identity — a privacy liability as much as a
disk one (ADR-030).

This is the default in code, on purpose: deletion is irreversible and an upgrade
must not start removing an operator's audit trail because a default moved (R-84).
`compose.prod.yaml` turns it on. So this alert usually means a deployment assembled
by hand, not a regression.

### What to look at

```bash
curl -s localhost:8000/metrics | grep -E 'retention_enabled|audit_retention_period'
docker compose logs firewall-api | jq -c 'select(.event=="audit_retention_disabled")'
uv run python scripts/purge_audit.py     # dry run: what has already accumulated
docker compose exec postgres psql -U firewall -d firewall -c \
  "select relname, n_live_tup, pg_size_pretty(pg_total_relation_size(relid))
     from pg_stat_user_tables order by n_live_tup desc;"
```

### What to do now

1. Run the dry run first. If a long-disabled deployment is turned on cold, the first
   sweep has a large backlog to work through — it is bounded per sweep and will take
   several passes, which is by design.
2. Set `FIREWALL_RETENTION_ENABLED=true` and restart. The first sweep runs at
   startup, so the effect is immediate and visible.
3. Confirm the periods are the ones you intend before enabling, not after:
   `firewall_audit_retention_period_seconds` reports what is actually configured.

### Escalate when

The deployment is subject to a data-protection commitment about retention periods.
Then this is not a ticket — every day it stays off is a day of data held past what
was promised, and the backups inherit it too (R-83).

### Resolved when

`min(firewall_retention_enabled)` is 1 and
`firewall_audit_oldest_row_age_seconds` is trending down toward the configured
period. The first is configuration; only the second is evidence.

---

## FirewallDetectorErrorRateHigh

**`critical` · component: detection · `calibration: unvalidated`**

### What it means

A detector is erroring on more than 1% of its runs. The consequence depends on how
that detector is configured to fail:

* **fail-closed** (the default): every errored run is a `503 detector_failure` to
  the caller. This is an availability incident.
* **fail-open**: requests pass **uninspected**. This is a security incident, and it
  is quieter than the first one — which is why the fail-open detectors are named in
  a startup warning.

### What to look at

```bash
curl -s localhost:8000/metrics | grep firewall_detector_errors_total
docker compose logs --since 30m firewall-api | jq -c 'select(.event|test("detector_(failed|error|timeout)"))' | tail -20
docker compose logs firewall-api | jq -c 'select(.event=="fail_open_detectors_configured")'
curl -s localhost:8000/api/v1/detectors | jq
```

The `error_kind` label separates the two common causes: a `TimeoutError` means the
detector is too slow for its budget, anything else means it is broken.

### What to do now

1. **Timeouts:** check whether the host is under CPU pressure before raising
   `timeout_ms`. Raising the timeout on a saturated host converts errors into
   latency and moves the problem to `FirewallGatewayOverheadHigh`.
2. **Anything else:** the detector is broken. Disabling it in policy is a decision
   to run without that protection — make it consciously and write it down; do not
   let a timeout increase quietly become that decision.
3. Check the failure mode before doing either. `on_error: fail_open` on the erroring
   detector means traffic is passing uninspected *right now*.

### Escalate when

The erroring detector is fail-open, or `injection.heuristic` is erroring at all —
that one is the primary input protection and blocking depends on it.

### Resolved when

The ratio is below 1% for thirty minutes **and** you know which of the two causes it
was. A timeout that stopped when traffic dropped has not been fixed.

---

## FirewallDetectorErrorsPresent

**`warning` · component: detection**

### What it means

A detector errored at least once in the last thirty minutes, at a rate too low to
trip the ratio alert. On a low-traffic instance a detector can be badly broken and
never reach 1% of a small denominator, which is why this exists separately.

### What to look at

Same as `FirewallDetectorErrorRateHigh`. Additionally, correlate against the audit
trail, which records every detector result including the ones that errored:

```bash
docker compose exec postgres psql -U firewall -d firewall -c \
  "select detector, error_kind, count(*) from detector_results
    where errored and created_at > now() - interval '1 day'
    group by 1,2 order by 3 desc;"
```

### What to do now

Nothing urgent. Determine whether it is a recurring trickle or a one-off — the query
above answers that over a day, which the metric's thirty-minute window cannot.

### Escalate when

The same `detector`/`error_kind` pair appears on consecutive days. A reproducible
error is a defect, not a blip, and it will eventually happen under load.

### Resolved when

No errors for a full day at representative traffic. Closing this during a quiet
period proves nothing.

---

## FirewallBlockRateStepChange

**`warning` · component: detection · `calibration: unvalidated`**

### What it means

The block rate differs from the same window yesterday by more than ten points.

**In this product a step change is almost always a policy change, not an attack.**
Thresholds, the detector registry, a new caller with different traffic, a
deployment — all of these move the block rate far more than adversaries do. Start
from that assumption and make the attack hypothesis earn its place.

### What to look at

```bash
curl -s 'localhost:8000/api/v1/overview?hours=48' | jq '.decisions'
curl -s 'localhost:8000/api/v1/security/events?hours=6&page_size=50' | jq '.items[] | {category, detector, severity, created_at}'
docker compose logs firewall-api | jq -c 'select(.event=="startup") | {policy_version, policy_name, input_detectors}'
```

`policy_version` is a hash of the loaded policy and it is recorded on **every audit
row**. If it changed, the cause is almost certainly that:

```sql
select policy_version, decision, count(*) from request_traces
 where created_at > now() - interval '2 days' group by 1,2 order by 1;
```

### What to do now

1. Compare `policy_version` across the window. A change there explains a step
   change, and the fix is to decide whether the new policy is right — not to
   silence the alert.
2. If the policy is unchanged, break the change down by category and by caller. One
   caller moving is an integration change; all callers moving is a traffic or model
   change.
3. A **fall** in block rate deserves more attention than a rise. A rise is usually
   false positives, which are visible and complained about. A fall is protection
   quietly not firing, which nobody reports.

### Escalate when

The block rate fell with no policy change, or one category rose sharply while the
others stayed flat. Both patterns suggest the detector, not the traffic, changed.

### Resolved when

The change is attributed. Attribution — not the rate returning to its old value —
is the resolution: a deliberate policy change should keep the new rate, and the
right action is to let the comparison window move on.

---

## FirewallUpstreamErrorsHigh

**`critical` · component: upstream · `calibration: unvalidated`**

### What it means

More than a tenth of requests are ending in an upstream error. The firewall is
working; the model endpoint behind it is not, and the protected application is
failing for its users.

The gateway is the first thing anyone blames when LLM calls fail, so the first job
is separating the two.

### What to look at

```bash
curl -s localhost:8000/metrics | grep -E 'firewall_upstream_(errors_total|latency_seconds_count)'
docker compose logs --since 15m firewall-api | jq -c 'select(.event=="upstream_transport_error")' | tail
curl -s 'localhost:8000/api/v1/metrics/latency?hours=1' | jq '{gateway_ms, upstream_ms}'
```

`upstream_ms.n` being far below `gateway_ms.n` is normal — a blocked request never
calls the model. That gap is the point of separating them and is not evidence of a
problem.

### What to do now

1. Check the provider's status page and your own egress before anything else.
2. `kind` on the error counter distinguishes a transport failure from a 5xx: the
   first is network or DNS on your side, the second is the provider's.
3. Do not disable detectors to "reduce load". Blocked requests never reach the
   upstream, so the firewall is if anything reducing the pressure on it.

### Escalate when

Errors are transport-kind and the provider reports healthy — that is your egress
path, and in the reference production topology the gateway reaches the internet on a
dedicated `egress` network worth checking separately.

### Resolved when

The ratio is below 1% for fifteen minutes and callers confirm success. The metric
counts what the gateway saw; the caller is the one who knows whether it worked.

---

## FirewallRetentionStalled

**`warning` · component: audit**

### What it means

No instance has completed a successful retention sweep in three hours, against an
hourly interval. Deletion has stopped and the store is growing again.

Note the gap this alert **cannot** see: a process whose every sweep has failed since
startup never sets the success timestamp, so its gauge stays at zero and is filtered
out of this expression on purpose — without that filter, `time() - 0` is the whole
Unix epoch and this alert would fire permanently on every instance with retention
off. `FirewallRetentionSweepsFailing` covers that case; the two are complementary
and neither is redundant.

### What to look at

```bash
curl -s localhost:8000/metrics | grep -E 'retention_(last_success|sweeps_total|enabled)|oldest_row_age'
docker compose logs --since 6h firewall-api | jq -c 'select(.event|startswith("retention_"))'
uv run python scripts/purge_audit.py       # dry run: is there a backlog
```

### What to do now

1. If sweeps are failing, follow `FirewallRetentionSweepsFailing`.
2. If sweeps are not running at all — no `retention_sweep` log lines and no failures
   either — the scheduler task is gone. Only a process restart brings it back; it is
   deliberately created once at startup.
3. `scripts/purge_audit.py --execute` clears the backlog by hand in the meantime.
   It runs the same sweeper with the same configuration, so it cannot delete
   anything the scheduler would not have.

### Escalate when

A restart does not resume sweeping, or `firewall_audit_oldest_row_age_seconds` keeps
climbing after it does.

### Resolved when

The timestamp is advancing on every instance **and** the oldest-row age is falling.
The timestamp alone only proves a sweep ran, not that it kept up.

---

## FirewallRetentionSweepsFailing

**`warning` · component: audit**

### What it means

At least one retention sweep raised in the last hour. The failure is caught,
counted and logged by design — a sweep that killed its task would turn a transient
database error into permanent, silent growth — which is precisely why nothing else
will mention it. The process stays healthy and `/ready` stays ready.

### What to look at

```bash
docker compose logs --since 2h firewall-api | jq -c 'select(.event=="retention_sweep_failed")'
curl -s localhost:8000/metrics | grep retention_sweeps_total
```

The log deliberately carries `error_kind` and not the exception text, which can
contain SQL parameters.

### What to do now

1. A statement timeout is the most likely cause: `Database` applies a five-second
   command timeout and a very large backlog can push a single batch past it. Lower
   `FIREWALL_RETENTION_BATCH_SIZE` — the batch is the tuning knob that exists for
   exactly this.
2. A permissions error means the application role lost `DELETE` on the audit tables.
   Retention needs it and ADR-012's original grant list did not include it (R-82).
3. A connection error is a database problem, not a retention one.

### Escalate when

Failures persist after the batch size is reduced, or the oldest-row age crosses the
configured period while they continue.

### Resolved when

An hour with no failures and a rising success timestamp.

---

## FirewallAuditBacklogExceedsRetention

**`warning` · component: audit · `calibration: unvalidated`**

### What it means

The oldest surviving row in a table is more than 1.5× its configured retention
period. Data is being kept longer than the policy says, which is both a disk and a
privacy issue.

**This is the alert that matters most about retention**, and it is deliberately not
built on the delete counter. A counter can tick steadily while the backlog grows —
deletion that removes a thousand rows an hour while two thousand arrive looks
healthy on every metric except this one (ADR-030).

The comparison is against `firewall_audit_retention_period_seconds`, which the
application exports from its own configuration. Change
`FIREWALL_RETENTION_TRACE_DAYS` and this alert follows automatically; it has no
number of its own to go stale.

### What to look at

```bash
curl -s localhost:8000/metrics | grep -E 'oldest_row_age|retention_period|rows_deleted'
docker compose logs --since 6h firewall-api | jq -c 'select(.event=="retention_budget_exhausted")'
uv run python scripts/purge_audit.py
```

`retention_budget_exhausted` appearing on consecutive sweeps is the diagnosis: the
per-sweep ceiling is stopping the sweep before it clears what is due.

### What to do now

1. If the budget is being exhausted, raise `FIREWALL_RETENTION_MAX_ROWS_PER_SWEEP`
   or shorten `FIREWALL_RETENTION_INTERVAL_S`. Both are safe; both mean more
   deletion per unit time.
2. If the budget is *not* being exhausted and the age is still climbing, deletion is
   working and arrival simply exceeds it. That is a capacity finding, and the answer
   at volume is partitioning rather than a bigger `DELETE` (OD-43).
3. A one-off catch-up: `scripts/purge_audit.py --execute`, repeatedly. Each run is
   bounded and safe to interrupt.

### Escalate when

The age keeps climbing after the interval and ceiling are both raised. That is the
trigger written into OD-43 for migrating these tables to declarative partitioning,
and it is a planned piece of work, not an emergency.

### Resolved when

The age is back below the configured period and stays there across several sweeps.

---

## FirewallAuditQueueSaturating

**`warning` · component: audit · `calibration: unvalidated`**

### What it means

The audit write queue has been more than half full for ten minutes. The writer is
not keeping up with arrivals. Nothing has been lost yet — this is the leading
indicator for `FirewallAuditEventsDropped`, and acting on it is how you avoid that
page.

This alert cannot fire in `sync` mode: there is no queue, so
`firewall_audit_queue_capacity` is absent and the expression yields nothing rather
than dividing by a fabricated denominator.

### What to look at

```bash
curl -s localhost:8000/metrics | grep -E 'audit_queue_(depth|capacity)|audit_write_failures'
docker compose exec postgres psql -U firewall -d firewall -c \
  "select state, count(*), max(now()-query_start) from pg_stat_activity group by 1;"
```

### What to do now

Treat the database, not the queue. Depth rising means writes are slow — check locks,
vacuum activity and disk. A larger queue only buys more time before the same
outcome.

### Escalate when

Depth is climbing monotonically rather than oscillating. A queue that oscillates is
absorbing bursts, which is its job; one that only climbs will reach capacity and
start dropping, and you can estimate when from the slope.

### Resolved when

Depth returns to near zero. Sustained non-zero depth on a healthy database means the
write rate genuinely exceeds what one writer can do, which is a sizing conversation
rather than an incident.

---

## FirewallConcurrencyRejections

**`warning` · component: capacity**

### What it means

Requests were refused with `503` because the process was already at its in-flight
ceiling. This is admission control working as designed — it exists so the process
sheds load instead of degrading for everyone — but every rejection is a caller
whose request did not happen.

### What to look at

```bash
curl -s localhost:8000/metrics | grep -E 'concurrency_rejections|firewall_active_requests'
docker compose logs --since 30m firewall-api | jq -c 'select(.event=="admission_rejected")' | wc -l
docker compose logs firewall-api | jq -c 'select(.event=="admission_control")'
```

Compare `firewall_active_requests` against the configured ceiling. If active is
pinned at the ceiling, the limit is binding; if it is well below, the rejections
were bursts.

### What to do now

1. Decide whether the ceiling or the traffic is wrong. `FIREWALL_MAX_CONCURRENT_REQUESTS`
   ships as a development default, not a measured one (R-67), so "the limit is too
   low" is a perfectly likely answer.
2. Check for a retry storm. A client retrying on 503 turns a brief saturation into a
   sustained one, and the rejection counter rises faster than real demand.
3. Volumetric shaping belongs at the edge, which can refuse a connection for the
   price of a RST. The in-process ceiling is a safety net, not the control
   (ADR-025).

### Escalate when

Rejections continue at a stable request rate — that means per-request cost went up,
and the cause is upstream latency or a detector, not the limit.

### Resolved when

Rejections stop and you have decided which of the two it was. Raising the ceiling
without deciding just moves the wall.

---

## FirewallCallerAuthFailureSpike

**`warning` · component: authentication · `calibration: unvalidated`**

### What it means

Sustained `/v1` authentication failures. The `reason` label separates the two
completely different situations this can be:

| `reason` | Usually |
|---|---|
| `missing_credential` | An integration that was never configured with a key |
| `malformed_credential` | A client sending the wrong header format |
| `unknown_credential` | A **rotated or revoked** key still in use — or credential guessing |

A steady rate from one source is a broken integration. A rising rate from many
sources is someone probing.

### What to look at

```bash
curl -s localhost:8000/metrics | grep -E 'caller_auth_failures_total|auth_failure_rate_limited_total'
docker compose logs --since 30m firewall-api | jq -c 'select(.event=="caller_auth_denied") | {reason}' | sort | uniq -c
docker compose logs firewall-api | jq -c 'select(.event=="caller_auth_enforced") | {callers}'
```

The denial log carries the **reason only** — never the presented credential, which
is deliberate and means you cannot identify the client from this log alone. Source
addresses come from the edge's access log.

### What to do now

1. Refusals happen in middleware, before any detector runs, so they cost no
   inference and never reach the upstream. There is no cost emergency here.
2. `FIREWALL_AUTH_FAILURES_PER_MINUTE` throttles repeated failures per client
   address before the credential comparison. If `firewall_auth_failure_rate_limited_total`
   is also rising, the throttle is already doing its job.
3. Rotation is additive: configure the new digest alongside the old, move the
   caller, then drop the old entry. A rotation done in the other order produces
   exactly this alert.

### Escalate when

`unknown_credential` is rising from many distinct source addresses. That is
guessing, and the edge is the place to stop it.

### Resolved when

The failure rate returns to baseline and the responsible integration is identified.
"It stopped" without knowing which caller it was leaves you unable to tell the same
event from an attack next time.

---

## FirewallOperatorAuthDenialSpike

**`warning` · component: authentication · `calibration: unvalidated`**

### What it means

Sustained denials on the operator console surface. **The common cause is a
misconfigured proxy, not an attacker** — specifically a proxy that has stopped
setting the identity header, at which point every legitimate operator request is
refused (R-61).

Identity is only read when the socket peer falls inside `FIREWALL_TRUSTED_PROXIES`.
A proxy that moved to a new address stops being trusted and every request through it
is denied, correctly.

### What to look at

```bash
curl -s localhost:8000/metrics | grep firewall_auth_denials_total
docker compose logs --since 30m firewall-api | jq -c 'select(.event=="auth_denied") | {access_class, reason}' | sort | uniq -c
docker compose logs firewall-api | jq -c 'select(.event=="startup") | {trusted_proxies, operator_roles, metrics_networks}'
```

`access_class` tells you which surface: `operator` is the console, `internal` is
`/metrics` — and a spike on `internal` is usually a scraper that lost its network
allowance rather than anything to do with people.

### What to do now

1. Compare the proxy's actual source address against `FIREWALL_TRUSTED_PROXIES`. In
   a container deployment this changes when networks are recreated.
2. Check the `reason` label. A reason meaning "untrusted peer" is a topology
   problem; one meaning "missing role" is an authorisation configuration problem.
3. `X-Forwarded-For` is never consulted by this application, so do not try to fix
   this by setting it.

### Escalate when

Denials come from addresses outside your infrastructure entirely. The console
should not be reachable from there at all, and that is a network exposure question
before it is an authentication one.

### Resolved when

The rate returns to baseline and operators can reach the console. Verify by using
it, not by reading the metric.

---

## FirewallGatewayOverheadHigh

**`warning` · component: performance · `calibration: unvalidated`**

### What it means

p95 gateway overhead is above 100 ms. **This metric excludes the audit write**
(R-77): `total_ms` is frozen before it, so what a caller actually waits for is
higher than this number. Quote it as "gateway overhead", never as end-to-end
latency.

For scale, the Phase 15 benchmark on the reference machine measured about 1.7 ms
p50 for everything except the audit write, and about 10.5 ms p50 for the
synchronous write. 100 ms is far above both — this threshold is a loose safety net,
not a target, and no SLO is claimed anywhere in this project.

### What to look at

```bash
curl -s 'localhost:8000/api/v1/metrics/latency?hours=1' | jq
curl -s localhost:8000/metrics | grep firewall_detector_latency_seconds_bucket | tail -20
```

`by_detector` in the latency endpoint is the decomposition that matters: the
pipeline runs detectors concurrently, so it costs its slowest member, and one slow
detector sets the whole figure.

### What to do now

1. Attribute it first. A single slow detector, a slow audit write and a saturated
   host produce the same p95 and have different fixes.
2. Check whether the host is CPU-bound. Detectors run concurrently on a bounded
   thread pool and contention shows up here before it shows up anywhere else.
3. `FIREWALL_EXPOSE_TIMING_HEADERS=true` gives per-stage timings per response for
   diagnosis. It is **off in production on purpose** — precise per-detector timings
   are a side channel that leaks which detector fired. Turn it off again afterwards.

### Escalate when

p95 rises with no traffic increase and no detector change. That usually means the
audit path, which this metric cannot see — check `firewall_audit_queue_depth` and
the database.

### Resolved when

p95 is back below the threshold. If the fix was a configuration change, re-measure
rather than assuming: this project's benchmark discipline applies to incidents too.

---

# Conditions that are deliberately NOT alerts

An alert nobody can act on trains people to ignore the ones they can. Each of these
was considered and rejected, with the condition that would change the decision.

### `/ready` returning 503 on one instance

The orchestrator already acts on it — that is what a readiness probe is for. Paging
a human to watch a load balancer remove an instance duplicates a working control.

*Would become an alert if:* the whole pool is unready simultaneously, which is a
different signal (no healthy backends) and belongs to whatever fronts the pool.

### Certificate expiry

This process holds no certificate. TLS terminates at the edge and monitoring an
expiry belongs to whatever issues it (R-69). An expiry check here could only ever
fire at restart, which would be worse than no check because it would look like one.

### `firewall_rate_limited_requests_total`

Counted **per process**. With N replicas a fleet threshold is wrong by a factor of
N, and the metric's own description says so. It is a dashboard signal for capacity
planning, not a page.

*Would become an alert if:* enforcement becomes distributed (OD-38), at which point
the count means what an operator would assume it means.

### `firewall_audit_rows_deleted_total`

The one metric about retention that must **not** be alerted on. A counter can tick
steadily while the backlog grows, so both "healthy" and "hopelessly behind" produce
a rising counter. `firewall_audit_oldest_row_age_seconds` answers the question this
one only appears to.

### A retention sweep that deleted zero rows

Entirely normal. Nothing was old enough. Alerting on it would page someone every
hour on a young deployment.

### Individual 4xx responses, and blocks themselves

A block is the product working. Paging on the thing the system exists to do is how
alert fatigue starts. Block *rate* changes are alerted; blocks are not.

### `firewall_active_requests` on its own

A gauge with no threshold worth defending. What matters is rejections, which are
alerted, and saturation, which shows up as latency.

### PII redactions

No metric exists and none is proposed. A count of redactions is a count of how much
sensitive data passed through, and alerting on it would push operators toward
inspecting exactly the content this system exists to avoid storing.

### Detector latency p95 in isolation

It surfaces as gateway overhead, which is alerted. A separate detector-latency alert
would fire simultaneously with that one for the same underlying cause, and two pages
for one incident is worse than one.

### "No traffic"

A blackbox concern about whether the service is reachable, not a property of the
firewall. It belongs to an uptime check that speaks HTTP, not to a rule over
counters that stop being produced when nothing happens.
