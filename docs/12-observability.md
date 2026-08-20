# Observability

Three signals, one correlation key. Everything a `request_id` touches — a log line, a
metric exemplar, a span, an audit row — can be joined on it.

```
                    request_id (contextvar, bound at the outermost middleware)
                              │
        ┌─────────────────────┼─────────────────────┐
        ▼                     ▼                     ▼
   structlog JSON      Prometheus /metrics      OTel spans
   (stdout → any        (scrape → Grafana)      (OTLP → Langfuse,
    log pipeline)                                Tempo, Jaeger, …)
        │
        ▼
   PostgreSQL audit tables
```

## Logging

`structlog` with a JSON renderer to stdout. Containers do not manage log files; the
platform does.

Every line carries `request_id`, `event`, `level`, `timestamp`, `logger`, plus the
service/version/environment. The `request_id` comes from a `contextvar` bound once in
middleware, so no function has to thread it through its signature — a detail that matters
because the alternative is a `request_id` parameter on every internal API, which people
eventually stop passing.

### Content is not logged

Redaction is enforced by a **structlog processor at the sink**, not by discipline at each
call site. The processor drops or transforms any key in a known content set
(`content`, `prompt`, `completion`, `messages`, `text`, `raw_text`, `normalized_text`)
according to `content_logging`:

| Mode | Behaviour | Intended use |
|---|---|---|
| `none` (default) | Content keys removed entirely | Production |
| `hash` | Replaced with truncated SHA-256 + length | Production where payload correlation is needed |
| `full` | Passed through | Local debugging only; **downgraded to `hash` when `environment=production`**, in code, not by convention |

Placing this at the sink means a future contributor who logs `logger.info("blocked", prompt=text)`
does not create a leak. A dedicated security test asserts that a known prompt string never
appears in captured log output at the default configuration
([FR/NFR verification](01-requirements.md)).

Never logged under any mode: the upstream API key, the database URL, `Authorization`
headers, `.env` values. These are typed `SecretStr` so an accidental interpolation renders
as `**********`.

## Metrics

Prometheus text exposition on `GET /metrics`, disableable via `metrics_enabled`.

| Metric | Type | Labels | Why |
|---|---|---|---|
| `firewall_requests_total` | counter | `route`, `status`, `decision` | Traffic and block-rate |
| `firewall_decisions_total` | counter | `direction`, `action`, `category` | **Block rate by category is the operator's primary false-positive alarm** — a spike usually means a policy change, not an attack |
| `firewall_detector_latency_seconds` | histogram | `detector`, `direction` | Per-detector budget; the pipeline costs its slowest member |
| `firewall_detector_errors_total` | counter | `detector`, `error_kind` | **Alert on this.** A detector erroring is a silent security failure even when it fails closed |
| `firewall_gateway_overhead_seconds` | histogram | `route` | The headline number, measured in production, not only in benchmarks |
| `firewall_upstream_latency_seconds` | histogram | `model`, `outcome` | Separates "the firewall is slow" from "the model is slow" |
| `firewall_upstream_errors_total` | counter | `kind` | |
| `firewall_audit_write_failures_total` | counter | — | Audit sink health; see [ADR-012](adr/ADR-012-persistence-and-retention.md) |
| `firewall_request_bytes` | histogram | `route` | Sizing and abuse detection |
| `firewall_caller_requests_total` | counter | `caller` | Authenticated gateway traffic by calling application ([ADR-024](adr/ADR-024-llm-caller-authentication.md)). `caller` comes from configuration, not the wire, and still passes through `bounded_label` |
| `firewall_caller_auth_failures_total` | counter | `reason` | **Alert on a sustained rate.** Either a caller's credential is wrong or rotated, or someone is probing for one. `reason` is a closed enum, never a presented credential |
| `firewall_rate_limited_requests_total` | counter | `caller`, `limit` | Per-caller ceiling hits, `limit` being `rate` or `concurrency`. Counted **per process**: with N replicas the real ceiling is N times the configured one |
| `firewall_audit_events_dropped_total` | counter | — | Audit records discarded because the write queue was full ([ADR-029](adr/ADR-029-audit-write-architecture.md)). **Alert on any nonzero value** — the audit trail is incomplete from that moment, and nothing else says so |
| `firewall_audit_queue_depth` | gauge | — | Records waiting to be written. Sustained depth is the leading indicator: it precedes either dropping or the request path starting to wait |
| `firewall_audit_rows_deleted_total` | counter | `table` | Rows removed by the retention sweep ([ADR-030](adr/ADR-030-audit-retention.md)). Includes the rows the foreign key cascaded, not only the parents — `detector_results` is four times the volume of `request_traces`, and a counter that reported only parents would understate the work by that factor |
| `firewall_retention_sweeps_total` | counter | `outcome` | `success` or `failed`. A sustained `failed` rate means the audit store is growing without bound and nothing else is saying so |
| `firewall_retention_last_success_timestamp_seconds` | gauge | — | **Alert on its age, not its value.** Retention failing quietly is the failure mode that matters; the process stays healthy either way |
| `firewall_audit_oldest_row_age_seconds` | gauge | `table` | **The metric that says retention is working**, which the delete counter does not: a counter can tick steadily while the backlog grows. Compare against the configured period. Reported for the two age-swept tables only — `min(created_at)` on `detector_results` would be a sequential scan of the largest table in the schema |
| `firewall_retention_enabled` | gauge | — | 1 when this process deletes rows past their period ([ADR-030](adr/ADR-030-audit-retention.md)). A configuration fact reported whether it is on or off, so "nothing is enforcing retention" is a value an alert can match rather than an absent series nobody notices (R-84) |
| `firewall_audit_retention_period_seconds` | gauge | `table` | The configured maximum age, exported so an alert compares the backlog against the period **actually in force** instead of a number copied into a rule file. Change `FIREWALL_RETENTION_TRACE_DAYS` and the alert follows ([ADR-031](adr/ADR-031-alerting-and-incident-response.md)) |
| `firewall_audit_queue_capacity` | gauge | — | Bound on the write queue. **Absent in `sync` mode**, which is the honest representation: there is no queue to saturate, so the saturation alert has no data rather than a fabricated denominator |
| `firewall_https_enforced` | gauge | — | 1 when this process refuses requests whose client hop was not TLS ([ADR-026](adr/ADR-026-secure-transport.md)). **Alert on a production instance reporting 0.** No label: there is nothing to break it down by that would not be constant or unbounded. Certificate *expiry* is deliberately absent — this process holds no certificate, and monitoring one belongs to whatever issues it (R-69) |
| `firewall_auth_denials_total` | counter | `access_class`, `reason` | Operator-console refusals ([ADR-023](adr/ADR-023-operator-authentication.md)). Both labels are closed enums — `reason` is never derived from a header |

Bucket boundaries are chosen for this domain, not left at library defaults: detector and
overhead histograms use millisecond-resolution buckets (1, 2, 5, 10, 25, 50, 100, 250, 500,
1000 ms), while upstream latency uses second-resolution buckets. Default buckets would put
the entire interesting range of gateway overhead into a single bucket.

**No label is ever derived from user content.** Model names and route templates are bounded
sets; a label sourced from a prompt is an unbounded-cardinality memory leak and a content
leak at the same time.

`firewall_gateway_overhead_seconds` is computed as total handler wall-clock minus measured
upstream wall-clock. That definition is stated here, in the metric's help text, and in
[performance-benchmarking.md](15-performance-benchmarking.md), because a
gateway-overhead number is meaningless without it.

## Tracing

OpenTelemetry is the tracing substrate; Langfuse is an OTLP **exporter**, configured, not
coded ([ADR-008](adr/ADR-008-observability-and-privacy.md)). Instrumenting against the
OTel API rather than a vendor SDK means switching to Tempo, Jaeger or Honeycomb is an
environment variable, and it keeps a security product from depending on one observability
vendor's availability.

Span structure per request:

```
firewall.request                       (root; request_id, model, decision)
├── firewall.validate
├── firewall.normalize
├── firewall.detect.input              (batch)
│   ├── detector.injection.heuristic   (score, detected, errored)
│   ├── detector.jailbreak.stub
│   └── detector.pii.regex
├── firewall.policy.input              (action, category, policy_version)
├── firewall.upstream                  (upstream host, status, tokens)
├── firewall.detect.output             (batch)
└── firewall.policy.output
```

Span attributes follow the same content rules as logs: scores, categories, latencies and
hashes — never prompt text. Langfuse's usual value proposition is showing you the prompt;
in this deployment it shows you the *shape* of the prompt. That trade is deliberate and is
called out for operators who expect otherwise.

Tracing is **off by default** (`tracing_enabled=false`). A security gateway that ships
telemetry to a third party out of the box would be the wrong default for a product whose
entire premise is that this data is sensitive.

## Health and readiness

Two endpoints with genuinely different meanings — conflating them is how a deployment ends
up routing traffic to a process whose models have not loaded.

| Endpoint | Question | Checks | On failure |
|---|---|---|---|
| `GET /health` | Is the process alive? | Nothing external. Constant-time. | Liveness probe restarts the container |
| `GET /ready` | Can it serve correctly? | Policy loaded and valid · all detectors warmed up · database reachable (when `persist_events`) · upstream base URL configured | `503` with a per-check breakdown; load balancer removes the instance |

`/ready` returning `503` for a detector that failed to warm up is the same principle as
`fail_closed`: an instance that cannot inspect should not receive traffic it would have to
either wave through or reject.

Neither endpoint requires authentication, and neither reveals configuration values — only
check names and pass/fail.

## Alerting

The catalogue above says "alert on this" in several places. Since Phase 17 those are
evaluated rules rather than instructions in a table:

* **[`deploy/alerts/firewall.rules.yaml`](../deploy/alerts/firewall.rules.yaml)** —
  16 rules, two severities (`critical` = wake someone, `warning` = a ticket).
* **[`docs/runbook.md`](runbook.md)** — one entry per alert: what it means, what to
  inspect, what to do now, when to escalate, when it is over. Plus the conditions
  that are deliberately **not** alerts, each with the circumstance that would change
  the decision.
* **[`deploy/alerts/firewall.rules.test.yaml`](../deploy/alerts/firewall.rules.test.yaml)**
  — `promtool test rules` cases, run in CI. Every alert is exercised, and the
  near-misses are asserted as carefully as the firing cases.

Rules, runbook and this catalogue are bound by `tests/unit/test_alert_rules.py`: an
alert with no runbook entry, a runbook entry with no alert, or a rule naming a metric
this application does not export all fail the suite.

**Thresholds marked `calibration: unvalidated` are development defaults**, not
measured values, for the same reason the rate limits are (R-67). They are labelled
in both the rule file and the runbook so nobody mistakes one for evidence.

`compose.observability.yaml` runs Prometheus over the development stack to evaluate
them against a real gateway. Alertmanager is deliberately not shipped: routing and
escalation belong to whatever an operator already runs ([ADR-031](adr/ADR-031-alerting-and-incident-response.md)).

## What an operator actually watches

1. `firewall_detector_errors_total` — nonzero means protection is degraded *now*.
2. `firewall_decisions_total{action="block"}` rate by category — a step change is almost
   always a policy or model change, not a coordinated attack.
3. `firewall_gateway_overhead_seconds` p95 — the number the platform team will ask about.
4. `firewall_audit_write_failures_total` — the audit trail going quiet is itself an event.
5. **`/ready` advisory findings** — logged as `ready_with_advisories`. They never change the
   status code, so nothing else will page anyone about a stale audit schema or a trusted
   range that spans a whole network ([ADR-027](adr/ADR-027-readiness-contract.md)).
5. `/ready` flapping — usually memory pressure from model loading.


---

## Implemented in Phase 5

The catalogue above is no longer a plan. `app/observability/metrics.py` exposes
every metric in it through `GET /metrics`, and `tests/api/test_metrics_endpoint.py`
asserts the endpoint against **this document** rather than against the code, so the
two cannot drift apart silently.

### The cardinality assumption is now enforced, not trusted

This document said "model names and route templates are bounded sets". Route
templates genuinely are. **Model names are not** — they arrive from the client, and
a caller sending a unique string per request would turn one label into an unbounded
memory leak.

`bounded_label` caps each open-ended label at 32 distinct values and collapses the
rest to `other`. A security test drives 80 distinct model names through the gateway
and asserts the series count stays bounded. The assumption is now a property of the
code.

Status labels are HTTP **classes** (`4xx`), never raw codes, for the same reason.

### Where metrics are emitted

From the single point where the audit record is assembled
(`app/api/v1/chat.py`), not from a second traversal of the request. Metrics and the
audit table are therefore derived from one object, and a discrepancy between the
dashboard and the audit trail cannot come from two code paths disagreeing.

### The Security Operations API

`app/api/dashboard/` serves the read-only query layer the dashboard consumes;
`docs/dashboard-api-contract.md` is the authoritative contract. Aggregation happens
in PostgreSQL (`percentile_cont`, `date_trunc`), bounded before the query is issued:
30-day maximum window, 200-row page cap, whitelisted bucket intervals and a
1500-bucket ceiling.

**No cache, and none is justified yet.** Measured against the live stack, every
endpoint answers in under 7 ms at p99 on a small dataset — the slowest is
`/overview` at 4.7 ms p50, which issues six aggregate queries. That is a
slow-query smoke test on a small table, **not** a production performance claim.
Revisit materialisation when a real dataset says so (§19 of the Phase 5 brief).
