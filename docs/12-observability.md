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

## What an operator actually watches

1. `firewall_detector_errors_total` — nonzero means protection is degraded *now*.
2. `firewall_decisions_total{action="block"}` rate by category — a step change is almost
   always a policy or model change, not a coordinated attack.
3. `firewall_gateway_overhead_seconds` p95 — the number the platform team will ask about.
4. `firewall_audit_write_failures_total` — the audit trail going quiet is itself an event.
5. `/ready` flapping — usually memory pressure from model loading.
