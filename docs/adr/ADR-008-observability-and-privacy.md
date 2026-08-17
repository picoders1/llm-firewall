# ADR-008: OpenTelemetry-First Observability, Langfuse as an Exporter

**Status:** Accepted
**Date:** 2026-08-17
**Phase:** 0 (logging, metrics, span structure), Phase 5 (exporter wiring)

## Context

The brief named Langfuse, which is a good LLM-observability product. But instrumenting
directly against a vendor SDK means the vendor's client library sits on the request path of a
security control, its API shape is embedded across the codebase, and switching costs a
refactor.

There is a sharper problem specific to this product. LLM-observability tools are built to
show you **the prompt and the completion** — that is their core value. This system's entire
premise is that prompts are sensitive enough to require a firewall. Wiring in a tool whose
default behaviour is to ship every prompt to a SaaS backend would contradict the product.

## Decision

**Instrument against the OpenTelemetry API. Treat Langfuse as one OTLP exporter among
several, configured rather than coded.**

```
app code ──► OTel API ──► OTLP exporter ──► Langfuse | Tempo | Jaeger | Honeycomb | none
```

1. Application code imports only `opentelemetry.trace`. No vendor SDK appears outside
   configuration.
2. The exporter is selected by environment variable. Switching backends is a deploy-time
   change.
3. **Tracing is off by default** (`tracing_enabled=false`). A security gateway must not ship
   telemetry to a third party out of the box.
4. **Span attributes obey the same content rules as logs** ([logging.md](../10-security-model.md)):
   scores, categories, latencies, hashes, decisions — never prompt or completion text, never
   secrets. In practice this means Langfuse shows the *shape* of traffic rather than its
   content, and operators who expect otherwise are told so explicitly.
5. **Three signals, one correlation key.** `request_id` binds logs, metric exemplars, spans
   and audit rows. It is bound once in a contextvar at the outermost middleware.
6. **Metrics are Prometheus-native** (`prometheus-client`, `/metrics`). Pull-based scraping
   is the operational standard for this kind of service and does not depend on the tracing
   backend being available.

Span structure and the metric catalogue are in
[observability.md](../12-observability.md).

## Alternatives considered

| Alternative | Rejected because |
|---|---|
| **Langfuse SDK directly** | Vendor lock-in on the request path of a security control, and its natural usage pattern is prompt capture — the thing this product exists to protect. Its value here (prompt/completion inspection) is precisely what we cannot use. |
| **OTel auto-instrumentation for everything** | Convenient, and it captures HTTP bodies and database parameters by default. For this application that is an automatic prompt-leak. Manual, explicit spans only. |
| **Logs only, no tracing** | Cheapest, and it loses per-stage latency attribution — which is exactly the data needed to defend a gateway-overhead claim. |
| **OTel metrics instead of Prometheus client** | Defensible, and would unify the signal path. Rejected for now: the Prometheus client is simpler, the scrape model needs no collector, and metrics are the signal most likely to be needed when the tracing backend is down. Revisit if a collector becomes part of the standard deployment. |
| **Ship prompts to Langfuse for debugging** | Would make the observability backend the largest sensitive-data store in the architecture, defeating the product. |
| **Build a custom trace viewer** | Reinventing solved tooling. |

## Consequences

### Positive
* No vendor lock-in; backend choice is an environment variable, and a Langfuse outage cannot
  affect the gateway's request path.
* Content-free telemetry by construction — the privacy posture is a property of the design,
  not of operator discipline.
* Metrics remain available independently of tracing.
* One correlation key makes cross-signal investigation mechanical.

### Negative / accepted costs
* **Langfuse's headline features are unusable here.** Prompt playback, prompt versioning and
  content-based session inspection all depend on content this system will not send. What
  remains is latency and decision traces — real value, but less than a Langfuse user expects.
  Stated so nobody is surprised.
* OTel's API surface is more verbose than a purpose-built SDK, and manual spans are code that
  must be maintained.
* Two libraries for two signals (Prometheus for metrics, OTel for traces) instead of one.
* Traces disabled by default means the observability story requires an explicit opt-in step
  in deployment.

### Revisit when
Prometheus and OTel metrics need to merge behind a collector; or a self-hosted Langfuse
deployment inside the operator's trust boundary makes content-carrying spans acceptable for
that operator — which would be a per-deployment configuration decision, never a default.

## Verification

* No file under `app/` imports a Langfuse SDK — checked by an import test.
* `tests/security/test_log_leakage.py` — a canary prompt appears in no log record at default
  configuration.
* `tests/unit/test_span_attributes.py` — span attributes contain no content keys.
* `tests/api/test_metrics.py` — `/metrics` exposes the documented catalogue and no
  user-content-derived label.
* Default configuration boots with tracing disabled — settings test.
