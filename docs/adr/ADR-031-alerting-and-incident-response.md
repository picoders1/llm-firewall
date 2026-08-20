# ADR-031: Alerting Policy and Incident Runbook

**Status:** Accepted
**Date:** 2026-08-20
**Phase:** 17
**Fulfils:** [docs/19](../19-implementation-roadmap.md) tasks 5.6 (alert rules) and 5.7 (runbook, one entry per alert)

## Context

Twenty-three metrics, a Security Operations API, structured logs and an audit trail
— and **not one rule that says when any of it means someone should act**. The alarms
existed only as prose in the metric catalogue: *"alert on this"*, *"alert on any
nonzero value"*, *"alert on its age, not its value"*. Instructions in a table in
`docs/12-observability.md` are not an alerting policy; nothing evaluates them and
nobody is woken by them.

The gap matters more here than in an ordinary service. Most of what this system
detects is **silent by construction**: a fail-open detector that stops working
passes traffic uninspected and returns 200s; a full audit queue drops records while
every request succeeds; retention that stops running leaves a process perfectly
healthy. The failure modes this product cares about do not announce themselves in
latency or error rate, which is where a generic monitoring setup looks.

## Decision

Sixteen alert rules in `deploy/alerts/firewall.rules.yaml`, one runbook entry each
in `docs/runbook.md`, and a documented list of the conditions that are deliberately
**not** alerts.

### Two severities, defined by response

| | Meaning |
|---|---|
| `critical` | Wake someone now. Security evidence is being lost, protection is degraded, or the protected application is failing for its users. |
| `warning` | A ticket for the next working day. |

Five criticals, eleven warnings. There is no third level, because a severity that
means "look at it eventually" is a severity that means nothing, and every alerting
system that has one accumulates everything there.

The names are the conventional Alertmanager ones rather than a vocabulary of our
own. A private vocabulary would be clearer to read here and would have to be
translated by every deployment that already routes on `severity`.

### Symptom-based, with one deliberate exception

Rules fire on what an operator can act on, not on internal state. The exception is
the pair of configuration gauges (`firewall_https_enforced`,
`firewall_retention_enabled`), which are causes rather than symptoms — the symptom
of an unenforced transport is a credential someone else already has, which is not a
signal any metric will produce.

### Configuration is exported so alerts cannot go stale

Three gauges were added: `firewall_retention_enabled`,
`firewall_audit_retention_period_seconds{table}` and `firewall_audit_queue_capacity`.

They exist because the alternative is worse. A rule that says "older than 30 days"
is correct until someone sets `FIREWALL_RETENTION_TRACE_DAYS=7`, after which it is
silently wrong for three weeks at a time and nothing connects the two. Comparing
against the period the application actually has configured makes that class of drift
impossible, and a promtool test proves it by running the backlog alert against a
**seven**-day deployment.

`firewall_audit_queue_capacity` is absent in `sync` mode rather than zero. An
absent series makes the saturation rule produce no result; a zero would make it
divide by a denominator that does not exist.

### Every rule is unit-tested, and the near-misses are the point

`deploy/alerts/firewall.rules.test.yaml` drives the shipped rules through
`promtool test rules` with synthetic series: 24 cases, every alert exercised at
least once, asserted by `tests/unit/test_alert_rules.py` so an alert cannot be added
without one.

The cases that earn their keep are the ones asserting **silence**:

* A single transient audit-write failure does **not** page. `rate() > 0 for 10m`
  means a database that is down, not a blip.
* `firewall_retention_last_success_timestamp_seconds` is `0` on any process where
  retention is off or has not yet swept. Without the `> 0` filter inside the
  aggregation, `time() - 0` is the entire Unix epoch, and the staleness alert fires
  instantly and permanently on every such instance — which is how an alert gets
  switched off by the first operator who sees it.
* `sync` mode has no queue, so the saturation alert has no data rather than a
  fabricated ratio.
* An idle instance does not alert on a block-rate step change, because the traffic
  floor stops ratio arithmetic being dominated by single requests.

Each of those is a way an alert file quietly becomes useless. None of them is
visible in the rule text.

### The rules and the runbook are bound in both directions

`tests/unit/test_alert_rules.py` fails if an alert has no runbook section **or** a
runbook section names no alert, and it checks that each rule's `runbook` annotation
resolves to the anchor it advertises. It also checks that every metric a rule names
is actually exported by the application registry — the failure that prevents is the
quiet one, since a rule naming a renamed metric evaluates to an empty vector forever
and looks exactly like health.

### Thresholds are labelled as the guesses they are

Every threshold not derived from a documented invariant carries
`calibration: unvalidated`, and the runbook repeats it — enforced by test, so a
number cannot be presented as measured in one place and as a guess in the other.

This project has no production traffic. Publishing tuned-looking numbers without
traffic to tune against would be exactly the unbacked claim
[docs/22](../22-evidence-and-claims.md) refuses, and R-67 already records the same
problem for the shipped rate limits. Shipping labelled guesses beats shipping an
empty file: an operator can adjust a starting point and cannot adjust nothing.

### What is deliberately not an alert

Documented in the runbook with the circumstance that would change each call. The
substantive ones:

* **`firewall_audit_rows_deleted_total`** — the one retention metric that must not
  be alerted on. A counter ticks steadily whether deletion is keeping up or hopelessly
  behind; `firewall_audit_oldest_row_age_seconds` answers the question it only
  appears to (ADR-030).
* **`/ready` on a single instance** — the orchestrator already acts on it. Paging a
  human to watch a load balancer remove an instance duplicates a working control.
* **Certificate expiry** — this process holds no certificate. A check here could
  only fire at restart, which is worse than no check because it looks like one (R-69).
* **`firewall_rate_limited_requests_total`** — counted per process, so a fleet
  threshold is wrong by a factor of N. It becomes alertable if enforcement becomes
  distributed (OD-38).
* **Blocks themselves** — the product working. Block *rate changes* are alerted.
* **PII redaction counts** — no metric exists and none is proposed. Alerting on how
  much sensitive data passed through pushes operators toward inspecting exactly the
  content this system exists not to store.

### Alertmanager is not shipped

`compose.observability.yaml` runs Prometheus over the development stack to evaluate
the rules against a real gateway. It stops there. Routing, silencing, escalation
policy and on-call rotation belong to whatever an operator already runs, and a
second opinion about them from this repository would be noise in someone else's
working setup. The rules carry the labels those systems route on.

## The defect this phase found

**`/metrics` could not be scraped by Prometheus at all.** `app/observability/metrics.py`
imported `CONTENT_TYPE_LATEST` from `prometheus_client.openmetrics.exposition` while
generating the body with `generate_latest`, which emits the Prometheus **text**
format. Prometheus trusts the declared content type, parsed the body as OpenMetrics,
and rejected every scrape:

```
llm-firewall  down  "data does not end with # EOF"
```

Every metric in the catalogue was unreachable, so **no alert in this repository
could ever have fired**, and neither could any dashboard have been built. The fix is
one import.

It is worth being precise about why nothing caught it. `tests/api/test_metrics_endpoint.py`
asserts the endpoint against `docs/12-observability.md` — a good test, and it passes
against a body no Prometheus will accept, because it is not a Prometheus. The bug
was not in the exposition and not in the catalogue; it was in the one property
neither artefact describes. It is recorded as **R-87**, and
`tests/integration/test_alerting.py` now scrapes with the real server so it cannot
return.

## Alternatives considered

| Alternative | Rejected because |
|---|---|
| **Ship an Alertmanager configuration too** | Routing and escalation are properties of an organisation, not of this application. A shipped config would be either ignored or, worse, adopted and wrong |
| **One severity** | Everything becomes a page and the pages get ignored, which is indistinguishable from having no alerts |
| **Four or five severities** | Every level below "act today" accumulates alerts nobody triages. Two forces the question "is this worth waking someone for" at authoring time, which is the only time it gets an honest answer |
| **SLO burn-rate alerting** | The correct shape for a mature service and impossible here: no SLO exists, and Phase 15 explicitly refused to publish one from laptop-class measurements. Inventing an availability target to alert against would be fabricating the number the alert depends on |
| **Alert on `/ready`** | Duplicates the orchestrator, and ADR-027 already made the requirement level of each check the decision point. A ready/unready alert would re-litigate that in a second place |
| **Hardcode retention thresholds in the rule file** | The application owns the periods. A rule with its own copy is a second source of truth that drifts silently and asymmetrically — the rule gets stale, the config does not |
| **Log-based alerting instead of metrics** | The structured logs carry more detail, and turning them into alerts requires a log pipeline this project does not specify. Complementary, not a substitute; the runbook uses the logs as *evidence* for every alert |
| **Skip promtool tests; the expressions are simple** | Four of them were not. The zero-valued gauge, the single-failure hold, the absent-series division and the idle-instance ratio were all found by writing the test, not by reading the rule |
| **Grafana dashboards in this phase** | Roadmap task 5.4, and a different job: a dashboard answers "what is happening", an alert answers "should someone act". Doing both at once usually produces alerts derived from panels, which is backwards |

## Consequences

### Positive

* Every documented alarm in the metric catalogue is now an evaluated rule with
  instructions attached.
* An alert cannot ship without a runbook entry, a promtool test, or a metric that
  exists — all three are test-enforced.
* Three classes of configuration drift are impossible by construction: rule vs
  retention period, rule vs metric name, rule vs runbook.
* The scrape path is verified end to end against a real Prometheus, which is how the
  content-type defect surfaced.

### Negative / accepted costs

* **Most thresholds are guesses.** They are labelled, but a labelled guess still
  pages someone at the wrong time. The first weeks of real traffic should change
  most of them and that is expected maintenance, not a defect.
* **`FirewallBlockRateStepChange` cannot fire on a deployment younger than a day.**
  It compares against `offset 1d`, which returns nothing before then — silently.
  Accepted: the alternative is a fixed block-rate threshold, and nobody knows what
  the right block rate is for a deployment they have not seen.
* **The rules assume one Prometheus scrapes all replicas.** Aggregations are written
  for that. A federated or sharded setup needs them revisited, and nothing detects
  that they were not.
* **promtool tests are synthetic.** They prove the expressions mean what was
  intended against series someone wrote; they cannot prove the thresholds are right.
* No alert covers the window between a process starting and its first scrape.
* Two alerts (`FirewallHTTPSEnforcementDisabled`, `FirewallRetentionDisabled`)
  re-assert startup invariants and cannot fire in a correctly built production
  process — the same honest limitation as the readiness security checks (R-71).
  Their value is catching a relaxed check or a mislabelled instance, which is real
  but narrower than it looks.

### Revisit when

Real traffic exists — recalibrate every `calibration: unvalidated` threshold and
delete the label as each is replaced by a measured value. Also when an SLO is
defined (burn-rate alerts become possible and better), and when rate limiting
becomes distributed (OD-38), at which point
`firewall_rate_limited_requests_total` means what an operator would assume.

## Verification

* `promtool check rules` — 16 rules, valid.
* `promtool test rules` — 24 test cases across the shipped rule file, every alert
  exercised, firing and near-miss both asserted. The harness was negative-controlled:
  a deliberately wrong expected annotation fails the run with a diff, so the suite
  can bite.
* `tests/unit/test_alert_rules.py` — 88 tests binding rules, runbook, registry and
  promtool coverage in both directions.
* `tests/integration/test_alerting.py` — runs both promtool commands, and against a
  live Prometheus asserts the target is **up**, the shipped rules are loaded, and
  every metric the rules name appears in scraped data.
* Observed end to end against the development stack, which runs with HTTPS
  enforcement and retention both off. Prometheus scraped the gateway, evaluated the
  shipped rules, and moved `FirewallHTTPSEnforcementDisabled` from `pending` to
  **`firing`** after its five-minute hold, carrying `severity=critical`,
  `component=transport` and its runbook anchor. `FirewallRetentionDisabled` was
  observed `pending` under its deliberately longer thirty-minute hold — the hold
  that exists so a rolling restart cannot raise a ticket. Both are correct for that
  configuration: a development stack genuinely is not enforcing HTTPS and genuinely
  is not deleting anything.
