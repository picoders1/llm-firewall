# Dashboard API contract

The backend/frontend contract for the Security Operations Dashboard. The frontend
(Vanilla HTML/CSS/JS, Phase 8) is written against **this document**, not against
whatever the implementation happens to return.

Implemented in `app/api/dashboard/`. Every endpoint is **read-only**. There is no
policy-editing, threshold-tuning or data-mutating endpoint, and there will not be
one here: a policy that changes without a reviewed deployment is a policy nobody
can audit.

---

## The rule that governs every response

**Real data only.** Every number comes from the audit tables or from a committed
evaluation artefact. Nothing is defaulted, sampled, smoothed or filled in.

Where there is nothing to report, the API says so explicitly rather than returning
a plausible-looking number:

| `status` | meaning | frontend should render |
|---|---|---|
| `ok` | real observations exist and are returned | the data |
| `empty` | the query succeeded and matched nothing | an empty state, not a zero-value chart |
| `degraded` | a dependency is unavailable, so the answer is unknown | a degraded banner — **not** "no traffic" |

`empty` and `degraded` are different claims and must look different. Zero requests
is a measurement; an unreachable database is not.

**A percentile is never returned without its sample size.** Every percentile block
carries `n`. When `n` is 0 the percentiles are `null`, not `0` — zero milliseconds
is a measurement, absence is not.

---

## Exposure and authentication

Every endpoint in this document is in the **operator** access class
([ADR-023](adr/ADR-023-operator-authentication.md)). Identity is terminated
outside the process — at a reverse proxy, identity-aware ingress or SSO edge —
and enforced by `app/middleware/auth.py` before any handler runs. No route here
performs its own check, deliberately: a per-route check is one that someone
forgets to add.

| Class | Paths | Requirement |
|---|---|---|
| Public | `/health`, `/ready` | none |
| Operator | `/dashboard/**`, everything in this document, and **any path not listed elsewhere** | authenticated operator; `GET`/`HEAD` only |
| Internal | `/metrics` | a declared scrape network **or** an operator identity |
| Gateway | `/v1/**` | a **caller** credential, which is a separate boundary with its own setting, header and principal type ([ADR-024](adr/ADR-024-llm-caller-authentication.md)). An operator identity does not authenticate a model call, and a caller key does not open this API |

Unknown paths default to **operator**, so an endpoint added to this API later is
protected before anyone remembers to classify it.

**Outside production the boundary is off** (`console_auth_mode` derives to
`disabled`), which is what keeps `docker compose up` a single command with no
credential. Setting it to `disabled` *in* production is refused at startup.

**Why this changed.** Phase 5 stated the assumption "internal network, or behind
a reverse proxy" here rather than leaving it implicit, precisely so it could not
be inherited by accident. The Phase 9 audit found that no such proxy existed
anywhere in the repository — the assumption was correct in shape and unenforced
in fact. What is exposed if the boundary is missing is still not prompt content,
which remains structurally impossible (see *Sensitivity*); it is thresholds and
block rates by category, which together describe how to tune an evasion against
this gateway without tripping it.

### `GET /api/v1/system/status` — caller-boundary fields

`caller_auth_mode` (`disabled` | `api_key` | `proxy`) and `caller_auth_enforced`.

Included on a documented operational need: "is `/v1` protected right now?" is a
question an operator has during an incident, and the alternative to answering it
here is shelling into the container. **A mode name and a boolean only** — never a
caller id, never a credential, never a digest. §23 of the Phase 10 brief permits
exactly this much and no more.

### `GET /api/v1/session`

Reports the authenticated operator, and nothing more than the console needs to
render a header: `authenticated`, `enforced`, `subject`, `role`, `logout_path`.
No email, no group list, no token, no identity-provider name.

It sits behind the boundary like everything else, so a `401` here **is** the
answer "not signed in" — which is what lets the console distinguish an expired
session from an unreachable gateway without a second, unprotected endpoint
existing purely to report authentication state.

---

## Sensitivity rules

Two independent layers, so a mistake in one does not become a leak:

1. **The audit schema cannot store content.** No column in `request_traces`,
   `detector_results` or `security_events` can hold a prompt or a completion —
   asserted against the table metadata by `tests/security/test_audit_privacy.py`.
2. **The DTO boundary lists every field explicitly.** No ORM row is returned from
   any endpoint. A column added to the schema cannot reach the API by being picked
   up automatically, because nothing iterates over columns.

**Never exposed, by any endpoint, in any field, including diagnostics:** prompt
text · model output · PII values · authorization headers · API keys · tokens ·
cookies · upstream credentials · stack traces · `source_ref` · absolute
filesystem paths · database URLs.

**Exposed instead:** `request_id`, timestamps, direction, detector name, category,
decision, severity, score, threshold, `policy_version`, provenance, trust,
latencies, HTTP status, a truncated content **hash** and a content **length**.

Evaluation responses expose benchmark metadata (CPU model, GPU, memory) because a
latency figure is uninterpretable without it, but the exact kernel and platform
strings are dropped, and `predictions.csv` is never read.

---

## Bounds

Every database-backed endpoint is bounded before the query is issued.

| Bound | Value |
|---|---|
| Maximum time window | **30 days** (720 h) |
| Default time window | 24 h |
| Minimum time window | 1 minute |
| Maximum page size | **200** |
| Default page size | 50 |
| Bucket intervals | `1m`, `5m`, `1h` — whitelist |
| Maximum buckets per response | **1500** |

A larger window is **clamped**, and the response says so: `window.requested_hours`,
`window.granted_hours` and `window.clamped` are always returned, so a dashboard
cannot render "last 90 days" over a 30-day answer.

An interval the caller **names** that would exceed 1500 buckets is **rejected**
with 400 — silently returning coarser data than asked for is its own kind of lie.
When no interval is given, the finest one that fits the window is chosen
automatically, so a 30-day overview is a valid request rather than an error.

Filters are validated against closed sets before they become SQL expressions. An
unknown filter value is a **400**, never silently ignored — ignoring it would show
unfiltered data under a filtered heading.

---

## Errors

All errors use the project's existing envelope (`app/api/errors.py`):

```json
{"error": {"message": "...", "type": "invalid_request_error", "request_id": "..."}}
```

| Status | When |
|---|---|
| 400 | invalid filter value, unknown interval, bucket limit exceeded, malformed parameter |
| 404 | unknown event id or evaluation run id |
| 405 | any mutating method — no endpoint here accepts one |
| 503 | event **detail** requested while persistence is disabled |

Note the deliberate asymmetry: list endpoints return `status: "degraded"` with an
empty payload when the database is absent, because a dashboard can still render
the rest of the page. A single-event lookup has nothing to degrade to, so it 503s.

---

## Endpoints

Base path `/api/v1`. All methods `GET`.

### `GET /overview`

Aggregate counts and a decision time-series.

**Query:** `hours` (float, clamped), `interval` (`1m|5m|1h`, auto-chosen if absent).

**Returns:** `window`, `status`, `total_requests`, `allowed_requests`,
`warned_requests`, `redacted_requests`, `blocked_requests`,
`not_evaluated_requests`, `detector_failures`, `upstream_failures`,
`requests_by_category[]`, `requests_by_detector[]`, `decisions_over_time[]`.

The five decision counts sum to `total_requests`. `not_evaluated` is a real
category: a request rejected before policy ran was never allowed, and recording it
as `allow` would claim a policy examined it.

### `GET /security/events`

**Query:** `hours`, `page` (≥1), `page_size` (≤200), and filters `decision`,
`category`, `detector`, `direction`, `severity` (0–10), `provenance`, `trust`,
`request_id`.

Ordering is `created_at DESC, id DESC`. The id tiebreak matters: `created_at` is
not unique, and an unstable sort makes page 2 silently drop or repeat rows.

**Returns:** `items[]` (`SecurityEventSummary`), `page{page,page_size,total,has_more}`,
`window`, `status`.

Offset pagination, not cursor: the bounded window plus the 200-row cap keeps
offsets shallow, and cursors would complicate a contract that does not yet need
them. Revisit if a deployment routinely pages deeply.

### `GET /security/events/{event_id}`

One event LEFT JOINed to its request trace. Left, not inner: `security_events`
outlives `request_traces` under retention, so an inner join would make old events
**disappear** rather than show with null operational fields.

Adds `policy_version`, `http_status`, `decision`, `gateway_latency_ms`,
`detector_latency_ms`, `upstream_latency_ms`, `upstream_called`, `details`.

**Null means "not recorded". It never means zero.**

### `GET /metrics/latency`

**Returns:** `gateway_ms`, `detector_ms`, `upstream_ms`, each
`{p50,p95,p99,n}`, plus `by_detector{}`.

`upstream_ms.n` is legitimately lower than `gateway_ms.n` — a blocked request
never calls the model. That gap is the point of separating them.

### `GET /metrics/traffic`

**Query:** `hours`, `interval`.
**Returns:** `points[]` of `{bucket, requests, success, client_errors,
server_errors, upstream_failures, detector_failures}`, plus `totals` and
`interval`. Buckets are ordered ascending. `totals` is `null` when there are no
points.

### `GET /detectors`

Configuration exactly as loaded — never as hoped.

**Returns per detector:** `name`, `category`, `directions[]`, `enabled`, `action`,
`threshold`, `timeout_ms`, `on_error`, `consumes_provenance`, `emits_spans`,
`calibrated`, `baseline`, `trust_overlays`, `enforcing`.

`enforcing` exists so a dashboard cannot imply a warn-only model is protecting
anything: it is true only when the detector is enabled **and** its action is
`block` or `redact`. `injection.transformer` reports
`enabled=false, action=warn, threshold=0.9955, enforcing=false, calibrated=true`,
and `injection.heuristic` reports `calibrated=false, baseline=true` — the
heuristic's score is a rule sum, not a probability.

### `GET /policy`

Diagnostic only. **Returns:** `policy_version`, `policy_name`, `generated_at`,
`detector_count`, `enabled_detector_count`, `active_actions[]`,
`provenance_overlay_count`, `inspect_roles[]`, `blocking_detectors[]`,
`fail_open_detectors[]`. No secret value is reachable — policy YAML structurally
rejects secret-shaped keys at load time.

### `GET /system/status`

**Returns:** `version`, `environment`, `ready`, `started_at`, `uptime_seconds`,
`dependencies[]`, `detectors_warmed`. Dependency status is `ok` /
`unavailable` / `not_configured` — no host, port, path or DSN.

`/health` and `/ready` keep their existing semantics and are unchanged.

### `GET /evaluations` and `GET /evaluations/{run_id}`

Read-only view over committed artefacts in `eval/results/`. **No evaluation table
exists**, deliberately: the harness writes those files, and copying them into
PostgreSQL would create a second copy that can disagree with the first.

Only runs with a **valid final artefact** are reported. Directories without one
are counted in `note` — an evaluation that vanished from the list is
indistinguishable from one that never ran.

`status` is one of `complete`, `superseded`, `failed`, `invalid`, `running`.
`superseded` is derived, not guessed: when several complete runs share a detector,
dataset and split, the newest is current. **The frontend must not render a
non-`complete` run as a benchmark result.**

`decision` is separate from `status`: ADR-019 and ADR-020 are *complete* runs whose
*decision* was FAILURE. A failed experiment is a finished one.

---

## `GET /metrics`

Prometheus exposition, outside `/api/v1`. **Internal** access class: reachable
from a declared scrape network or with an operator identity, never public. Safe to scrape
internally. Catalogue and label rules in
[12-observability.md](12-observability.md). Every label is a route template, an
enum, a registry detector name, an exception class name or an HTTP status class.
Open-ended labels are **bounded in code**, not assumed: above 32 distinct values a
label collapses to `other`, so a caller sending a unique `model` per request
cannot create a series per request.

A freshly started process exposes counters at zero. That is an empty state.

---

## The frontend built from this

Implemented in Phase 8: `dashboard/`, served at `/dashboard`. Architecture in
[ADR-022](adr/ADR-022-dashboard-frontend-architecture.md), details in
[23-dashboard-frontend.md](23-dashboard-frontend.md). The console is same-origin
with this API, which is why no CORS header appears anywhere in the contract.

## What the frontend builds from this

| View | Endpoints |
|---|---|
| Overview | `/overview` |
| Security events + detail | `/security/events`, `/security/events/{id}` |
| Detector / policy state | `/detectors`, `/policy` |
| Traffic & latency | `/metrics/traffic`, `/metrics/latency` |
| Evaluation comparison | `/evaluations`, `/evaluations/{run_id}` |
| System health | `/system/status`, `/health`, `/ready` |

---

## Known gaps

* **Provenance has fewer distinct values than the enum suggests.** It is derived
  from the message role, so live traffic shows `user_input`/`principal` on input
  events and `model_output`/`derived` on output-direction ones — genuinely two
  populations, but `tool_result`/`external` only appear once an integration
  actually sends tool or retrieved content. The filters work today; their
  selectivity depends on the deployment. **No index exists on those columns**
  because two values across a large table is not selective enough to justify one —
  add it when a deployment's distribution says otherwise, not before.
* **Operator authentication only** — no per-operator authorisation beyond the
  `OPERATOR` role, and no audit of who read what. See *Exposure* above.
* **Offset pagination** will get expensive if anyone pages deeply. The bounds make
  that unlikely rather than impossible.
* **Gateway overhead is per-request wall clock**, not a controlled benchmark. It is
  honest as an operational signal and must not be quoted as a product claim
  (docs/22-evidence-and-claims.md).
