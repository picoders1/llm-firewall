# Security Model

How the gateway handles sensitive content, and how it protects itself. The *threats* are
catalogued in [09-threat-model.md](09-threat-model.md); this document is the control side of
that ledger.

* **Part 1 — Content handling, logging and retention.** The uncomfortable property of this
  product: a firewall that inspects prompts is a system that has all the prompts.
* **Part 2 — Hardening baseline.** Limits, timeouts, secrets, container and supply-chain
  posture, and what is deliberately delegated to the deployment.

---

## Part 1 — Content handling, logging and retention


The uncomfortable property of this product: **a firewall that inspects prompts is, by
construction, a system that has all the prompts.** Every prompt worth protecting passes
through it, and the naive implementation — log everything, you'll want it for debugging —
turns the security control into the largest single collection of sensitive user text in the
architecture.

This document states how that is handled and what it costs.

### Principle

> Record enough to investigate an incident. Record nothing that would make the recording
> itself the incident.

Concretely: decisions, scores, categories, latencies, and *fingerprints* of content are
recorded. Content is not.

### Content-logging modes

Set by `FIREWALL_CONTENT_LOGGING`.

| Mode | Emitted | Investigation value | Risk | Use |
|---|---|---|---|---|
| `none` | Nothing derived from content | Decisions and scores only | Minimal | **Default. Production.** |
| `hash` | `sha256:<16 hex>` + character length | Correlate repeat payloads, count distinct attacks, prove two events shared a payload | Fingerprint only; not reversible for realistic prompts | Production where campaign detection matters |
| `full` | Content, truncated to a configured preview length | Complete | **Creates a sensitive datastore** | Local development only |

`full` is **refused in production**: `Settings.effective_content_logging()` downgrades it to
`hash` when `environment=production`. Enforced in code, with a unit test, because a
production incident is exactly when someone reaches for `full` at 3 a.m.

#### Why hashing is genuinely useful, and its honest limit

Hashing turns "someone is probing us" into a `GROUP BY content_hash` — repeat-payload
detection with no prompt storage. The limit: a short, low-entropy, or guessable prompt can
be confirmed by an attacker who can hash candidates. The hash proves *sameness*, it does
not protect *secrecy* of a guessable string. For high-entropy prompts (the ones that matter)
it is effectively opaque.

### Enforcement point

Redaction is a **structlog processor at the sink**, not a rule each call site follows.

```
logger.info("decision", detector=..., score=..., content=text)
                                                   │
                          ┌────────────────────────▼──────────────────────┐
                          │ redact_content processor                      │
                          │  keys: content, prompt, completion, messages, │
                          │        text, raw_text, normalized_text,       │
                          │        matched, span_text                     │
                          │  none → drop · hash → fingerprint · full → keep│
                          └───────────────────────────────────────────────┘
```

The reason for sink-level enforcement: a future contributor *will* write
`logger.info("blocked", prompt=text)`. At the sink, that line is harmless. Enforced per
call site, it is a leak that passes review because it looks like debugging.

**Verified by test.** `tests/security/test_log_leakage.py` drives a request containing a
known canary string through the app with captured logs and asserts the canary appears in no
log record, at the default configuration. It is a security test, and its failure blocks CI.

### Never logged, in any mode

Upstream API key · `Authorization` headers · database URL and password · full upstream URLs
with query strings · `.env` contents · matched span *contents* (offsets and labels only) ·
stack traces returned to clients (server-side only).

Secrets are typed `SecretStr`, so accidental interpolation renders `**********` rather than
the value. That is a safety net beneath the rule, not a substitute for it.

### What *is* recorded, always

`request_id` · timestamp · model · upstream host · decision and category · triggering
detector · per-detector score, threshold, latency, error state · gateway/upstream/detector
latency · status code · token and character counts · policy version · content hash and
length (in `hash` mode) · client identifier (never the key).

This set is sufficient to answer: what was blocked, why, by which detector, under which
policy, how expensive it was, and whether the same payload has been seen before.

It is *not* sufficient to answer: what did the user actually say. That is the trade, and it
is deliberate. Operators who need the second answer must knowingly enable `full` outside
production and accept what they have created.

### Log injection

Client-supplied `X-Request-ID` is validated (≤128 chars, `[A-Za-z0-9-_:.]` only) before it
is bound to the logging context. Without that, a header containing a newline and a forged
JSON object writes attacker-controlled records into the security log — a real attack on the
audit trail, not a theoretical one. JSON rendering makes forgery harder, but the header is
untrusted input and is validated as such.

### Retention

| Store | Default | Rationale |
|---|---|---|
| stdout logs | Platform-defined | Out of our control; document what the platform does |
| `request_traces` (and `detector_results`, by cascade) | 30 days | Tuning window |
| `security_events` | 180 days | Investigations start late |
| `content_preview` column | Never populated in production | |
| Evaluation data | Indefinite | Public benchmark data, no user content |

Retention values are printed at startup so a deployment cannot silently retain more than
intended — including when retention is **off**, which is the code default and which
startup reports as a warning naming the consequence.

Enforcement is a scheduled deletion job, not a runbook step, and since
[ADR-030](adr/ADR-030-audit-retention.md) that job exists rather than being planned:
an in-process sweeper, off the request path, deleting in bounded batches by age and
by nothing else. `uv run python scripts/purge_audit.py` reports what it would delete
without deleting it; `--execute` is required to actually delete, and there is no flag
that lets a purge be aimed at particular rows.

`policy_decisions` appears in earlier versions of this table because ADR-012
anticipated it. It was never created and nothing writes it.

### Deployment obligations (the gateway cannot enforce these)

1. **TLS terminates at or before the gateway.** Plaintext prompts on the wire defeat
   everything here — and so do plaintext credentials. Since P12 the application verifies
   this rather than trusting it: `FIREWALL_HTTPS_ENFORCED` plus a trusted proxy asserting
   `X-Forwarded-Proto`, refused at startup in production if absent
   ([ADR-026](adr/ADR-026-secure-transport.md)).
2. **The log pipeline inherits the sensitivity of what it carries.** Even at `none`, block
   events reveal who is being blocked and for what; treat the log store as security data.
3. **The database holds the audit trail.** Restrict access, encrypt at rest, and back up —
   note that backups inherit the retention policy and will outlive the deletion job unless
   configured otherwise.
4. **`full` content logging is a decision with a data-protection consequence**, not a debug
   flag. If your organisation has a DPIA process, this is in scope for it.

### Data-subject requests

At `none` or `hash`, the system holds **no personal data attributable to an individual** —
by design, hashes are not linked to user identity, and the gateway does not receive user
identifiers unless the client sends them. Erasure of prompt content is therefore
unnecessary: it was never stored.

If an operator adds a `client_id` that identifies a natural person, or enables `full`, that
changes and becomes the operator's obligation. Stated here so the choice is informed. This
is a description of the system's behaviour, not legal advice, and it is not a compliance
claim of any kind.

---

## Part 2 — Hardening baseline


Controls the gateway implements, and the ones it deliberately delegates. Numbered by
threat ID from [threat-model.md](09-threat-model.md) where applicable.

### Request limits

| Control | Default | Notes |
|---|---|---|
| `max_request_bytes` | 256 KiB | Enforced on `Content-Length` **and** during body streaming, so a chunked request cannot bypass it. `413` before the body is fully read (T-16) |
| `max_inspect_chars` | 100 000 per message | Bounds detector CPU. Truncation is recorded on the event, so a partially-inspected request is never mistaken for a clean one |
| JSON depth / array size | Framework defaults + explicit `messages` length cap | A 10 000-message conversation is a CPU amplification vector |
| Base64 decode budget | 8 segments per message | Decoding is attacker-triggerable work |

The truncation-recording detail matters more than it looks: silently inspecting the first
100 KB of a 10 MB message and returning `allow` is a bypass. Recording it makes the gap
visible in the audit trail and in metrics.

### Timeout budget

Every outbound wait has an explicit bound. Unbounded waits are how a proxy turns one slow
dependency into total unavailability.

| Stage | Default | On expiry |
|---|---|---|
| Detector (per detector) | 250 ms | Per `on_error`: `fail_closed` → BLOCK (default) |
| Upstream connect | 5 s | `502` |
| Upstream read | 60 s | `504` |
| Database statement | 5 s | Logged, metric incremented, request continues (see [ADR-012](adr/ADR-012-persistence-and-retention.md)) |
| Server keep-alive / graceful shutdown | uvicorn defaults, explicit | |

The total added budget is bounded and stated: detection contributes at most
`max(detector_timeouts)` per direction, because detectors run concurrently.

### Failure posture

`fail_closed` is the default for every security-critical detector
([ADR-007](adr/ADR-007-detector-failure-semantics.md)). Two consequences we accept
knowingly:

* A detector bug becomes an availability incident rather than a silent security hole. That
  is the correct direction for a security control, and `firewall_detector_errors_total` is
  an alerting metric precisely so it is caught as a *bug*, not survived as a degradation.
* An operator may set `fail_open` per detector. It is visible in the policy file, appears
  in review, and is logged at startup with a warning naming each fail-open detector.

### Secrets

* Environment variables only. YAML policy files **structurally reject** keys matching
  `*_key`, `*secret*`, `*token*`, `*password*` — a validator, so it fails at startup rather
  than being caught in review (T-19).
* `SecretStr` typing means accidental interpolation renders `**********`.
* No secret is baked into the image, and `.env` is git-ignored with only `.env.example`
  committed.
* `gitleaks` runs in CI and in the pre-commit hook.

### Container posture

| Control | Implementation |
|---|---|
| Non-root | Dedicated `app` user, `USER app` before `CMD`; the process cannot write to its own code |
| Minimal runtime | Multi-stage build; compilers and build headers exist only in the builder stage |
| Read-only root filesystem | `read_only: true` with an explicit `tmpfs` for `/tmp` |
| Dropped capabilities | `cap_drop: [ALL]`, `security_opt: [no-new-privileges:true]` |
| Pinned base | `python:3.12-slim-<digest>` — a tag is mutable, a digest is not |
| Health check | `HEALTHCHECK` on `/health`; orchestrators use `/ready` for traffic |
| Resource limits | Memory and CPU limits set in compose; a model-loading OOM should kill one container, not the host |
| No secrets in layers | Build args never carry secrets; `.dockerignore` excludes `.env`, `.git`, tests |

### Supply chain

| Control | Tool | Gate |
|---|---|---|
| Dependency pinning | `uv.lock`, committed, hash-verified | CI checks the lock is current |
| Known vulnerabilities | `pip-audit` | CI job |
| Image CVEs | Trivy | CI job |
| Static security lint | `ruff` bandit rules (`S`) | CI job, blocking |
| Secret scanning | `gitleaks` | CI + pre-commit |
| Type checking | `mypy --strict` on `app/` | CI job, blocking |
| Model integrity (P2) | Pinned revision digest, `safetensors` only, checksum verified on download | Download script |

Dependency count is itself a control. Every addition must answer "does this materially
improve the architecture" ([ADR-001](adr/ADR-001-technology-stack.md)); the runtime set
is currently twelve packages, and heavy optional stacks (transformers, Presidio, pandas)
live behind extras so the default image does not carry them.

### HTTP response headers

`X-Content-Type-Options: nosniff` · `Cache-Control: no-store` (completions can be
sensitive; caching proxies must not retain them) · `Referrer-Policy: no-referrer` ·
`X-Request-ID` echoed · `X-Firewall-Decision` so clients can detect modified content.

**CSP** is applied per-response by the routes that serve HTML — the console
(`app/api/dashboard_static.py`) and the unauthenticated notice page — and nowhere else. A
policy strict enough for a browser origin is meaningless on a JSON API and would only invite
loosening; both HTML policies carry no `'unsafe-inline'` and no `'unsafe-eval'`, which is
possible only because the frontend was written to that constraint rather than retrofitted
([ADR-022](adr/ADR-022-dashboard-frontend-architecture.md), [ADR-023](adr/ADR-023-operator-authentication.md)).

**HSTS** follows the *request*, not the setting: sent when `FIREWALL_HTTPS_ENFORCED` is on
**and** a trusted proxy stated that this particular request's client hop was TLS. The probe
paths stay reachable over plaintext under enforcement so a misconfigured deployment is
diagnosable, and a response that travelled in the clear must not pin the operator's browser
to a scheme that hop does not serve — the pin outlives the mistake, which is what makes an
over-eager HSTS worse than a missing one. The reference edge sets its own and hides the
application's, so exactly one arrives ([ADR-026](adr/ADR-026-secure-transport.md)).

### Error responses

Errors carry a type, a safe message and the request ID. They never carry stack traces,
upstream response bodies, configuration values, matched rules or scores. Block responses
state the category only (T-13) — anything more turns the gateway into a tuning oracle for
the attacker, and the detail is available to the operator by request ID in the audit trail.

### Delegated — not implemented here, and stated so

| Concern | Owner | Why not here |
|---|---|---|
| TLS termination | **Edge — with a reference config since P12** | The gateway still should not manage certificates, and does not: it terminates no TLS and holds no key. What changed is that a reference TLS listener now ships, and the application *verifies* that a trusted proxy terminated TLS rather than assuming it ([ADR-026](adr/ADR-026-secure-transport.md)) |
| **Operator** authentication (T-24) | Reverse proxy / identity-aware ingress — **enforced in-process since P9** | Identity is an existing organisational concern; duplicating it adds a second thing to get wrong. What changed in [ADR-023](adr/ADR-023-operator-authentication.md) is that the application now *verifies* the boundary is there instead of assuming it: identity headers are read only from a trusted peer, and production refuses to start without one |
| **Caller** authentication for `/v1/**` (T-26) | **The gateway itself, since P10** | No longer delegated. A service API key is verified in-process against configured digests, ahead of detector inference ([ADR-024](adr/ADR-024-llm-caller-authentication.md)). An ingress may terminate it instead (`caller_auth_mode=proxy`), but the gateway still decides whether the asserted caller is allowed |
| Volumetric rate limiting (T-18) | **Edge — with a reference config since P11** | Still the edge's job, and deliberately: it can refuse a connection for the price of a `RST`, before the application allocates anything. What changed is that a reference nginx configuration now ships and is exercised in CI, and the application keeps a small in-process safety net for when the edge is missing ([ADR-025](adr/ADR-025-edge-abuse-protection.md)) |
| Network egress control (T-14) | Network policy | The gateway cannot prevent the app from calling the model directly; if that path is open, the firewall is advisory |
| Secret storage | Platform (Vault, cloud secret manager) | The gateway consumes env vars; how they get there is the platform's job |
| WAF / DDoS | Edge | |

T-14 deserves emphasis: **if the application can reach the upstream provider directly, this
gateway is a suggestion.** Enforcing that it cannot is a deployment task, and it belongs in
the deployment checklist.

### Deployment checklist

1. Upstream reachable **only** from the gateway's network identity (T-14).
2. **TLS terminated at the edge, and the application told so.** `FIREWALL_HTTPS_ENFORCED=true`
   with `FIREWALL_TRUSTED_PROXIES` naming the ingress, and the ingress setting
   `X-Forwarded-Proto`. An absent assertion is refused, not assumed secure.
3. **Rate limiting, connection limits and read timeouts at the ingress** (T-18, T-17).
   `deploy/docker/edge/` is a reference configuration; any ingress providing the same
   controls is acceptable. The values shipped there are development defaults, not
   measured ones — size them from your own traffic ([ADR-025](adr/ADR-025-edge-abuse-protection.md)).
4. `FIREWALL_ENVIRONMENT=production` set — this is what refuses `full` content logging.
5. Database role has no `DROP`; migrations run under a separate role.
6. Alerts configured on `firewall_detector_errors_total` and
   `firewall_audit_write_failures_total`.
7. Log and database retention aligned with the documented policy, backups included.
8. `/ready`, not `/health`, wired to the load balancer.
9. **Operator identity terminated at the ingress**, with `FIREWALL_TRUSTED_PROXIES` naming
   the ingress address — not a whole cluster range, and never `0.0.0.0/0`, which the
   application refuses at startup (T-24, T-25).
10. **The ingress strips inbound copies** of `X-Auth-Request-User`, `X-Auth-Request-Groups`
   and `X-Firewall-Proxy-Secret` before injecting its own. The application refuses them from
   an untrusted peer regardless — two independent controls, either sufficient (R-61).
11. **Caller authentication configured** — `FIREWALL_CALLER_API_KEYS` with one digest per
   calling application, generated by `scripts/generate_caller_key.py`. The raw key goes to
   the caller and never to the gateway (T-26). Production refuses to start without this.
12. **Port 8000 still not published to the internet.** Caller authentication makes it safe
   from anonymous use, not safe to expose: there is no rate limiting at the edge (T-18) and
   the per-caller ceiling is per process (T-28).
13. **A per-caller rate limit set from measured traffic** — `FIREWALL_CALLER_RATE_LIMIT_PER_MINUTE`
   and `FIREWALL_CALLER_MAX_CONCURRENT_REQUESTS`. Both default to off, because a limit chosen
   without knowing the traffic is a guess that will page someone.
14. **A global in-flight ceiling** — `FIREWALL_MAX_CONCURRENT_REQUESTS`, sized from the
   instance's CPU budget. It rejects rather than queues, so a burst becomes a 503 instead of
   a memory problem.
15. **Certificate material mounted at run time**, never committed and never baked into an
   image. `deploy/certs/` is gitignored as a directory and excluded from every build context;
   the edge exits rather than starting if the pair is missing, unreadable, mismatched or
   expired.
16. **`/ready` wired to the load balancer, and its advisory findings alerted on.** It now
   asserts the security boundary and the audit schema, and reports degradations that do not
   stop serving — a `/8` trusted range, a stale schema — which nothing else surfaces
   ([ADR-027](adr/ADR-027-readiness-contract.md)).
17. **Certificate expiry monitored outside the gateway.** nginx holds a certificate until
   reload, so one that expires while running is not caught by the start-up check.
18. **Decide on `FIREWALL_AUTH_FAILURES_PER_MINUTE`.** Off by default because it throttles by
   *address*, so a legitimate caller sharing an egress gateway with an attacker is refused for
   the window (R-65). Enable it where callers have distinct addresses; leave it off and rely
   on the edge where they do not.

---

## Provenance metadata — handling rules

[ADR-017](adr/ADR-017-provenance-aware-detection-context.md) adds four metadata
fields, implemented in Phase A+B. Provenance is metadata *about* content and is never content, so the
`content_logging` default of `none`
([ADR-008](adr/ADR-008-observability-and-privacy.md)) is unchanged and unaffected.

| Field | Audit | Logs | Metric label | Traces | Dashboard | Eval report |
|---|---|---|---|---|---|---|
| `provenance` (6-value enum) | yes | yes | **yes** | yes | yes | yes |
| `trust` (5-value enum) | yes | yes | **yes** | yes | yes | yes |
| `source_kind` (caller string) | yes | yes | **no** | yes | yes | yes |
| `source_ref` (caller string) | yes | yes | **no** | yes | truncated | aggregate only |
| Source content | **never** | **never** | **never** | **never** | **never** | **never** |
| Source URL, file path, connector credentials | **never** | **never** | **never** | **never** | **never** | **never** |

Three rules, each with a reason rather than a preference:

**Enums may be metric labels; caller strings may not.** `provenance` and `trust`
are bounded at six and five values, which cannot explode a time series.
`source_kind` and `source_ref` are attacker-controllable strings — using them as
labels is an unbounded-cardinality denial of service against the metrics backend,
reachable by any client. This is why `source_kind` is validated to a short
lowercase charset even though no policy rule reads it.

**`source_ref` is a correlation handle, not a locator.** Validation rejects `://`,
leading `/`, and anything over 64 characters. A URL or file path leaks internal
structure and sometimes credentials; an opaque connector-issued id or a hash
carries the same correlation value with none of that.

**A malformed claim never rejects the request.** Turning a metadata defect into a
`400` would make the firewall a new availability risk on a path that has none
today. Malformed claims are dropped and the request proceeds — asserted for
non-strings, unknown enum values, nested objects, and 100,000-character values in
`tests/security/test_provenance_spoofing.py`.

**A rejection reason never echoes the caller's value.** Embedding an
attacker-supplied string in a log line makes logs a reflection surface and a
flooding vector, so `Assignment.rejected_claims` carries a fixed short reason code
(`x-firewall-provenance:would_raise_trust`) and never the submitted value.
