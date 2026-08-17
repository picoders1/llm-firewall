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
| `request_traces`, `detector_results`, `policy_decisions` | 30 days | Tuning window |
| `security_events` | 180 days | Investigations start late |
| `content_preview` column | Never populated in production | |
| Evaluation data | Indefinite | Public benchmark data, no user content |

Retention values are printed at startup so a deployment cannot silently retain more than
intended. Enforcement is a scheduled deletion job (Phase 5), not a runbook step.

### Deployment obligations (the gateway cannot enforce these)

1. **TLS terminates at or before the gateway.** Plaintext prompts on the wire defeat
   everything here.
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

Not set: HSTS and CSP. This is an API, not a browser origin, and TLS is terminated at the
ingress — setting security headers the component does not own is theatre.

### Error responses

Errors carry a type, a safe message and the request ID. They never carry stack traces,
upstream response bodies, configuration values, matched rules or scores. Block responses
state the category only (T-13) — anything more turns the gateway into a tuning oracle for
the attacker, and the detail is available to the operator by request ID in the audit trail.

### Delegated — not implemented here, and stated so

| Concern | Owner | Why not here |
|---|---|---|
| TLS termination | Ingress / service mesh | The gateway should not manage certificates |
| Client authentication and authorisation | Ingress / API gateway | Identity is an existing organisational concern; duplicating it adds a second thing to get wrong |
| Rate limiting (T-18) | Ingress today; gateway in Phase 6 | Designed, not built. **README states: deploy behind a rate-limiting ingress** |
| Network egress control (T-14) | Network policy | The gateway cannot prevent the app from calling the model directly; if that path is open, the firewall is advisory |
| Secret storage | Platform (Vault, cloud secret manager) | The gateway consumes env vars; how they get there is the platform's job |
| WAF / DDoS | Edge | |

T-14 deserves emphasis: **if the application can reach the upstream provider directly, this
gateway is a suggestion.** Enforcing that it cannot is a deployment task, and it belongs in
the deployment checklist.

### Deployment checklist

1. Upstream reachable **only** from the gateway's network identity (T-14).
2. TLS terminated at or before the gateway.
3. Rate limiting at the ingress until Phase 6 lands (T-18).
4. `FIREWALL_ENVIRONMENT=production` set — this is what refuses `full` content logging.
5. Database role has no `DROP`; migrations run under a separate role.
6. Alerts configured on `firewall_detector_errors_total` and
   `firewall_audit_write_failures_total`.
7. Log and database retention aligned with the documented policy, backups included.
8. `/ready`, not `/health`, wired to the load balancer.

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
