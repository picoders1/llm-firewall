# ADR-025 — Edge abuse protection and in-process admission control

**Status:** Accepted · **Date:** 2026-08-19 · **Phase:** 11
**Closes:** T-18 (request flood), T-17 (slowloris)
**Extends:** [ADR-023](ADR-023-operator-authentication.md), [ADR-024](ADR-024-llm-caller-authentication.md)
**Opens:** [OD-38](../21-open-decisions.md) (distributed enforcement)

---

## Context

ADR-024 closed anonymous *use* of the model. It did not close anonymous
*arrival*. Its own limitation section said so:

> The per-caller limiter engages only **after** a caller is identified […] it
> does nothing about a flood of anonymous requests or credential guesses.

Every refusal is cheap, and every refusal is still paid for: a TCP handshake, a
TLS handshake, an ASGI scope, a JSON error body, a log line, a metric increment.
At a few thousand requests per second that is the whole process, and the gateway
stops serving the callers it authenticated correctly.

### What the audit found

| Question | Finding |
|---|---|
| Where does TLS terminate? | Nowhere in this repository. Documented as an ingress obligation ([docs/17](../17-deployment-architecture.md) obligation 2). |
| Is there a reverse proxy? | One: `deploy/docker/console-proxy`, operator-only, opt-in, and it has **no `limit_req`, no `limit_conn`, no `client_max_body_size` and no timeouts**. The default stack has no proxy at all. |
| Who can reach `:8000`? | In the default stack, anything that can reach the host. |
| Any proxy-level rate limiting anywhere? | **None.** |
| Uvicorn tuning? | All defaults — no `--limit-concurrency`, no timeout flags. |
| Existing concurrency controls? | Detector thread pool `CapacityLimiter(8)`; per-caller ceiling (off by default); upstream `max_connections=100` with **no keepalive cap**. **No global in-flight ceiling.** |
| Retries? | None. Correct, and left alone (§13). |
| Multiple replicas? | Architecturally supported (stateless), none configured. |

So the gap is not "the design was wrong" — it is that the layer the design
delegates to has never existed in the repository, exactly as with ADR-023.

## Decision

**Two layers, with the expensive one delegated to the edge and a deliberately
small safety net in the process.**

```
   connection  →  EDGE (nginx reference config)
                    limit_conn        connection floods
                    limit_req         anonymous request floods
                    client_max_body   oversized bodies
                    header/body timeouts   slow clients
                        │
                        ▼
                  APPLICATION
                    admission        global in-flight ceiling      503
                    body limit       256 KiB, re-checked           413
                    caller auth      service API key (ADR-024)     401
                    auth throttle    per-client failure ceiling    429
                    per-caller       rate + concurrency (ADR-024)  429
                        │
                        ▼
                    detectors → policy → upstream
```

### 1. The split is by *what each layer can know*, not by preference

The edge can refuse a connection for the price of a `RST`, before the
application allocates anything. It cannot tell one caller from another, because
the credential it would need to read belongs to the application.

The application knows exactly who is calling. It has already paid for the
connection by the time it finds out.

So: **volume at the edge, identity in the application.** No limit is duplicated
across both except the body size, and that one is deliberate — the application
must not depend on a particular ingress being present, since the project
supports several.

### 2. The application layer is a safety net, and is sized like one

`FIREWALL_MAX_CONCURRENT_REQUESTS` bounds in-flight requests. It rejects rather
than queues: an unbounded queue in front of a bounded worker pool converts a
burst into a memory problem instead of a rejection.

It is registered **outermost of all middleware** — before request-id binding,
before the body is read, before either identity boundary. Its 503 therefore
carries no correlation id, which is the honest cost of refusing that early.

`/health` and `/ready` are exempt. An orchestrator that cannot reach `/ready`
during a burst restarts or de-pools the instance, turning a load spike into an
outage; the probe must report saturation, not be a casualty of it.

### 3. Authentication-failure throttling, and what it costs

`FIREWALL_AUTH_FAILURES_PER_MINUTE` refuses a client that keeps presenting bad
credentials — **before** the credential comparison, so guessing costs a
dictionary lookup rather than a SHA-256 and a scan of every configured digest.

**The cost of that ordering is real and is recorded as R-65.** A client identity
is an address, and addresses are shared. A legitimate caller behind the same NAT
or egress gateway as an attacker is refused for the rest of the window, and
cannot clear its own count because it never reaches the comparison. Moving the
check after authentication would remove the collateral damage — and would also
remove the protection, since an attacker would then get a full comparison per
attempt regardless.

This is why it ships **off by default**, and why the edge — which can afford to
be generous because it is cheap — is the primary defence. It is also why the
reference edge overlay leaves it off: enabling it at 20/min made the edge
integration suite trip over itself, which is R-65 reproducing in miniature and is
noted in `compose.edge.yaml` rather than tuned away.

### 4. The throttling key is never the client's to choose

`X-Forwarded-For` is not parsed at all. The identity is the socket peer, unless
the peer is inside `FIREWALL_TRUSTED_PROXIES`, in which case one configured
header (`X-Real-IP`) is read instead — the same rule as ADR-023, sharing the same
function rather than a copy of it.

The threat here is **evasion, not impersonation**: a client that could pick its
own throttling key would pick a new one per request and never reach a limit.
Choosing "the right entry" from a forwarded-for chain is a class of bug avoided
by not having the feature.

### 5. Limiter state cannot become the attack

Every in-process map keyed by a client identity is capped and expiring.
`_Bounded` holds at most `MAX_TRACKED_CLIENTS` (16,384) entries, evicting expired
ones first and then the least recently seen.

**Expiry alone bounds nothing** — an attacker sending from a new address every
millisecond adds entries faster than a 60-second window removes them. Under a
distributed flood the throttle degrades: an attacker who can cycle through more
addresses than the cap can push their own entry out. It degrades into "no worse
than having no throttle", never into unbounded memory. Asserted at 50,000
distinct addresses.

### 6. Status codes: 429 is about you, 503 is about us

| Condition | Code | Reasoning |
|---|---|---|
| Per-caller rate or concurrency (ADR-024) | **429** + `Retry-After` | a limit that is yours; slow down |
| Authentication-failure throttle | **429** + `Retry-After` | same — a limit attached to the client |
| Edge `limit_req` / `limit_conn` | **429** | nginx defaults to 503; overridden, because 503 tells a client the *server* is broken and its backoff logic reacts differently |
| Global in-flight ceiling | **503** + `Retry-After` | a statement about this server, not about the client; retrying elsewhere is a valid response |

---

## The reference edge

`deploy/docker/edge/nginx.conf.template`, wired by `compose.edge.yaml`.

**An example production deployment, not the only supported one.** The project
supports any ingress that can provide these controls — an ALB, Envoy, an API
gateway, a Kubernetes Ingress. What is normative is the *set of controls*; nginx
is one way to get them.

It is a **separate proxy** from the operator console proxy. Merging them would
put an operator credential store in front of machine traffic, which is the
confusion ADR-024 §5 exists to prevent. The gateway edge authenticates nobody: it
clears the operator identity headers rather than relaying them, and returns 404
for `/dashboard`, `/api/` and `/metrics` so a deployment cannot accidentally
publish the security console on the gateway's public address.

**Every number in it is a development default.** None is derived from measured
traffic, and none is an SLO:

| | Development default | Example production starting point |
|---|---|---|
| `limit_req` rate | 5 r/s per address | size from measured p95 traffic per client |
| `limit_req` burst | 10, `nodelay` | 2–4× the rate |
| `limit_conn` | 20 per address | 100+ where clients pool connections |
| `client_max_body_size` | 256k | keep equal to `FIREWALL_MAX_REQUEST_BYTES` |

The development values are deliberately low enough that the limits are
observable by hand. Publishing a "recommended production rate" without traffic
data would be exactly the unbacked claim this project refuses to make
([docs/22](../22-evidence-and-claims.md)).

### Timeouts, and who owns which

| Timeout | Owner | Value | Why there |
|---|---|---|---|
| header / body read | edge | 10s / 15s | a client dribbling bytes holds a worker; the application never sees the socket (T-17) |
| proxy read | edge | 75s | **longer** than the application's upstream read timeout, so a slow model produces the application's 504 envelope rather than the proxy's bare HTML |
| detector | application | 250ms | ADR-007, unchanged |
| upstream connect / read | application | 5s / 60s | unchanged |

No value was changed on the existing three. §12 asks for review, not adjustment,
and adjusting them without evidence is how a timeout becomes a superstition.

### Upstream protection

`max_keepalive_connections` is now bounded (20) alongside `max_connections`
(100). An unbounded keepalive pool holds file descriptors open against the
provider long after the burst that created them has passed.

**No retries were added**, and the absence is deliberate: a retry on a POST to a
model is a second billed inference, and on an upstream outage it doubles the
load that caused it.

---

## Alternatives considered

| | Option | Why not |
|---|---|---|
| A | **Redis-backed distributed limiter** | Would make the per-process limit exact across replicas. Rejected: it adds a datastore whose failure mode is "the gateway stops working" to buy precision on a control that is approximate by design. §21 asks for the deployment requirement to decide, and no deployment has stated one. OD-38 records the trigger. |
| B | **In-process IP rate limiting instead of an edge** | Cheaper to ship, and wrong: by the time Python sees the request the connection, TLS and scope are already paid for. It would also be per process, so it would not bound a flood at all — only redistribute it. |
| C | **Uvicorn `--limit-concurrency`** | Genuinely useful and *complementary*, but it returns a bare 503 with no envelope, no metric and no exemption for probes. The middleware gives the same bound with an OpenAI-shaped body and a readiness probe that still answers. |
| D | **Banning abusive addresses** (fail2ban-style) | A ban turns R-65's collateral damage from a one-minute nuisance into an outage for everyone behind a shared egress. A throttle is recoverable; a ban needs an operator. |
| E | **Rate limiting inside the detector pipeline** | Too late by construction — the point is to refuse before inference. |

---

## Consequences

**Gained.** A flood of anonymous requests is refused at the edge for the price of
a `RST`. A process that receives one anyway bounds its own in-flight work and
returns 503 rather than exhausting memory. Credential guessing is throttled per
client. The edge is exercised by real integration tests against real nginx, not
asserted from its configuration file.

**Cost.** A deployment now wants an ingress with these controls configured —
which docs/17 already required, but which is now a thing to get right rather
than a sentence. The reference config is one topology among several.

**Not gained, stated plainly.**

* **Enforcement is still per process.** N replicas allow N times the
  application-side limit (R-63). The edge is where a global limit belongs, and
  the reference config gives one — for the single-edge topology it describes.
* **R-65: the auth-failure throttle punishes shared addresses.** Off by default
  for that reason.
* **No limit values are evidence-based.** Everything shipped is a development
  default, labelled as one.
* **TLS is still not terminated anywhere in this repository.** The reference edge
  listens on plain HTTP; a production deployment terminates TLS in front of it or
  in it, and that configuration is not shipped.
* **The console proxy still has no rate limiting.** Deliberately out of scope
  here — it fronts a different boundary with a different traffic profile — and
  now recorded as R-66 rather than left implicit.

---

## Verification

`tests/security/test_edge_abuse_protection.py` (14) and
`tests/unit/test_admission.py` (19) cover the application layer;
`tests/integration/test_edge_proxy.py` (10) drives real nginx over a real
socket and **runs in CI**, which is the gap Phase 9 left open for the console
proxy and this ADR closes for the gateway edge.

The tests that would catch a real regression:

* a credential-guessing flood becomes 429 and never reaches the upstream
* a client cannot evade the throttle by varying `X-Real-IP` or `X-Forwarded-For`
  from an untrusted peer — **and the same headers from the trusted peer are
  honoured**, so the first assertion is about trust and not about the header
  never being read
* 50,000 distinct addresses leave the state map at or under its cap
* eviction prefers expired entries over live ones, so a burst of stale addresses
  cannot reset an attacker's own count
* a concurrency slot is returned after a handler raises — a leaked slot converges
  on refusing everything while the process still reports itself healthy
* `/health` and `/ready` answer while the ceiling is refusing everything else
* through real nginx: an anonymous flood is refused, the refusal is 429 and not
  nginx's default 503, a 400 KB body is refused with 413, `/dashboard` and
  `/metrics` return 404, and a valid caller credential still gets a normal
  completion
