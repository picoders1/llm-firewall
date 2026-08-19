# ADR-023 — Operator authentication for the Security Operations console

**Status:** Accepted · **Date:** 2026-08-19 · **Phase:** 9
**Supersedes the exposure assumption in:** [ADR-022](ADR-022-dashboard-frontend-architecture.md),
[docs/dashboard-api-contract.md](../dashboard-api-contract.md)
**Resolves:** [OD-35](../21-open-decisions.md)

---

## Context

Phase 5 shipped a read-only Security Operations API and Phase 8 shipped a browser
console on top of it. Both were built on one stated assumption: *internal network,
or behind a reverse proxy that terminates authentication.* That assumption was
written into the contract document precisely so it could not be inherited by
accident — and it was the last thing in this project protecting the console.

The audit that opened Phase 9 found the assumption was not merely unenforced; the
architecture it names does not exist in this repository:

| Question | Finding |
|---|---|
| Is there a reverse proxy? | **No.** `compose.yaml` has three services — `firewall-api`, `mock-upstream`, `postgres` — and publishes `firewall-api` directly on host port 8000. |
| Is there ingress or deployment tooling? | **No.** `deploy/` contained only Dockerfiles. Kubernetes manifests are Phase 7 and unwritten. |
| Does authentication exist anywhere in the application? | **No.** No middleware, no dependency, no route decorator. |
| Is CORS configured? | **No CORS middleware exists.** The console is same-origin, so there is nothing to configure — and nothing misconfigured. |
| What does the documented production topology assume? | [docs/17](../17-deployment-architecture.md) draws `ingress (TLS, authn/z, rate limiting)` at the top. The intended shape was right; nothing enforced it. |

So the gap is narrower and sharper than "add authentication". The intended
architecture already terminates identity at the edge. What was missing is the
application's half: **a way to tell whether that edge is actually in front of it,
and a refusal when it is not.**

### What is exposed if the console is reached

Traffic volumes, block rates by category, detector configuration, thresholds,
policy version, latency percentiles, and finalised evaluation reports. No prompt
text, no completion text, no PII and no secrets — the audit schema cannot store
the first four ([docs/11](../11-data-model.md)) and the DTOs are a second line of
defence for the rest.

That was the original argument for leaving it open, and it is still true. It is
also incomplete. Thresholds plus block rates by category is a description of how
to tune an evasion against this specific gateway without ever tripping it, which
is threat **T-13** with the guesswork removed. Operationally sensitive is not
confidential, but it is not nothing.

---

## Decision

**Terminate operator identity outside the process, and enforce inside it.**

```
Browser
   │  (organisation's own sign-in)
   ▼
Reverse proxy / identity-aware ingress          ← authenticates; strips inbound identity headers
   │  X-Auth-Request-User: alice                ← injects authoritative values
   ▼
LLM Firewall — OperatorAuthMiddleware           ← trusts those headers ONLY from a trusted peer
   │
   ▼
PostgreSQL / upstream
```

Four decisions make this up.

### 1. No user model, no credential store, no login page

The application stores no password, mints no token, and has no concept of an
account. Adding one would mean a credential store, a session mechanism and a
reset path — three new attack surfaces inside a security gateway — to duplicate
something every plausible deployment target already terminates.

There is deliberately no `password` or `token` mode. The mechanism is a header
contract that oauth2-proxy, Cloudflare Access, an identity-aware ingress, Traefik
`forwardAuth` and an enterprise SSO edge all already speak.

### 2. Trust is derived from the peer address, never from a header

`AuthConfig.authenticate` reads nothing until the socket's peer
(`scope["client"]`) falls inside `FIREWALL_TRUSTED_PROXIES`. **`X-Forwarded-For`
is never consulted.** A forwarded-for chain is client-supplied — an attacker
prepends whatever they like — so trusting it would turn the anti-spoofing check
into a self-signed permission slip. The peer address is the one value in an HTTP
request a remote client cannot choose.

The proxy owns the other half: it must overwrite inbound copies of the identity
headers. `nginx`'s `proxy_set_header` does that for every header it names, which
is why the reference configuration names all three and a test asserts that list
matches the three the application reads. Neither half is trusted to be sufficient
alone.

### 3. Access classes, assigned by path, defaulting closed

| Class | Paths | Requirement |
|---|---|---|
| **Public** | `/health`, `/ready` | none — a probe that needs a credential takes healthy instances out of rotation the first time the credential rotates |
| **Internal** | `/metrics` | a declared scrape network **or** an operator identity |
| **Gateway** | `/v1/**` | unchanged — application traffic, not operator traffic (see *Limitations*) |
| **Operator** | everything else, including `/dashboard/**`, `/api/v1/**`, `/docs`, `/openapi.json`, and any path added later | authenticated operator, `GET`/`HEAD` only |

Unknown paths are **operator**, not public. A route added next week is protected
until someone classifies it deliberately; the cost is that an anonymous request
for a nonexistent path answers 401 rather than 404, which also stops the boundary
being used to enumerate routes.

`/metrics` was the one §4 asked for an explicit decision on. It is **both**
network-restricted and authenticatable: a Prometheus job is not a person and is
admitted by `FIREWALL_METRICS_NETWORKS`; an operator reading raw counters during
an incident comes through the proxy like everything else. It is never open merely
because it is boring.

### 4. Production cannot be unauthenticated by omission

`console_auth_mode` defaults to `None`, meaning *derive from the environment*:
`proxy` in production, `disabled` elsewhere. Setting it to `disabled` in
production is refused at startup, and `proxy` without `FIREWALL_TRUSTED_PROXIES`
is refused too — as is a `0.0.0.0/0` trusted range, which would report
`operator_auth_enforced` in the startup log while trusting the entire internet.

This is the same shape as `effective_content_logging`: the safe value is derived,
not remembered.

---

## Alternatives considered

| | Option | Why not |
|---|---|---|
| A | **Application-level password login** | A credential store, a session table and a reset path added to a security gateway, to solve a problem the deployment edge already solves. §2 of the brief rules it out and the reasoning is sound: three new attack surfaces to protect data that contains no secrets. |
| B | **Static bearer token in the console** | The token has to live somewhere in the browser. `localStorage` is readable by any script that ever gets in — and the console's whole CSP posture exists to make that hard, so undoing it for convenience would be self-defeating. Rejected in ADR-022 already, for the same reason. |
| C | **mTLS to the application** | Genuinely strong, and the right answer for `INTERNAL_SERVICE` traffic in a mesh. Rejected as the *primary* mechanism because it does not solve the browser case: operators would need client certificates provisioned into browsers, which no deployment target here does. It remains compatible — an mTLS-terminating ingress is exactly one of the boundaries this design accepts. |
| D | **Network policy alone (no application check)** | This is what was already assumed, and it is why the gap existed. It cannot be verified from inside the process, produces no signal when it is missing, and fails silently rather than loudly. |
| E | **OIDC implemented in the application** | An OAuth client, token validation, JWKS rotation and a callback route — a meaningful amount of security-critical code, duplicating a proxy that can be dropped in front. Reconsider only if a deployment target appears that cannot run one. |

**A note on what was *not* rejected on complexity.** Option C is more complex than
the chosen design and is not rejected for being so; it is rejected for not
covering the browser. If this project later grows a service-to-service operator
API, mTLS is the first thing to reach for.

---

## Session, cookies and CSRF

The application sets **no cookie** and issues **no token**. It has no ambient
credential of its own, so it cannot be the target of a CSRF attack in the usual
sense — there is nothing for a browser to attach automatically.

The proxy is a different matter. It will typically hold a cookie session, and a
browser will attach that cookie to a cross-site request. Three things bound the
exposure today:

1. Every operator endpoint is `GET`/`HEAD`. Nothing mutates.
2. The boundary **rejects** other methods on the operator surface itself, not just
   by routing. A mutating endpoint added later cannot inherit read-only
   authentication without an edit to `app/middleware/auth.py`, where this section
   is referenced.
3. The console's CSP carries `frame-ancestors 'none'` and `form-action 'none'`,
   and it is same-origin so no CORS grant exists to widen it.

**Before any mutating endpoint is added**, all of the following are required, and
this list is the acceptance criterion: `SameSite=Lax` or stricter on the proxy's
session cookie; an `Origin`/`Referer` check on every non-`GET`; and either a
double-submit token or a custom header the browser will not send cross-site. None
of these are implemented, because there is nothing yet that needs them — but the
design does not assume read-only forever.

---

## Local development

`docker compose up -d` is unchanged: outside production the boundary is off, the
console is open on `:8000`, and the stack still starts with one command and no
credential (NFR-012).

The boundary can be exercised locally without an identity provider:

```bash
docker compose -f compose.yaml -f compose.console-auth.yaml up -d --build
open http://localhost:8088/dashboard      # operator / development-only
```

The overlay adds an nginx reverse proxy on `:8088` **and** flips the application
into enforcing mode — it is an override file rather than a compose profile
because a profile can add a service but cannot do the second half, and either
half alone is useless.

**The development proxy uses HTTP basic auth deliberately, because basic auth is
obviously unsuitable for production and nobody will mistake it for the real
thing.** Its value is not the authentication; it is that the two obligations a
real proxy must meet — strip inbound, inject authoritative — appear as four
`proxy_set_header` lines that can be read, tested and copied.

The development credential is generated at container start from an environment
variable. No password hash is committed: a hash in git is a credential in git,
however weak, and this repository's pre-commit secret scan exists to prevent
exactly that.

---

## Consequences

**Gained.** The console and its data are unreachable without an operator
identity, and the boundary refuses to start half-configured rather than
discovering the problem on the first anonymous request. Denials are counted
(`firewall_auth_denials_total`) and logged with a closed-enum reason, so the
difference between "the proxy is misconfigured" and "someone is probing" is
visible in a dashboard rather than inferred from silence.

**Cost.** A deployment that serves the console now needs a proxy in front of it,
which is a real operational requirement that did not exist yesterday. The
development story absorbs that with the overlay above; production does not, and
should not.

**Not gained, and stated plainly.**

* **`/v1/chat/completions` remains unauthenticated.** It is a different access
  class with a different story — its callers are applications, not people — and
  this phase deliberately did not widen its scope to reach it. But an
  unauthenticated gateway holding the operator's upstream API key is an open
  proxy to a paid model, and that is a real finding, not a technicality. Recorded
  as **R-60**, with the mitigation until it is addressed: do not expose port 8000
  beyond the application network.
* **No rate limiting on the boundary.** An attacker can attempt identity headers
  as fast as they like; each attempt fails at the peer check, but the attempts
  are free. Ingress rate limiting is already obligation 3 in
  [docs/17](../17-deployment-architecture.md) and remains T-18/Phase 6.
* **The reference proxy is not exercised in CI.** It has been run manually, and
  the strip obligation was observed directly: a request carrying
  `X-Auth-Request-User: root` through the proxy arrives as `subject: operator`.
  But no automated test starts nginx, so that is a one-time observation rather
  than a regression guard. What *is* asserted by test is the configuration's
  shape — the header list matches the three the application reads, the probe
  locations carry no auth, no credential is committed. See
  [docs/22](../22-evidence-and-claims.md).
* **No third-party identity proxy has been integrated.** The header contract is
  the one oauth2-proxy and identity-aware ingresses emit, and the names are
  configurable, but oauth2-proxy, Cloudflare Access and an ingress controller have
  all gone untested here.

---

## Verification

`tests/security/test_operator_auth.py` (35 cases) is the substantive one. The
tests that would catch a real regression:

* an identity header from an untrusted peer is refused — **and the identical
  headers from the trusted peer succeed**, which is what stops the first test
  being satisfied by any broken request
* `X-Forwarded-For: 127.0.0.1` alongside the forged identity changes nothing
* a subject containing `\n`, `\r\n` or `\x00` is **refused, not sanitised** —
  trimming it would hide a misconfigured proxy while writing a forged record into
  the security log
* a refusal body contains no header name, no CIDR, no role name and no secret
* the denial log's `reason` is always a member of `DenyReason`, and the
  attacker-supplied subject never appears in it
* `POST`/`PUT`/`PATCH`/`DELETE` are refused for an authenticated operator
* `0.0.0.0/0` and `::/0` as trusted ranges refuse to start
* `//evil.example` as a logout path is refused at config load

`tests/unit/test_auth_identity.py` covers the access-class table exhaustively,
including near-misses (`/healthz` is not `/health`) and IPv4-mapped IPv6 peers.
`tests/api/test_auth_boundary.py` covers envelopes, the notice page's CSP hash,
and that the default development stack is unchanged.


---

## Amendment — 2026-08-19: the gateway limitation is closed

This ADR recorded one limitation as live:

> **`/v1/chat/completions` remains unauthenticated.** […] an unauthenticated
> gateway holding the operator's upstream API key is an open proxy to a paid
> model […] Recorded as **R-60**.

[ADR-024](ADR-024-llm-caller-authentication.md) closes it with a separate
boundary: a service API key on `Authorization: Bearer`, verified against
configured digests, enforced in middleware ahead of detector inference. R-60 is
resolved and OD-36 with it.

**Nothing decided here changes.** The operator boundary keeps its own setting,
its own header, its own principal type and its own access classes; ADR-024
deliberately does not reuse them, because merging the two trust domains would let
a stolen console session drive the model. The two share exactly one thing — the
rule that an identity header is read only from a trusted peer address, never from
`X-Forwarded-For` — and they share it by calling the same function rather than by
copying it.

The `GATEWAY` access class described above is unchanged in meaning: the operator
middleware still hands `/v1/**` through untouched. It is now handed to
`CallerAuthMiddleware` rather than straight to the router.
