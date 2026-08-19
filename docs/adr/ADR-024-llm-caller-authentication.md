# ADR-024 — Caller authentication and abuse protection for `/v1`

**Status:** Accepted · **Date:** 2026-08-19 · **Phase:** 10
**Resolves:** [OD-36](../21-open-decisions.md), [R-60](../20-risk-register.md)
**Extends:** [ADR-023](ADR-023-operator-authentication.md) — see its *Amendment* section
**Constrained by:** [ADR-004](ADR-004-openai-compatible-contract.md)

---

## Context

ADR-023 closed the operator boundary and named what it deliberately left open:

> `/v1/chat/completions` remains unauthenticated. […] an unauthenticated gateway
> holding the operator's upstream API key is an open proxy to a paid model, and
> that is a real finding, not a technicality.

This ADR closes it. The audit that opened the phase found:

| Question | Finding |
|---|---|
| How is `/v1` exposed? | Directly. `compose.yaml` publishes port 8000; nothing in front of it in any environment. |
| Is there a reverse proxy? | Only the optional **operator** console proxy from ADR-023, which is a different boundary and must stay one. |
| Is a trusted application network defined? | **No.** Documented as an obligation in [docs/17](../17-deployment-architecture.md); never expressible in configuration. |
| Are inbound API keys represented in configuration? | **No.** `upstream_api_key` is outbound only. |
| Is the upstream credential shared by all callers? | **Yes**, and unavoidably: one process, one provider account. Which is exactly why the callers need identities. |
| Can a caller influence the upstream credential? | **No, structurally** — see *Upstream isolation* below. This was the one thing already right. |

## Decision

**A service API key presented as `Authorization: Bearer`, verified against
configured SHA-256 digests, enforced in middleware ahead of the handler.**
Optionally, caller identity terminated at a trusted ingress instead. Plus a
per-caller rate and concurrency ceiling, because identity without a limit is
half a control.

### 1. Bearer API key, because the client already sends one

ADR-004 stakes the project's adoption argument on one line:

```python
client = OpenAI(base_url="http://gateway/v1", api_key="...")
```

The SDK turns `api_key=` into `Authorization: Bearer`. **The mechanism that
requires no client change is the one the client is already using**, and every
alternative — a custom header, a signed envelope, mTLS in the application —
costs an integration change and buys nothing over a secret in a header on a TLS
connection.

### 2. The gateway stores digests, never keys

`FIREWALL_CALLER_API_KEYS` holds `<caller_id>:<sha256-hex>` pairs. The raw key
lives only in the caller's configuration.

This matters for the way this kind of secret actually leaks: an environment
dump, a `docker inspect`, a misrouted log, a support bundle. All of those, on
the gateway side, now yield nothing presentable.

Unsalted SHA-256 is correct here and would be wrong for a password.
`scripts/generate_caller_key.py` mints `secrets.token_urlsafe(32)` — 256 bits —
so there is no dictionary to run and no rainbow table to build, and a work
factor would only add latency to every request. **The assumption is
load-bearing**, which is why the helper generates the key rather than accepting
one someone chose; a hand-written `prod-key-2026` would silently break it while
producing a digest that looks identical.

Comparison is `hmac.compare_digest`, and the loop over configured callers
**does not stop at the first match** — returning early would make response time
depend on a credential's position in the list.

### 3. Enforced in middleware, ahead of everything expensive

    request-id → body limit → security headers → caller auth → router → detectors → upstream

Two reasons this is not a route dependency. First, cost: the layer-2 transformer
is ~95 ms of CPU per call (ADR-021), so authenticating inside the handler would
let an anonymous client spend real compute on every request it is about to be
refused — a denial of service that authentication was supposed to prevent.
Second, coverage: `/v1/models` is protected by the same rule without its handler
mentioning it, and so is whatever `/v1` route is added next.

The body limit stays **outside**, so an oversized body is rejected before a
header is read.

### 4. Two boundaries, kept apart

| | Operator (ADR-023) | Caller (this ADR) |
|---|---|---|
| Who | a person | an application |
| Where | `/dashboard`, `/api/v1/**` | `/v1/**` |
| Credential | proxy-injected identity header | `Authorization: Bearer`, or a proxy-injected caller header |
| Setting | `FIREWALL_CONSOLE_AUTH_MODE` | `FIREWALL_CALLER_AUTH_MODE` |
| Principal type | `Principal` | `CallerPrincipal` |

Separate types rather than one with a role field, so a function that expects one
cannot be handed the other by a later refactor — the type checker enforces the
separation the design depends on. Both directions are tested: an operator
identity does not authenticate a model call, and a service key does not open the
console.

They share exactly one thing: the peer-address rule, because there is only one
correct way to decide whether a header may be trusted and duplicating it would
let the two copies drift.

### 5. Proxy mode asserts identity; the gateway still authorises

In `proxy` mode the ingress supplies `X-Firewall-Caller` and the peer address
must fall inside `FIREWALL_CALLER_TRUSTED_PROXIES`. `X-Forwarded-For` is never
consulted — it is client-supplied, so trusting it would let a caller write its
own permission slip.

**A caller id the gateway does not recognise is still refused.** The ingress says
*who* is calling; this gateway says whether that caller is allowed. Which is why
`proxy` mode also requires `FIREWALL_CALLER_API_KEYS` — for the identity list,
not for the secrets.

### 6. Production cannot be open by omission

`caller_auth_mode` derives from the environment: `api_key` in production,
`disabled` elsewhere. Refused at startup: `disabled` in production; `api_key`
with no configured keys (which would reject every caller while reporting itself
protected — a different failure from an open gateway and an equally bad one);
`proxy` with no trusted range, or with `0.0.0.0/0`.

---

## Upstream isolation — already structural, now pinned

The client's credential cannot become the gateway's, and the mechanism is worth
stating precisely because it is *not* a filter:

`HttpUpstreamClient` builds its `authorization` header **once at construction**
from `FIREWALL_UPSTREAM_API_KEY`, and its only request-time input is
`chat_completions(payload: dict)` — a JSON body. There is no parameter through
which an inbound header could travel.

So there is no denylist to maintain and no header that gets forwarded because
someone forgot to add it. `tests/security/test_upstream_credential_isolation.py`
pins the shape: it asserts the method signature is `(self, payload)` on both the
Protocol and the implementation, so a refactor that adds a `headers=` parameter
fails there before it can leak anything. `Authorization`, `Proxy-Authorization`,
`Cookie`, `X-Api-Key`, `X-Forwarded-*` and `Host` are each tested end to end.

---

## Abuse protection

Authentication answers *who*, not *how much*. A caller whose credential leaked,
or whose retry loop went wrong, is authenticated all the way to the bill.

**Sliding-window rate limit and a concurrency ceiling, per caller, in this
process.** The window slides rather than resetting on a calendar boundary: a
fixed window lets a caller send its full allowance in the last second of one and
again in the first second of the next — twice the limit across two seconds,
which is exactly when a runaway retry loop does its damage.

Both default to **0 (off)**, because a limit chosen without knowing a
deployment's traffic is a guess that will page someone.

**The scaling limitation, stated rather than hidden: the limits are per process,
so N replicas allow N times the configured value.** No Redis (§16 asks for that
restraint, and it is right — a datastore whose failure mode is "the gateway
stops working" is a poor trade for an approximate ceiling). A deployment needing
an exact global limit should set it at the ingress, which already sees every
request.

Request size is unchanged: `max_request_bytes` (256 KiB) is enforced by
`BodyLimitMiddleware`, before authentication, by `Content-Length` pre-check *and*
streaming byte count — so `Transfer-Encoding: chunked` is not a bypass.

---

## Audit and events

`request_traces.caller_id` records **which** application called, never **how** it
proved it. The value can only ever be a configured label; an unrecognised
identity never becomes a principal, so nothing from the wire reaches the column.
`NULL` means the boundary was off or the row predates it — a different fact from
"anonymous", and not one to backfill a guess into. Migration `0003`, additive and
nullable. Retention is unchanged and governed by ADR-012.

**Failed authentication writes no database row.** A client that can create a
security-event row per request has a cheap way to fill an operator's disk,
turning the audit trail itself into the denial-of-service vector (§21). Refusals
are counted and logged instead: `firewall_caller_auth_failures_total{reason}`,
with `reason` a closed enum that is never derived from a presented credential.

---

## Alternatives considered

| | Option | Why not |
|---|---|---|
| A | **Database-backed API keys with a management API** | The requirement is "a handful of trusted applications", and this would add a table, a CRUD surface, a rotation workflow and an admin UI — every one of them a new attack surface on a security gateway. §25 rules it out and the reasoning holds until a deployment actually manages callers independently. |
| B | **mTLS between application and gateway** | Strong, and the right answer inside a service mesh that already issues certificates. Rejected as the primary mechanism because it requires certificate provisioning in every calling application, which no deployment target here has — and it is not mutually exclusive: an mTLS-terminating ingress is precisely what `proxy` mode is for. |
| C | **Network policy alone** | This is what was already assumed, and R-60 is the record of how that went. It cannot be verified from inside the process and produces no signal when it is missing. |
| D | **Reuse the operator boundary** | Tempting — the machinery exists. Rejected because it merges the two trust domains: a stolen dashboard session would drive the model, and a service key would read the security event log (§5). |
| E | **Per-caller upstream credentials** | Would give real per-caller billing separation. Rejected as out of scope and probably wrong here: it multiplies the number of provider secrets the gateway holds, which is the asset this phase is protecting. |

---

## Consequences

**Gained.** `/v1` cannot be used anonymously in production; an unauthorised
request is refused before normalisation, before detector inference and before the
upstream; the audit trail names the calling application; and a runaway caller has
a ceiling.

**Cost.** Every calling application now needs a credential deployed to it, and
rotation is a deployment rather than an API call. For a handful of trusted
applications that is the right trade; past roughly a dozen independently managed
callers it is not, and alternative A becomes the answer.

**Not gained, stated plainly.**

* **Rate limits are per process.** With N replicas the real ceiling is N times
  the configured one.
* **No token-level or cost budget.** The ceiling is on requests, not on tokens
  spent, so one caller sending very large prompts can outspend one sending many
  small ones while staying inside the same limit.
* **No caller proxy has been run.** `api_key` mode is exercised end to end in
  containers; `proxy` mode is unit- and API-tested only. No nginx or ingress has
  been driven against the caller boundary, and CI does not start one (§28).
* **Revocation requires a deployment.** There is no expiry and no disabled flag:
  a credential that is not configured is not a credential.
* **`/v1/models` still returns 501.** Authenticating an unimplemented endpoint is
  correct but does not implement it.

---

## Verification

`tests/security/test_caller_auth.py` (43) and
`tests/security/test_upstream_credential_isolation.py` (14) are the substantive
ones. The tests that would catch a real regression:

* every refusal asserts `upstream.call_count == 0` — a `401` alone does not prove
  the model was never reached, since the gateway could have authenticated on the
  way back
* the correct credential succeeds, so the refusals are not satisfied by any
  broken request
* an identity header from an untrusted peer is refused, including alongside a
  forged `X-Forwarded-For`
* the `401` bodies for *missing* and *wrong* credentials are byte-identical apart
  from the correlation id
* the presented credential never appears in a log line, a metric label, a
  response, or an audit row
* `chat_completions`'s signature is `(self, payload)` — the structural reason no
  client header can reach the provider
* an operator identity does not authenticate a model call, and a service key does
  not open the console
* failed authentication writes no audit row, across 20 attempts
* no path shape — encoded traversal, double slashes, trailing slash, uppercase —
  falls between the two boundaries into a class neither one claims

`tests/unit/test_caller_ratelimit.py` (9) covers the window boundary on an
injected clock, and that a concurrency rejection does not also spend the rate
allowance.
