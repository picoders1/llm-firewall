# ADR-027 — What `/ready` means

**Status:** Accepted · **Date:** 2026-08-19 · **Phase:** 13
**Corrects:** the audit-availability classification, which contradicted [ADR-012](ADR-012-persistence-and-retention.md)
**Extends:** [ADR-023](ADR-023-operator-authentication.md), [ADR-024](ADR-024-llm-caller-authentication.md), [ADR-025](ADR-025-edge-abuse-protection.md), [ADR-026](ADR-026-secure-transport.md)
**Opens:** [OD-40](../21-open-decisions.md)

---

## Context

Four phases added boundaries — operator identity, caller credentials, admission
control, transport verification — and `/ready` learned about none of them. It
checked three things: policy loaded, detectors warmed, database reachable.

### What the audit found

| Question | Finding |
|---|---|
| What does `/ready` check? | `policy_loaded`, `detectors_warmed`, `database` (a bare `SELECT 1`). |
| Does it know about the security boundaries? | **No.** Nothing about operator auth, caller auth, trusted proxies or HTTPS. |
| Does it check schema/migration state? | **No.** A gateway whose database is one revision behind reports ready and loses every audit row. |
| Is the database check correctly classified? | **No, and backwards.** It fails readiness whenever the store is unreachable — which contradicts ADR-012's decision that an audit-write failure must not fail the request. |
| Who consumes the response? | The operator console renders `checks` as a list of `{name, passed, detail}`. |
| Is `/ready` authenticated? | No — PUBLIC access class, deliberately, so an orchestrator can always reach it. |

The gap the phase brief names is real but narrower than it first appears, and
being precise about it is most of this decision.

## Decision

**`/ready` answers: can this instance safely accept production traffic through
the boundary its deployment configured?** Every check declares a *category* and a
*requirement level*, and only `required` failures change the status code.

### 1. Two honest kinds of check

**Re-assertions.** Most security-boundary checks restate an invariant the process
already refuses to start without: production cannot run with an unauthenticated
console (ADR-023), `api_key` mode cannot run with no keys (ADR-024), HTTPS
enforcement cannot run without a trusted proxy (ADR-026). **Readiness cannot
discover a violation of these — the process would not be alive to answer.**

Saying otherwise would be the dishonest version of this ADR. They earn their
place for two narrower reasons: the security contract becomes machine-readable at
the load balancer, and they are a regression net for the day someone relaxes a
startup check without noticing what depended on it.
`tests/security/test_readiness_contract.py` walks one list twice — asserting each
configuration is refused at startup *and* reported unready by an independently
assembled state — so the two cannot drift.

**Genuinely new information.** Two checks report what nothing else does: the
applied database schema revision, and audit-store reachability *classified by
whether this deployment needs it*.

### 2. The requirement level is the substance

| | Meaning | Effect of failure |
|---|---|---|
| `required` | the instance cannot serve correctly without it | **503**, out of rotation |
| `advisory` | a real degradation that does not stop correct serving | reported and logged, **status unchanged** |

Marking everything `required` is how a readiness probe turns a degraded
dependency into an outage. Marking everything `advisory` is how it stops being a
probe. Each check is classified deliberately:

| Check | Category | Level | Why |
|---|---|---|---|
| `policy_loaded` | configuration | required | no policy means no security decision |
| `operator_boundary` | security_boundary | required | production must not serve an unauthenticated console |
| `caller_boundary` | security_boundary | required | production must not serve an unauthenticated `/v1`; `api_key` with no keys refuses every caller |
| `transport` | security_boundary | required | production must require HTTPS, and enforcement must be *possible* |
| `trusted_proxy_breadth` | security_boundary | **advisory** | `10.0.0.0/8` is accepted at startup but means a whole network can assert identity. Usually a mistake, occasionally deliberate |
| `detectors_warmed` | detectors | required | an instance that cannot inspect must not receive traffic (ADR-007) |
| `database` | database | **required iff `require_audit`** | see below |
| `database_schema` | database | **required iff `require_audit`** | see below |

### 3. The database correction

The previous behaviour failed readiness whenever PostgreSQL was unreachable.
[ADR-012](ADR-012-persistence-and-retention.md) says the opposite:

> Audit-write failure does not fail the request by default: the security
> decision is unaffected by a database outage, only the record is lost.

So with `require_audit=false` an instance with a dead database still makes
*correct security decisions*. Taking every instance out of rotation for that
turns an audit outage into a traffic outage — the exact failure the brief's §5
warns about, and one that would have made this project's own stated posture
unreachable in practice.

`require_audit=true` inverts ADR-012's trade: every request fails, so the
instance genuinely cannot serve and must leave rotation. The requirement level
therefore follows the setting.

### 4. Deliberately not readiness conditions

| Dependency | Classification | Why |
|---|---|---|
| **Upstream LLM** | NOT a readiness condition | The gateway returns a controlled 502/504 with its own envelope, and inspection still works. Failing readiness would take the whole fleet out for a provider outage the gateway is *designed* to survive — and with the fleet out, nothing reports the outage cleanly. |
| **Edge / ingress** | NOT a readiness condition | The application cannot observe it, and probing outward from a readiness handler builds a dependency loop: the edge routes on `/ready`, and `/ready` would depend on the edge. |
| **Live authenticated traffic** | NOT a readiness condition | §7 is explicit: readiness validates configuration, not client behaviour. "No authenticated request recently" would make a quiet Sunday look like an outage. |
| **Dashboard / evaluation artefacts** | NOT a readiness condition | Operator conveniences; their absence does not affect the security decision. |
| **Detector *model* files for disabled detectors** | NOT a readiness condition | `injection.transformer` ships disabled and warn-only, so an instance without its weights is correctly ready (§10). An *enabled* detector that fails to warm never reaches readiness — `pipeline.warmup()` raises and the process does not start. |

### 5. `/health` is unchanged

Liveness only, constant time, no database, no authentication, no TLS, no
detectors. The separation is the point: `/health` failing means "restart me",
`/ready` failing means "take me out of rotation", and a probe that conflates them
restarts a process whose dependency is elsewhere.

`/health`, `/ready` and `/metrics` remain exempt from HTTPS enforcement
(ADR-026) and stay in the PUBLIC access class. An orchestrator that cannot read
readiness de-pools a healthy instance, so the probe must answer even when the
boundary it describes is broken — which is precisely when it is most useful.

### 6. The response is additive, not reshaped

The brief illustrates an object keyed by category. The shipped contract keeps the
existing **list** of checks and adds `category` and `requirement` to each.

The operator console renders that list; reshaping it would have broken a working
consumer to match an illustrative snippet. Additive is a stable contract. The
console now renders an advisory failure as an amber *Advisory* rather than a red
*Fail*, because a finding that is not taking the instance out of rotation must
not look like one that is.

### 7. Nothing an unauthenticated reader should not have

`/ready` is a public probe that now describes the security boundary. No detail
names a mode, a CIDR, a caller id, a role, a filesystem path or a credential:
they report "not enforced", "2 caller(s) configured", "reachable". The
operator-authenticated `/api/v1/system/status` carries the specifics. Asserted by
driving a fully configured instance and scanning the body for every one of them.

The one identifier that *is* published is the policy version hash, which already
appears on the operator API and identifies which reviewed policy is in force.

---

## Alternatives considered

| | Option | Why not |
|---|---|---|
| A | **Fail readiness on any unhealthy dependency** | The §5 mistake. It would take the fleet out for an audit-store blip that ADR-012 explicitly decided to survive. |
| B | **Reshape the response to categories** | Matches the brief's illustration and breaks the console for no gain. The classification is carried in fields instead, which is equally machine-readable. |
| C | **Probe the upstream from `/ready`** | Turns a provider outage into a gateway outage, and the gateway's whole value during one is returning a controlled error. |
| D | **Require exact schema equality unconditionally** | Would break the expand/contract rollout [docs/17](../17-deployment-architecture.md) prescribes, where a new instance briefly runs against the previous revision. Left advisory unless audit is mandatory (OD-40). |
| E | **Authenticate `/ready`** | An orchestrator that cannot read it de-pools healthy instances, and a credential in a liveness probe is a credential in a Kubernetes manifest. Discretion is handled by what the payload says, not by gating it. |
| F | **A separate `/ready/deep` endpoint** | A second contract to keep correct, for information the categorised breakdown already carries. |

---

## Consequences

**Gained.** Readiness describes the boundary rather than a subset of the
process. Schema skew is visible — a class of silent failure nothing detected
before. An audit-store outage no longer empties the fleet. Advisory findings
(a `/8` trusted range, a stale schema on a best-effort deployment) surface
without paging anyone.

**Cost.** More surface in a hot-path endpoint. Mitigated by keeping every check
in-process except one database round trip that carries both facts, and by caching
the expected schema revision for the process lifetime.

**Not gained, stated plainly.**

* **The security-boundary checks cannot fail in a correctly built process.**
  They are a contract and a regression net, not a discovery mechanism (R-71).
* **Schema equality is exact.** With `require_audit=true` an expand/contract
  rollout would fail readiness on the intermediate revision (R-72, OD-40). No
  deployment here uses expand/contract yet.
* **Certificate expiry, edge health and upstream availability are outside this
  contract** and are monitoring concerns.
* **A readiness pass says configuration is sound, never that traffic is
  flowing.** Those need different instruments.

---

## Verification

`tests/unit/test_readiness.py` (23) evaluates the contract without an HTTP layer;
`tests/security/test_readiness_contract.py` (16) drives it over HTTP.

The tests that would catch a real regression:

* an advisory failure leaves the instance ready; a required one does not
* an unreachable store is **advisory** with `require_audit=false` and
  **required** with `require_audit=true` — the correction, asserted both ways
* a schema one revision behind is reported with **both** revisions named, and an
  un-migrated database is distinguished from a stale one
* an unknown *expected* revision does not assert a mismatch — "I cannot tell" is
  not "they differ"
* each configuration refused at startup is **also** reported unready by an
  independently assembled state, walked from one shared list so the two cannot
  drift
* a `/8` trusted range is flagged and the instance stays ready
* the response body of a fully configured instance contains no CIDR, caller id,
  mode name, role, path or credential
* `/health` answers while the database is unreachable and the boundary is
  misconfigured
