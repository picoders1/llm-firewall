# ADR-028 — Deployment manifests that enforce the documented topology

**Status:** Accepted · **Date:** 2026-08-19 · **Phase:** 14
**Refines:** [ADR-013](ADR-013-deployment-strategy.md) (Compose first, Kubernetes conditionally)
**Enforces:** [ADR-023](ADR-023-operator-authentication.md), [ADR-024](ADR-024-llm-caller-authentication.md), [ADR-025](ADR-025-edge-abuse-protection.md), [ADR-026](ADR-026-secure-transport.md), [ADR-027](ADR-027-readiness-contract.md)
**Opens:** [OD-41](../21-open-decisions.md)

---

## Context

Five phases produced deployment obligations. Every one lived in a numbered list
in [docs/17](../17-deployment-architecture.md), and **the artefacts in the
repository contradicted several of them**:

| Obligation | What the artefacts actually did |
|---|---|
| "Port 8000 reachable from the ingress only" | `compose.yaml` publishes `8000:8000`, and no overlay can remove it |
| "PostgreSQL reachable from the firewall pods only" | `compose.yaml` publishes `5434:5432` |
| "Secrets from the platform's secret manager, injected as environment variables" | four `SecretStr` settings passed as plain env, readable by `docker inspect` |
| "`/ready`, not `/health`, wired to the load balancer" | the image's `HEALTHCHECK` probes `/health` |
| "The upstream must be unreachable from the application" | one flat network, everything reachable from everything |

That is the same shape as the gap Phase 9 found for operator auth and Phase 12
for TLS: the intended architecture was right and no artefact enforced it. An
overlay could not fix it, because what makes a deployment production is mostly
what it *removes*, and Compose overlays can only add.

## Decision

**Ship a standalone reference production Compose file, and make the topology a
test rather than a paragraph.**

### 1. Docker Compose is the reference production target; Kubernetes is deferred

ADR-013 said "Compose first, Kubernetes conditionally… and only if justified".
It is still not justified:

* One stateless service, one database, one edge. No autoscaling requirement.
* **No measured sizing.** Phase 4 never ran, so any `resources.requests`,
  HPA target or replica count would be invented — which
  [docs/22](../22-evidence-and-claims.md) exists to prevent.
* Decisively: **no Kubernetes tooling is available here.** No `kubectl`, `kind`,
  `minikube` or `k3d`, so manifests could not be validated even client-side. In a
  repository whose whole discipline is "do not claim what you cannot
  demonstrate", shipping unvalidated YAML would be documentation wearing an
  infrastructure costume.

Recorded as **OD-41** with the trigger: a deployment that actually needs multiple
replicas, or a cluster to validate against.

The three targets are kept distinct, which is what §3 asks for:

| | File | Purpose |
|---|---|---|
| Development | `compose.yaml` (+ `edge`, `tls`, `console-auth` overlays) | one command, no credentials, ports published for convenience |
| **Reference production** | **`compose.prod.yaml`** | the enforced topology; only the edge is published |
| Verification | `compose.prod-selftest.yaml` | adds a mock upstream and unprivileged ports, and **changes nothing else** |
| Future orchestration | — | deferred (OD-41) |

### 2. Standalone, not an overlay

`compose.prod.yaml` redefines the stack rather than layering on `compose.yaml`,
because a Compose overlay cannot un-publish a port. Layering would have produced
a "production" stack that still exposed the gateway and the database — which is
precisely the failure being corrected.

### 3. Three networks, and the database on an internal one

```
   internet ──▶ edge ──[edge net]──▶ firewall-api ──[egress net]──▶ upstream
                                          │
                                     [data net: internal]
                                          ▼
                                      postgres
```

`data` is `internal: true`: the Docker network has no gateway to the outside, so
the database's isolation does not depend on a host firewall rule being right. The
gateway is the only member of more than one network — verified live, where the
edge container cannot even *resolve* `postgres`.

`egress` is separate from `data` so the audit store never sits on the network
that reaches the model provider.

### 4. Secrets are mounted files

The four `SecretStr` settings arrive at `/run/secrets/FIREWALL_*`, which
pydantic-settings reads directly through `secrets_dir` — no glue code, because
it looks for a file named after the prefixed setting.

An environment variable is readable by anything that can run `docker inspect`,
anything that can read `/proc/<pid>/environ`, and every crash reporter that dumps
the environment on the way down. A mounted file is not in any of those places.

`secrets_dir` is set only when `/run/secrets` exists, resolved at import:
pydantic-settings warns on a missing directory, and every developer machine and
CI runner would otherwise carry a warning about a path only containers have.

**Environment variables still win** on precedence. ADR-011 documents that chain
and a deployment must always be able to override; files are an alternative source
for four settings, not a new layer above them.

### 5. `/ready` is the health gate

The production stack probes `/ready`, and `depends_on: service_healthy` makes the
edge wait for it. Since ADR-027 readiness asserts the security boundary and the
audit schema, so **a container that lost its configuration never becomes healthy
and never has an edge started in front of it**. The image's own `HEALTHCHECK`
still probes `/health`, which is correct for liveness; the deployment overrides
it for readiness.

### 6. The topology is a test

`tests/security/test_deployment_topology.py` (43 cases) parses the manifests and
asserts each obligation: only the edge publishes, the database is internal-only
and shares no network with the edge, every credential is mounted rather than
exported, every service drops all capabilities, the gateway is probed on
`/ready`, migrations are a separate profile, and the verification overlay
weakens nothing.

`tests/integration/test_prod_topology.py` (12 cases) then probes the running
stack, because a manifest can be correct while a stale container still holds a
binding.

---

## What running it actually found

Three defects that reading the manifests would not have surfaced.

**An empty upstream key made every request fail with an opaque 502.**
`Bearer ` — with its trailing space — is an illegal header value that h11 refuses
locally, so `HttpUpstreamClient` raised `LocalProtocolError` before any request
left the process. The operator who hits this is exactly the one who created the
secret file and has not filled it in yet. Fixed: an empty key is treated as
absent, which is also the correct behaviour for a self-hosted upstream that needs
no credential.

**Mode-600 secret files were unreadable by the non-root container.** The
application image runs as uid 10001 with every capability dropped, so it has no
`DAC_OVERRIDE` and cannot read a file it does not own. Granting the container
`DAC_OVERRIDE` was rejected — that is the capability to bypass every file
permission, handed over to read three files. `scripts/init_prod_secrets.sh`
chowns to the container uid where it has the privilege, and otherwise falls back
to mode 0444 inside a 0700 directory (the directory is what protects them on the
host) while printing exactly what it did and why.

**Rotating the database secret does not rotate the database password.**
`POSTGRES_PASSWORD` initialises the data directory on first run only, so a
regenerated secret produced `InvalidPasswordError` against an existing volume.
Not a manifest bug — a real operational property, now in the deployment doc.
Readiness stayed *ready* throughout, correctly: with `require_audit=false` an
audit outage is advisory (ADR-027), which is that decision demonstrating itself.

---

## Alternatives considered

| | Option | Why not |
|---|---|---|
| A | **Kubernetes manifests** | No measured sizing, no cluster to validate against, no `kubectl` on this machine. Would be unvalidatable YAML in a repository that refuses unverified claims. Deferred, not rejected (OD-41). |
| B | **A production overlay on `compose.yaml`** | Cannot un-publish a port, so the result would still expose the gateway and the database. The bug, re-shipped. |
| C | **Docker Swarm** | Would give rolling updates and `uid`/`gid`/`mode` on secrets. Rejected as a second orchestrator to learn for one property; if orchestration is warranted, OD-41's answer is more likely Kubernetes. |
| D | **Keep secrets as environment variables** | Simpler, and readable by `docker inspect`, `/proc/<pid>/environ` and any crash dump. |
| E | **Grant the container `DAC_OVERRIDE`** | Solves the file-permission problem by giving the container the power to bypass all file permissions. Solved by ownership instead. |
| F | **Bake a `.env` into the image** | Puts credentials in a layer that survives `docker rmi` of the container and is readable by anyone who can pull. |

---

## Consequences

**Gained.** The documented topology is now an artefact that can be run, probed
and diffed. The gateway and the database are unreachable from the host —
verified, not asserted. Credentials are files. A container that loses its
security configuration never becomes healthy.

**Cost.** A second Compose file to keep in step with the first. Mitigated by the
topology tests, which fail on a manifest edit that publishes the gateway or
un-mounts a secret.

**Not gained, stated plainly.**

* **No rolling-update semantics.** Plain Compose restarts a container; it cannot
  drain one. A single-node deployment has a brief outage on restart (R-74).
* **No Kubernetes, and no cluster-level enforcement** — no NetworkPolicy, no
  PodDisruptionBudget, no readiness-gated rollout (OD-41).
* **`internal: true` is Docker's network isolation, not a firewall.** A process
  on the host with the right privileges can still reach a container network.
* **Resource limits are not sized.** The values carried over from the development
  stack, and Phase 4's measurements still do not exist (R-67 again).
* **The edge image still inherits `EXPOSE 80`** from the nginx base, which makes
  `docker ps` list a port nothing serves. Cosmetic, unremovable in a Dockerfile,
  noted so it is not mistaken for a published port.
* **Certificate and secret rotation are manual**, and rotating a database secret
  needs an `ALTER ROLE` as well as a new file.

---

## Verification

Static: `tests/security/test_deployment_topology.py` (43). Runtime:
`tests/integration/test_prod_topology.py` (12).

Observed against the running stack:

* `:8000`, `:5434` and `:8081` **closed** from the host while `:8443` serves —
  and `docker inspect` shows no port bindings on the gateway or the database
* the edge container cannot resolve `postgres` at all
* anonymous 401 · wrong credential 401 · valid credential 200 · injection **403**
  with `upstream_called = false` · plain HTTP **308**
* audit rows land in the private database carrying the caller id
* `/ready` reports `HTTPS required`, `enforcing`, `1 caller(s) configured` —
  without naming a CIDR, a mode or a caller
