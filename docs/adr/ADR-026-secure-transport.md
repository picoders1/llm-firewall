# ADR-026 — Secure transport: where TLS terminates, and what the application does about it

**Status:** Accepted · **Date:** 2026-08-19 · **Phase:** 12
**Closes:** the obligation stated since Phase 0 and never implementable — "TLS terminates at or before the gateway"
**Extends:** [ADR-023](ADR-023-operator-authentication.md), [ADR-024](ADR-024-llm-caller-authentication.md), [ADR-025](ADR-025-edge-abuse-protection.md)

---

## Context

Three phases built controls that all depend on the same thing:

* an operator identity injected by a proxy (ADR-023)
* a caller's bearer credential (ADR-024)
* a proxy shared secret, and a throttling key derived from a client address (ADR-025)

Every one of them crosses the wire. None of them was protected in transit by
anything in this repository.

### What the audit found

| Question | Finding |
|---|---|
| Current listeners | **Plain HTTP only.** Both shipped nginx configurations were `listen 8080;`. The string `ssl` did not appear anywhere in `deploy/`. |
| Where does TLS terminate? | Nowhere. `docs/17` obligation 2 said "at or before the gateway" and no artefact implemented it. |
| Reverse proxies | `console-proxy` (operators, opt-in) and `edge` (gateway, opt-in). Neither with TLS. |
| Who can reach `:8000`? | Anything that can reach the host — the compose file publishes it. |
| Forwarded headers | `X-Real-IP` is read from a trusted peer (ADR-025). **`X-Forwarded-Proto` was not read at all**, so the application had no notion of whether the client's hop was TLS. |
| `FIREWALL_HTTPS_ENFORCED` | Existed since Phase 9 and did exactly one thing: add an HSTS header. It *enforced* nothing. A process could tell browsers "always use HTTPS" while accepting credentials over plaintext. |
| Cookies | **None.** No `Set-Cookie` anywhere; authentication is entirely proxy- and header-based. §12's suspicion confirmed rather than assumed. |
| Upstream TLS | `verify` is never touched, so httpx's default validation applies. The default base URL is the HTTP mock, which is development-only. |
| CSP | Strong, no `unsafe-*`. Preserved unchanged. |

## Decision

**TLS terminates at the edge. The application does not terminate TLS, and does
not pretend it can observe it — it requires a trusted proxy to say so.**

```
   Internet
      │  HTTPS
      ▼
   EDGE  :8443 TLS 1.2/1.3, HSTS, h2   │  :8080 → 308 redirect (probes exempt)
      │  limit_req / limit_conn / body / timeouts (ADR-025)
      │  X-Forwarded-Proto: $scheme    ← set by nginx from the connection
      │  plaintext, internal network
      ▼
   LLM FIREWALL
      │  HttpsRequiredMiddleware  ← 426 unless a TRUSTED proxy said https
      │  operator auth · caller auth · admission
      ▼
   detectors → policy → upstream (HTTPS to a real provider, validated)
```

### 1. The edge terminates; the application verifies

The application cannot observe its own transport — by the time a request reaches
it, the connection is a plaintext internal hop, which is correct. So the only
source of truth about the *client's* hop is the proxy that terminated it.

That makes `X-Forwarded-Proto` a security input, and it is treated as one:
**read only when the socket peer falls inside `FIREWALL_TRUSTED_PROXIES`** — the
rule ADR-023 established for identity and ADR-025 reused for throttling keys,
applied a third time by calling the same function rather than copying it. A
direct client sending `X-Forwarded-Proto: https` convinces nobody, because
nothing looks at the header until the peer has been vouched for.

Only that one header is read. RFC 7239 `Forwarded` is not parsed: it is a
structured field with its own history of parsing bugs, and no ingress this
project documents prefers it. A chain is read **left to right** — `https,http`
means the client spoke HTTPS to the outermost proxy, and reading the last entry
would report the internal plaintext hop and refuse every request in a correct
deployment.

### 2. `FIREWALL_HTTPS_ENFORCED` now enforces

When on, the operator and gateway surfaces are served only if a trusted proxy
states the client's hop was HTTPS. Otherwise **426 Upgrade Required** — RFC
9110's exact condition, chosen over 403 because 403 reads as "your credential
was rejected" and sends an operator to debug the wrong boundary.

**Absence is refused, not assumed secure.** An ingress that forgets the header
takes the deployment down rather than quietly serving credentials in the clear.
That is the uncomfortable direction and it is the right one: the alternative
fails silently and only becomes visible in a packet capture; this fails at the
first request, in a way that names the missing header.

Two exemptions, both deliberate:

* **`/health`, `/ready`** — a deployment whose TLS is misconfigured needs its
  probes to keep answering, or the failure is total instead of legible, and an
  orchestrator that cannot reach `/ready` de-pools a healthy instance.
* **`/metrics`** — the edge returns 404 for it, so a scraper reaches the pod
  directly across the internal network, which this ADR documents as intentionally
  plaintext (see *The internal hop*). Enforcing HTTPS here would refuse every
  scrape in the topology the project actually ships. It keeps its own boundary
  (a declared scrape network or an operator identity) and carries no credential
  and no content.

### 3. Production cannot be plaintext

`TransportPolicy.from_settings` refuses to start when:

* the environment is production and `https_enforced` is false — the gateway
  carries operator identities, caller credentials and an upstream key, and
  serving those over plaintext is an absent control, not a degraded one;
* `https_enforced` is true and `trusted_proxies` is empty — nothing could ever
  assert the hop was TLS, so every request would be refused. A deployment that is
  *down* rather than protected, and better discovered at startup than at the
  first request.

### 4. HSTS is emitted only on a response that travelled over TLS

Previously the header followed the *setting*. It now follows the *request*: the
edge emits it on its TLS listener, and the application emits it only when a
trusted proxy said this particular hop was HTTPS.

The reason is the probe exemption. `/health` stays reachable over plaintext under
enforcement, and a response that travelled in the clear must not pin the
operator's browser to a scheme that hop does not serve. **The pin outlives the
mistake**, which is what makes an over-eager HSTS worse than a missing one. The
edge additionally hides the upstream's header and sets its own, so exactly one
arrives — duplicated security headers are the kind of thing someone later
"fixes" in the wrong direction.

### 5. Certificates are runtime mounts, always

Nothing in this repository and nothing in any image layer contains a key.

* `deploy/certs/` is gitignored **as a directory**, so `git add deploy/certs`
  cannot succeed by accident, and `*.pem`, `*.key`, `*.crt`, `*.p12`, `*.pfx` are
  ignored globally.
* `.dockerignore` excludes the same paths, so a stray file cannot become an image
  layer — where it would survive every `docker rmi` of the running container and
  be readable by anyone who can pull the image.
* Development material is **generated** by `scripts/generate_dev_cert.sh`, not
  committed. A committed private key is in the history forever, and "only for
  development" is a property of intent, not of the file: the moment someone
  reaches for it in a hurry it becomes a production key whose private half is
  public. It is self-signed, 30 days, and says `DEVELOPMENT ONLY` in the CN — a
  development certificate that looks production-valid is how one ends up in
  production.

The interface is two paths (`EDGE_TLS_CERT`, `EDGE_TLS_KEY`) and a mount. Which
CA fills them is the deployment's business: Let's Encrypt, an enterprise CA,
cert-manager, an ingress controller, a cloud load balancer. **This repository
defines the interface and pins itself to no issuer.** No ACME client is
implemented.

Rotation is: write the new pair to the mounted path, then restart or `nginx -s
reload` the edge. nginx reads certificates at configuration load, so a swapped
file is not picked up until then. The directory rather than two files is mounted
so a pair swaps atomically from the host's point of view.

### 6. Fail closed, checked for real

`render-edge-config.sh` refuses to start the container when the certificate is
missing, unreadable, not a PEM certificate, expired, or **paired with a key that
belongs to a different certificate**.

That last one is the case worth the code: it survives startup and fails at the
first handshake, long after a deployment has been declared successful. The check
compares the public half extracted from each file, before nginx is asked to load
either.

"`ssl_certificate` is present in the config" would prove none of this, which is
why `tests/integration/test_tls_failure_modes.py` starts real containers with
deliberately broken material and asserts they exit.

---

## The internal hop

**Edge → firewall is plaintext, deliberately, and that is a decision rather than
an omission.** It runs on a compose network / cluster network carrying only those
two participants; the edge was moved onto that network *exclusively* in this
phase, which also fixed a latent ADR-025 bug (a container with two interfaces
egresses from whichever the route table picks, so the gateway saw the edge's
other address and no `/32` could name it — silently disabling every control that
depended on the peer address).

mTLS between edge and firewall was **not** added. §23 is explicit that it should
not be automatic, and it would buy confidentiality on a hop that a network policy
already isolates, at the cost of a certificate lifecycle for internal
components. It becomes the right answer when the internal network is shared with
workloads outside this system's trust boundary — recorded as OD-39 rather than
implemented.

`/metrics` is scraped across that same plaintext internal network. It carries no
credential and no content, and it keeps its own access boundary.

---

## Alternatives considered

| | Option | Why not |
|---|---|---|
| A | **Terminate TLS in the application** (uvicorn `--ssl-keyfile`) | Puts certificate lifecycle, cipher configuration and renewal into a Python process that is already responsible for the security pipeline, and duplicates what every deployment target terminates anyway. It would also make `/ready` and `/metrics` HTTPS, complicating probes and scraping for no gain. |
| B | **Trust `X-Forwarded-Proto` from anyone** | The entire attack. A client sets one header and the gateway believes its plaintext connection was secure. |
| C | **Assume HTTPS when the header is absent** | Fails silently, which is the failure mode this whole ADR exists to remove. |
| D | **Pin a cipher list** | A hand-written `ssl_ciphers` string is a snapshot of someone's advice on the day it was written, and it rots silently. What is pinned instead is the protocol floor, which is the property that matters and which a real handshake can test. OpenSSL 3.x defaults are maintained by people who track this full time. |
| E | **HSTS preload** | `preload` is close to irreversible for a domain, and this repository does not know the domain it will run under. A deployment that wants it adds the directive knowingly. |
| F | **mTLS edge → firewall** | See *The internal hop*. Deferred to OD-39, not rejected. |

---

## Consequences

**Gained.** HTTPS exists in the reference deployment, with a real certificate
interface and no key anywhere in the repository. `FIREWALL_HTTPS_ENFORCED` means
what it says. Production refuses to start plaintext. Weak TLS versions are
refused by handshake, not by assertion. Invalid TLS material stops the container
rather than silently degrading. HTTP/2 is available and HTTP/1.1 — which the
OpenAI SDK speaks — still works.

**Cost.** A deployment now needs certificate material at a mounted path, and an
ingress that sets `X-Forwarded-Proto`. Both are ordinary, and both are now
failure-fast rather than silent.

**Not gained, stated plainly.**

* **The internal hop is plaintext** (OD-39).
* **No ACME client, no renewal automation.** The interface is a path and a
  restart; certificate lifecycle belongs to whatever issues them.
* **`nginx -t` resolves the backend hostname at startup**, so the edge will not
  start if `firewall-api` does not resolve yet. Correct for compose (`depends_on:
  service_healthy`), and a real consideration in Kubernetes where a Service can
  briefly have no endpoints.
* **The development certificate expires in 30 days** and is regenerated by
  re-running the script. Deliberate: a long-lived development certificate is one
  that gets copied somewhere.
* **HSTS is not preloaded** and `includeSubDomains` may be wrong for a deployment
  whose siblings are not HTTPS — it is a value to review, not to inherit.
* **Performance was measured on a mock upstream on one machine.** It shows no
  regression; it is not a production figure.

---

## Verification

`tests/security/test_secure_transport.py` (26) covers the trust boundary and the
enforcement without containers. `tests/integration/test_tls_edge.py` (19) and
`tests/integration/test_tls_failure_modes.py` (6) drive real TLS and real
containers.

The tests that would catch a real regression:

* a direct client asserting `X-Forwarded-Proto: https` (with a forged
  `X-Forwarded-For` alongside) is refused — **and the same headers from the
  trusted peer succeed**, so the refusal is about trust and not about the header
  never being read
* a trusted proxy honestly reporting `http` is refused, and an absent assertion
  is refused
* a valid credential over plaintext is refused, and HTTPS with no credential is
  still 401 — the two boundaries compose rather than substitute
* TLS 1.0 and TLS 1.1 handshakes fail, **and 1.2 and 1.3 succeed**, so the
  rejection tests are not satisfied by a server that refuses everything
* the served certificate's SANs cover the hostname, with verification on
* the served leaf is byte-identical to the file on disk
* HTTP redirects with **308**, preserving the method, and the plain listener
  proxies no gateway path at all
* HSTS is present over HTTPS and absent over HTTP
* ALPN negotiates `h2` when offered and `http/1.1` when that is all a client offers
* containers exit on: missing certificate, missing key, corrupt certificate,
  mismatched key, unknown mode — **and start on a valid pair**
* an injection is still blocked with `security_block` over HTTPS
