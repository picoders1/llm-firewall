# ADR-022: Serving a browser console from the gateway, without a framework

**Status:** Accepted. **Implemented 2026-08-19.**
**Date:** 2026-08-19
**Phase:** 8
**Follows** [ADR-008](ADR-008-observability-and-privacy.md) (observability and privacy)
and the Phase 5 dashboard API.

> The gateway now serves HTML. That invalidates a stated assumption, so it is
> recorded here rather than absorbed silently.

## The assumption this changes

`app/middleware/request_id.py` sets three response headers and omits a Content
Security Policy with an explicit reason:

> HSTS and CSP are deliberately absent — this is an API, not a browser origin,
> and TLS terminates at the ingress.

That was correct while the only client was an SDK. Serving a console makes the
gateway a browser origin, and the reasoning no longer holds.

## Decision

### Same origin, not a separate host

The console is served by the gateway at `/dashboard`. The alternative — a
separate static host — would require CORS on every dashboard endpoint, and CORS
on a security API is a policy surface with no upside here. Same origin means the
browser enforces the boundary, the API client needs no base URL, and there is no
preflight and no credential to store.

### A CSP scoped to dashboard responses

A strict policy is applied to `/dashboard*` responses only:

```
default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:;
font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none';
object-src 'none'; form-action 'none'
```

API responses keep exactly the headers they had, which is why the existing header
tests still pass unchanged.

Note what is absent: no `'unsafe-inline'`, no `'unsafe-eval'`. Most dashboards
cannot ship that policy because a framework injects inline styles or evaluates
templates at runtime. This one can **because it was written to the constraint
from the start** — no inline `<script>`, no inline `<style>`, no `eval`, no
`innerHTML`. The policy is a consequence of the implementation, not a wish
imposed on it. `tests/api/test_dashboard_static.py` asserts the directives, and
`tests/security/test_dashboard_frontend_safety.py` asserts the primitives that
would force them to be relaxed are absent from every module.

`connect-src 'self'` also means the console can only ever talk to the gateway
that served it — a compromised dependency could not exfiltrate to another origin,
which matters more here than in an ordinary product because the data is security
telemetry.

### No framework, and no build step

Vanilla HTML, CSS and ES modules. The browser loads the files as written; there
is no bundler, no transpiler and no `node_modules`. `dashboard/package.json`
exists solely to mark the directory as ES modules for Node's test runner, and
declares no dependencies — asserted by test.

The uniformity that a framework usually provides comes instead from a convention:
every page module exports `meta`, `skeleton()`, `load(signal, context)` and
`view(data, context)`. The shell renders any page without knowing which one it
has, and that render path is about twenty lines.

The costs are real and accepted: no virtual DOM, so pages re-render wholesale
rather than diffing; no type checking on the frontend; and template literals
would be more concise than `el()` calls. The last is the point — `el()` cannot
produce markup from a string, so a server-controlled detector name cannot become
an execution primitive.

### History-API routing with a server fallback

Real paths (`/dashboard/events/42`), not hash URLs, because the server already
resolves unknown `/dashboard/*` paths to `index.html`. That is one route on the
backend and it makes deep links survive a refresh.

Paths **with a file extension** are excluded from the fallback and 404 instead:
returning `index.html` for a missing `.js` makes the browser try to execute a
document, which surfaces as a confusing application error rather than a missing
file.

Traversal is refused by resolving the candidate path and requiring it to stay
under the dashboard root — a containment check, not a pattern match on `..`.

## Consequences

**The console cannot change security decisions.** It issues only `GET` requests
against read-only endpoints. There is no policy-editing surface, and there will
not be one here.

**It is unauthenticated**, like `/metrics`, and inherits the same assumed
boundary: internal network or a reverse proxy. That is recorded in
`docs/dashboard-api-contract.md` and tracked as OD-35. No content is exposed even
if reached — the audit schema cannot store prompts — but traffic volumes, block
rates and policy version are.

**Node becomes a test-time dependency**, not a runtime one. `node --test` runs the
formatter and URL-safety suites with zero installed packages. Playwright was
considered and rejected: the rules most likely to put a wrong number on screen
(a null percentile rendering as `0 ms`, an FPR of 0.0092 rounding to `1%`) are
properties of pure functions, and a browser driver would prove they were called
rather than that they are right.

## Revisit when

The console is served outside an operator's network (authentication, OD-35), or
when a view needs streaming updates and polling stops being adequate.
