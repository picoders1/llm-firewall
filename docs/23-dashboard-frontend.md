# 23 — Security Operations Dashboard (frontend)

The operator-facing console. Vanilla HTML, CSS and ES modules; no framework, no
build step, no runtime dependencies. Architecture decision:
[ADR-022](adr/ADR-022-dashboard-frontend-architecture.md). API contract:
[dashboard-api-contract.md](dashboard-api-contract.md).

## Architecture

```
dashboard/
  index.html            shell markup; one external module script, no inline code
  css/  tokens · base · layout · components · pages
  js/
    app.js              router + shell wiring; the single render path
    router.js           History API, aborts the previous page's requests
    api.js              the only module that calls fetch()
    state.js            two small stores and a refresh coordinator
    dom.js              el() / svg() / icon() / safeHref() — no innerHTML, ever
    formatters.js       null-safe presentation
    charts.js           SVG line, distribution and bar rendering
    components/         primitives.js (states, badges, tables), shell.js
    pages/              overview · events · event-detail · detectors ·
                        traffic · evaluations · evaluation-detail · system
```

**What replaces a framework** is a convention, not a library. Every page module
exports the same four things:

```js
export const meta = { title, subtitle };
export function skeleton() {}                  // loading state
export async function load(signal, context) {} // fetch, never throws for HTTP errors
export function view(data, context) {}         // pure render
```

`app.js` renders any page without knowing which one it has, and that render path
is roughly twenty lines. Adding a screen is one module plus one route entry.

**Failure isolation** is a property of `load`. Pages needing several endpoints use
`api.getAll`, which resolves each independently and returns `{ok, data|error}` per
key, so a dead endpoint degrades one panel rather than blanking the console.

**Navigation aborts in-flight work.** The router holds an `AbortController` per
navigation; clicking through four screens cannot leave four responses racing to
write into a DOM that has moved on.

## Static delivery

Served by the gateway itself at `/dashboard` (`app/api/dashboard_static.py`), so
the console is same-origin with the API: no CORS, no base URL, no credential.

* Real paths, not hash routing. Unknown `/dashboard/*` paths fall back to
  `index.html`, so a deep link survives a refresh.
* Paths **with a file extension** are excluded from that fallback and 404 —
  serving HTML for a missing `.js` makes the browser execute a document.
* Traversal is refused by resolving the candidate and requiring it to stay under
  the dashboard root, rather than pattern-matching `..`.
* The image ships `dashboard/` and the ~200K of finalised `result.json` reports;
  `.dockerignore` keeps the ~6.7M of per-sample predictions out.

## Design system

Everything resolves to a custom property in `css/tokens.css`; no component
hard-codes a colour. Dark-first — a console is read for hours in a dim room — with
a real light scheme whose contrast is chosen against its own backgrounds rather
than inverted.

**Status is never colour alone.** Every decision state carries a **glyph**, a
**word** and a colour: Allow ●, Warn ▲, Redact ◆, Block ■, Failure ✕, Unknown ○.
The interface still reads on a monochrome display and to a colour-blind operator.

Spacing is a 4px scale; anything off it looks like a mistake. Elevation is three
shadows used to suggest depth, not to decorate. Numeric columns use tabular
figures so a column of latencies does not jitter as digits change.

**Responsive**, designed per breakpoint rather than shrunk: persistent sidebar at
≥1024px; drawer with scrim below that; header metadata that also lives on the
System view is dropped at ≤768px rather than wrapped; two-column KPI grid at
≤480px.

## Accessibility

* Semantic landmarks, a skip link, and focus moved to `<main>` on navigation so
  keyboard users land on the new page.
* Visible focus ring everywhere; table rows are `tabindex="0"` with Enter/Space
  activation, so the events table is fully keyboard-navigable.
* Charts are `role="img"` with a text summary **and** a visually-hidden data
  table, so the numbers are readable and not merely paintable.
* `prefers-reduced-motion` collapses transitions and stops the skeleton shimmer
  and refresh spinner. No meaning is carried by motion.
* Loading regions are `role="status"` with `aria-busy`, rather than silently blank.

## Security posture

| Control | Implementation |
|---|---|
| No HTML injection | `innerHTML`, `outerHTML`, `insertAdjacentHTML` and `document.write` appear nowhere in the source — asserted per-file. All text goes through `textContent` |
| No dynamic code | No `eval`, no `new Function`, no string-bodied timers, no injected `<script>` |
| URL safety | `safeHref` allows only same-origin paths and fragments; `javascript:`, `data:`, protocol-relative and absolute external URLs are refused |
| CSP | `default-src 'self'` with no `unsafe-inline` and no `unsafe-eval`, on dashboard responses only. API headers unchanged |
| Clickjacking | `frame-ancestors 'none'` plus `X-Frame-Options: DENY` |
| Exfiltration | `connect-src 'self'` — the console can only talk to the gateway that served it |
| Storage | One key persisted: the colour theme. No token, no event data, no `sessionStorage` |
| Third parties | No external origin referenced, no analytics, no fonts, no CDN |
| Content | No page reads a content-shaped field; asserted by scanning property accesses |
| Identity | The console stores **no session and no subject**. It asks `/api/v1/session` every time, so a stolen browser profile yields nothing. `document.cookie` and `sessionStorage` appear nowhere |
| Sign-out link | Rendered only when the gateway reports a path, and only through `safeHref` — a mistyped setting cannot walk an operator to an attacker-chosen host |

## Authenticated states

Since Phase 9 the console sits behind an operator boundary
([ADR-023](adr/ADR-023-operator-authentication.md)), which gives the frontend three
states it must tell apart. Collapsing any two would send an operator to debug the
wrong thing.

| State | What the console shows | Why it is separate |
|---|---|---|
| Authenticated | The subject in the header, plus a sign-out link when the proxy published one | The only state where data is rendered |
| Session expired (`401`) | "Session expired", and a **Reload** action | Reloading re-runs the proxy's sign-in flow, so it is a real remedy |
| Access denied (`403`) | "Access denied", and **no reload action** | Reloading can never admit an unauthorised account; offering it would be a loop dressed as a remedy |
| Authentication disabled | An explicit "Auth disabled" badge | Development only. Showing a name here would be a fabricated security property, which is worse than a missing one |
| Unknown | "Unknown" | The session request failed. Never rendered as authenticated |

Polling stops on the first identity failure. An expired session that keeps
refreshing turns one idle tab into a steady stream of `401`s in the security log,
which is exactly the signal an operator needs to stay meaningful.

The console does **not** have a login page, and adding one would be a regression:
identity is terminated at the boundary, and a form here would either be theatre or
a second credential path. A browser that reaches the gateway unauthenticated gets a
static notice page instead — served with `default-src 'none'` and a CSP **hash**
for its single inline `<style>`, so no `'unsafe-inline'` enters the policy.

## Real data only

No metric in the frontend is hard-coded. Two rules are enforced in code and
tested:

1. **A null percentile renders "No observations", never `0 ms`.** Zero is a
   measurement; absence is not.
2. **A rate is not rounded into a bigger one.** `0.0092` renders as `0.92%`, not
   `1%` — the project's published benign FPR must survive its own dashboard.

Scores keep four decimals so 0.9955 and 0.9954 — two different locked thresholds
in this project — remain distinguishable.

The Evaluation view separates **evidence state** from **outcome**: a run can be
`complete` and have a `FAILURE` decision, which is exactly what ADR-019 and
ADR-020 are. Rendering "complete" as success would misreport the project's two
most important negative results.

## Testing

| Suite | Command | Covers |
|---|---|---|
| Formatters and URL safety | `node --test tests/frontend/*.test.mjs` | null handling, rounding, `safeHref` rejections |
| Static delivery | `pytest tests/api/test_dashboard_static.py` | routes, deep links, traversal, CSP, content types |
| Frontend safety | `pytest tests/security/test_dashboard_frontend_safety.py` | the primitives above, per file |
| Contract conformance | `pytest tests/api/test_dashboard_contract_conformance.py` | every field a page reads exists in the API |

Node is a **test-time** dependency only, with zero installed packages. Playwright
was considered and rejected: the failures that matter most here (a null rendering
as zero, an FPR rounding up) are properties of pure functions, and a browser
driver would prove they were called rather than that they are right. That trade
is recorded in ADR-022 and revisitable if interaction bugs start escaping.
