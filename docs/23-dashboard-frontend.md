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

**Styles are objects, never strings.** The CSP refuses style *attributes*, and
`setAttribute("style", ...)` is one. `el()` therefore takes `style` as an object
and applies it through the CSSOM, which CSP permits; static rules live in CSS and
only measurements cross from JavaScript, as custom properties
(`{"--bar-width": "42%"}`) consumed by a stylesheet rule. Passing a string
throws.

This was found in Phase 18 as a live defect rather than designed in: 40 call
sites built elements with style strings, the browser dropped every one, and the
console rendered distribution bars 0px wide and bar-list labels with no gap
between a detector name and its count. The pre-existing inline-style test only
read `index.html`, so it could not see it. Both halves are now asserted —
`test_no_style_attribute_is_ever_written` scans every call site, and
`tests/frontend/style-safety.test.mjs` proves the mechanism they rely on.

**Responsive**, designed per breakpoint rather than shrunk: persistent sidebar at
≥1024px; drawer with scrim below that; header metadata that also lives on the
System view is dropped at ≤768px rather than wrapped; two-column KPI grid at
≤480px.

## Interaction model

The console is **read-only by construction** — the operator surface refuses every
non-GET at the middleware boundary (ADR-023) — so interaction here can only ever
mean *asking a better question faster*. There is no command that changes the
gateway, and none may be added without moving that boundary first.

Within that limit the console is meant to be driven, not just read:

| Surface | Behaviour |
|---|---|
| KPI tiles (Overview) | Link into the event explorer filtered to that decision. "Total Requests" deliberately does not: the event list holds non-benign decisions only, so the link would land on a smaller number |
| Detector and category bars | Drill through to the events behind the bar |
| Command palette (`Ctrl`/`⌘`+`K`) | Fuzzy search over views and saved filters; a pasted correlation id offers a direct jump to its events |
| `G` then `O`/`E`/`D`/`T`/`V`/`S` | Go to a view. Suppressed while typing, and the prefix expires after 1.5s |
| `R`, `Shift`+`T`, `?`, `Esc` | Refresh, toggle theme, shortcut sheet, dismiss overlay |
| Correlation ids and content hashes | Copy affordance, degrading through Clipboard API → `execCommand` → select-the-text, because the console is routinely opened over plain HTTP on a LAN address where `navigator.clipboard` does not exist |

Sorting is **not** offered on the events table. It is server-paginated, so
sorting the fifty rows in hand would present a page-local ordering as if it were
a global one.

## The header, and what earns a place in it

The header answers four questions and nothing else: *which gateway is this*,
*is it well*, *what rules are in force*, and *is what I am reading current*.

It previously showed eight label-and-value pairs separated by pipes, all at the
same visual weight — so an unauthenticated security boundary read as no more
urgent than the word "development". The rule now is **normal is quiet, abnormal
is loud**:

| Element | Behaviour |
|---|---|
| Readiness | A dot and a word. Links to System Health |
| Environment | Small-caps chip, dashed and muted. `production` alone gets solid accent treatment, because it is the one environment worth recognising instantly |
| Policy | The short hash, linked to Detector & Policy. It determines every decision the gateway makes, so it is always visible |
| Security | **Both** boundaries — operator (ADR-023) and caller (ADR-024) — collapsed into one indicator. A quiet lock when both are enforced; an amber chip naming what is open when either is not |
| Operator | Rendered only on a genuine authenticated session, with a `safeHref`-checked sign-out |
| Freshness | Relative time, auto-refresh toggle, manual refresh |

The header used to report the operator boundary only, so a gateway whose `/v1`
was wide open looked identical to one that was not. Neither state is reachable in
production — the process refuses to start that way — which is precisely why the
indicator must not be mistaken for decoration: it is a development signal, and
development is where the mistake gets made.

Below 1024px the environment, policy and operator chips drop and buttons become
icon-only; readiness and the security state stay, because they are the two facts
worth interrupting someone for. The security chip keeps its colour and glyph and
sheds only its label, and its accessible name comes from visually-hidden detail
rather than the label, so nothing is lost to a screen reader.

## The sidebar footer

It read "Observability console / Read-only — no policy control". The first line
said nothing the brand two inches above did not, and the second stated a real
guarantee as though it were an apology.

What is there now is the guarantee, as a property: **this console cannot change
anything.** Every route on the operator surface is a `GET` and the boundary
refuses anything else, so a mutating endpoint cannot inherit read-only
authentication without an edit there (ADR-023). Saying so explains the absence of
a single edit control anywhere in the interface — it turns "there are no buttons"
from a gap into a stated property. The gateway version sits beneath it, because
"which build am I looking at" is the other thing a footer is for.

## Charts

Drawn as SVG with no charting library, at the container's **measured pixel
width** — one SVG unit is one CSS pixel. A single `ResizeObserver` serves every
chart on the page and unobserves elements once they leave the DOM, because the
router replaces a page's nodes wholesale and an observer holding a detached
subtree is a leak that only appears after a long session.

This replaced a fixed 720-unit viewBox stretched by `preserveAspectRatio="none"`.
That kept layout entirely in CSS and needed no resize handling, but non-uniform
scaling distorts **text** as well as geometry: on a phone the chart compressed to
about half its authored width and took the axis labels with it; on a wide monitor
the same labels stretched. Label density now follows available width, so a narrow
chart thins its axis rather than overlapping it.

Every chart still carries a text summary and a visually-hidden data table, and a
series with no observations renders an empty state rather than a flat line at
zero — a flat line at zero is a measurement.

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
* Overlays (palette, shortcut sheet) trap focus, restore it on close, and are
  fully operable from the keyboard — which is the point of them.

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
