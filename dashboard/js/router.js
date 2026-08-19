/**
 * Client-side routing on the History API.
 *
 * Real paths rather than hash URLs, because the server already falls back to
 * `index.html` for unknown `/dashboard/*` paths — a deep link survives a refresh
 * and costs one route on the backend (`app/api/dashboard_static.py`).
 *
 * Every navigation aborts the previous page's in-flight requests. Without that,
 * clicking through four screens leaves four responses racing to write into a DOM
 * that has moved on, and the slowest one wins.
 */

const BASE = "/dashboard";

export class Router {
  constructor({ routes, onNavigate }) {
    this.routes = routes;
    this.onNavigate = onNavigate;
    this.controller = null;

    window.addEventListener("popstate", () => this.resolve());
    document.addEventListener("click", (event) => this.interceptLink(event));
  }

  interceptLink(event) {
    if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey) return;
    const anchor = event.target.closest?.("a[href]");
    if (!anchor) return;
    const href = anchor.getAttribute("href");
    if (!href?.startsWith(`${BASE}/`) && href !== BASE) return;
    if (anchor.target === "_blank") return;
    event.preventDefault();
    this.navigate(href);
  }

  navigate(path, { replace = false } = {}) {
    const current = window.location.pathname + window.location.search;
    if (path === current) return;
    window.history[replace ? "replaceState" : "pushState"]({}, "", path);
    this.resolve();
  }

  /** Update the query string without adding a history entry or re-rendering. */
  setQuery(params) {
    const url = new URL(window.location.href);
    url.search = "";
    for (const [key, value] of Object.entries(params)) {
      if (value === null || value === undefined || value === "") continue;
      url.searchParams.set(key, String(value));
    }
    window.history.replaceState({}, "", url.pathname + url.search);
  }

  get query() {
    return Object.fromEntries(new URL(window.location.href).searchParams.entries());
  }

  resolve() {
    // Abort the outgoing page's requests before the incoming page starts.
    this.controller?.abort(new DOMException("navigated away", "AbortError"));
    this.controller = new AbortController();

    const path = window.location.pathname.replace(/\/+$/, "") || BASE;
    const relative = path.startsWith(BASE) ? path.slice(BASE.length) || "/" : "/";

    for (const route of this.routes) {
      const match = route.pattern.exec(relative);
      if (match) {
        this.onNavigate({
          route,
          params: match.slice(1).map(decodeURIComponent),
          query: this.query,
          signal: this.controller.signal,
        });
        return;
      }
    }
    this.onNavigate({ route: null, params: [], query: {}, signal: this.controller.signal });
  }
}

export const path = (segment = "") => `${BASE}${segment}`;
