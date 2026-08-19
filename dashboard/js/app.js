/**
 * Application entry point.
 *
 * Wires the router, shell and pages together. Every page module exposes the same
 * four things — `meta`, `skeleton()`, `load(signal, context)` and `view(data,
 * context)` — so the shell can render any of them without knowing which one it
 * has. That uniformity is what replaces a framework here: there is one render
 * path, and it is twenty lines long.
 *
 * Failure isolation is a property of `load`: pages that need several endpoints
 * use `getAll`, which resolves each independently, so one dead endpoint degrades
 * one panel instead of blanking the console.
 */

import { el, render } from "./dom.js";
import { Router, path } from "./router.js";
import { ErrorKind, endpoints } from "./api.js";
import { renderHeader, renderSidebar } from "./components/shell.js";
import { createRefreshCoordinator, loadTheme, saveTheme, shell } from "./state.js";
import { emptyState } from "./components/primitives.js";

import * as overview from "./pages/overview.js";
import * as events from "./pages/events.js";
import * as eventDetail from "./pages/event-detail.js";
import * as detectors from "./pages/detectors.js";
import * as traffic from "./pages/traffic.js";
import * as evaluations from "./pages/evaluations.js";
import * as evaluationDetail from "./pages/evaluation-detail.js";
import * as system from "./pages/system.js";

const ROUTES = [
  { pattern: /^\/$/, page: overview },
  { pattern: /^\/events$/, page: events },
  { pattern: /^\/events\/([^/]+)$/, page: eventDetail },
  { pattern: /^\/detectors$/, page: detectors },
  { pattern: /^\/traffic$/, page: traffic },
  { pattern: /^\/evaluations$/, page: evaluations },
  { pattern: /^\/evaluations\/([^/]+)$/, page: evaluationDetail },
  { pattern: /^\/system$/, page: system },
];

const sidebarEl = document.getElementById("sidebar");
const headerEl = document.getElementById("header");
const mainEl = document.getElementById("main");

let theme = loadTheme();
document.documentElement.dataset.theme = theme;

const refresher = createRefreshCoordinator({ intervalMs: 30000 });
let current = null;

const router = new Router({ routes: ROUTES, onNavigate: handleNavigate });

function context(navigation) {
  return {
    navigate: (target) => router.navigate(target),
    setQuery: (params) => {
      router.setQuery(params);
      renderPage(navigation, { silent: true });
    },
    params: navigation.params,
    query: router.query,
  };
}

function paintShell() {
  renderSidebar(sidebarEl, {
    activePath: window.location.pathname,
    onNavigate: () => closeDrawer(),
  });
  renderHeader(headerEl, {
    state: shell.get(),
    theme,
    polling: refresher.enabled,
    onRefresh: () => refresher.refresh(),
    onToggleMenu: () => toggleDrawer(),
    onTogglePolling: () => {
      refresher.toggle();
      paintShell();
    },
    onToggleTheme: () => {
      theme = theme === "dark" ? "light" : "dark";
      document.documentElement.dataset.theme = theme;
      saveTheme(theme);
      paintShell();
    },
  });
}

shell.subscribe(paintShell);

/**
 * The two identity failures, told apart.
 *
 * A 401 mid-session means the boundary's session ended; reloading re-runs its
 * sign-in flow, so a reload is a real remedy and is offered. A 403 means this
 * account will never be admitted, so offering a reload would be a loop — the
 * only honest next step is a person.
 *
 * Neither message names the identity provider, the header, or any part of the
 * gateway's configuration. The console does not know those things and must not
 * appear to.
 */
function identityNotice(kind) {
  if (kind === ErrorKind.FORBIDDEN) {
    return emptyState(
      "Access denied",
      "You are signed in, but this account is not authorised for the security console. " +
        "Ask an administrator to grant operator access.",
    );
  }
  return el("div", { class: "identity-notice" }, [
    emptyState(
      "Session expired",
      "Your operator session is no longer valid. Reload to sign in again through your " +
        "organisation's access boundary.",
    ),
    el("div", { class: "identity-notice__action" }, [
      // An empty href re-requests the current URL, which is what triggers the
      // boundary's own flow. It is not a link the console can be made to point
      // anywhere else.
      el("a", { class: "btn btn--primary", href: "", text: "Reload" }),
    ]),
  ]);
}

function pageHeader(meta, extra = null) {
  return el("div", { class: "page-head" }, [
    el("div", { class: "page-head__text" }, [
      el("h1", { text: meta.title }),
      meta.subtitle ? el("p", { class: "page-head__sub", text: meta.subtitle }) : null,
    ]),
    extra ? el("div", { class: "page-head__actions" }, [extra]) : null,
  ]);
}

async function renderPage(navigation, { silent = false } = {}) {
  const { route, signal } = navigation;
  if (!route) {
    render(
      mainEl,
      pageHeader({ title: "Not found", subtitle: "That view does not exist" }),
      emptyState("Unknown view", "The address you followed does not match any screen in this console."),
    );
    return;
  }

  const page = route.page;
  const ctx = context(navigation);

  if (!silent) {
    render(mainEl, pageHeader(page.meta), page.skeleton());
  }

  shell.set((state) => ({ ...state, refreshing: true }));
  try {
    const data = await page.load(signal, ctx);
    if (signal.aborted) return;
    render(mainEl, pageHeader(page.meta), page.view(data, ctx));
    shell.set((state) => ({ ...state, lastUpdated: new Date().toISOString(), refreshing: false }));
  } catch (error) {
    if (error?.name === "AbortError" || signal.aborted) return;
    shell.set((state) => ({ ...state, refreshing: false }));
    if (error?.kind === ErrorKind.UNAUTHENTICATED || error?.kind === ErrorKind.FORBIDDEN) {
      // Stop polling first. An expired session that keeps refreshing turns one
      // operator's idle tab into a steady stream of 401s in the security log,
      // which is exactly the signal an operator needs to stay meaningful.
      refresher.disable();
      shell.set((state) => ({ ...state, session: { authenticated: false, enforced: true } }));
      render(mainEl, pageHeader(page.meta), identityNotice(error.kind));
      return;
    }
    render(
      mainEl,
      pageHeader(page.meta),
      emptyState("This view could not be loaded", error?.userMessage ?? "An unexpected error occurred."),
    );
  }
}

function handleNavigate(navigation) {
  current = navigation;
  paintShell();
  // Move focus to the content region so keyboard and screen-reader users land
  // on the new page rather than at the top of an unchanged document.
  mainEl.focus({ preventScroll: true });
  window.scrollTo({ top: 0, behavior: "instant" });
  renderPage(navigation);
  refresher.setHandler(() => renderPage(current, { silent: true }));
}

/** Shell-level facts, loaded once and refreshed with the page. */
async function loadShellState() {
  const [systemResult, policyResult, sessionResult] = await Promise.allSettled([
    endpoints.system(),
    endpoints.policy(),
    endpoints.session(),
  ]);
  shell.set((state) => ({
    ...state,
    system: systemResult.status === "fulfilled" ? systemResult.value : null,
    policy: policyResult.status === "fulfilled" ? policyResult.value : null,
    // A failed session request leaves this null, which the header renders as
    // "Unknown" — never as an authenticated operator, and never as a name.
    session: sessionResult.status === "fulfilled" ? sessionResult.value : null,
  }));
}

function toggleDrawer() {
  const open = sidebarEl.dataset.open === "true";
  sidebarEl.dataset.open = open ? "false" : "true";
  if (!open) {
    const scrim = el("div", { class: "scrim", onClick: closeDrawer });
    scrim.id = "scrim";
    document.body.append(scrim);
  } else {
    closeDrawer();
  }
}

function closeDrawer() {
  sidebarEl.dataset.open = "false";
  document.getElementById("scrim")?.remove();
}

document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") closeDrawer();
});

// Boot.
paintShell();
router.resolve();
loadShellState();
setInterval(loadShellState, 60000);

export { router };
