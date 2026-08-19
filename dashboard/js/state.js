/**
 * Application state.
 *
 * Deliberately not a reactive framework. Two small observable stores and a
 * refresh coordinator cover everything six screens need; anything more would be
 * a framework written badly (§23).
 *
 * Nothing here persists anything except the colour theme. No event data, no
 * request content, no token — the console keeps nothing across reloads that it
 * could leak.
 */

const THEME_KEY = "llmfw.theme";

export function createStore(initial) {
  let value = initial;
  const listeners = new Set();
  return {
    get: () => value,
    set(next) {
      value = typeof next === "function" ? next(value) : next;
      for (const listener of listeners) listener(value);
    },
    subscribe(listener) {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
  };
}

/** Shell-level facts the header renders and every page may read. */
export const shell = createStore({
  system: null,
  policy: null,
  // Who the gateway says is asking, or null while unknown. The console never
  // derives this from a cookie or a stored token — it asks, every time.
  session: null,
  lastUpdated: null,
  refreshing: false,
});

/**
 * Refresh coordination.
 *
 * Polling is opt-in and visible: it is off by default, the header shows the last
 * update, and it pauses while the tab is hidden. A console that silently refetches
 * forever is one nobody can reason about (§31).
 */
export function createRefreshCoordinator({ intervalMs = 30000 } = {}) {
  let timer = null;
  let running = false;
  let handler = null;

  async function run() {
    // Overlapping refreshes would interleave writes into the same DOM.
    if (running || document.hidden || !handler) return;
    running = true;
    try {
      await handler();
    } finally {
      running = false;
    }
  }

  document.addEventListener("visibilitychange", () => {
    if (!document.hidden && timer) run();
  });

  return {
    setHandler(next) { handler = next; },
    refresh: run,
    get enabled() { return timer !== null; },
    enable() {
      if (timer) return;
      timer = setInterval(run, intervalMs);
    },
    disable() {
      if (!timer) return;
      clearInterval(timer);
      timer = null;
    },
    toggle() { this.enabled ? this.disable() : this.enable(); },
  };
}

export function loadTheme() {
  try {
    const stored = localStorage.getItem(THEME_KEY);
    return stored === "light" || stored === "dark" ? stored : "dark";
  } catch {
    return "dark";
  }
}

export function saveTheme(theme) {
  try {
    localStorage.setItem(THEME_KEY, theme);
  } catch {
    /* private mode; the theme simply will not persist */
  }
}
