/**
 * Application shell: sidebar, header, mobile drawer.
 *
 * The header shows only values the API returned. There is no hard-coded
 * environment name, no placeholder version and no invented "last synced"
 * timestamp — if a value is unknown it says so, because a security console that
 * displays a confident wrong environment is worse than one that displays none.
 */

import { el, icon, render, safeHref } from "../dom.js";
import { path } from "../router.js";
import { formatRelative, formatTimestamp } from "../formatters.js";
import { openShortcuts } from "./palette.js";

const NAV = [
  { href: path("/"), label: "Overview", iconName: "overview" },
  { href: path("/events"), label: "Security Events", iconName: "events" },
  { href: path("/detectors"), label: "Detector & Policy", iconName: "detectors" },
  { href: path("/traffic"), label: "Traffic & Latency", iconName: "traffic" },
  { href: path("/evaluations"), label: "Evaluation", iconName: "evaluations" },
  { href: path("/system"), label: "System Health", iconName: "system" },
];

function brandMark() {
  const node = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  node.setAttribute("width", "26");
  node.setAttribute("height", "26");
  node.setAttribute("viewBox", "0 0 32 32");
  node.setAttribute("aria-hidden", "true");
  const shield = document.createElementNS("http://www.w3.org/2000/svg", "path");
  shield.setAttribute("d", "M16 2 5 6.5v9.2c0 7 4.7 13.6 11 14.3 6.3-.7 11-7.3 11-14.3V6.5L16 2z");
  shield.setAttribute("fill", "currentColor");
  shield.setAttribute("opacity", "0.18");
  const outline = document.createElementNS("http://www.w3.org/2000/svg", "path");
  outline.setAttribute("d", "M16 2 5 6.5v9.2c0 7 4.7 13.6 11 14.3 6.3-.7 11-7.3 11-14.3V6.5L16 2z");
  outline.setAttribute("fill", "none");
  outline.setAttribute("stroke", "currentColor");
  outline.setAttribute("stroke-width", "1.6");
  const bars = document.createElementNS("http://www.w3.org/2000/svg", "path");
  bars.setAttribute("d", "M10.5 16.2h11M13 12.4h6M13 20h6");
  bars.setAttribute("stroke", "currentColor");
  bars.setAttribute("stroke-width", "1.6");
  bars.setAttribute("stroke-linecap", "round");
  node.append(shield, outline, bars);
  return node;
}

export function renderSidebar(container, { activePath, onNavigate, version = null }) {
  render(
    container,
    el("div", { class: "brand" }, [
      el("span", { class: "brand__mark" }, [brandMark()]),
      el("span", { class: "brand__text" }, [
        el("span", { class: "brand__name", text: "LLM Firewall" }),
        el("span", { class: "brand__sub", text: "Security Ops" }),
      ]),
    ]),
    el("nav", { class: "nav", "aria-label": "Sections" }, [
      el("div", { class: "nav__label", text: "Monitoring" }),
      ...NAV.map((item) => {
        const active =
          item.href === path("/") ? activePath === path("/") || activePath === path("") : activePath.startsWith(item.href);
        return el(
          "a",
          {
            class: "nav__link",
            href: item.href,
            "aria-current": active ? "page" : null,
            onClick: onNavigate,
          },
          [icon(item.iconName, 16), el("span", { text: item.label })],
        );
      }),
    ]),
    /**
     * "Observability console" used to sit here and said nothing the brand two
     * inches above did not already say. What replaces it is the one fact about
     * this surface an operator cannot infer from looking at it: **it cannot
     * change anything.**
     *
     * That is not a caveat, it is an enforced property — the operator boundary
     * refuses every non-GET, so a mutating endpoint cannot inherit read-only
     * authentication without moving the boundary first (ADR-023). Stating it
     * explains the absence of a single edit control anywhere in the console,
     * and turns "there are no buttons" from a gap into a guarantee.
     */
    el("div", { class: "sidebar__footer" }, [
      el("div", { class: "assurance", title: "Every route on this surface is a GET. The operator boundary refuses anything else, so this console cannot alter policy, detectors or data." }, [
        icon("lock", 13),
        el("div", { class: "assurance__text" }, [
          el("span", { class: "assurance__title", text: "Read-only console" }),
          el("span", { class: "assurance__sub", text: "Cannot alter policy or data" }),
        ]),
      ]),
      el("button", { class: "sidebar__help", type: "button", onClick: () => openShortcuts() }, [
        icon("keyboard", 13),
        el("span", { text: "Keyboard shortcuts" }),
        el("kbd", { class: "kbd kbd--sm", text: "?" }),
      ]),
      version ? el("span", { class: "sidebar__build mono", text: `v${version}`, title: `Gateway version ${version}` }) : null,
    ]),
  );
}

/**
 * The two security boundaries, as one indicator.
 *
 * There are two, and they are independent: the **operator** boundary in front of
 * the console (ADR-023) and the **caller** boundary in front of `/v1`
 * (ADR-024). The header used to report only the first, so a gateway whose
 * `/v1` was wide open looked identical to one that was not.
 *
 * Normal is quiet: when both are enforced this is a small lock, because a
 * correctly configured system should not spend header space telling you so.
 * Abnormal is loud, and names which boundary is open — that is the state worth
 * interrupting someone for. In production neither can be open, since the
 * process refuses to start that way; this is therefore a development signal,
 * which is exactly why it must not be mistaken for decoration.
 */
function securityState(session, system) {
  const operatorOpen = session ? session.enforced === false : null;
  const callerOpen = system ? system.caller_auth_enforced === false : null;

  if (operatorOpen === null && callerOpen === null) {
    return { tone: "unknown", label: "Auth unknown", detail: "The gateway did not report its authentication state." };
  }

  const open = [operatorOpen ? "console" : null, callerOpen ? "/v1" : null].filter(Boolean);
  if (!open.length) {
    return { tone: "secure", label: "Authenticated", detail: "Operator and caller boundaries are both enforced." };
  }
  return {
    tone: "open",
    // Named as a state, not an action: this chip sits among buttons, and
    // "Auth off" reads like something you just pressed.
    label: open.length === 2 ? "Unauthenticated" : `${open[0]} unauthenticated`,
    detail: `Unauthenticated: ${open.join(" and ")}. Refused at startup when FIREWALL_ENVIRONMENT=production.`,
  };
}

export function renderHeader(container, { state, onRefresh, onToggleMenu, onToggleTheme, theme, polling, onTogglePolling, onOpenPalette }) {
  const { system, policy, session, lastUpdated, refreshing } = state;

  const ready = system
    ? system.ready
      ? { cls: "allow", glyph: "\u25cf", label: "Ready" }
      : { cls: "warn", glyph: "\u25b2", label: "Not ready" }
    : { cls: "unknown", glyph: "\u25cb", label: "Unknown" };

  const security = securityState(session, system);
  const environment = system?.environment ?? "unknown";
  const isProduction = environment === "production";
  const policyHash = policy?.policy_version ? policy.policy_version.replace("sha256:", "") : null;

  // --- What the gateway is, and whether it is well ------------------------
  const posture = el("div", { class: "posture" }, [
    el(
      "a",
      {
        class: `posture__item posture__status posture__status--${ready.cls}`,
        href: path("/system"),
        title: system ? `Readiness: ${ready.label}. Open System Health.` : "Readiness unknown",
      },
      [
        el("span", { class: "posture__glyph", text: ready.glyph, "aria-hidden": "true" }),
        el("span", { text: ready.label }),
      ],
    ),
    el("span", {
      class: `posture__item posture__env${isProduction ? " posture__env--production" : ""}`,
      text: environment,
      title: `Environment: ${environment}`,
    }),
    policyHash
      ? el(
          "a",
          {
            class: "posture__item posture__policy",
            href: path("/detectors"),
            title: `Policy in force: sha256:${policyHash}. Open Detector & Policy.`,
          },
          [
            icon("detectors", 13),
            el("span", { class: "mono", text: policyHash.slice(0, 8) }),
          ],
        )
      : null,
    el(
      "a",
      {
        class: `posture__item posture__security posture__security--${security.tone}`,
        href: path("/system"),
        title: security.detail,
      },
      security.tone === "secure"
        ? [icon("lock", 13), el("span", { class: "sr-only", text: security.label })]
        : [
            el("span", { class: "posture__glyph", text: security.tone === "open" ? "\u25b2" : "\u25cb", "aria-hidden": "true" }),
            // The label is dropped on narrow screens, so the accessible name
            // must not depend on it. The amber chip and glyph still carry the
            // signal visually; the tooltip and this text carry it otherwise.
            el("span", { class: "posture__label", text: security.label }),
            el("span", { class: "sr-only", text: security.detail }),
          ],
    ),
  ]);

  // The signed-in operator, when there is one. Rendered only on a real
  // authenticated session: an unauthenticated console must never show a name,
  // and `safeHref` refuses a logout path that is not a same-origin absolute
  // path, so a mistyped setting cannot walk an operator to another host.
  if (session?.authenticated) {
    const logout = session.logout_path ? safeHref(session.logout_path) : null;
    posture.append(
      el("span", { class: "posture__item posture__operator", title: session.subject ?? "Authenticated operator" }, [
        icon("user", 13),
        el("span", { class: "posture__subject", text: session.subject ?? "Authenticated" }),
        logout ? el("a", { class: "posture__out", href: logout, text: "Sign out" }) : null,
      ]),
    );
  }

  // --- Whether what you are reading is current ----------------------------
  const controls = el("div", { class: "controls" }, [
    el(
      "span",
      {
        class: "controls__updated",
        title: lastUpdated ? `Last refreshed ${formatTimestamp(lastUpdated)}` : "Not refreshed yet",
      },
      [
        icon("system", 12),
        el("span", { text: lastUpdated ? formatRelative(lastUpdated) : "\u2014" }),
        el("span", { class: "sr-only", text: "since this view was last refreshed" }),
      ],
    ),
    el(
      "button",
      {
        class: `btn btn--sm${polling ? " btn--on" : ""}`,
        type: "button",
        "aria-pressed": polling ? "true" : "false",
        title: polling ? "Auto-refreshing every 30s \u2014 click to stop" : "Auto-refresh is off \u2014 click to start",
      onClick: onTogglePolling,
      },
      [icon("pulse", 13), el("span", { class: "btn__label", text: polling ? "30s" : "Auto" })],
    ),
    el(
      "button",
      {
        class: "btn btn--sm btn--icon",
        type: "button",
        "aria-label": theme === "dark" ? "Switch to light theme" : "Switch to dark theme",
        title: theme === "dark" ? "Switch to light theme (Shift+T)" : "Switch to dark theme (Shift+T)",
        onClick: onToggleTheme,
      },
      [icon(theme === "dark" ? "sun" : "moon", 14)],
    ),
    el(
      "button",
      {
        class: "btn btn--primary btn--sm",
        type: "button",
        disabled: refreshing,
        title: "Reload this view (R)",
        onClick: onRefresh,
      },
      [
        el("span", { class: refreshing ? "btn__spin" : "" }, [icon("refresh", 14)]),
        el("span", { class: "btn__label", text: refreshing ? "Refreshing" : "Refresh" }),
      ],
    ),
  ]);

  render(
    container,
    el("button", { class: "menu-toggle", type: "button", "aria-label": "Open navigation", onClick: onToggleMenu }, [
      icon("menu", 18),
    ]),
    el(
      "button",
      {
        class: "cmdk",
        type: "button",
        "aria-label": "Open the command palette",
        title: "Search views and filters (Ctrl+K)",
        onClick: onOpenPalette,
      },
      [
        icon("search", 14),
        el("span", { class: "cmdk__text", text: "Search" }),
        el("kbd", { class: "kbd kbd--sm cmdk__key", text: "Ctrl K" }),
      ],
    ),
    el("div", { class: "header__meta" }, [posture, controls]),
  );
}

export { NAV };
