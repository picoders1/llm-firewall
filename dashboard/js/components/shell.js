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
import { badge } from "./primitives.js";

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

export function renderSidebar(container, { activePath, onNavigate }) {
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
    el("div", { class: "sidebar__footer" }, [
      el("span", { text: "Observability console" }),
      el("span", { text: "Read-only — no policy control" }),
    ]),
  );
}

/**
 * The signed-in operator, or an honest statement that nobody is.
 *
 * Three states, because collapsing them would misinform: a named operator, an
 * explicit "authentication disabled" (development, where the boundary is off and
 * pretending otherwise would be a fabricated security property), and "unknown"
 * while the session request is still in flight or failed.
 *
 * The sign-out link is rendered only when the gateway reported a path for it,
 * and only through `safeHref`, which refuses anything that is not a same-origin
 * absolute path — the console must not be able to walk an operator to an
 * attacker-chosen host because a setting was mistyped.
 */
function identity(session) {
  if (session && session.authenticated) {
    const href = session.logout_path ? safeHref(session.logout_path) : null;
    return el("div", { class: "header__item header__item--optional" }, [
      el("span", { class: "muted", text: "Operator" }),
      el("span", { class: "identity" }, [
        el("strong", { text: session.subject ?? "Authenticated" }),
        href ? el("a", { class: "identity__out", href, text: "Sign out" }) : null,
      ]),
    ]);
  }
  const unenforced = session && session.enforced === false;
  return el("div", { class: "header__item header__item--optional" }, [
    el("span", { class: "muted", text: "Operator" }),
    unenforced
      ? badge("Auth disabled", "warn", "▲")
      : badge("Unknown", "unknown", "○"),
  ]);
}

export function renderHeader(container, { state, onRefresh, onToggleMenu, onToggleTheme, theme, polling, onTogglePolling }) {
  const { system, policy, session, lastUpdated, refreshing } = state;

  const readiness = system
    ? system.ready
      ? badge("Ready", "allow", "●")
      : badge("Not ready", "warn", "▲")
    : badge("Unknown", "unknown", "○");

  render(
    container,
    el("button", { class: "menu-toggle", type: "button", "aria-label": "Open navigation", onClick: onToggleMenu }, [
      icon("menu", 18),
    ]),
    el("div", { class: "header__meta" }, [
      el("div", { class: "header__item" }, [
        el("span", { class: "muted", text: "Environment" }),
        el("strong", { text: system?.environment ?? "Unknown" }),
      ]),
      el("div", { class: "header__divider" }),
      el("div", { class: "header__item" }, [el("span", { class: "muted", text: "Status" }), readiness]),
      el("div", { class: "header__divider header__item--optional" }),
      el("div", { class: "header__item header__item--optional" }, [
        el("span", { class: "muted", text: "Policy" }),
        el("strong", {
          class: "mono",
          // The full hash is the tooltip; the truncation is display only.
          text: policy?.policy_version ? policy.policy_version.replace("sha256:", "").slice(0, 8) : "—",
          title: policy?.policy_version ?? "Policy version unavailable",
        }),
      ]),
      el("div", { class: "header__divider header__item--optional" }),
      identity(session),
      el("div", { class: "header__divider header__item--optional" }),
      el("div", { class: "header__item header__item--optional" }, [
        el("span", { class: "muted", text: "Updated" }),
        el("strong", {
          text: lastUpdated ? formatRelative(lastUpdated) : "—",
          title: lastUpdated ? formatTimestamp(lastUpdated) : "Not refreshed yet",
        }),
      ]),
      el(
        "button",
        {
          class: "btn btn--sm",
          type: "button",
          "aria-pressed": polling ? "true" : "false",
          title: polling ? "Auto-refresh every 30s — click to stop" : "Auto-refresh is off",
          onClick: onTogglePolling,
        },
        [polling ? "Auto 30s" : "Auto off"],
      ),
      el(
        "button",
        {
          class: "btn btn--sm",
          type: "button",
          "aria-label": theme === "dark" ? "Switch to light theme" : "Switch to dark theme",
          onClick: onToggleTheme,
        },
        [icon(theme === "dark" ? "sun" : "moon", 14)],
      ),
      el(
        "button",
        { class: "btn btn--primary btn--sm", type: "button", disabled: refreshing, onClick: onRefresh },
        [
          el("span", { class: refreshing ? "btn__spin" : "" }, [icon("refresh", 14)]),
          el("span", { text: refreshing ? "Refreshing" : "Refresh" }),
        ],
      ),
    ]),
  );
}

export { NAV };
