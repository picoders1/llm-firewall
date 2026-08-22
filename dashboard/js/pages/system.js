/**
 * System health.
 *
 * Dependency status uses the backend's own vocabulary — `ok`, `unavailable`,
 * `not_configured` — because "not configured" and "unavailable" are different
 * operational facts and collapsing them into "unhealthy" would page someone at
 * 3am for a deployment that never had a database.
 */

import { el, icon } from "../dom.js";
import { endpoints, getAll } from "../api.js";
import { badge, card, defineList, errorState, errorBanner, kpi, loading, skeletonCards } from "../components/primitives.js";
import { formatTimestamp, formatUptime, titleCase } from "../formatters.js";

export function skeleton() {
  return loading(el("div", { class: "stack" }, [skeletonCards(3)]));
}

export async function load(signal) {
  return getAll(
    {
      system: (abort) => endpoints.system({ signal: abort }),
      ready: (abort) => endpoints.ready({ signal: abort }),
      policy: (abort) => endpoints.policy({ signal: abort }),
    },
    { signal },
  );
}

const DEP_STATE = {
  ok: { label: "Healthy", cls: "allow", glyph: "●" },
  unavailable: { label: "Unavailable", cls: "block", glyph: "■" },
  not_configured: { label: "Not configured", cls: "unknown", glyph: "○" },
};

function dependency(dep) {
  const state = DEP_STATE[dep.status] ?? { label: "Unknown", cls: "unknown", glyph: "○" };
  return el("div", { class: "dep" }, [
    el("div", {
      class: "dep__icon",
      style: { background: `var(--${state.cls}-bg)`, color: `var(--${state.cls})` },
    }, [icon(dep.status === "ok" ? "check" : "info", 16)]),
    el("div", { class: "u-min-0" }, [
      el("div", { class: "dep__name", text: titleCase(dep.name) }),
      el("div", { class: "dep__detail", text: dep.detail ?? "No additional detail" }),
    ]),
    el("div", { class: "dep__status" }, [badge(state.label, state.cls, state.glyph)]),
  ]);
}

export function view(data) {
  const nodes = [];
  if (!data.system.ok) return errorState(data.system.error);
  const system = data.system.data;

  nodes.push(
    el("div", { class: "grid grid--kpi" }, [
      kpi({
        label: "Readiness",
        value: system.ready ? "Ready" : "Not ready",
        state: system.ready ? "allow" : "warn",
        glyph: system.ready ? "●" : "▲",
        foot: system.detectors_warmed ? "Detectors warmed" : "Detectors not warmed",
      }),
      kpi({ label: "Version", value: system.version }),
      kpi({ label: "Environment", value: titleCase(system.environment) }),
      kpi({
        label: "Uptime",
        value: formatUptime(system.uptime_seconds),
        foot: system.started_at ? `Started ${formatTimestamp(system.started_at, { seconds: false })}` : null,
      }),
      // "Is /v1 protected right now?" is a question an operator has during an
      // incident, and the alternative to answering it here is shelling into the
      // container. Mode and a boolean only: no caller ids, no credentials.
      kpi({
        label: "Gateway callers",
        value: system.caller_auth_enforced ? "Authenticated" : "Open",
        state: system.caller_auth_enforced ? "allow" : "warn",
        glyph: system.caller_auth_enforced ? "●" : "▲",
        foot: system.caller_auth_enforced
          ? `Mode: ${titleCase(String(system.caller_auth_mode ?? "unknown").replace(/_/g, " "))}`
          : "/v1 is unauthenticated — development only",
      }),
    ]),
  );

  nodes.push(
    card("Dependencies", el("div", {}, (system.dependencies ?? []).map(dependency)), { flush: true }),
  );

  if (data.ready.ok) {
    const checks = data.ready.data.checks ?? [];
    nodes.push(
      card(
        "Readiness checks",
        el(
          "div",
          {},
          checks.map((check) => {
            // A failing ADVISORY check is a real finding that is NOT taking this
            // instance out of rotation, so it must not look like one that is.
            // Rendering both as a red "Fail" would send an operator to page
            // someone about a broad trusted range (ADR-027).
            const state = check.passed
              ? { cls: "allow", glyph: "\u25cf", label: "Pass", iconName: "check" }
              : check.requirement === "advisory"
                ? { cls: "warn", glyph: "\u25b2", label: "Advisory", iconName: "alert" }
                : { cls: "block", glyph: "\u25a0", label: "Fail", iconName: "alert" };
            return el("div", { class: "dep" }, [
              el("div", {
                class: "dep__icon",
                style: { background: `var(--${state.cls}-bg)`, color: `var(--${state.cls})` },
              }, [icon(state.iconName, 16)]),
              el("div", { class: "u-min-0" }, [
                el("div", { class: "dep__name", text: titleCase(check.name) }),
                el("div", { class: "dep__detail mono truncate", text: check.detail ?? "\u2014" }),
              ]),
              el("div", { class: "dep__status" }, [badge(state.label, state.cls, state.glyph)]),
            ]);
          }),
        ),
        { flush: true },
      ),
    );
  } else {
    nodes.push(card("Readiness checks", errorBanner("Readiness unavailable", data.ready.error.userMessage)));
  }

  if (data.policy.ok) {
    const policy = data.policy.data;
    nodes.push(
      card(
        "Active configuration",
        defineList([
          ["Policy", policy.policy_name],
          ["Version", el("span", { class: "mono", text: policy.policy_version })],
          ["Detectors enabled", `${policy.enabled_detector_count} of ${policy.detector_count}`],
          ["Provenance overlays", String(policy.provenance_overlay_count)],
        ]),
      ),
    );
  }

  return el("div", { class: "stack" }, nodes);
}

export const meta = { title: "System Health", subtitle: "Process, dependencies and readiness" };
