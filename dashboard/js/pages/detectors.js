/**
 * Detector inventory and policy state.
 *
 * The load-bearing distinction on this screen is between a detector that is
 * **enforcing** and one that merely exists. `injection.transformer` is enabled
 * =false, action=warn, enforcing=false, and the UI must not let a reader mistake
 * a calibrated model for a protecting one (§13).
 *
 * Mode is rendered from `enforcing` and `enabled` as the backend reports them —
 * never inferred from the presence of a threshold.
 */

import { el } from "../dom.js";
import { endpoints, getAll } from "../api.js";
import {
  badge, card, defineList, emptyState, errorState, errorBanner,
  kpi, loading, skeletonBlock,
} from "../components/primitives.js";
import { formatCount, formatDuration, formatScore, titleCase } from "../formatters.js";

export function skeleton() {
  return loading(el("div", { class: "card" }, [el("div", { class: "card__body" }, [skeletonBlock(8)])]));
}

export async function load(signal) {
  return getAll(
    {
      detectors: (abort) => endpoints.detectors({ signal: abort }),
      policy: (abort) => endpoints.policy({ signal: abort }),
    },
    { signal },
  );
}

/** Four mutually exclusive modes, each with a word and a shape. */
function mode(detector) {
  if (!detector.enabled) return badge("Disabled by policy", "unknown", "○");
  if (detector.enforcing) return badge("Blocking", "block", "■");
  if (detector.action === "warn") return badge("Warn only", "warn", "▲");
  return badge(titleCase(detector.action), "redact", "◆");
}

function detectorRow(detector) {
  return el("article", { class: "detector" }, [
    el("div", {}, [
      el("div", { class: "detector__name", text: detector.name }),
      el("div", { class: "detector__meta" }, [
        el("span", { class: "tag", text: titleCase(detector.category) }),
        ...detector.directions.map((direction) => el("span", { class: "tag", text: direction })),
        detector.calibrated
          ? badge("Calibrated", "accent", "◇")
          : badge("Uncalibrated baseline", "unknown", "○"),
        detector.consumes_provenance
          ? badge("Reads provenance", "accent", "◇")
          : null,
      ]),
      el("div", { class: "detector__specs" }, [
        spec("Threshold", formatScore(detector.threshold)),
        spec("Action", titleCase(detector.action)),
        spec("Timeout", formatDuration(detector.timeout_ms)),
        spec("On error", titleCase(detector.on_error)),
        spec("Trust overlays", String(detector.trust_overlays)),
        spec("Emits spans", detector.emits_spans ? "Yes" : "No"),
      ]),
    ]),
    el("div", { class: "detector__mode" }, [
      mode(detector),
      el("span", {
        class: "muted",
        class: "u-text-xs u-max-22",
        text: detector.enforcing
          ? "Can block traffic"
          : detector.enabled
            ? "Records evidence; cannot block"
            : "Not part of the decision path",
      }),
    ]),
  ]);
}

function spec(label, value) {
  return el("div", { class: "spec" }, [
    el("span", { class: "spec__label", text: label }),
    el("span", { class: "spec__value", text: value }),
  ]);
}

export function view(data) {
  const nodes = [];

  if (!data.detectors.ok) return errorState(data.detectors.error);
  const detectors = data.detectors.data;

  const enforcing = detectors.filter((detector) => detector.enforcing);
  const warnOnly = detectors.filter((detector) => detector.enabled && !detector.enforcing);
  const disabled = detectors.filter((detector) => !detector.enabled);

  nodes.push(
    el("div", { class: "grid grid--kpi" }, [
      kpi({ label: "Registered", value: formatCount(detectors.length) }),
      kpi({ label: "Blocking", value: formatCount(enforcing.length), state: "block", glyph: "■" }),
      kpi({ label: "Warn only", value: formatCount(warnOnly.length), state: "warn", glyph: "▲" }),
      kpi({ label: "Disabled", value: formatCount(disabled.length), glyph: "○" }),
    ]),
  );

  nodes.push(
    card(
      "Detector inventory",
      el("div", {}, detectors.map(detectorRow)),
      { flush: true, hint: "As loaded from policy" },
    ),
  );

  if (!data.policy.ok) {
    nodes.push(card("Policy", errorBanner("Policy unavailable", data.policy.error.userMessage)));
  } else {
    const policy = data.policy.data;
    nodes.push(
      card(
        "Policy",
        el("div", { class: "stack" }, [
          defineList([
            ["Policy name", policy.policy_name],
            ["Version", el("span", { class: "mono", text: policy.policy_version })],
            ["Detectors configured", String(policy.detector_count)],
            ["Detectors enabled", String(policy.enabled_detector_count)],
            ["Active actions", policy.active_actions.map(titleCase).join(", ") || null],
            [
              "Blocking detectors",
              policy.blocking_detectors.length
                ? el("span", { class: "mono", text: policy.blocking_detectors.join(", ") })
                : null,
            ],
            [
              "Fail-open detectors",
              policy.fail_open_detectors.length
                ? el("span", { class: "mono", text: policy.fail_open_detectors.join(", ") })
                : "None — every detector fails closed",
            ],
            [
              "Provenance overlays",
              policy.provenance_overlay_count === 0
                ? el("span", {}, [
                    el("span", { text: "0 " }),
                    el("span", { class: "muted", text: "— provenance is recorded but never tightens a decision" }),
                  ])
                : String(policy.provenance_overlay_count),
            ],
            ["Inspected roles", policy.inspect_roles.join(", ")],
          ]),
          el("div", { class: "banner banner--degraded u-m-0", role: "note" }, [
            el("div", {}, [
              el("strong", { text: "Read-only" }),
              el("span", {
                text: "This console cannot modify policy. Thresholds, actions and overlays change only through a reviewed deployment.",
              }),
            ]),
          ]),
        ]),
      ),
    );
  }

  if (!detectors.length) {
    nodes.push(emptyState("No detectors registered", "The policy contains no detector definitions."));
  }

  return el("div", { class: "stack" }, nodes);
}

export const meta = {
  title: "Detector & Policy",
  subtitle: "What is inspecting traffic, and what is merely watching",
};
