/**
 * Evaluation / red-team results.
 *
 * The screen exists to make one thing obvious: **this firewall is measured, not
 * claimed.** So the loudest element on each row is its evidence state, and the
 * separation the brief insists on is enforced visually:
 *
 *   status  = did the run finish and produce a valid artefact?
 *   decision = did it meet its pre-registered criteria?
 *
 * A run can be `complete` and still have failed its criteria — ADR-019 and
 * ADR-020 are exactly that. Rendering "complete" as a success would misreport
 * the project's two most important negative results (§17, §19).
 */

import { el, icon } from "../dom.js";
import { path } from "../router.js";
import { endpoints } from "../api.js";
import { formatCount, formatRate, formatScore, formatTimestamp } from "../formatters.js";
import { badge, card, emptyState, errorState, loading, skeletonBlock } from "../components/primitives.js";

export function skeleton() {
  return loading(el("div", { class: "stack" }, [skeletonBlock(4), skeletonBlock(4)]));
}

export async function load(signal) {
  try {
    return { ok: true, data: await endpoints.evaluations({ signal }) };
  } catch (error) {
    if (error?.name === "AbortError") throw error;
    return { ok: false, error };
  }
}

/** Evidence state — about the artefact, not about the outcome. */
export function evidenceBadge(status) {
  switch (status) {
    case "complete":
      return badge("Measured", "allow", "●");
    case "superseded":
      return badge("Superseded", "unknown", "○");
    case "running":
      return badge("Running", "warn", "▲");
    case "failed":
      return badge("Run failed", "failure", "✕");
    case "invalid":
      return badge("Invalid", "failure", "✕");
    default:
      return badge("Unknown", "unknown", "○");
  }
}

/** Outcome — about the criteria, and deliberately separate. */
export function decisionBadgeFor(decision) {
  if (!decision) return null;
  const upper = String(decision).toUpperCase();
  if (upper.includes("FAIL")) return badge(upper, "block", "■");
  if (upper.includes("PARTIAL")) return badge(upper, "warn", "▲");
  if (upper.includes("SUCCESS")) return badge(upper, "allow", "●");
  return badge(upper, "unknown", "○");
}

export function metric(label, value, ci = null) {
  return el("div", { class: "metric" }, [
    el("span", { class: "metric__label", text: label }),
    el("span", { class: "metric__value", text: value }),
    ci ? el("span", { class: "metric__ci", text: ci }) : null,
  ]);
}

function runCard(run, navigate) {
  return el("article", { class: "eval" }, [
    el("header", { class: "eval__head" }, [
      el("div", { style: "min-width:0" }, [
        el("div", { class: "eval__id", text: run.run_id }),
        el("div", { class: "eval__sub" }, [
          [run.detector, run.dataset && `${run.dataset}/${run.dataset_version ?? ""}`, run.created_at && formatTimestamp(run.created_at, { seconds: false })]
            .filter(Boolean)
            .join(" · "),
        ]),
      ]),
      el("div", { class: "eval__states" }, [evidenceBadge(run.status), decisionBadgeFor(run.decision)]),
    ]),
    el("div", { class: "eval__metrics" }, [
      metric("Recall", run.recall === null ? "—" : formatScore(run.recall)),
      metric("Precision", run.precision === null ? "—" : formatScore(run.precision)),
      metric("F1", run.f1 === null ? "—" : formatScore(run.f1)),
      metric("FPR", run.fpr === null ? "—" : formatRate(run.fpr)),
      metric("FNR", run.fnr === null ? "—" : formatRate(run.fnr)),
      metric("Threshold", run.threshold === null ? "—" : formatScore(run.threshold)),
      metric("Samples", run.sample_count === null ? "—" : formatCount(run.sample_count)),
    ]),
    el("div", { style: "padding:0 var(--space-5) var(--space-4)" }, [
      el("a", { class: "btn btn--sm", href: path(`/evaluations/${encodeURIComponent(run.run_id)}`) }, [
        "View detail",
        icon("chevron", 14),
      ]),
    ]),
  ]);
}

export function view(result, { navigate }) {
  if (!result.ok) return errorState(result.error);
  const payload = result.data;

  if (!payload.items.length) {
    return emptyState(
      "No finalized evaluation runs available",
      "Only runs with a valid final artefact are reported here. Nothing in eval/results/ currently qualifies.",
    );
  }

  const measured = payload.items.filter((run) => run.status === "complete");
  const superseded = payload.items.filter((run) => run.status === "superseded");

  const key = el("div", { class: "evidence-key" }, [
    el("span", {}, ["● Measured — a finished run with a valid artefact"]),
    el("span", {}, ["○ Superseded — a newer run covers the same detector and split"]),
    el("span", {}, ["■ FAILURE is an outcome, not a broken run"]),
  ]);

  const nodes = [
    card(
      "Evidence",
      el("div", { class: "stack" }, [
        el("p", { class: "secondary", style: "font-size:var(--text-sm)" }, [
          "Every figure below comes from a committed evaluation artefact carrying its dataset checksum. ",
          "A run marked Measured completed and produced a valid report — it does not mean the run met its criteria. ",
          "Those are separate columns on purpose.",
        ]),
        key,
      ]),
    ),
    ...measured.map((run) => runCard(run, navigate)),
  ];

  if (superseded.length) {
    nodes.push(
      card(
        `Superseded runs (${superseded.length})`,
        el("div", { class: "stack" }, superseded.map((run) => runCard(run, navigate))),
        { hint: "Retained for the record; a newer run covers the same detector and split" },
      ),
    );
  }

  if (payload.note) {
    nodes.push(
      el("p", { class: "muted", style: "font-size:var(--text-xs)" }, [payload.note]),
    );
  }

  return el("div", { class: "stack" }, nodes);
}

export const meta = {
  title: "Evaluation",
  subtitle: "Measured detection quality, including the runs that failed",
};
