/**
 * One evaluation run.
 *
 * Confidence intervals are shown wherever the artefact carries them, because a
 * point estimate without its interval is the single easiest way to overstate a
 * result (§33). Where the artefact has no interval, none is displayed — and none
 * is computed here, since recomputing statistics in the browser would make the
 * dashboard a second, unreviewed source of evidence (§3).
 */

import { el, icon } from "../dom.js";
import { path } from "../router.js";
import { endpoints } from "../api.js";
import {
  card, defineList, emptyState, errorState, loading, skeletonBlock,
} from "../components/primitives.js";
import { decisionBadgeFor, evidenceBadge, metric } from "./evaluations.js";
import {
  formatCount, formatDuration, formatInterval, formatRate, formatScore, formatTimestamp, titleCase,
} from "../formatters.js";

export function skeleton() {
  return loading(el("div", { class: "card" }, [el("div", { class: "card__body" }, [skeletonBlock(8)])]));
}

export async function load(signal, { params }) {
  try {
    return { ok: true, data: await endpoints.evaluation(params[0], { signal }) };
  } catch (error) {
    if (error?.name === "AbortError") throw error;
    return { ok: false, error };
  }
}

const ci = (run, key) => formatInterval(run.confidence_intervals?.[key]);

export function view(result) {
  if (!result.ok) return errorState(result.error);
  const run = result.data;

  const header = card(
    null,
    el("div", { class: "stack" }, [
      el("div", { class: "u-row u-row--top u-row--wrap" }, [
        el("div", { class: "u-min-0" }, [
          el("h2", { class: "mono u-break-all", text: run.run_id }),
          el("p", { class: "muted u-text-sm eval__runmeta" }, [
            [run.detector, run.dataset && `${run.dataset}/${run.dataset_version ?? ""}`]
              .filter(Boolean)
              .join(" · "),
          ]),
        ]),
        el("div", { class: "u-row u-row--wrap u-push" }, [
          evidenceBadge(run.status),
          decisionBadgeFor(run.decision),
        ]),
      ]),
    ]),
  );

  const detection = card(
    "Attack detection quality",
    el("div", { class: "eval__metrics u-flush" }, [
      metric("Recall", run.recall === null ? "—" : formatScore(run.recall), ci(run, "recall_ci95")),
      metric("Precision", run.precision === null ? "—" : formatScore(run.precision), ci(run, "precision_ci95")),
      metric("F1", run.f1 === null ? "—" : formatScore(run.f1)),
    ]),
    { hint: "Point estimate with 95% Wilson interval where recorded" },
  );

  const falsePositives = card(
    "False-positive behaviour",
    el("div", { class: "eval__metrics u-flush" }, [
      metric("FPR", run.fpr === null ? "—" : formatRate(run.fpr), ci(run, "fpr_ci95")),
      metric("FNR", run.fnr === null ? "—" : formatRate(run.fnr)),
      metric("Threshold", run.threshold === null ? "—" : formatScore(run.threshold)),
    ]),
  );

  const latencyBlocks = Object.entries(run.latency ?? {}).filter(
    ([, value]) => value && typeof value === "object",
  );
  const performance = card(
    "Performance",
    latencyBlocks.length
      ? el("div", { class: "eval__metrics u-flush" }, latencyBlocks.flatMap(([name, block]) => [
          metric(`${titleCase(name)} p50`, block.p50_ms !== undefined ? formatDuration(block.p50_ms) : "—"),
          metric(`${titleCase(name)} p95`, block.p95_ms !== undefined ? formatDuration(block.p95_ms) : "—"),
          metric(`${titleCase(name)} n`, block.n !== undefined ? formatCount(block.n) : "—"),
        ]))
      : el("p", { class: "not-available", text: "This run recorded no latency block." }),
  );

  const identity = card(
    "Benchmark identity",
    defineList([
      ["Detector", run.detector],
      ["Dataset", run.dataset],
      ["Split", run.dataset_version],
      ["Dataset checksum", run.dataset_sha256 ? el("span", { class: "mono truncate", text: run.dataset_sha256 }) : null],
      ["Model / implementation", run.model_version ? el("span", { class: "mono", text: run.model_version }) : null],
      ["Sample count", run.sample_count === null ? null : formatCount(run.sample_count)],
      ["Completed", run.created_at ? formatTimestamp(run.created_at) : null],
      ["Evidence state", titleCase(run.status)],
      ["Artefact", run.artefact_path ? el("span", { class: "mono truncate", text: run.artefact_path }) : null],
    ]),
  );

  const categories = Object.entries(run.category_metrics ?? {});
  const categoryTable = categories.length
    ? el("div", { class: "table-wrap" }, [
        el("table", { class: "table" }, [
          el("thead", {}, [
            el("tr", {}, [
              el("th", { scope: "col", text: "Category" }),
              el("th", { scope: "col", class: "num", text: "n" }),
              el("th", { scope: "col", class: "num", text: "Recall" }),
              el("th", { scope: "col", class: "num", text: "Recall 95% CI" }),
              el("th", { scope: "col", class: "num", text: "FPR" }),
            ]),
          ]),
          el(
            "tbody",
            {},
            categories.map(([name, block]) =>
              el("tr", {}, [
                el("td", { text: titleCase(name) }),
                el("td", { class: "num", text: block.n !== undefined ? formatCount(block.n) : "—" }),
                el("td", { class: "num", text: block.recall !== undefined && block.recall !== null ? formatScore(block.recall) : "—" }),
                el("td", { class: "num", text: formatInterval(block.recall_ci95) ?? "—" }),
                el("td", { class: "num", text: block.fpr !== undefined && block.fpr !== null ? formatRate(block.fpr) : "—" }),
              ]),
            ),
          ),
        ]),
      ])
    : emptyState("No per-category metrics", "This run did not record a category breakdown.");

  const warnings = run.benchmark_metadata?.warnings ?? [];
  const validity = card(
    "Validity",
    el("div", { class: "stack" }, [
      warnings.length
        ? el(
            "ul",
            { class: "eval__warnlist" },
            warnings.map((warning) => el("li", { text: String(warning) })),
          )
        : el("p", { class: "muted u-text-sm", text: "No validity warnings were recorded." }),
      run.benchmark_metadata?.disclaimer
        ? el("p", { class: "muted u-text-xs", text: String(run.benchmark_metadata.disclaimer) })
        : null,
    ]),
  );

  const machine = run.benchmark_metadata?.machine ?? {};
  const environment = card(
    "Benchmark environment",
    Object.keys(machine).length
      ? defineList(
          Object.entries(machine).map(([key, value]) => [
            titleCase(key),
            typeof value === "object" && value !== null
              ? el("span", { class: "mono", text: JSON.stringify(value) })
              : String(value),
          ]),
        )
      : el("p", { class: "not-available", text: "No machine metadata was recorded." }),
    { hint: "Required to interpret a latency figure" },
  );

  return el("div", { class: "stack" }, [
    el("a", { class: "btn btn--ghost btn--sm u-self-start", href: path("/evaluations") }, [
      icon("back", 14),
      "Back to evaluations",
    ]),
    header,
    el("div", { class: "grid grid--2" }, [detection, falsePositives]),
    el("div", { class: "grid grid--2" }, [performance, identity]),
    card("Per-category metrics", categoryTable, { flush: categories.length > 0 }),
    el("div", { class: "grid grid--2" }, [validity, environment]),
  ]);
}

export const meta = { title: "Evaluation detail", subtitle: "One measured run, with its intervals" };
