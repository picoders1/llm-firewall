"""Report writing: machine-readable, human-readable, and a plot.

Artefacts land in `eval/results/<run_id>/` and are never overwritten — a run id
carries a timestamp, so history accumulates and a regression is visible (§22).

The precision-recall plot is hand-rolled SVG. matplotlib would be a heavy
dependency for one line chart, and an SVG the reader can open in any browser is
better for a document meant to be reviewed.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from eval.metrics.classification import precision_recall_curve
from eval.runner import EvaluationResult

RESULTS_ROOT = Path(__file__).resolve().parents[1] / "eval" / "results"

REQUIRED_METADATA = ("run_id", "git", "machine", "dataset", "detector_config")


class UnstampedReportError(RuntimeError):
    """Refuses to emit a report that could not be reconstructed."""


def _check_stamped(metadata: dict[str, Any]) -> None:
    missing = [key for key in REQUIRED_METADATA if not metadata.get(key)]
    if missing:
        raise UnstampedReportError(
            f"refusing to write a report missing {missing}. A report that cannot name its "
            "commit, dataset and machine is not evidence (docs/13-evaluation-strategy.md)."
        )
    if not metadata["dataset"].get("checksum"):
        raise UnstampedReportError("refusing to write a report without a dataset checksum")


def write_report(result: EvaluationResult, root: Path | None = None) -> Path:
    """Write every artefact for one run and return its directory."""
    _check_stamped(result.metadata)

    directory = (root or RESULTS_ROOT) / result.run_id
    directory.mkdir(parents=True, exist_ok=True)

    metrics = result.metrics()
    payload = {
        "metadata": result.metadata,
        "metrics": metrics,
        "operating_point": result.operating_point.as_dict() if result.operating_point else None,
        "dataset_integrity": result.dataset_report,
        "warnings": result.warnings,
        "disclaimer": (
            "Internal benchmark result. Not a published project metric until the "
            "methodology and sample size support it (docs/22-evidence-and-claims.md)."
        ),
    }
    (directory / "result.json").write_text(
        json.dumps(payload, indent=2, sort_keys=False) + "\n", encoding="utf-8"
    )

    _write_predictions(directory / "predictions.csv", result)
    _write_sweep(directory / "threshold_sweep.csv", result)
    _write_pr_curve(directory / "precision_recall.svg", result)
    (directory / "report.md").write_text(_markdown(result, metrics), encoding="utf-8")

    _update_manifest(root or RESULTS_ROOT, result, metrics)
    return directory


def _write_predictions(path: Path, result: EvaluationResult) -> None:
    """Per-sample results — the raw material for error analysis.

    Without them, "recall improved" cannot become "here are the twelve prompts
    that still get through", which is the only version of that sentence worth
    anything. Sample text is **not** written: the labels and ids are enough to
    join back to the dataset, and a results directory should not become a second
    copy of the corpus.
    """
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "sample_id",
                "category",
                "label",
                "score",
                "predicted",
                "outcome",
                "preprocess_ms",
                "inference_ms",
                "errored",
                "reasons",
            ]
        )
        for sample, prediction in zip(result.samples, result.predictions, strict=True):
            predicted = prediction.score >= result.threshold
            if sample.label and predicted:
                outcome = "tp"
            elif sample.label:
                outcome = "fn"
            elif predicted:
                outcome = "fp"
            else:
                outcome = "tn"
            writer.writerow(
                [
                    sample.sample_id,
                    sample.category.value,
                    int(sample.label),
                    f"{prediction.score:.6f}",
                    int(predicted),
                    outcome,
                    f"{prediction.preprocess_ms:.4f}",
                    f"{prediction.inference_ms:.4f}",
                    int(prediction.errored),
                    ";".join(prediction.reasons),
                ]
            )


def _write_sweep(path: Path, result: EvaluationResult) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["threshold", "tp", "fp", "tn", "fn", "precision", "recall", "f1", "fpr"])
        for point in result.sweep:
            matrix = point.matrix
            writer.writerow(
                [
                    f"{point.threshold:.4f}",
                    matrix.tp,
                    matrix.fp,
                    matrix.tn,
                    matrix.fn,
                    f"{matrix.precision:.4f}",
                    f"{matrix.recall:.4f}",
                    f"{matrix.f1:.4f}",
                    f"{matrix.fpr:.4f}",
                ]
            )


def _write_pr_curve(path: Path, result: EvaluationResult) -> None:
    points = precision_recall_curve(result.labels, result.scores)
    width, height, pad = 520, 380, 55
    plot_w, plot_h = width - 2 * pad, height - 2 * pad

    def x(recall: float) -> float:
        return pad + recall * plot_w

    def y(precision: float) -> float:
        return height - pad - precision * plot_h

    path_data = " ".join(
        f"{'M' if index == 0 else 'L'}{x(recall):.1f},{y(precision):.1f}"
        for index, (_, recall, precision) in enumerate(points)
    )
    ticks = "".join(
        f'<line x1="{x(v):.1f}" y1="{height - pad}" x2="{x(v):.1f}" y2="{height - pad + 5}" '
        f'stroke="#666"/><text x="{x(v):.1f}" y="{height - pad + 20}" font-size="11" '
        f'text-anchor="middle" fill="#444">{v:.1f}</text>'
        f'<line x1="{pad - 5}" y1="{y(v):.1f}" x2="{pad}" y2="{y(v):.1f}" stroke="#666"/>'
        f'<text x="{pad - 10}" y="{y(v) + 4:.1f}" font-size="11" text-anchor="end" '
        f'fill="#444">{v:.1f}</text>'
        for v in (0.0, 0.25, 0.5, 0.75, 1.0)
    )
    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" \
viewBox="0 0 {width} {height}">
<rect width="{width}" height="{height}" fill="#fff"/>
<text x="{width / 2}" y="24" font-size="14" text-anchor="middle" fill="#111">\
Precision-Recall — {result.detector} on {result.benchmark}/{result.split.value} \
(n={len(result.samples)})</text>
<rect x="{pad}" y="{pad}" width="{plot_w}" height="{plot_h}" fill="none" stroke="#ccc"/>
{ticks}
<path d="{path_data}" fill="none" stroke="#1f77b4" stroke-width="2"/>
<text x="{width / 2}" y="{height - 8}" font-size="12" text-anchor="middle" fill="#111">\
Recall</text>
<text x="14" y="{height / 2}" font-size="12" text-anchor="middle" fill="#111" \
transform="rotate(-90 14 {height / 2})">Precision</text>
</svg>
"""
    path.write_text(svg, encoding="utf-8")


def _fmt_ci(values: list[float]) -> str:
    return f"[{values[0]:.3f}, {values[1]:.3f}]"


def _markdown(result: EvaluationResult, metrics: dict[str, Any]) -> str:
    c = metrics["classification"]
    latency = metrics["latency"]["total"]
    meta = result.metadata
    machine = meta["machine"]

    lines = [
        f"# Evaluation — {result.detector}",
        "",
        f"**Run:** `{result.run_id}`  ",
        f"**Benchmark:** `{result.benchmark}` / `{result.split.value}`  ",
        f"**Samples:** {c['n']} ({c['n_attack']} attack, {c['n_benign']} benign)  ",
        f"**Threshold:** {metrics['threshold']}",
        "",
        "> Internal benchmark result. **Not** a published project metric.",
        "",
    ]

    if result.warnings:
        lines += ["## ⚠ Validity warnings", ""]
        lines += [f"* {warning}" for warning in result.warnings]
        lines.append("")

    lines += [
        "## Classification",
        "",
        "| Metric | Value | 95% CI |",
        "|---|---|---|",
        f"| Recall (detection rate) | {c['recall']:.4f} | {_fmt_ci(c['recall_ci95'])} |",
        f"| Precision | {c['precision']:.4f} | {_fmt_ci(c['precision_ci95'])} |",
        f"| **FPR** | **{c['fpr']:.4f}** | {_fmt_ci(c['fpr_ci95'])} |",
        f"| FNR | {c['fnr']:.4f} | — |",
        f"| F1 | {c['f1']:.4f} | — |",
        f"| Accuracy | {c['accuracy']:.4f} | — |",
        "",
        f"Confusion: TP={c['tp']} FP={c['fp']} TN={c['tn']} FN={c['fn']}",
        "",
        f"Threshold-free: average precision {metrics['threshold_free']['average_precision']:.4f}, "
        f"ROC-AUC {metrics['threshold_free']['roc_auc']:.4f}",
        "",
        "## Per category",
        "",
        "| Category | n | Recall | FPR | TP | FP | FN |",
        "|---|---|---|---|---|---|---|",
    ]
    for name, stats in metrics["per_category"].items():
        lines.append(
            f"| {name} | {stats['n']} | {stats['recall']:.4f} | {stats['fpr']:.4f} | "
            f"{stats['tp']} | {stats['fp']} | {stats['fn']} |"
        )

    lines += [
        "",
        "## Latency (detector only, not gateway overhead)",
        "",
        "| Stage | mean | p50 | p95 | p99 | max |",
        "|---|---|---|---|---|---|",
    ]
    for stage in ("preprocess", "inference", "total"):
        s = metrics["latency"][stage]
        lines.append(
            f"| {stage} | {s['mean_ms']:.3f} ms | {s['p50_ms']:.3f} | {s['p95_ms']:.3f} | "
            f"{s['p99_ms']:.3f} | {s['max_ms']:.3f} |"
        )
    lines += [
        "",
        f"Single-threaded throughput: {latency['throughput_per_s_single_threaded']:.1f}/s "
        "(reciprocal of mean latency — not a concurrency measurement).",
        "",
    ]
    if not latency["percentiles_reliable"]:
        lines += [f"> {latency['percentiles_warning']}", ""]

    if result.operating_point:
        point = result.operating_point.as_dict()
        lines += [
            "## Threshold selection",
            "",
            f"* Objective: `{point['objective']}` (constraint: {point['constraint']})",
            f"* Selected threshold: **{point['threshold']}**",
            f"* Constraint satisfied: **{point['constraint_satisfied']}**",
            f"* Rationale: {point['rationale']}",
            "",
        ]

    lines += [
        "## Operating points",
        "",
        "| Threshold | Recall | Precision | FPR | TP | FP | FN |",
        "|---|---|---|---|---|---|---|",
    ]
    for row in meta.get("operating_point_table", []):
        lines.append(
            f"| {row['threshold']} | {row['recall']:.4f} | {row['precision']:.4f} | "
            f"{row['fpr']:.4f} | {row['tp']} | {row['fp']} | {row['fn']} |"
        )

    lines += [
        "",
        "## Data sources",
        "",
        "| Dataset | Licence | Commercial use | Contamination risk |",
        "|---|---|---|---|",
    ]
    for name, info in meta["dataset"].get("sources", {}).items():
        lines.append(
            f"| {name} | {info['licence']} | {info['commercial_use']} | "
            f"{info['contamination_risk']} |"
        )

    gpu = machine["gpu"]
    lines += [
        "",
        "## Reproducibility",
        "",
        f"* Commit: `{meta['git']['commit']}` (dirty: {meta['git']['dirty']})",
        f"* Dataset checksum: `{meta['dataset']['checksum']}`",
        f"* Config hash: `{meta['config_hash']}`",
        f"* Lockfile: `{meta['lockfile_hash']}`",
        f"* Python {machine['python_version']} on {machine['os']}",
        f"* CPU: {machine['cpu_model']} ({machine['cpu_count_logical']} logical), "
        f"{machine['memory_total_gb']} GB RAM",
        f"* GPU: {gpu.get('name', 'none')} {gpu.get('memory', '')}",
        f"* Seed: {meta['seed']}",
        "",
        f"> {machine['machine_class']}",
        "",
        "## Threats to validity",
        "",
        "* **Static datasets underestimate an adaptive attacker.** Every case here is one "
        "someone already published; a real attacker iterates against *this* deployment.",
        "* **Public corpora may be in a model's training data.** Any published detector's "
        "numbers on them are optimistically biased.",
        "* **Benign representativeness.** FPR measured on this corpus does not predict FPR on "
        "a specific application's traffic.",
        "* **Label noise.** The jailbreak/roleplay boundary is a judgement call.",
        "",
    ]
    return "\n".join(lines) + "\n"


def _update_manifest(root: Path, result: EvaluationResult, metrics: dict[str, Any]) -> None:
    """Append-only index of every run."""
    root.mkdir(parents=True, exist_ok=True)
    manifest_path = root / "manifest.jsonl"
    c = metrics["classification"]
    entry = {
        "run_id": result.run_id,
        "detector": result.detector,
        "benchmark": result.benchmark,
        "split": result.split.value,
        "threshold": metrics["threshold"],
        "n": c["n"],
        "recall": c["recall"],
        "precision": c["precision"],
        "fpr": c["fpr"],
        "f1": c["f1"],
        "mean_latency_ms": metrics["latency"]["total"]["mean_ms"],
        "commit": result.metadata["git"]["commit"],
        "dataset_checksum": result.metadata["dataset"]["checksum"],
        "finished_at": result.metadata["finished_at"],
    }
    with manifest_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry) + "\n")
