"""Threshold sweep on dev, frozen evaluation on the independent hold-out.

Answers one question: **does any operating point of the ML classifier beat the
heuristic by enough to justify its false-positive and latency cost?**

The methodology is the point, so it is enforced rather than described:

* **Calibration reads `public/dev` only.** The `full` benchmark *contains* the
  independent hold-out, so its dev split carries 92 hold-out samples; selecting a
  threshold there would leak the hold-out into calibration. `public/dev` excludes
  it by construction, and :func:`_assert_no_holdout` re-checks that at runtime.
* **Operating points are chosen, frozen and written to disk before the hold-out
  is scored.** The freeze is a separate phase, not a convention.
* **Nothing after the freeze may change a threshold.** If every dev-selected
  point fails on the hold-out, that is the result.

    uv run python -m scripts.threshold_analysis
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from eval.detectors import build_detector
from eval.loaders.registry_loader import load_benchmark
from eval.metadata import git_state, lockfile_hash, machine_metadata
from eval.metrics.classification import ConfusionMatrix, confusion_at, wilson_interval
from eval.metrics.latency import latency_stats
from eval.schema import DETECTOR_SCOPE, Sample, Split

RESULTS = Path(__file__).resolve().parents[1] / "eval" / "results"
SCOPE = DETECTOR_SCOPE["injection.heuristic"]

CANDIDATE = "injection.protectai_deberta_v2"
BASELINE = "injection.heuristic"
ALTERNATIVE = "injection.arch_guard"

# The production threshold, unchanged by this analysis.
BASELINE_THRESHOLD = 0.85

# Sensitivity bands, not claimed SLOs. The project has never asserted an
# operational FPR tolerance and does not start here; the band that matters is
# whichever one a deploying operator can live with, so several are reported
# (docs/13-evaluation-strategy.md). 0.0241 is included because it is the
# heuristic's measured hold-out FPR — the like-for-like comparison point.
FPR_TARGETS: tuple[float, ...] = (0.005, 0.01, 0.02, 0.0241, 0.025, 0.05)

# Categories the hold-out metadata supports, analysed separately because an
# aggregate FPR hides that the failures concentrate in security work.
BREAKDOWN_SUBCATEGORIES = (
    "quoted_attack",
    "ignore_previous_ordinary",
    "override_ordinary",
    "human_instructions",
    "security_policy",
    "system_prompt_engineering",
    "injection_discussion",
    "jailbreak_discussion",
    "guardrail_docs",
    "code_with_attack_strings",
)
BREAKDOWN_DOMAINS = (
    "security_operations",
    "incident_response",
    "technical_documentation",
    "software_engineering",
    "compliance",
    "ai_safety",
)


def _assert_no_holdout(samples: list[Sample], where: str) -> None:
    """Runtime guard: the independent hold-out must never reach calibration."""
    contaminated = [s for s in samples if s.source == "internal_authored"]
    if contaminated:
        raise RuntimeError(
            f"HOLD-OUT LEAK: {len(contaminated)} independent hold-out samples reached "
            f"{where}. Threshold selection must never see them "
            f"(docs/13-evaluation-strategy.md)."
        )


async def score(
    detector_name: str, samples: list[Sample], threshold: float
) -> list[dict[str, Any]]:
    detector = build_detector(detector_name, threshold=threshold)
    await detector.warmup()
    try:
        rows = []
        for sample in samples:
            prediction = await detector.predict(sample)
            rows.append(
                {
                    "sample_id": sample.sample_id,
                    "label": sample.label,
                    "score": prediction.score,
                    "category": sample.category.value,
                    "sub_category": sample.sub_category,
                    "domain": sample.domain,
                    "hard_negative": sample.notes == "hard_negative",
                    "latency_ms": prediction.total_ms,
                }
            )
    finally:
        await detector.aclose()
    return rows


def sweep(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Full sweep over every distinct observed score, plus a fine uniform grid.

    Candidate thresholds are the observed scores themselves: a transformer's
    scores saturate near 0 and 1, so a uniform grid alone would step straight
    past every operating point that actually exists.
    """
    labels = [r["label"] for r in rows]
    scores = [r["score"] for r in rows]
    grid = {round(i / 1000, 4) for i in range(1001)}
    grid.update(round(s, 6) for s in scores)
    # Just above each observed score, so a point that excludes exactly that
    # sample is reachable.
    grid.update(min(1.0, round(s + 1e-6, 6)) for s in scores)

    table = []
    for threshold in sorted(grid):
        matrix = confusion_at(labels, scores, threshold)
        table.append({"threshold": threshold, **matrix.as_dict()})
    return table


def select_operating_points(table: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Highest dev recall within each FPR band. Dev only."""
    points = []
    for target in FPR_TARGETS:
        eligible = [row for row in table if row["fpr"] <= target]
        if not eligible:
            points.append(
                {
                    "name": f"fpr<={target}",
                    "target_fpr": target,
                    "threshold": None,
                    "achievable": False,
                    "note": "no threshold on dev meets this FPR budget",
                }
            )
            continue
        # Highest recall; ties broken toward the higher (more conservative)
        # threshold so the frozen point is the least aggressive one that achieves it.
        best = max(eligible, key=lambda r: (r["recall"], r["threshold"]))
        points.append(
            {
                "name": f"fpr<={target}",
                "target_fpr": target,
                "threshold": best["threshold"],
                "achievable": True,
                "dev": best,
            }
        )
    return points


def pareto_frontier(table: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Points where no other threshold has both >= recall and <= FPR."""
    ordered = sorted(table, key=lambda r: (r["fpr"], -r["recall"]))
    frontier: list[dict[str, Any]] = []
    best_recall = -1.0
    for row in ordered:
        if row["recall"] > best_recall:
            frontier.append(row)
            best_recall = row["recall"]
    return frontier


def subset_metrics(
    rows: list[dict[str, Any]], threshold: float, predicate: Any
) -> dict[str, Any] | None:
    subset = [r for r in rows if predicate(r)]
    if not subset:
        return None
    labels = [r["label"] for r in subset]
    scores = [r["score"] for r in subset]
    matrix = confusion_at(labels, scores, threshold)
    benign_n = matrix.negatives
    fpr_lo, fpr_hi = wilson_interval(matrix.fp, benign_n) if benign_n else (0.0, 0.0)
    return {
        "n": len(subset),
        "n_benign": benign_n,
        "fp": matrix.fp,
        "tn": matrix.tn,
        "fpr": round(matrix.fpr, 4),
        "fpr_ci95": [round(fpr_lo, 4), round(fpr_hi, 4)],
    }


def evaluate_frozen(rows: list[dict[str, Any]], threshold: float) -> dict[str, Any]:
    labels = [r["label"] for r in rows]
    scores = [r["score"] for r in rows]
    matrix: ConfusionMatrix = confusion_at(labels, scores, threshold)
    recall_lo, recall_hi = wilson_interval(matrix.tp, matrix.positives)
    fpr_lo, fpr_hi = wilson_interval(matrix.fp, matrix.negatives)

    by_sub = {}
    for name in BREAKDOWN_SUBCATEGORIES:
        result = subset_metrics(rows, threshold, lambda r, n=name: r["sub_category"] == n)
        if result:
            by_sub[name] = result
    by_domain = {}
    for name in BREAKDOWN_DOMAINS:
        result = subset_metrics(
            rows, threshold, lambda r, n=name: r["domain"] == n and not r["label"]
        )
        if result:
            by_domain[name] = result

    extraction = [r for r in rows if r["category"] == "system_prompt_extraction"]
    ext_tp = sum(1 for r in extraction if r["score"] >= threshold)

    return {
        "threshold": threshold,
        "overall": {
            **matrix.as_dict(),
            "recall_ci95": [round(recall_lo, 4), round(recall_hi, 4)],
            "fpr_ci95": [round(fpr_lo, 4), round(fpr_hi, 4)],
        },
        "all_benign": subset_metrics(rows, threshold, lambda r: not r["label"]),
        "hard_negatives": subset_metrics(
            rows, threshold, lambda r: not r["label"] and r["hard_negative"]
        ),
        "ordinary_benign": subset_metrics(
            rows, threshold, lambda r: not r["label"] and not r["hard_negative"]
        ),
        "by_sub_category": by_sub,
        "by_domain": by_domain,
        "system_prompt_extraction": {
            "n": len(extraction),
            "tp": ext_tp,
            "fn": len(extraction) - ext_tp,
            "recall": round(ext_tp / len(extraction), 4) if extraction else 0.0,
            "recall_ci95": [round(v, 4) for v in wilson_interval(ext_tp, len(extraction))],
        },
    }


# --- plots (hand-rolled SVG: vector, diffable, no plotting dependency) -------


def _line_plot(
    path: Path,
    title: str,
    x_label: str,
    y_label: str,
    series: list[tuple[str, str, list[tuple[float, float]]]],
    x_max: float = 1.0,
    markers: list[tuple[float, float, str]] | None = None,
) -> None:
    width, height, pad = 640, 400, 70
    plot_w, plot_h = width - 2 * pad, height - 2 * pad

    def px(x: float) -> float:
        return pad + (min(x, x_max) / x_max) * plot_w

    def py(y: float) -> float:
        return height - pad - y * plot_h

    parts = []
    for index, (name, colour, points) in enumerate(series):
        if not points:
            continue
        d = " ".join(
            f"{'M' if i == 0 else 'L'}{px(x):.1f},{py(y):.1f}" for i, (x, y) in enumerate(points)
        )
        parts.append(f'<path d="{d}" fill="none" stroke="{colour}" stroke-width="2"/>')
        parts.append(
            f'<rect x="{pad + 8}" y="{pad + 8 + index * 16}" width="10" height="10" '
            f'fill="{colour}"/><text x="{pad + 24}" y="{pad + 17 + index * 16}" '
            f'font-size="11" fill="#222">{name}</text>'
        )
    for x, y, label in markers or []:
        parts.append(
            f'<circle cx="{px(x):.1f}" cy="{py(y):.1f}" r="4" fill="#d62728"/>'
            f'<text x="{px(x) + 7:.1f}" y="{py(y) - 6:.1f}" font-size="10" fill="#d62728">'
            f"{label}</text>"
        )
    ticks = "".join(
        f'<line x1="{px(v * x_max):.1f}" y1="{height - pad}" x2="{px(v * x_max):.1f}" '
        f'y2="{height - pad + 5}" stroke="#666"/>'
        f'<text x="{px(v * x_max):.1f}" y="{height - pad + 19}" font-size="10" '
        f'text-anchor="middle" fill="#444">{v * x_max:.3g}</text>'
        f'<line x1="{pad - 5}" y1="{py(v):.1f}" x2="{pad}" y2="{py(v):.1f}" stroke="#666"/>'
        f'<text x="{pad - 9}" y="{py(v) + 4:.1f}" font-size="10" text-anchor="end" '
        f'fill="#444">{v:.2f}</text>'
        for v in (0.0, 0.25, 0.5, 0.75, 1.0)
    )
    path.write_text(
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}"><rect width="{width}" height="{height}" fill="#fff"/>'
        f'<text x="{width / 2}" y="26" font-size="14" text-anchor="middle" fill="#111">{title}</text>'
        f'<rect x="{pad}" y="{pad}" width="{plot_w}" height="{plot_h}" fill="none" stroke="#ccc"/>'
        f"{ticks}{''.join(parts)}"
        f'<text x="{width / 2}" y="{height - 8}" font-size="12" text-anchor="middle" '
        f'fill="#111">{x_label}</text>'
        f'<text x="16" y="{height / 2}" font-size="12" text-anchor="middle" fill="#111" '
        f'transform="rotate(-90 16 {height / 2})">{y_label}</text></svg>\n',
        encoding="utf-8",
    )


def _bar_plot(path: Path, title: str, bars: list[tuple[str, float]], ymax: float) -> None:
    width, height, pad = 700, 360, 80
    plot_w, plot_h = width - 2 * pad, height - 2 * pad
    slot = plot_w / max(1, len(bars))
    parts = []
    for index, (name, value) in enumerate(bars):
        h = 0 if ymax <= 0 else (value / ymax) * plot_h
        x = pad + index * slot + slot * 0.15
        w = slot * 0.7
        y = height - pad - h
        parts.append(
            f'<rect x="{x:.1f}" y="{y:.1f}" width="{w:.1f}" height="{h:.1f}" fill="#1f77b4"/>'
            f'<text x="{x + w / 2:.1f}" y="{y - 5:.1f}" font-size="10" text-anchor="middle" '
            f'fill="#111">{value:.3f}</text>'
            f'<text x="{x + w / 2:.1f}" y="{height - pad + 14:.1f}" font-size="9" '
            f'text-anchor="middle" fill="#444" transform="rotate(-20 {x + w / 2:.1f} '
            f'{height - pad + 14:.1f})">{name}</text>'
        )
    path.write_text(
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}"><rect width="{width}" height="{height}" fill="#fff"/>'
        f'<text x="{width / 2}" y="26" font-size="14" text-anchor="middle" fill="#111">{title}</text>'
        f'<line x1="{pad}" y1="{height - pad}" x2="{width - pad}" y2="{height - pad}" '
        f'stroke="#666"/>{"".join(parts)}</svg>\n',
        encoding="utf-8",
    )


async def main(argv: list[str] | None = None) -> int:
    argparse.ArgumentParser(description="Threshold sweep and deployability analysis").parse_args(
        argv
    )

    started = datetime.now(UTC)
    run_id = f"{started.strftime('%Y%m%dT%H%M%SZ')}__threshold-deployability"
    out = RESULTS / run_id
    out.mkdir(parents=True, exist_ok=True)

    # ---------- PHASE 1: dev only ------------------------------------------
    public, _ = load_benchmark("public")
    dev = [s for s in public if s.split is Split.DEV and s.category in SCOPE]
    _assert_no_holdout(dev, "dev calibration split")
    print(
        f"DEV (public only): n={len(dev)}  attack={sum(s.label for s in dev)}  "
        f"benign={sum(1 for s in dev if not s.label)}"
    )
    print("  hold-out samples present: 0 (asserted)\n")

    print("scoring candidate on dev …")
    dev_rows = await score(CANDIDATE, dev, 0.5)
    print("scoring baseline on dev …")
    dev_base = await score(BASELINE, dev, BASELINE_THRESHOLD)

    dev_table = sweep(dev_rows)
    with (out / "dev_threshold_sweep.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(dev_table[0]))
        writer.writeheader()
        writer.writerows(dev_table)

    operating_points = select_operating_points(dev_table)
    frontier = pareto_frontier(dev_table)
    baseline_dev = confusion_at(
        [r["label"] for r in dev_base], [r["score"] for r in dev_base], BASELINE_THRESHOLD
    )

    (out / "dev_metrics.json").write_text(
        json.dumps(
            {
                "split": "public/dev",
                "n": len(dev),
                "note": "calibration split; excludes the independent hold-out by construction",
                "candidate": CANDIDATE,
                "baseline": {
                    "detector": BASELINE,
                    "threshold": BASELINE_THRESHOLD,
                    **baseline_dev.as_dict(),
                },
                "pareto_frontier_points": len(frontier),
                "operating_points": operating_points,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    # ---------- FREEZE ------------------------------------------------------
    frozen = {
        point["name"]: point["threshold"] for point in operating_points if point.get("achievable")
    }
    (out / "operating_points.json").write_text(
        json.dumps(
            {
                "frozen_at": datetime.now(UTC).isoformat(),
                "selected_on": "public/dev",
                "policy": (
                    "Thresholds are frozen here, BEFORE the hold-out is scored. Nothing "
                    "downstream may change them. If every point fails on the hold-out, that "
                    "is the result (docs/13-evaluation-strategy.md)."
                ),
                "frozen_thresholds": frozen,
                "dev_selection": operating_points,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print(
        f"\nFROZEN {len(frozen)} operating points from dev: "
        f"{ {k: round(v, 4) for k, v in frozen.items()} }\n"
    )

    # ---------- PHASE 2: hold-out, frozen thresholds only -------------------
    holdout, _ = load_benchmark("holdout")
    ho = [s for s in holdout if s.category in SCOPE]
    print(
        f"HOLD-OUT: n={len(ho)}  attack={sum(s.label for s in ho)}  "
        f"benign={sum(1 for s in ho if not s.label)}"
    )

    print("scoring candidate on hold-out …")
    ho_rows = await score(CANDIDATE, ho, 0.5)
    print("scoring baseline on hold-out …")
    ho_base = await score(BASELINE, ho, BASELINE_THRESHOLD)
    print("scoring alternative on hold-out …")
    ho_alt = await score(ALTERNATIVE, ho, 0.5)

    holdout_results = {
        name: evaluate_frozen(ho_rows, threshold) for name, threshold in frozen.items()
    }
    baseline_holdout = evaluate_frozen(ho_base, BASELINE_THRESHOLD)
    alternative_holdout = evaluate_frozen(ho_alt, 0.5)

    latency = {
        CANDIDATE: latency_stats([r["latency_ms"] for r in ho_rows]).as_dict(),
        BASELINE: latency_stats([r["latency_ms"] for r in ho_base]).as_dict(),
        ALTERNATIVE: latency_stats([r["latency_ms"] for r in ho_alt]).as_dict(),
    }

    (out / "holdout_metrics.json").write_text(
        json.dumps(
            {
                "note": "frozen thresholds from public/dev; no threshold selected here",
                "n": len(ho),
                "candidate": holdout_results,
                "baseline": {"detector": BASELINE, **baseline_holdout},
                "alternative": {"detector": ALTERNATIVE, **alternative_holdout},
                "latency": latency,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    with (out / "predictions.jsonl").open("w", encoding="utf-8") as handle:
        for detector, rows in (
            (CANDIDATE, ho_rows),
            (BASELINE, ho_base),
            (ALTERNATIVE, ho_alt),
        ):
            for row in rows:
                handle.write(json.dumps({"detector": detector, "split": "holdout", **row}) + "\n")

    # ---------- artefacts ----------------------------------------------------
    _line_plot(
        out / "recall_vs_fpr_dev.svg",
        "Recall vs FPR — DEV (public, calibration split)",
        "false-positive rate",
        "recall",
        [("ProtectAI DeBERTa", "#1f77b4", [(r["fpr"], r["recall"]) for r in frontier])],
        x_max=0.2,
        markers=[(baseline_dev.fpr, baseline_dev.recall, "heuristic")],
    )
    ho_curve = pareto_frontier(sweep(ho_rows))
    _line_plot(
        out / "recall_vs_fpr_holdout.svg",
        "Recall vs FPR — independent HOLD-OUT (curve shown for context only)",
        "false-positive rate",
        "recall",
        [("ProtectAI DeBERTa", "#ff7f0e", [(r["fpr"], r["recall"]) for r in ho_curve])],
        x_max=0.3,
        markers=[
            (
                baseline_holdout["all_benign"]["fpr"],
                baseline_holdout["overall"]["recall"],
                "heuristic",
            )
        ],
    )
    _line_plot(
        out / "threshold_vs_fpr.svg",
        "Threshold vs FPR",
        "threshold",
        "false-positive rate",
        [("dev", "#1f77b4", [(r["threshold"], r["fpr"]) for r in dev_table])],
    )
    _line_plot(
        out / "threshold_vs_recall.svg",
        "Threshold vs recall",
        "threshold",
        "recall",
        [("dev", "#2ca02c", [(r["threshold"], r["recall"]) for r in dev_table])],
    )
    worst = max(frozen.items(), key=lambda kv: kv[1]) if frozen else None
    if worst:
        result = holdout_results[worst[0]]
        _bar_plot(
            out / "hard_negative_fpr.svg",
            f"Hold-out FPR by sub-category at frozen threshold {worst[1]:.4f}",
            [(k, v["fpr"]) for k, v in result["by_sub_category"].items()],
            max([v["fpr"] for v in result["by_sub_category"].values()] + [0.05]),
        )

    (out / "manifest.json").write_text(
        json.dumps(
            {
                "run_id": run_id,
                "purpose": "threshold sweep on dev; frozen-threshold validation on hold-out",
                "started_at": started.isoformat(),
                "finished_at": datetime.now(UTC).isoformat(),
                "calibration_split": "public/dev (excludes independent hold-out)",
                "validation_split": "holdout (independent, never tuned on)",
                "methodology": {
                    "thresholds_selected_on": "public/dev",
                    "thresholds_frozen_before_holdout_scoring": True,
                    "holdout_used_for_selection": False,
                    "holdout_leak_guard": "scripts.threshold_analysis._assert_no_holdout",
                    "confidence_intervals": "Wilson score, 95%, two-sided",
                    "plot_format": (
                        "SVG rather than PNG: vector, diffable in review, and avoids adding a "
                        "plotting dependency for five figures"
                    ),
                },
                "detectors": {
                    "candidate": CANDIDATE,
                    "baseline": f"{BASELINE} @ {BASELINE_THRESHOLD}",
                    "alternative": ALTERNATIVE,
                },
                "git": git_state(),
                "lockfile_hash": lockfile_hash(),
                "machine": machine_metadata(),
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    _write_reports(
        out,
        operating_points,
        frozen,
        holdout_results,
        baseline_dev,
        baseline_holdout,
        alternative_holdout,
        latency,
        len(dev),
        len(ho),
        ho_rows,
    )

    print(
        f"\n{'operating point':<16}{'thr':>8}{'devRec':>8}{'devFPR':>8}"
        f"{'hoRec':>8}{'hoFPR':>8}{'hoHardFPR':>11}"
    )
    print("-" * 67)
    print(
        f"{'heuristic':<16}{BASELINE_THRESHOLD:>8.2f}{baseline_dev.recall:>8.4f}"
        f"{baseline_dev.fpr:>8.4f}{baseline_holdout['overall']['recall']:>8.4f}"
        f"{baseline_holdout['all_benign']['fpr']:>8.4f}"
        f"{baseline_holdout['hard_negatives']['fpr']:>11.4f}"
    )
    for point in operating_points:
        if not point.get("achievable"):
            print(f"{point['name']:<16}{'—':>8}  not achievable on dev")
            continue
        result = holdout_results[point["name"]]
        print(
            f"{point['name']:<16}{point['threshold']:>8.4f}{point['dev']['recall']:>8.4f}"
            f"{point['dev']['fpr']:>8.4f}{result['overall']['recall']:>8.4f}"
            f"{result['all_benign']['fpr']:>8.4f}"
            f"{result['hard_negatives']['fpr']:>11.4f}"
        )
    print(f"\n→ {out}")
    return 0


def _write_reports(
    out: Path,
    operating_points: list[dict[str, Any]],
    frozen: dict[str, float],
    holdout_results: dict[str, Any],
    baseline_dev: ConfusionMatrix,
    baseline_holdout: dict[str, Any],
    alternative_holdout: dict[str, Any],
    latency: dict[str, Any],
    dev_n: int,
    ho_n: int,
    ho_rows: list[dict[str, Any]],
) -> None:
    cand_lat = latency[CANDIDATE]["mean_ms"]
    base_lat = latency[BASELINE]["mean_ms"]

    lines = [
        "# Threshold sweep and deployability analysis",
        "",
        f"Calibration: `public/dev` (n={dev_n}) — **excludes the independent hold-out**.  ",
        f"Validation: independent hold-out (n={ho_n}), frozen thresholds only.",
        "",
        "## Operating points",
        "",
        "| Point | Threshold | Dev recall | Dev FPR | HO recall | HO FPR | HO FPR CI95 | HO hard-neg FPR | Latency |",
        "|---|---|---|---|---|---|---|---|---|",
        f"| **heuristic (production)** | {BASELINE_THRESHOLD} | {baseline_dev.recall:.4f} | "
        f"{baseline_dev.fpr:.4f} | {baseline_holdout['overall']['recall']:.4f} | "
        f"**{baseline_holdout['all_benign']['fpr']:.4f}** | "
        f"{baseline_holdout['all_benign']['fpr_ci95']} | "
        f"{baseline_holdout['hard_negatives']['fpr']:.4f} | {base_lat:.3f} ms |",
    ]
    for point in operating_points:
        if not point.get("achievable"):
            lines.append(f"| {point['name']} | — | not achievable on dev | | | | | | |")
            continue
        r = holdout_results[point["name"]]
        lines.append(
            f"| {point['name']} | {point['threshold']:.4f} | {point['dev']['recall']:.4f} | "
            f"{point['dev']['fpr']:.4f} | {r['overall']['recall']:.4f} | "
            f"**{r['all_benign']['fpr']:.4f}** | {r['all_benign']['fpr_ci95']} | "
            f"{r['hard_negatives']['fpr']:.4f} | {cand_lat:.1f} ms |"
        )

    lines += [
        "",
        "## Hold-out false positives by sub-category, at each frozen point",
        "",
        "| Sub-category | n benign | " + " | ".join(frozen) + " |",
        "|---" * (2 + len(frozen)) + "|",
    ]
    any_result = next(iter(holdout_results.values()))
    for sub in any_result["by_sub_category"]:
        cells = []
        n_benign = any_result["by_sub_category"][sub]["n_benign"]
        for name in frozen:
            stats = holdout_results[name]["by_sub_category"].get(sub)
            cells.append(f"{stats['fpr']:.3f}" if stats else "—")
        lines.append(f"| {sub} | {n_benign} | " + " | ".join(cells) + " |")

    lines += [
        "",
        "## Hold-out false positives by business domain",
        "",
        "| Domain | n benign | " + " | ".join(frozen) + " |",
        "|---" * (2 + len(frozen)) + "|",
    ]
    for domain in any_result["by_domain"]:
        n_benign = any_result["by_domain"][domain]["n_benign"]
        cells = [
            f"{holdout_results[name]['by_domain'][domain]['fpr']:.3f}"
            if domain in holdout_results[name]["by_domain"]
            else "—"
            for name in frozen
        ]
        lines.append(f"| {domain} | {n_benign} | " + " | ".join(cells) + " |")

    lines += [
        "",
        "## System-prompt extraction (ADR-014 rationale)",
        "",
        "| Detector | threshold | n | TP | FN | recall | 95% CI |",
        "|---|---|---|---|---|---|---|",
    ]
    for name, threshold in frozen.items():
        e = holdout_results[name]["system_prompt_extraction"]
        lines.append(
            f"| ProtectAI @ {name} | {threshold:.4f} | {e['n']} | {e['tp']} | {e['fn']} | "
            f"{e['recall']:.4f} | {e['recall_ci95']} |"
        )
    for label, result, threshold in (
        ("Arch-Guard", alternative_holdout, 0.5),
        ("heuristic", baseline_holdout, BASELINE_THRESHOLD),
    ):
        e = result["system_prompt_extraction"]
        lines.append(
            f"| {label} | {threshold} | {e['n']} | {e['tp']} | {e['fn']} | {e['recall']:.4f} | "
            f"{e['recall_ci95']} |"
        )

    lines += [
        "",
        "## Latency",
        "",
        "| Detector | mean ms | p95 ms | vs heuristic |",
        "|---|---|---|---|",
    ]
    for name, stats in latency.items():
        ratio = stats["mean_ms"] / base_lat if base_lat else 0
        lines.append(
            f"| `{name}` | {stats['mean_ms']:.3f} | {stats['p95_ms']:.3f} | {ratio:.0f}x |"
        )

    lines += [
        "",
        "## Methodology guarantees",
        "",
        "* Thresholds selected on `public/dev`, which excludes the independent hold-out; "
        "`_assert_no_holdout` raises if a hold-out sample reaches calibration.",
        "* Operating points frozen to `operating_points.json` **before** the hold-out was scored.",
        "* No threshold was adjusted after seeing hold-out results.",
        "* Wilson 95% intervals on every rate; denominators reported throughout.",
        "",
    ]
    (out / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    # --- fpr_analysis.md -----------------------------------------------------
    fa = [
        "# False-positive analysis at frozen operating points",
        "",
        "Does raising the threshold fix the security-language false positives?",
        "",
    ]
    for name, threshold in sorted(frozen.items(), key=lambda kv: kv[1]):
        r = holdout_results[name]
        fa += [
            f"## {name} (threshold {threshold:.4f})",
            "",
            f"* All benign: {r['all_benign']['fp']}/{r['all_benign']['n_benign']} "
            f"FPR **{r['all_benign']['fpr']:.4f}** {r['all_benign']['fpr_ci95']}",
            f"* Hard negatives: {r['hard_negatives']['fp']}/{r['hard_negatives']['n_benign']} "
            f"FPR **{r['hard_negatives']['fpr']:.4f}**",
            f"* Ordinary benign: {r['ordinary_benign']['fp']}/"
            f"{r['ordinary_benign']['n_benign']} FPR {r['ordinary_benign']['fpr']:.4f}",
            f"* Attack recall: {r['overall']['recall']:.4f} {r['overall']['recall_ci95']}",
            "",
        ]
        quoted = r["by_sub_category"].get("quoted_attack")
        if quoted:
            fa.append(
                f"* **quoted_attack**: {quoted['fp']}/{quoted['n_benign']} "
                f"FPR **{quoted['fpr']:.4f}** {quoted['fpr_ci95']}"
            )
        fa.append("")

    fa += [
        "## Worst-scoring benign samples (highest-confidence false positives)",
        "",
        "| score | sub-category | domain | sample_id |",
        "|---|---|---|---|",
    ]
    worst = sorted((r for r in ho_rows if not r["label"]), key=lambda r: -r["score"])[:15]
    for row in worst:
        fa.append(
            f"| {row['score']:.4f} | {row['sub_category']} | {row['domain']} | "
            f"`{row['sample_id']}` |"
        )
    fa.append("")
    (out / "fpr_analysis.md").write_text("\n".join(fa) + "\n", encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
