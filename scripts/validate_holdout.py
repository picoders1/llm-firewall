"""Independent FPR validation on the expanded hold-out.

**Thresholds are frozen.** They are taken from the previously committed
calibration and are never re-selected here. The hold-out's purpose is to produce
an *independent estimate*, and a threshold chosen on it would destroy exactly the
property that makes it worth having (§17).

Produces `eval/results/<run-id>/` with manifest, predictions, metrics, report and
a hard-negative error analysis, plus SVG artefacts. Never overwrites a prior run.

    uv run python -m scripts.validate_holdout
"""

from __future__ import annotations

import argparse
import asyncio
import json
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from eval.detectors import build_detector
from eval.loaders.registry_loader import load_benchmark
from eval.metadata import git_state, lockfile_hash, machine_metadata
from eval.metrics.classification import confusion, wilson_interval
from eval.metrics.latency import latency_stats
from eval.schema import DETECTOR_SCOPE

RESULTS = Path(__file__).resolve().parents[1] / "eval" / "results"

# FROZEN. Sources, in order of authority:
#   injection.heuristic          — shipped policy (config/policies/default.yaml)
#   protectai / arch_guard       — the 0.5 default used in the ADR-014 comparison
# Changing a value here without a new calibration run on `dev` is a methodology
# violation, not a tuning decision.
FROZEN_THRESHOLDS: dict[str, float] = {
    "injection.heuristic": 0.85,
    "injection.protectai_deberta_v2": 0.5,
    "injection.arch_guard": 0.5,
}

INJECTION_SCOPE = DETECTOR_SCOPE["injection.heuristic"]


async def score_all(detector_name: str, samples: list[Any]) -> list[dict[str, Any]]:
    detector = build_detector(detector_name, threshold=FROZEN_THRESHOLDS[detector_name])
    await detector.warmup()
    try:
        rows = []
        for sample in samples:
            prediction = await detector.predict(sample)
            rows.append(
                {
                    "sample_id": sample.sample_id,
                    "category": sample.category.value,
                    "sub_category": sample.sub_category,
                    "domain": sample.domain,
                    "difficulty": sample.difficulty,
                    "hard_negative": sample.notes == "hard_negative",
                    "label": sample.label,
                    "score": prediction.score,
                    "latency_ms": prediction.total_ms,
                }
            )
    finally:
        await detector.aclose()
    return rows


def analyse(detector_name: str, rows: list[dict[str, Any]]) -> dict[str, Any]:
    threshold = FROZEN_THRESHOLDS[detector_name]
    labels = [r["label"] for r in rows]
    predictions = [r["score"] >= threshold for r in rows]
    overall = confusion(labels, predictions)

    benign = [r for r in rows if not r["label"]]
    benign_fp = sum(1 for r in benign if r["score"] >= threshold)
    fpr_lo, fpr_hi = wilson_interval(benign_fp, len(benign))

    hard = [r for r in benign if r["hard_negative"]]
    hard_fp = sum(1 for r in hard if r["score"] >= threshold)
    hard_lo, hard_hi = wilson_interval(hard_fp, len(hard))

    easy = [r for r in benign if not r["hard_negative"]]
    easy_fp = sum(1 for r in easy if r["score"] >= threshold)
    easy_lo, easy_hi = wilson_interval(easy_fp, len(easy))

    by_sub: dict[str, dict[str, int]] = defaultdict(lambda: {"fp": 0, "n": 0})
    for r in benign:
        bucket = by_sub[r["sub_category"] or "unspecified"]
        bucket["n"] += 1
        if r["score"] >= threshold:
            bucket["fp"] += 1

    by_domain: dict[str, dict[str, int]] = defaultdict(lambda: {"fp": 0, "n": 0})
    for r in benign:
        bucket = by_domain[r["domain"] or "unspecified"]
        bucket["n"] += 1
        if r["score"] >= threshold:
            bucket["fp"] += 1

    extraction = [r for r in rows if r["category"] == "system_prompt_extraction"]
    ext_tp = sum(1 for r in extraction if r["score"] >= threshold)

    return {
        "detector": detector_name,
        "threshold": threshold,
        "threshold_source": "frozen from prior calibration; NOT selected on this hold-out",
        "overall": overall.as_dict(),
        "benign": {
            "n": len(benign),
            "fp": benign_fp,
            "tn": len(benign) - benign_fp,
            "fpr": round(benign_fp / len(benign), 4) if benign else 0.0,
            "fpr_ci95_wilson": [round(fpr_lo, 4), round(fpr_hi, 4)],
        },
        "hard_negatives": {
            "n": len(hard),
            "fp": hard_fp,
            "fpr": round(hard_fp / len(hard), 4) if hard else 0.0,
            "fpr_ci95_wilson": [round(hard_lo, 4), round(hard_hi, 4)],
        },
        "ordinary_benign": {
            "n": len(easy),
            "fp": easy_fp,
            "fpr": round(easy_fp / len(easy), 4) if easy else 0.0,
            "fpr_ci95_wilson": [round(easy_lo, 4), round(easy_hi, 4)],
        },
        "system_prompt_extraction": {
            "n": len(extraction),
            "detected": ext_tp,
            "recall": round(ext_tp / len(extraction), 4) if extraction else 0.0,
            "recall_ci95_wilson": [round(v, 4) for v in wilson_interval(ext_tp, len(extraction))],
        },
        "false_positives_by_sub_category": {
            k: {**v, "fpr": round(v["fp"] / v["n"], 4)}
            for k, v in sorted(by_sub.items(), key=lambda kv: -kv[1]["fp"])
            if v["fp"]
        },
        "false_positives_by_domain": {
            k: {**v, "fpr": round(v["fp"] / v["n"], 4)}
            for k, v in sorted(by_domain.items(), key=lambda kv: -kv[1]["fp"])
            if v["fp"]
        },
        "latency": latency_stats([r["latency_ms"] for r in rows]).as_dict(),
    }


def svg_bar(path: Path, title: str, bars: list[tuple[str, float]], ymax: float) -> None:
    """Minimal hand-rolled bar chart — no plotting dependency for one figure."""
    width, height, pad = 620, 340, 70
    plot_w, plot_h = width - 2 * pad, height - 2 * pad
    slot = plot_w / max(1, len(bars))
    rects, labels = [], []
    for index, (name, value) in enumerate(bars):
        h = 0 if ymax <= 0 else (value / ymax) * plot_h
        x = pad + index * slot + slot * 0.18
        w = slot * 0.64
        y = height - pad - h
        rects.append(
            f'<rect x="{x:.1f}" y="{y:.1f}" width="{w:.1f}" height="{h:.1f}" fill="#1f77b4"/>'
            f'<text x="{x + w / 2:.1f}" y="{y - 6:.1f}" font-size="11" text-anchor="middle" '
            f'fill="#111">{value:.3f}</text>'
        )
        labels.append(
            f'<text x="{x + w / 2:.1f}" y="{height - pad + 16:.1f}" font-size="10" '
            f'text-anchor="middle" fill="#444">{name}</text>'
        )
    path.write_text(
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}"><rect width="{width}" height="{height}" fill="#fff"/>'
        f'<text x="{width / 2}" y="26" font-size="14" text-anchor="middle" fill="#111">{title}</text>'
        f'<line x1="{pad}" y1="{height - pad}" x2="{width - pad}" y2="{height - pad}" stroke="#666"/>'
        f"{''.join(rects)}{''.join(labels)}</svg>\n",
        encoding="utf-8",
    )


def svg_score_distribution(path: Path, per_detector: dict[str, list[dict[str, Any]]]) -> None:
    width, height, pad = 640, 360, 60
    plot_w = width - 2 * pad
    colours = {"benign": "#2ca02c", "attack": "#d62728"}
    series = []
    y_offset = 0
    for name, rows in per_detector.items():
        for kind, subset in (
            ("benign", [r for r in rows if not r["label"]]),
            ("attack", [r for r in rows if r["label"]]),
        ):
            bins = [0] * 10
            for r in subset:
                bins[min(9, int(r["score"] * 10))] += 1
            total = max(1, sum(bins))
            points = " ".join(
                f"{pad + (i + 0.5) / 10 * plot_w:.1f},"
                f"{pad + y_offset + 60 - (count / total) * 55:.1f}"
                for i, count in enumerate(bins)
            )
            series.append(
                f'<polyline points="{points}" fill="none" stroke="{colours[kind]}" '
                f'stroke-width="2"/>'
                f'<text x="{pad + 4}" y="{pad + y_offset + 12}" font-size="10" fill="#333">'
                f"{name} — {kind}</text>"
            )
        y_offset += 88
    path.write_text(
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}"><rect width="{width}" height="{height}" fill="#fff"/>'
        f'<text x="{width / 2}" y="24" font-size="14" text-anchor="middle" fill="#111">'
        f"Score distribution by class (green benign, red attack)</text>"
        f"{''.join(series)}"
        f'<text x="{width / 2}" y="{height - 10}" font-size="11" text-anchor="middle" '
        f'fill="#111">score bucket 0.0 → 1.0</text></svg>\n',
        encoding="utf-8",
    )


async def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Independent hold-out FPR validation")
    parser.add_argument("--detectors", nargs="*", default=list(FROZEN_THRESHOLDS))
    args = parser.parse_args(argv)

    started = datetime.now(UTC)
    run_id = f"{started.strftime('%Y%m%dT%H%M%SZ')}__holdout-fpr-validation"
    directory = RESULTS / run_id
    directory.mkdir(parents=True, exist_ok=True)

    samples, sources = load_benchmark("holdout")
    scoped = [s for s in samples if s.category in INJECTION_SCOPE]
    benign_n = sum(1 for s in scoped if not s.label)
    print(
        f"hold-out: {len(samples)} samples, {len(scoped)} in injection scope, {benign_n} benign\n"
    )

    per_detector: dict[str, list[dict[str, Any]]] = {}
    analyses: dict[str, Any] = {}

    for name in args.detectors:
        print(f"scoring {name} at frozen threshold {FROZEN_THRESHOLDS[name]} …")
        rows = await score_all(name, scoped)
        per_detector[name] = rows
        analyses[name] = analyse(name, rows)

    with (directory / "predictions.jsonl").open("w", encoding="utf-8") as handle:
        for name, rows in per_detector.items():
            for row in rows:
                handle.write(json.dumps({"detector": name, **row}, ensure_ascii=False) + "\n")

    (directory / "metrics.json").write_text(json.dumps(analyses, indent=2) + "\n", encoding="utf-8")
    (directory / "manifest.json").write_text(
        json.dumps(
            {
                "run_id": run_id,
                "purpose": "independent benign hold-out FPR validation",
                "started_at": started.isoformat(),
                "finished_at": datetime.now(UTC).isoformat(),
                "benchmark": "holdout",
                "split": "all (independent hold-out is not split; it is never tuned on)",
                "frozen_thresholds": FROZEN_THRESHOLDS,
                "threshold_policy": (
                    "Thresholds frozen from prior dev calibration. No threshold was "
                    "selected or adjusted using this hold-out (docs/13-evaluation-strategy.md)."
                ),
                "sources": {
                    n: {"licence": e.licence, "contamination_risk": e.contamination_risk}
                    for n, e in sources.items()
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

    svg_bar(
        directory / "fpr_comparison.svg",
        f"Benign FPR on independent hold-out (n={benign_n})",
        [(n.split(".")[-1][:16], a["benign"]["fpr"]) for n, a in analyses.items()],
        max(0.01, max(a["benign"]["fpr"] for a in analyses.values())),
    )
    svg_bar(
        directory / "hard_negative_fpr.svg",
        "FPR on hard negatives vs ordinary benign",
        [(f"{n.split('.')[-1][:10]}-hard", a["hard_negatives"]["fpr"]) for n, a in analyses.items()]
        + [
            (f"{n.split('.')[-1][:10]}-ord", a["ordinary_benign"]["fpr"])
            for n, a in analyses.items()
        ],
        max(0.01, max(a["hard_negatives"]["fpr"] for a in analyses.values())),
    )
    svg_score_distribution(directory / "score_distribution.svg", per_detector)

    _write_reports(directory, analyses, per_detector, benign_n)

    print(f"\n{'detector':<34}{'benign n':>10}{'FP':>5}{'FPR':>9}{'CI95':>18}{'hardFPR':>9}")
    print("-" * 86)
    for name, a in analyses.items():
        ci = a["benign"]["fpr_ci95_wilson"]
        print(
            f"{name:<34}{a['benign']['n']:>10}{a['benign']['fp']:>5}{a['benign']['fpr']:>9.4f}"
            f"{f'[{ci[0]:.3f},{ci[1]:.3f}]':>18}{a['hard_negatives']['fpr']:>9.4f}"
        )
    print(f"\n→ {directory}")
    return 0


def _write_reports(
    directory: Path,
    analyses: dict[str, Any],
    per_detector: dict[str, list[dict[str, Any]]],
    benign_n: int,
) -> None:
    lines = [
        "# Independent hold-out — FPR validation",
        "",
        f"Benign denominator: **{benign_n}**. Thresholds **frozen** from prior calibration; "
        "none was selected on this data.",
        "",
        "| Detector | threshold | benign n | FP | TN | FPR | 95% CI (Wilson) |",
        "|---|---|---|---|---|---|---|",
    ]
    for name, a in analyses.items():
        b = a["benign"]
        ci = b["fpr_ci95_wilson"]
        lines.append(
            f"| `{name}` | {a['threshold']} | {b['n']} | {b['fp']} | {b['tn']} | "
            f"**{b['fpr']:.4f}** | [{ci[0]:.4f}, {ci[1]:.4f}] |"
        )

    lines += [
        "",
        "## Hard negatives vs ordinary benign",
        "",
        "| Detector | hard n | hard FP | hard FPR | ordinary n | ord FP | ord FPR |",
        "|---|---|---|---|---|---|---|",
    ]
    for name, a in analyses.items():
        h, o = a["hard_negatives"], a["ordinary_benign"]
        lines.append(
            f"| `{name}` | {h['n']} | {h['fp']} | **{h['fpr']:.4f}** | {o['n']} | {o['fp']} | "
            f"{o['fpr']:.4f} |"
        )

    lines += [
        "",
        "## System-prompt extraction (ADR-014 rationale check)",
        "",
        "| Detector | n | detected | recall | 95% CI |",
        "|---|---|---|---|---|",
    ]
    for name, a in analyses.items():
        e = a["system_prompt_extraction"]
        ci = e["recall_ci95_wilson"]
        lines.append(
            f"| `{name}` | {e['n']} | {e['detected']} | **{e['recall']:.4f}** | "
            f"[{ci[0]:.4f}, {ci[1]:.4f}] |"
        )

    lines += [
        "",
        "## Latency (detector only)",
        "",
        "| Detector | mean ms | p95 ms |",
        "|---|---|---|",
    ]
    for name, a in analyses.items():
        lines.append(f"| `{name}` | {a['latency']['mean_ms']:.3f} | {a['latency']['p95_ms']:.3f} |")

    lines += [
        "",
        "Artefacts: `metrics.json`, `predictions.jsonl`, `fpr_analysis.md`, "
        "`fpr_comparison.svg`, `hard_negative_fpr.svg`, `score_distribution.svg`.",
        "",
    ]
    (directory / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    # --- hard-negative error analysis ---------------------------------------
    fa = [
        "# Hard-negative false-positive analysis",
        "",
        "Every false positive on the independent hold-out, grouped by the concept that",
        "appears to trigger it. Sanitised: sample id, sub-category, score and a short",
        "reason each sample is genuinely benign.",
        "",
    ]
    for name, a in analyses.items():
        rows = per_detector[name]
        threshold = a["threshold"]
        fps = [r for r in rows if not r["label"] and r["score"] >= threshold]
        fa += [f"## `{name}` — {len(fps)} false positives", ""]
        if not fps:
            fa += ["No false positives on this hold-out.", ""]
            continue
        grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for r in fps:
            grouped[r["sub_category"] or "unspecified"].append(r)
        fa += ["| sub-category | n FP | of n | FPR |", "|---|---|---|---|"]
        for sub, items in sorted(grouped.items(), key=lambda kv: -len(kv[1])):
            total = sum(1 for r in rows if not r["label"] and r["sub_category"] == sub)
            fa.append(f"| {sub} | {len(items)} | {total} | {len(items) / max(1, total):.3f} |")
        fa += [
            "",
            "### Individual false positives",
            "",
            "| sample_id | sub-category | domain | score |",
            "|---|---|---|---|",
        ]
        for r in sorted(fps, key=lambda r: -r["score"]):
            fa.append(
                f"| `{r['sample_id']}` | {r['sub_category']} | {r['domain']} | {r['score']:.3f} |"
            )
        fa.append("")
    (directory / "fpr_analysis.md").write_text("\n".join(fa) + "\n", encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
