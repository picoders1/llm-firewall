"""Evaluation CLI.

Designed so that misuse is hard rather than merely discouraged:

* `--split test` is refused unless `--frozen` is also given, so reporting on the
  held-out set is always a deliberate act.
* `--objective` (threshold calibration) is refused on the test split entirely.
  The refusal comes from :func:`eval.schema.require_tunable`, not from this CLI,
  so it holds for any caller.

    uv run python -m eval list
    uv run python -m eval run --detector injection.heuristic --benchmark holdout --split dev
    uv run python -m eval run --detector injection.heuristic --benchmark holdout --split dev \\
        --objective max_recall_at_fpr --constraint 0.01
    uv run python -m eval run --detector injection.heuristic --benchmark holdout \\
        --split test --frozen --threshold 0.85
    uv run python -m eval compare --benchmark holdout --split dev
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from typing import Any

from eval.detectors import available_detectors
from eval.loaders.registry_loader import BENCHMARKS, available_benchmarks, load_benchmark
from eval.metrics.calibration import Objective
from eval.report import write_report
from eval.runner import run_evaluation
from eval.schema import Split, validate_dataset


def _print_list() -> int:
    from eval.candidates import CANDIDATES, NOT_LOCALLY_BENCHMARKABLE

    print("Production detectors (app.detectors):")
    for name in available_detectors():
        print(f"  {name}")
    print("\nEvaluation-only candidates (NOT wired into the gateway):")
    for name, spec in sorted(CANDIDATES.items()):
        print(f"  {name:<34} {spec.hf_id}  [{spec.licence}]")
    print("\nNot locally benchmarkable:")
    for name, info in sorted(NOT_LOCALLY_BENCHMARKABLE.items()):
        print(f"  {name:<44} {info['reason'][:60]}...")
    print("\nBenchmarks:")
    for name, ready in available_benchmarks().items():
        state = "ready" if ready else "NOT AVAILABLE (run the download script)"
        print(f"  {name:<12} {state}  ({', '.join(BENCHMARKS[name])})")
    return 0


def _print_dataset(benchmark: str) -> int:
    samples, sources = load_benchmark(benchmark)
    report = validate_dataset(samples)
    print(f"Benchmark: {benchmark}  ({report['total']} samples)")
    print("\nSplits:")
    for split, counts in sorted(report["per_split"].items()):
        print(
            f"  {split:<6} total={counts['total']:<6} attack={counts['attack']:<6} "
            f"benign={counts['benign']}"
        )
    print("\nCategories:")
    for category, count in sorted(report["per_category"].items()):
        print(f"  {category:<28} {count}")
    print("\nSources:")
    for name, entry in sorted(sources.items()):
        print(
            f"  {name:<20} licence={entry.licence:<14} commercial={entry.commercial_use:<28} "
            f"contamination={entry.contamination_risk}"
        )
    print("\nIntegrity:")
    print(f"  cross-split leakage : {report['cross_split_leakage']}")
    print(f"  duplicate texts     : {report['duplicate_texts']}")
    print(f"  split assignment ok : {report['split_assignment_verified']}")
    return 0 if report["cross_split_leakage"] == 0 else 1


async def _run(args: argparse.Namespace) -> int:
    split = Split(args.split)

    if split is Split.TEST and not args.frozen:
        print(
            "REFUSED: the test split is frozen. Reporting on it must be deliberate:\n"
            "  add --frozen to acknowledge that this is a final, held-out measurement.\n"
            "  Calibrate on --split dev first.",
            file=sys.stderr,
        )
        return 2

    objective = Objective(args.objective) if args.objective else None
    if objective is not None and split is Split.TEST:
        print(
            "REFUSED: threshold calibration may not read the test split.\n"
            "  Calibrate on --split dev, then evaluate --split test --frozen --threshold <t>.",
            file=sys.stderr,
        )
        return 2

    result = await run_evaluation(
        detector_name=args.detector,
        benchmark=args.benchmark,
        split=split,
        threshold=args.threshold,
        objective=objective,
        constraint=args.constraint,
    )
    directory = write_report(result)
    metrics = result.metrics()
    c = metrics["classification"]

    print(f"\n{result.detector}  {result.benchmark}/{split.value}  n={c['n']}")
    print(f"  threshold {metrics['threshold']}")
    print(
        f"  recall {c['recall']:.4f}  precision {c['precision']:.4f}  "
        f"FPR {c['fpr']:.4f}  F1 {c['f1']:.4f}"
    )
    print(
        f"  TP={c['tp']} FP={c['fp']} TN={c['tn']} FN={c['fn']}  "
        f"mean {metrics['latency']['total']['mean_ms']:.3f} ms"
    )
    for warning in result.warnings:
        print(f"  ⚠ {warning}")
    print(f"  → {directory}")
    return 0


async def _compare(args: argparse.Namespace) -> int:
    """Every detector over identical data, for a like-for-like table."""
    split = Split(args.split)
    if split is Split.TEST and not args.frozen:
        print("REFUSED: --split test requires --frozen.", file=sys.stderr)
        return 2

    detectors = args.detectors or available_detectors()
    rows: list[dict[str, Any]] = []
    for name in detectors:
        try:
            result = await run_evaluation(detector_name=name, benchmark=args.benchmark, split=split)
        except Exception as exc:
            rows.append({"detector": name, "error": f"{type(exc).__name__}: {exc}"})
            continue
        write_report(result)
        metrics = result.metrics()
        c = metrics["classification"]
        rows.append(
            {
                "detector": name,
                "n": c["n"],
                "recall": c["recall"],
                "precision": c["precision"],
                "fpr": c["fpr"],
                "f1": c["f1"],
                "mean_ms": metrics["latency"]["total"]["mean_ms"],
                "p95_ms": metrics["latency"]["total"]["p95_ms"],
            }
        )

    header = f"{'detector':<28}{'n':>6}{'recall':>9}{'prec':>9}{'FPR':>9}{'F1':>8}{'mean ms':>10}{'p95 ms':>9}"
    print(f"\n{args.benchmark}/{split.value} — identical data, identical machine\n")
    print(header)
    print("-" * len(header))
    for row in rows:
        if "error" in row:
            print(f"{row['detector']:<28}  {row['error']}")
            continue
        print(
            f"{row['detector']:<28}{row['n']:>6}{row['recall']:>9.4f}{row['precision']:>9.4f}"
            f"{row['fpr']:>9.4f}{row['f1']:>8.4f}{row['mean_ms']:>10.3f}{row['p95_ms']:>9.3f}"
        )
    print("\nInternal benchmark results. Not published project metrics.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="eval", description="LLM Firewall evaluation harness")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="show available detectors and benchmarks")

    dataset = sub.add_parser("dataset", help="inspect a benchmark's composition and integrity")
    dataset.add_argument("benchmark")

    run = sub.add_parser("run", help="evaluate one detector on one split")
    run.add_argument("--detector", required=True)
    run.add_argument("--benchmark", required=True)
    run.add_argument("--split", required=True, choices=[s.value for s in Split])
    run.add_argument("--threshold", type=float, default=None)
    run.add_argument(
        "--objective",
        choices=[o.value for o in Objective],
        help="calibrate a threshold on this split (refused on test)",
    )
    run.add_argument(
        "--constraint",
        type=float,
        help="the objective's bound, e.g. the FPR budget for max_recall_at_fpr",
    )
    run.add_argument(
        "--frozen",
        action="store_true",
        help="acknowledge a final measurement on the held-out test split",
    )

    compare = sub.add_parser("compare", help="run several detectors over identical data")
    compare.add_argument("--benchmark", required=True)
    compare.add_argument("--split", required=True, choices=[s.value for s in Split])
    compare.add_argument("--detectors", nargs="*")
    compare.add_argument("--frozen", action="store_true")

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "list":
        return _print_list()
    if args.command == "dataset":
        return _print_dataset(args.benchmark)
    if args.command == "run":
        return asyncio.run(_run(args))
    if args.command == "compare":
        return asyncio.run(_compare(args))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
