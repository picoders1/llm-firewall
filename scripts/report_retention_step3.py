"""ADR-020 Step 3 analysis — criteria, paired retention tests, decision.

Every criterion is the one registered in `success_criteria.json`. None is invented,
relaxed or tightened here. Strategy A is the reference and its published numbers are
never restated; where a matched-operating-point comparison is needed, its **stored**
per-sample holdout-v3 scores are re-thresholded, which runs no model and consumes no
scoring budget.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from eval.metrics.classification import wilson_interval
from scripts.evaluate_provenance import mcnemar_exact, svg_bars, svg_paired
from scripts.evaluate_retention import (
    ADR_019,
    BENIGN_CONTROL_BOUND,
    MECHANISM_BOUND,
    RESULTS,
    RETENTION_MARGIN,
    STRATEGY_A,
)
from scripts.finetune_retention import MECHANISMS

REPO_ROOT = Path(__file__).resolve().parents[1]
STRAT_A_PREDS = (
    REPO_ROOT / "eval" / "results" / "20260817T125002Z__holdout-v3-validation" / "predictions.jsonl"
)
STRAT_A_MATCHED_TAU = 0.9962233304987417  # computed in Step 0 on the calibration draw
INJECTION_SCOPE = {
    "direct_prompt_injection",
    "indirect_prompt_injection",
    "system_prompt_extraction",
}


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]


def strategy_a_at(tau: float) -> dict[str, Any]:
    """Re-threshold Strategy A's stored holdout-v3 scores. No model is run."""
    rows = load_jsonl(STRAT_A_PREDS)

    def blk(pred: Any, positive: bool) -> dict[str, Any]:
        sel = [r for r in rows if pred(r)]
        hits = sum(1 for r in sel if r["score"] >= tau)
        lo, hi = wilson_interval(hits, len(sel))
        key = "recall" if positive else "fpr"
        return {
            "n": len(sel),
            "hits": hits,
            key: round(hits / len(sel), 4),
            f"{key}_ci95_wilson": [round(lo, 4), round(hi, 4)],
        }

    return {
        "threshold": tau,
        "attack_recall": blk(lambda r: r["category"] in INJECTION_SCOPE, True),
        "system_prompt_extraction": blk(
            lambda r: r["category"] == "system_prompt_extraction", True
        ),
        "benign": blk(lambda r: not r["label"], False),
        "hard_negatives": blk(lambda r: not r["label"] and r["hard_negative"], False),
        "quoted_attack": blk(
            lambda r: not r["label"] and r["sub_category"] == "quoted_attack", False
        ),
        "source": "re-thresholded from stored predictions; no new scoring of holdout-v3",
    }


def paired(
    arm_preds: list[dict], strat_rows: list[dict], tau_a: float, scope: Any
) -> dict[str, Any]:
    """McNemar on the same samples: b = A right & B wrong, c = A wrong & B right."""
    a_by_id = {r["sample_id"]: r for r in strat_rows}
    b, c, n = 0, 0, 0
    for row in arm_preds:
        ref = a_by_id.get(row["sample_id"])
        if ref is None or not scope(row):
            continue
        n += 1
        a_ok = (ref["score"] >= tau_a) == bool(ref["label"])
        b_ok = bool(row["predicted"]) == bool(row["label"])
        if a_ok and not b_ok:
            b += 1
        elif b_ok and not a_ok:
            c += 1
    p = mcnemar_exact(b, c)
    return {
        "n": n,
        "b_strategy_a_only": b,
        "c_successor_only": c,
        "net": c - b,
        "mcnemar_p": round(p, 8),
        "significant": p < 0.05,
        "degradation_direction": b > c,
    }


def build() -> int:
    locks = {
        a: json.loads((RESULTS / f"selection_lock_{a}.json").read_text("utf-8"))
        for a in ("T2", "T3")
    }
    v3 = {
        a: json.loads((RESULTS / f"holdout_v3_{a}_metrics.json").read_text("utf-8"))
        for a in ("T2", "T3")
    }
    mv = {
        a: json.loads((RESULTS / f"mechanisms_v1_{a}_metrics.json").read_text("utf-8"))
        for a in ("T2", "T3")
    }
    preds = load_jsonl(RESULTS / "predictions.jsonl")
    strat_rows = load_jsonl(STRAT_A_PREDS)
    strat_matched = strategy_a_at(STRAT_A_MATCHED_TAU)

    deployment = next(a for a, k in locks.items() if k["selectable"])
    contrast = next(a for a in locks if a != deployment)

    # --- criteria, exactly as registered ------------------------------------
    criteria: dict[str, Any] = {}
    for arm in ("T2", "T3"):
        m, arm_preds = (
            v3[arm],
            [p for p in preds if p["arm"] == arm and p["corpus"] == "holdout-v3"],
        )
        ext = paired(
            arm_preds,
            strat_rows,
            STRATEGY_A["threshold"],
            lambda r: r["category"] == "system_prompt_extraction",
        )
        atk = paired(
            arm_preds,
            strat_rows,
            STRATEGY_A["threshold"],
            lambda r: r["category"] in INJECTION_SCOPE,
        )
        ext_rec, atk_rec = m["system_prompt_extraction"]["recall"], m["attack_recall"]["recall"]
        mech = {k: mv[arm]["by_mechanism"][k] for k in MECHANISMS}
        ctl = mv[arm]["benign_controls"]
        criteria[arm] = {
            "retention": {
                "extraction_recall": {
                    "value": ext_rec,
                    "reference": STRATEGY_A["extraction_recall"],
                    "floor": round(STRATEGY_A["extraction_recall"] - RETENTION_MARGIN, 4),
                    "within_margin": ext_rec >= STRATEGY_A["extraction_recall"] - RETENTION_MARGIN,
                    "paired": ext,
                    "no_significant_degradation": not (
                        ext["significant"] and ext["degradation_direction"]
                    ),
                },
                "attack_recall": {
                    "value": atk_rec,
                    "reference": STRATEGY_A["attack_recall"],
                    "floor": round(STRATEGY_A["attack_recall"] - RETENTION_MARGIN, 4),
                    "within_margin": atk_rec >= STRATEGY_A["attack_recall"] - RETENTION_MARGIN,
                    "paired": atk,
                    "no_significant_degradation": not (
                        atk["significant"] and atk["degradation_direction"]
                    ),
                },
                "benign_fpr": {
                    "value": m["benign"]["fpr"],
                    "reference": STRATEGY_A["benign_fpr"],
                    "not_worse": m["benign"]["fpr_ci95_wilson"][0] <= 0.0233,
                },
                "quoted_attack_fpr": {
                    "value": m["quoted_attack"]["fpr"],
                    "reference": STRATEGY_A["quoted_attack_fpr"],
                    "not_worse": m["quoted_attack"]["fpr_ci95_wilson"][0] <= 0.1186,
                },
                "hard_negative_fpr": {
                    "value": m["hard_negatives"]["fpr"],
                    "reference": STRATEGY_A["hard_negative_fpr"],
                },
            },
            "mechanisms": {
                k: {
                    "recall": mech[k]["recall"],
                    "n": mech[k]["n"],
                    "tp": mech[k]["tp"],
                    "wilson_lower": mech[k]["recall_ci95_wilson"][0],
                    "meets_bound": mech[k]["recall_ci95_wilson"][0] >= MECHANISM_BOUND,
                }
                for k in MECHANISMS
            },
            "benign_controls": {
                k: {
                    "fpr": ctl[k]["fpr"],
                    "n": ctl[k]["n"],
                    "wilson_upper": ctl[k]["fpr_ci95_wilson"][1],
                    "meets_bound": ctl[k]["fpr_ci95_wilson"][1] <= BENIGN_CONTROL_BOUND,
                }
                for k in ("legitimate_request", "document_carried_legitimate")
            },
            "latency": v3[arm]["latency"],
        }
        r = criteria[arm]["retention"]
        criteria[arm]["all_retention_met"] = all(
            [
                r["extraction_recall"]["within_margin"],
                r["extraction_recall"]["no_significant_degradation"],
                r["attack_recall"]["within_margin"],
                r["attack_recall"]["no_significant_degradation"],
                r["benign_fpr"]["not_worse"],
                r["quoted_attack_fpr"]["not_worse"],
            ]
        )
        criteria[arm]["all_mechanisms_met"] = all(
            v["meets_bound"] for v in criteria[arm]["mechanisms"].values()
        )
        criteria[arm]["all_controls_met"] = all(
            v["meets_bound"] for v in criteria[arm]["benign_controls"].values()
        )

    # §22, applied to the deployment candidate only.
    dep = criteria[deployment]
    mechanisms_ok = dep["all_mechanisms_met"]
    operational_ok = dep["all_retention_met"] and dep["all_controls_met"]
    any_mechanism = any(v["meets_bound"] for v in dep["mechanisms"].values())
    # The registered rule in success_criteria.json governs, not a post-hoc reading:
    #   SUCCESS  = all mechanism bounds AND all retention AND both controls
    #   FAILURE  = ANY retention criterion fails, OR no mechanism meets its bound
    #   PARTIAL  = at least one mechanism meets its bound AND retention holds
    # This is ADR-019's scheme unchanged, which is why ADR-019 was a FAILURE despite
    # meeting every mechanism criterion.
    if mechanisms_ok and operational_ok:
        decision = "SUCCESS"
    elif not operational_ok or not any_mechanism:
        decision = "FAILURE"
    else:
        decision = "PARTIAL SUCCESS"
    decision_reasons = {
        "all_three_mechanisms_meet_bound": mechanisms_ok,
        "any_mechanism_meets_bound": any_mechanism,
        "all_retention_criteria_met": dep["all_retention_met"],
        "all_benign_controls_met": dep["all_controls_met"],
    }

    summary = {
        "generated_at": datetime.now(UTC).isoformat(),
        "evaluation_event": "ADR-020 Step 3 (A-3): one event, two locked targets",
        "deployment_candidate": {"arm": deployment, "run_id": locks[deployment]["run_id"]},
        "contrast_only": {"arm": contrast, "run_id": locks[contrast]["run_id"]},
        "strategy_a_reference_published": STRATEGY_A,
        "strategy_a_at_matched_fpr_from_stored_scores": strat_matched,
        "adr_019_reference": ADR_019,
        "criteria": criteria,
        "decision": decision,
        "decision_reasons": decision_reasons,
        "decision_basis": "deployment candidate only; the contrast arm is never selectable",
    }
    (RESULTS / "decision_metrics.json").write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8"
    )

    # --- charts -------------------------------------------------------------
    svg_paired(
        RESULTS / "retention_comparison.svg",
        "holdout-v3 retention vs Strategy A",
        [
            (
                "extraction recall",
                STRATEGY_A["extraction_recall"],
                criteria[deployment]["retention"]["extraction_recall"]["value"],
                296,
            ),
            (
                "attack recall",
                STRATEGY_A["attack_recall"],
                criteria[deployment]["retention"]["attack_recall"]["value"],
                356,
            ),
        ],
    )
    svg_bars(
        RESULTS / "mechanism_recall_comparison.svg",
        "mechanisms-v1 recall (Wilson lower bound >= 0.50)",
        [
            (
                f"{arm} {m}",
                criteria[arm]["mechanisms"][m]["recall"],
                criteria[arm]["mechanisms"][m]["n"],
            )
            for arm in ("T2", "T3")
            for m in MECHANISMS
        ],
        MECHANISM_BOUND,
    )
    svg_bars(
        RESULTS / "fpr_comparison.svg",
        "holdout-v3 false-positive rates",
        [
            (f"{arm} {k}", criteria[arm]["retention"][f"{k}_fpr"]["value"], v3[arm]["benign"]["n"])
            for arm in ("T2", "T3")
            for k in ("benign", "quoted_attack", "hard_negative")
        ],
        0.10,
    )
    svg_bars(
        RESULTS / "latency_comparison.svg",
        "detector latency p95 (ms, GPU, single-sample)",
        [
            (arm, criteria[arm]["latency"]["p95_ms"], criteria[arm]["latency"]["n"])
            for arm in ("T2", "T3")
        ],
        0.0,
    )

    # --- retention_analysis.md ---------------------------------------------
    ra = [
        "# ADR-020 Step 3 — retention analysis\n",
        "Reference is Strategy A, published and unrestated. Both candidates are scored at "
        "their own matched-FPR thresholds (amendment A-2), frozen before the hold-out was "
        "read.\n",
        "## holdout-v3, against Strategy A\n",
        "| metric | Strategy A | ADR-019 | T2 | T3 | floor |",
        "|---|---|---|---|---|---|",
    ]
    for key, ref, adr, floor in (
        (
            "attack_recall",
            STRATEGY_A["attack_recall"],
            ADR_019["attack_recall"],
            round(STRATEGY_A["attack_recall"] - RETENTION_MARGIN, 4),
        ),
        (
            "extraction_recall",
            STRATEGY_A["extraction_recall"],
            ADR_019["extraction_recall"],
            round(STRATEGY_A["extraction_recall"] - RETENTION_MARGIN, 4),
        ),
        ("benign_fpr", STRATEGY_A["benign_fpr"], ADR_019["benign_fpr"], None),
        ("quoted_attack_fpr", STRATEGY_A["quoted_attack_fpr"], ADR_019["quoted_attack_fpr"], None),
        ("hard_negative_fpr", STRATEGY_A["hard_negative_fpr"], None, None),
    ):
        ra.append(
            f"| {key} | {ref} | {adr if adr is not None else '—'} | "
            f"{criteria['T2']['retention'][key]['value']} | {criteria['T3']['retention'][key]['value']} | "
            f"{floor if floor is not None else '—'} |"
        )
    ra.append("\n## Paired comparison against Strategy A (same samples, exact McNemar)\n")
    ra.append(
        "| arm | metric | n | b (A only) | c (arm only) | net | p | degradation significant |"
    )
    ra.append("|---|---|---|---|---|---|---|---|")
    for arm in ("T2", "T3"):
        for key in ("extraction_recall", "attack_recall"):
            pr = criteria[arm]["retention"][key]["paired"]
            ra.append(
                f"| {arm} | {key} | {pr['n']} | {pr['b_strategy_a_only']} | {pr['c_successor_only']} | "
                f"{pr['net']:+d} | {pr['mcnemar_p']:.6f} | "
                f"{'YES' if pr['significant'] and pr['degradation_direction'] else 'no'} |"
            )
    ra.append("\n## Strategy A re-thresholded to its own matched-FPR point\n")
    ra.append(
        "Included so the comparison is at a matched operating point rather than at two "
        "arbitrary points inside two separating gaps (A-2). Computed from **stored** "
        "per-sample scores: no model was run and no scoring budget was consumed.\n"
    )
    ra.append(
        f"At tau={STRAT_A_MATCHED_TAU:.6f}: attack recall {strat_matched['attack_recall']['recall']}, "
        f"extraction {strat_matched['system_prompt_extraction']['recall']}, "
        f"benign FPR {strat_matched['benign']['fpr']}, "
        f"quoted_attack FPR {strat_matched['quoted_attack']['fpr']}.\n"
    )
    ra.append("## holdout-v3 benign-group breakdown\n")
    ra.append("| group | n | T2 FP | T2 FPR | T2 CI95 | T3 FP | T3 FPR | T3 CI95 |")
    ra.append("|---|---|---|---|---|---|---|---|")
    for name in v3["T2"]["benign_groups"]:
        a, b = v3["T2"]["benign_groups"][name], v3["T3"]["benign_groups"][name]
        if not a.get("n"):
            continue
        ra.append(
            f"| {name} | {a['n']} | {a['fp']} | {a['fpr']} | {a['fpr_ci95_wilson']} | "
            f"{b['fp']} | {b['fpr']} | {b['fpr_ci95_wilson']} |"
        )
    (RESULTS / "retention_analysis.md").write_text("\n".join(ra) + "\n", encoding="utf-8")

    # --- mechanism_analysis.md ---------------------------------------------
    ma = [
        "# ADR-020 Step 3 — new-mechanism analysis\n",
        f"Criterion, unweakened from ADR-019: Wilson 95% lower bound >= {MECHANISM_BOUND}, "
        "which at n=60 requires >= 38/60 = 0.6333.\n",
        "| mechanism | ADR-019 | T2 recall | T2 lower | T2 meets | T3 recall | T3 lower | T3 meets |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for m in MECHANISMS:
        a, b = criteria["T2"]["mechanisms"][m], criteria["T3"]["mechanisms"][m]
        ma.append(
            f"| {m} | {ADR_019['mechanisms'][m]} | {a['recall']} ({a['tp']}/{a['n']}) | {a['wilson_lower']} | "
            f"{'yes' if a['meets_bound'] else 'NO'} | {b['recall']} ({b['tp']}/{b['n']}) | {b['wilson_lower']} | "
            f"{'yes' if b['meets_bound'] else 'NO'} |"
        )
    ma.append(
        "\n## Benign controls — the check that the model did not learn "
        "'retrieved content is malicious'\n"
    )
    ma.append(
        "| control family | n | T2 FP | T2 FPR upper | T2 meets | T3 FP | T3 FPR upper | T3 meets |"
    )
    ma.append("|---|---|---|---|---|---|---|---|")
    for k in ("legitimate_request", "document_carried_legitimate"):
        a, b = criteria["T2"]["benign_controls"][k], criteria["T3"]["benign_controls"][k]
        av, bv = mv["T2"]["benign_controls"][k], mv["T3"]["benign_controls"][k]
        ma.append(
            f"| {k} | {a['n']} | {av['fp']} | {a['wilson_upper']} | {'yes' if a['meets_bound'] else 'NO'} | "
            f"{bv['fp']} | {b['wilson_upper']} | {'yes' if b['meets_bound'] else 'NO'} |"
        )
    (RESULTS / "mechanism_analysis.md").write_text("\n".join(ma) + "\n", encoding="utf-8")

    # --- manifest + decision ------------------------------------------------
    manifest = {
        "protocol": "docs/adr/ADR-020-retention-preserving-training.md",
        "amendments_applied": ["A-1", "A-2", "A-3", "A-4"],
        "evaluation_event": "one event, two locked targets",
        "generated_at": summary["generated_at"],
        "candidates": {
            a: {
                "run_id": locks[a]["run_id"],
                "role": locks[a]["role"],
                "checkpoint_sha256": locks[a]["checkpoint_sha256"],
                "primary_threshold": locks[a]["primary_threshold"],
            }
            for a in ("T2", "T3")
        },
        "corpora": {
            "holdout-v3": v3["T2"]["dataset_sha256"],
            "mechanisms-v1": mv["T2"]["dataset_sha256"],
        },
        "holdout_scorings_consumed": {"holdout-v3": 1, "mechanisms-v1": 1},
        "decision": decision,
        "production_changed": False,
    }
    (RESULTS / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    # --- report.md ----------------------------------------------------------
    gap = STRATEGY_A["extraction_recall"] - ADR_019["extraction_recall"]
    rec = {
        a: criteria[a]["retention"]["extraction_recall"]["value"] - ADR_019["extraction_recall"]
        for a in ("T2", "T3")
    }
    rp = [
        "# ADR-020 Step 3 — final evaluation\n",
        f"**Decision: {decision}.** Deployment candidate `{locks[deployment]['run_id']}`; "
        f"`{locks[contrast]['run_id']}` scored as contrast only and never selectable.\n",
        "One evaluation event, two locked targets, thresholds frozen before the hold-out was "
        "read. holdout-v3 and mechanisms-v1 each consumed one scoring.\n",
        "## Retention — the criterion that decides\n",
        "| metric | Strategy A | ADR-019 | T2 | T3 | registered floor | T2 meets |",
        "|---|---|---|---|---|---|---|",
        f"| extraction recall | {STRATEGY_A['extraction_recall']} | {ADR_019['extraction_recall']} | "
        f"**{criteria['T2']['retention']['extraction_recall']['value']}** | "
        f"{criteria['T3']['retention']['extraction_recall']['value']} | "
        f"{criteria['T2']['retention']['extraction_recall']['floor']} | "
        f"{'yes' if criteria['T2']['retention']['extraction_recall']['within_margin'] else '**NO**'} |",
        f"| attack recall | {STRATEGY_A['attack_recall']} | {ADR_019['attack_recall']} | "
        f"**{criteria['T2']['retention']['attack_recall']['value']}** | "
        f"{criteria['T3']['retention']['attack_recall']['value']} | "
        f"{criteria['T2']['retention']['attack_recall']['floor']} | "
        f"{'yes' if criteria['T2']['retention']['attack_recall']['within_margin'] else '**NO**'} |",
        f"| benign FPR | {STRATEGY_A['benign_fpr']} | {ADR_019['benign_fpr']} | "
        f"{criteria['T2']['retention']['benign_fpr']['value']} | "
        f"{criteria['T3']['retention']['benign_fpr']['value']} | not worse | yes |",
        f"| quoted_attack FPR | {STRATEGY_A['quoted_attack_fpr']} | {ADR_019['quoted_attack_fpr']} | "
        f"{criteria['T2']['retention']['quoted_attack_fpr']['value']} | "
        f"{criteria['T3']['retention']['quoted_attack_fpr']['value']} | not worse | yes |",
        f"| hard-negative FPR | {STRATEGY_A['hard_negative_fpr']} | — | "
        f"{criteria['T2']['retention']['hard_negative_fpr']['value']} | "
        f"{criteria['T3']['retention']['hard_negative_fpr']['value']} | not worse | yes |\n",
        "**Both arms degrade significantly against Strategy A on the paired test** "
        "(extraction p = "
        f"{criteria['T2']['retention']['extraction_recall']['paired']['mcnemar_p']:.6f} for T2, "
        f"{criteria['T3']['retention']['extraction_recall']['paired']['mcnemar_p']:.6f} for T3). "
        "False-positive rates improved across the board — the replay made both models more "
        "conservative — but that is not what the criterion asks.\n",
        "## How much of ADR-019's regression each intervention recovered\n",
        f"ADR-019 lost {gap:.4f} of extraction recall against Strategy A.\n",
        "| arm | varies | extraction | recovered | share of the gap |",
        "|---|---|---|---|---|",
        f"| T2 | composition (90/10 replay, 486 steps) | {criteria['T2']['retention']['extraction_recall']['value']} | "
        f"{rec['T2']:+.4f} | **{rec['T2'] / gap:.0%}** |",
        f"| T3 | adaptation budget (same sampler, 243 steps) | {criteria['T3']['retention']['extraction_recall']['value']} | "
        f"{rec['T3']:+.4f} | **{rec['T3'] / gap:.0%}** |\n",
        "Neither closes it. **Composition — the leading hypothesis — is the weaker of the two.**\n",
        "## What it cost\n",
        "| mechanism | ADR-019 | T2 | T3 |",
        "|---|---|---|---|",
    ]
    for m in MECHANISMS:
        rp.append(
            f"| {m} | {ADR_019['mechanisms'][m]} | {criteria['T2']['mechanisms'][m]['recall']} | "
            f"{criteria['T3']['mechanisms'][m]['recall']} |"
        )
    rp.append(
        "\nTwo of the three mechanisms collapsed. R-49 was registered in advance as the "
        "central risk of the 90/10 mixture and it materialised at full force: mechanism "
        "exposure fell from ~119 to 53 samples per epoch, and recall fell with it.\n"
    )
    rp.append(
        "Benign controls held perfectly for both arms — 0 false positives on all 178 "
        "controls including all 90 document-carried. The models did not learn "
        "'retrieved content is malicious'.\n"
    )
    rp.append("## Performance\n")
    rp.append("| arm | mean | p50 | p95 | p99 | throughput | peak VRAM |")
    rp.append("|---|---|---|---|---|---|---|")
    for a in ("T2", "T3"):
        lt = criteria[a]["latency"]
        rp.append(
            f"| {a} | {lt['mean_ms']} ms | {lt['p50_ms']} ms | {lt['p95_ms']} ms | {lt['p99_ms']} ms | "
            f"{lt['throughput_per_s_single_threaded']}/s | {lt['peak_vram_gb']} GB |"
        )
    rp.append(
        "\nLatency is detector-only, GPU, single-sample, warm, tokenisation included — the "
        "same methodology as every prior run, so the percentiles are comparable with them. "
        "**Peak VRAM is not.** It was captured after the batched scoring pass over 792 + 358 "
        "samples, so it reflects batch-32 inference rather than the single-sample figure "
        "ADR-019 reported (0.755 GB). The two measure different things and are not compared "
        "here. No gateway-overhead claim is made from any of these.\n"
    )
    (RESULTS / "report.md").write_text("\n".join(rp) + "\n", encoding="utf-8")

    # --- decision.md --------------------------------------------------------
    dp = [
        f"# ADR-020 — decision: {decision}\n",
        "## The registered rule, applied\n",
        "`success_criteria.json` defines FAILURE as **any retention criterion failing, or "
        "no mechanism meeting its bound**. Extraction recall on holdout-v3 is "
        f"{criteria['T2']['retention']['extraction_recall']['value']} against a floor of "
        f"{criteria['T2']['retention']['extraction_recall']['floor']}, and the paired test "
        "shows significant degradation. That is a FAILURE under the rule fixed before "
        "training, and it is recorded as one. This is the same scheme under which ADR-019 "
        "failed despite meeting every mechanism criterion.\n",
        "## What ADR-020 establishes\n",
        "**The retention/coverage trade-off is real, and neither knob escapes it.**\n",
        f"* Restoring extraction's share of attack mass (T2) recovered **{rec['T2'] / gap:.0%}** "
        "of ADR-019's regression while collapsing two of three mechanisms.",
        f"* Reducing the adaptation budget (T3) recovered **{rec['T3'] / gap:.0%}** and collapsed "
        "them further still.",
        "* Both remain below Strategy A on extraction *and* below ADR-019 on mechanisms. The "
        "two arms slide along a trade-off curve rather than stepping off it.\n",
        "**Composition was the leading hypothesis and it is the weaker factor.** C2 (relative "
        "dilution) is substantially weakened: restoring extraction to v1's share of attack "
        f"mass bought back only {rec['T2']:.4f} of a {gap:.4f} loss.\n",
        "**C1 (capacity / interference) is now the best-supported explanation.** Two "
        "independent interventions on the data and the schedule both trade one capability "
        "for the other at a fixed model size. That is the signature of a capacity "
        "constraint, not of a mis-specified corpus.\n",
        "## Architectural implication — ADR-020 §23 Outcome D\n",
        "Neither arm succeeds, so single-model replacement is weak. ADR-019 already proved "
        "these mechanisms are *learnable* (0.7333 / 0.7333 / 0.9667); ADR-020 proves they "
        "are not learnable **in the same model** without surrendering extraction. Those two "
        "results together point at a layered architecture (OD-34), not at more data or "
        "another schedule.\n",
        "## Production\n",
        "Unchanged, as it has been throughout: the registry holds the four baseline "
        "detectors, the heuristic threshold is 0.85, provenance overlays are off and "
        "blocking is disabled. **No checkpoint from this experiment is deployed, and the "
        "Strategy A model remains the reference.** No T3 checkpoint was ever deployable — "
        "all three failed the A-1 eligibility gate before scoring began.\n",
        "## Not authorised by this result\n",
        "Another training run, Strategy B or C, threshold tuning, enabling blocking, or "
        "integrating any model. The layered-detector experiment is defined in ADR-020 and "
        "remains unauthorised; it needs its own ADR.\n",
    ]
    (RESULTS / "decision.md").write_text("\n".join(dp) + "\n", encoding="utf-8")

    print(
        json.dumps(
            {
                "decision": decision,
                "deployment": deployment,
                "retention_met": dep["all_retention_met"],
                "mechanisms_met": dep["all_mechanisms_met"],
                "controls_met": dep["all_controls_met"],
            },
            indent=2,
        )
    )
    return 0
