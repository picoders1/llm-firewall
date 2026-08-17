# ADR-020 execution protocol

Operational companion to
[`docs/adr/ADR-020-retention-preserving-training.md`](../../../../docs/adr/ADR-020-retention-preserving-training.md).
The ADR carries the reasoning and the pre-registered criteria; this file is what an
operator follows. **Nothing here is authorised to run yet.**

Artefacts in this directory:

| File | Contents |
|---|---|
| `baseline_manifest.json` | Corpus and checkpoint hashes, immutable baselines, declared hold-out budget. Generated from artefacts — no value hand-entered |
| `variable_matrix.csv` | One row per arm; every variable in the causal table, marked controlled or varied |
| `success_criteria.json` | Criteria with denominators, targets, CI method, decision rules, directions |
| `protocol.md` | This file |

## Order of execution, with abort conditions

Steps 0 and 1 **train nothing** and **touch no hold-out**. Either can end the sequence.

```
Step 0  validate the selection proxy        no training, no hold-out
   │      └── gate fails ──> fallback: author holdout-v4, or declare extra v3 scorings. STOP.
Step 1  measure seed variance                no training, no hold-out
   │      └── gap < seed spread ──> amend ADR-019 to INCONCLUSIVE. STOP. Do not train.
Step 2  train T2 and T3, 3 seeds each        6 runs
Step 3  select on proxy + dev, then score the single winner once per hold-out
```

### Step 0 — validate the selection proxy

Score the two existing winners on the proxy corpora. Both checkpoints and all corpus
hashes are pinned in `baseline_manifest.json`.

```
checkpoints  artifacts/finetune/stratA__lr1e-05__ep2__seed13
             artifacts/finetune-mechanisms/mech__lr1e-05__ep2__seed13
corpora      eval/datasets/raw/lakera-gandalf.jsonl            (999 attacks)
             eval/datasets/raw/deepset-prompt-injections.jsonl (263 / 399)
             eval/datasets/raw/dolly-benign.jsonl              (4000 benign)
             eval/datasets/raw/oasst1-benign.jsonl             (4000 benign)
```

**Pass condition:** Strategy A strictly above ADR-019 on `lakera-gandalf`, significant
by exact McNemar (`scripts.evaluate_provenance.mcnemar_exact`).

**Rationale for the gate:** a proxy that cannot detect an effect already known to
exist cannot be trusted to rank arms whose effects are unknown.

**Report regardless of outcome**, including a negative one. Absolute numbers on these
corpora are **not** claimable as capability — ADR-014 used them for base-model
selection and they are plausibly in the base model's pretraining. They are used only
to rank two fine-tunes of the same base, where that bias cancels.

**On failure:** author `holdout-v4` targeting extraction, or declare additional
holdout-v3 scorings in advance. Do not proceed by scoring the hold-out more often
without declaring it.

### Step 1 — measure seed variance (C7)

```
artifacts/finetune-mechanisms/mech__lr1e-05__ep2__seed20260817
artifacts/finetune-mechanisms/mech__lr1e-05__ep2__seed31337
artifacts/finetune/stratA__lr1e-05__ep2__seed20260817
artifacts/finetune/stratA__lr1e-05__ep2__seed31337
```

Three runs per condition on the validated proxy. Report the within-condition spread
and the between-condition gap.

**Abort condition:** if the between-condition gap is smaller than the within-condition
spread, the regression is not attributable to the corpus change. Amend ADR-019 to
INCONCLUSIVE via its `amendment.md` (ADR-019 is immutable; it is amended, not edited)
and **stop**. No retention training is justified.

This is the project's first run-to-run variance estimate. The exact McNemar p = 1e-08
already recorded for ADR-019 concerns **sampling** error on holdout-v3 and says
nothing about variance **across training runs** — a distinct source that has never
been quantified here.

### Step 2 — train T2 and T3

New script `scripts/finetune_retention.py`. It must import its constants and training
loop from `scripts/finetune_strategy_a.py` exactly as `finetune_mechanisms.py` does,
so a difference in results cannot come from a difference in the loop.

Arms are fully specified in `variable_matrix.csv`:

| Arm | Sampler | Epochs | Steps/epoch | Total steps | Isolates |
|---|---|---|---|---|---|
| T2 | 90/10 v1:extension, attack fraction pinned to 0.194022, extraction ≥ 38.9189% of attack mass | 2 | 243 | 486 | composition only (steps identical to T1) |
| T3 | identical sampler to T2 | 1 | 243 | 243 | adaptation budget only (vs T2) |

Held constant: lr 1e-5, effective batch 16 (micro-batch 4 × accumulation 4, fused
AdamW), max length 512, weight decay 0.01, warmup 10%, base model
`protectai/deberta-v3-base-prompt-injection-v2`. Seeds 13, 20260817, 31337.
**Six runs.**

Steps per epoch use the trainer's exact ceiling formula,
`(n + BATCH_SIZE - 1) // BATCH_SIZE` at `scripts/finetune_strategy_a.py:284`.

**The one declared departure:** a weighted sampler. It changes *which rows are drawn*
and nothing else — no class weights, no custom loss, no curriculum. ADR-019's guard
test forbidding `WeightedRandomSampler` is scoped to `scripts/finetune_mechanisms.py`
and is **not** modified; the new script carries its own guards asserting the loss is
still the model's own cross-entropy.

Required per run, matching ADR-019's record-keeping: checkpoint hash, run manifest,
training-corpus hash, dev metrics, threshold lock. Technically failed runs stay in the
record with `status` in `{ok, failed, degenerate}` — they are not deleted.

### Step 3 — select, then score once

Rank the six checkpoints on the validated proxy plus dev. Lock the selection **before**
any hold-out is read; the lock records `holdout_used_in_selection: false`.

Then score **one** winner:

| Corpus | prior scorings | this ADR |
|---|---|---|
| holdout-v3 | 2 | 1 |
| mechanisms-v1 | 1 | 1 |
| holdout-indirect-v1 | 2 | 0 |
| holdout-v2 | 1 | 0 |

Anything beyond this requires a new ADR.

## Thresholds

Two thresholds are recorded per model.

1. **Primary** — dev-selected under the identical documented methodology and the same
   deterministic tie-break, keeping the successor comparable with the historical
   record. Note in the report that v2 dev is saturated, so this threshold is
   **underdetermined**: any value in the separating gap scores identically.
2. **Secondary, comparability only** — smallest τ giving ≤ 1% FPR on a frozen,
   seed-fixed 2,000-sample draw from the unused public benign pool, applied
   identically to every model, so models are compared at a matched operating point.

Published historical numbers are **not** restated. Matched-FPR figures appear as a
clearly labelled additional analysis beside them.

## Pre-flight checks

Before Step 2, a `--safety-check` phase must pass and be recorded:

- corpus hashes match `baseline_manifest.json` byte for byte
- 0 exact and 0 normalised collisions between the training mixture and every frozen
  hold-out, via `eval.schema.normalised_key`
- AST-based `verify_isolation()` proves no hold-out path is reachable from training
- the training input representation is stated explicitly (ADR-019 §9)
- realised sampler proportions are asserted against the targets in
  `variable_matrix.csv`, not merely configured — a mis-specified sampler would
  silently reintroduce the confound this experiment exists to remove

## Reporting

Report the outcome whatever it is. A negative result honestly reported is the point of
the exercise; ADR-019's failure is a completed, valuable experiment. Do not optimise
the report, do not retune criteria after seeing results, and do not present any
pre-registered failure mode as an insight discovered afterwards.

Report explicitly if:

- dev saturates again and selection is decided by tie-break (OD-23)
- the proxy gate fails
- any arm's realised proportions differ from target
- any run failed technically

## Production

Unchanged throughout: registry exactly `injection.heuristic`, `jailbreak.heuristic`,
`pii.regex`, `output.stub`; heuristic threshold 0.85; `by_trust` overlays 0; blocking
disabled. No checkpoint from this experiment enters the application runtime tree, and
`artifacts/` stays gitignored.
