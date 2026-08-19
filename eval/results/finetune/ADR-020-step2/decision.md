# ADR-020 Step 2 — decision

**Status: COMPLETE** — 6/6 runs, all manifests written, no hold-out accessed.

## Causal interpretation: DEFERRED to Step 3, and necessarily so

ADR-020 §18 asks three questions:

* **A** — does T2 recover retention while preserving mechanism learning?
* **B** — does T3 recover retention?
* **C** — does neither, promoting the layered-detector hypothesis?

**None of them can be answered by Step 2**, and answering them here would be a fabrication rather than a finding. Retention is defined on holdout-v3 (extraction recall, attack recall, benign FPR, quoted_attack FPR) and mechanism learning on mechanisms-v1. §15 forbids reading either, correctly — those are the single authorised scorings and they belong to Step 3.

The only within-Step-2 surface is dev, and dev is **partially discriminating**: it separates some runs, but the historical record shows dev saturation repeatedly failing to predict hold-out behaviour.

§18's own instruction governs: *do not claim a causal result if the observed arms cannot actually distinguish it.* They cannot, yet.

## What Step 2 does establish

1. **The six registered runs exist and completed**, with the matrix unexpanded — two arms, three seeds, one learning rate, no seventh configuration.
2. **The mixture realised as registered**, verified sample by sample rather than assumed from the configured ratio: v1 0.899949, extension 0.100051, attack fraction 0.19393, extraction 0.38992 of attack mass (at or above the registered floor), mechanisms exactly balanced.
3. **The contrasts are clean by construction.** T2 holds the step budget at ADR-019's 486 and varies only composition; T3 shares T2's sampler and varies only the adaptation budget. T3's epoch is byte-identical to T2's first epoch, asserted in `tests/evaluation/test_adr020_step2.py`.
4. **A quantified cost of the replay**: each new mechanism now receives 53 samples per epoch against ADR-019's ~150. If the mechanisms fail their Wilson bound in Step 3, this is the reason, and it was registered in advance as R-49.

## Step-3 decision: **PROCEED TO STEP 3**

Justified because the arms differ enough to be separable on the hold-out, the matrix is complete and unexpanded, and the registered question is still open — not because T2 scores better on dev, which ADR-020 §9 explicitly excludes as a basis for the decision.

### Precondition audit (§10)

| requirement | state |
|---|---|
| checkpoint selection rule | defined — amendment A-1, exact ordered keys |
| threshold-selection rule | defined — amendment A-2, matched-FPR primary |
| holdout-v3 scoring budget | defined — 1 event, 2 checkpoints (A-3) |
| mechanisms-v1 scoring budget | defined — 1 event, 2 checkpoints (A-3) |
| retention criteria | defined — `success_criteria.json`, 4 criteria, paired + margin |
| new-mechanism criteria | defined — Wilson lower >= 0.50, i.e. >= 38/60 |
| immutable model-selection lock | defined — locked before any hold-out is read |

**One requirement was NOT satisfied when this audit began, and was amended before Step 3 rather than after** (A-3, 2026-08-18). Step 3 originally scored a single pooled winner. Because T2 dominates T3 on every dev metric, the pooled winner would be a T2 and T3 would never be measured on holdout-v3 — making three of ADR-020's four registered causal outcomes unreachable and three of its six runs evidentially useless. Step 3 now scores the best T2 **and** the best T3 in one evaluation event, both locked in advance; the deployment candidate remains the single pooled winner and the other arm is contrast-only.

## Next

**Execute ADR-020 Step 3** — DEV-only final selection and threshold lock under A-1, A-2 and A-3, followed by the single authorised evaluation event on holdout-v3 and on mechanisms-v1.

Step 3 is a separate task and is not started here.

