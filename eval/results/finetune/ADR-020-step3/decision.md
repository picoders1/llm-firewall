# ADR-020 — decision: FAILURE

## The registered rule, applied

`success_criteria.json` defines FAILURE as **any retention criterion failing, or no mechanism meeting its bound**. Extraction recall on holdout-v3 is 0.7669 against a floor of 0.7946, and the paired test shows significant degradation. That is a FAILURE under the rule fixed before training, and it is recorded as one. This is the same scheme under which ADR-019 failed despite meeting every mechanism criterion.

## What ADR-020 establishes

**The retention/coverage trade-off is real, and neither knob escapes it.**

* Restoring extraction's share of attack mass (T2) recovered **15%** of ADR-019's regression while collapsing two of three mechanisms.
* Reducing the adaptation budget (T3) recovered **41%** and collapsed them further still.
* Both remain below Strategy A on extraction *and* below ADR-019 on mechanisms. The two arms slide along a trade-off curve rather than stepping off it.

**Composition was the leading hypothesis and it is the weaker factor.** C2 (relative dilution) is substantially weakened: restoring extraction to v1's share of attack mass bought back only 0.0135 of a 0.0912 loss.

**C1 (capacity / interference) is now the best-supported explanation.** Two independent interventions on the data and the schedule both trade one capability for the other at a fixed model size. That is the signature of a capacity constraint, not of a mis-specified corpus.

## Architectural implication — ADR-020 §23 Outcome D

Neither arm succeeds, so single-model replacement is weak. ADR-019 already proved these mechanisms are *learnable* (0.7333 / 0.7333 / 0.9667); ADR-020 proves they are not learnable **in the same model** without surrendering extraction. Those two results together point at a layered architecture (OD-34), not at more data or another schedule.

## Production

Unchanged, as it has been throughout: the registry holds the four baseline detectors, the heuristic threshold is 0.85, provenance overlays are off and blocking is disabled. **No checkpoint from this experiment is deployed, and the Strategy A model remains the reference.** No T3 checkpoint was ever deployable — all three failed the A-1 eligibility gate before scoring began.

## Not authorised by this result

Another training run, Strategy B or C, threshold tuning, enabling blocking, or integrating any model. The layered-detector experiment is defined in ADR-020 and remains unauthorised; it needs its own ADR.

