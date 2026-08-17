# Amendment — a directional flaw in ADR-018's criterion 3

**Found during analysis of this run, after the single evaluation. The corpus was
not re-scored; everything below is recomputed from the recorded artifacts.**

## The defect

ADR-018 pre-registered criterion 3 as:

> A2 vs A3: McNemar p < 0.05 on recall **or** FPR — i.e. provenance contributes
> something beyond segmentation.

That is satisfiable by a **degradation**. A significant result in either direction
passes it, so an arm that was significantly *worse* on recall would have been
recorded as evidence that provenance contributes.

This run tripped exactly that case: `A2_vs_A3_attack_recall` is significant
(p ≈ 0) with net **−22** — A2 is worse. As written, criterion 3 counted that as a
pass.

## The corrected criterion

The beyond-segmentation effect must be an improvement in the relevant direction:

* recall: `treatment_rate > control_rate` **and** significant, **or**
* FPR: `treatment_rate < control_rate` **and** significant.

## Recomputed result

| Half | Direction | Significant | Passes corrected criterion |
|---|---|---|---|
| A2 vs A3 recall | 0.5788 → 0.5365 — **worse** | yes | **no** |
| A2 vs A3 FPR | 0.0500 → 0.0000 — **better** | yes (p = 6.10e-05) | **yes** |

**Criterion 3 still passes, via the FPR half.** All four criteria remain met and
**the decision is unchanged: PROVENANCE BENEFICIAL.**

## Why this is recorded anyway

The verdict did not move, so nothing here rescues or damages the result. It is
recorded because the criterion *would* have accepted a degradation, and a future
pre-registration that reuses this wording would eventually be wrong in a way
nobody noticed. Every directional criterion needs its direction stated.

`metrics.json` retains the originally computed `decision_criteria` verbatim. This
file is the correction; neither is deleted.

## What criterion 3 was really testing

A2's recall deficit against A3 is not a failure of provenance. All 22 lost
detections are attacks whose payload sits in the **carrier** — `complicit_directive`
(14) and `system_marker` (8) — which A2 declines to score because it answers a
narrower question: *is there an instruction inside data that should not contain
one?* A direct instruction in the user's own turn is not that, and a different
detector is answerable for it.

All 15 false positives A2 avoids are `system_marker`, the shape ADR-016 showed
fires on `<|im_start|>system`-style markup regardless of content.
