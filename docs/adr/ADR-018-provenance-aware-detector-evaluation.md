# ADR-018: Provenance-aware detector — pre-registered evaluation protocol

**Status:** Accepted (protocol). **Written before the experiment was run; executed 2026-08-17.**
**Date:** 2026-08-17
**Phase:** 2P-D
**Follows** [ADR-016](ADR-016-provenance-aware-detection.md) (the diagnosis) and
[ADR-017](ADR-017-provenance-aware-detection-context.md) (the mechanism).

> **Outcome: PROVENANCE BENEFICIAL — and not sufficient for blocking.**
> Indirect-injection recall **0.1423 → 0.5365** (n=520, McNemar p ≈ 0, net +205)
> with benign-control FPR **0.0167 → 0.0000** and precision 1.0000. Provenance
> converted a delivery-channel problem into a content-recognition problem: variance
> across delivery shapes collapsed (sd 0.1644 → 0.0311) while variance across attack
> mechanisms rose (sd 0.0948 → 0.4523), with three mechanisms at perfect recall and
> three at zero. **46% of indirect injections still pass**, against ADR-015's ≥0.80,
> so blocking stays closed.
> Evidence: [`eval/results/provenance/20260817T141551Z__provenance-secondary/report.md`](../../eval/results/provenance/20260817T141551Z__provenance-secondary/report.md).
> A directional defect in criterion 3 was found and recorded in
> [`amendment.md`](../../eval/results/provenance/20260817T141551Z__provenance-secondary/amendment.md); the decision is
> unchanged.

## Context

ADR-016 measured indirect-injection recall at **0.1423** (n=520) with no delivery
shape reliably detected, and identified the cause as provenance being absent from
the detector's input. ADR-017 designed and Phase A+B+C implemented the mechanism
that supplies it. Nothing has yet shown the mechanism has security value.

This ADR fixes the experiment before it runs.

## A constraint discovered before designing the arms

Every sample in `holdout-indirect-v1` is a **single-part `user` message**. Running
the real gateway derivation over all 820 gives exactly two distinct triples:

```
(label=0, provenance=user_input, trust=principal)   300 benign controls
(label=1, provenance=user_input, trust=principal)   520 attacks
```

**Provenance is identical for attacks and benign controls.** In the flattened
form it carries *zero* discriminative information, so a "provenance-aware
detector" evaluated on the corpus as-is is guaranteed to show no effect. That
would be a tautology, not a finding about the architecture.

This is not a defect in the corpus — it is the accurate representation of what a
non-cooperating integration sends, and it is exactly the case ADR-016 measured.
But it means the architectural question is narrower and sharper than "does
provenance help":

> Does **isolating the untrusted span**, as ADR-017 §7 prescribes, and telling the
> detector which span is untrusted, improve indirect-injection detection?

## Two segmentation conditions — the text is never changed

Each sample contains exactly one embedded span drawn from the authoring pools
(`PAYLOADS` for attacks, `INERT_REFERENCES` for benign controls). Verified: **820
of 820 samples contain exactly one locatable pool string.** The span can therefore
be located deterministically without editing a single character.

| Condition | Segmentation | Provenance assigned |
|---|---|---|
| **FLAT** | one part: the whole sample text | `USER_INPUT` / `PRINCIPAL` (what the gateway derives today) |
| **SPLIT** | two parts: the carrier text, and the embedded span | carrier `USER_INPUT`/`PRINCIPAL`; span `EXTERNAL`/`UNTRUSTED` |

**No content is added or removed between conditions.** Extraction reorders — the
SPLIT parts are `(carrier, span)` while the original had the span in the middle —
so the precise invariant is that the multiset of non-whitespace **characters** is
identical, none added and none removed, and the span is handed to the model
verbatim. (Word-level comparison would fail spuriously: removing the span joins its
two neighbouring fragments into one token.) Order between parts is irrelevant
because each part is scored independently. Asserted by
`test_split_adds_and_removes_no_content` and
`test_the_embedded_span_is_scored_verbatim`. This is the same-text manipulation §7
of the task requires, and it is legitimate because multi-part content is already the
gateway's native representation (`_message_parts`).

**No label leakage.** In SPLIT, *both* attacks and benign controls have an
`EXTERNAL` part — an attack's contains a live instruction, a control's contains
inert prose about security. Provenance still does not reveal the label; the
detector must read the isolated span's content.

## Arms — same checkpoint, weights, tokenizer, normalisation, threshold

All four arms use the frozen Strategy A checkpoint
`stratA__lr1e-05__ep2__seed13`, SHA-256 `2995b260…`, at the frozen threshold
**0.9955**. No recalibration, no retraining.

| Arm | Segmentation | Uses provenance | What it does |
|---|---|---|---|
| **A0** `content_only_flat` | FLAT | no | Scores the whole text. **The control** — replicates the ADR-016 run. |
| **A1** `provenance_aware_flat` | FLAT | yes | May read provenance, which is constant. Tests whether the *field's existence* changes anything. |
| **A2** `provenance_aware_split` | SPLIT | yes | Scores **only** parts whose trust is `UNTRUSTED`. An instruction inside untrusted data is illegitimate; the user's own instruction is not. **The treatment.** |
| **A3** `content_only_split` | SPLIT | no | Scores **all** parts and takes the maximum, ignoring provenance. |

**A3 is the load-bearing control.** A2's advantage over A0 could come from
segmentation alone — a short isolated span is an easier input than the same
payload buried in 200 tokens of benign document. If A2 ≈ A3, the benefit is
segmentation, not provenance, and the honest conclusion is different. Without A3
this experiment could not tell those apart.

### Ablations (task §9)

| Mode | Manipulation | Expectation if provenance is genuinely used |
|---|---|---|
| **M1** correct provenance | = A2 | baseline for the ablation |
| **M2** provenance removed | all parts `UNKNOWN` | A2's score collapses — it has no untrusted part to score |
| **M3** detector prohibited | = A3 | isolates segmentation |
| **M4** provenance inverted | carrier tagged `EXTERNAL`, span tagged `USER_INPUT` | recall collapses; a detector that ignores provenance is unaffected |

M4 is a robustness probe, not a production scenario.

## Statistical method

**The comparison is paired** — identical samples under different arms — so
independent Wilson intervals are the wrong test: they ignore the pairing and
discard power. The primary test is **McNemar's exact binomial** on discordant
pairs, implemented in-repo so the arithmetic is auditable, consistent with the
project's refusal to import a statistics package for its headline numbers.

Wilson intervals are still reported per arm as descriptive statistics.

### Minimum detectable effect, calculated in advance

With 520 paired attack samples, treatment gaining `b` and losing `c`:

| b | c | exact two-sided p |
|---|---|---|
| 5 | 0 | 0.0625 |
| **6** | **0** | **0.0312 — significant** |
| 20 | 5 | 0.0041 |
| 10 | 10 | 1.0000 |

**Six net detections with no losses is detectable.** The test is sensitive enough
that a real effect of any practical size will register; correspondingly, a null
result cannot be blamed on power.

## Pre-registered decision criteria

Fixed now. Not to be adjusted after seeing results.

**PROVENANCE BENEFICIAL** — all of:
1. A2 vs A0 attack recall: McNemar p < 0.05 with net gain ≥ +6 detections.
2. A2 benign-control FPR: Wilson upper bound ≤ **0.10** (the ADR-015
   hard-negative bound).
3. A2 vs A3: McNemar p < 0.05 on recall **or** FPR — i.e. provenance contributes
   something beyond segmentation.
4. M2 (provenance removed) degrades A2 materially, proving the effect depends on
   provenance rather than on the field's presence.

**PROVENANCE PARTIALLY BENEFICIAL** — criterion 1 met, but any of: FPR exceeds
the bound; A2 ≈ A3 (benefit attributable to segmentation); or the gain is confined
to a minority of delivery shapes.

**PROVENANCE INSUFFICIENT** — criterion 1 not met, or the recall gain is bought
with a benign-control FPR above the bound.

**INCONCLUSIVE** — an arm fails to run, or the corpus cannot support the
comparison.

## Threshold, and a limitation registered in advance

The frozen 0.9955 was calibrated on the **dev split of the fine-tuning corpus**,
whose samples are whole short messages. Scoring an isolated span is a different
input distribution, so **the threshold may be mis-set for A2 and A3**. If those
arms underperform, threshold mismatch is a live alternative explanation to
"provenance does not help", and the report must say so rather than claim a clean
null.

A full threshold sweep will be reported for A2/A3 as a **diagnostic explicitly
excluded from the decision**. Recording that exclusion now is what prevents the
sweep from becoming threshold-fishing on a frozen corpus after the fact.

## Detector benefit and policy benefit are measured separately

Task §12/§13. Conflating them would let a policy overlay conceal a detector
failure.

* **Experiment A (this ADR's arms)** — does the *detector* benefit from provenance?
* **Experiment B (policy ablation)** — holding the content-only detector fixed,
  how much does a `by_trust` overlay change the *decision*? Reported in
  `policy_ablation.json`, computed with experiment-only configuration, and never
  enabled in the shipped policy.

Experiment B is not a detector result and must not be reported as one.

## Corpus status

`holdout-indirect-v1` was **already evaluated once**
(`eval/results/20260817T130736Z__indirect-delivery-shape`). This run is therefore
a **provenance-aware secondary evaluation** of an immutable, previously evaluated
corpus — not a fresh hold-out. It gets its own run ID and report, the prior result
stands unchanged, and the corpus is not modified.

The methodological cost is real: a corpus scored twice is no longer a clean
estimate of generalisation. It is the right corpus for a *paired architectural
comparison*, which is what this is, and a future claim about absolute performance
needs a new hold-out.

## Expected failure modes

Recorded before running so they cannot be presented as insight afterwards:

1. **Segmentation, not provenance, explains any gain** — the reason A3 exists.
2. **Threshold mismatch on isolated spans** — registered above.
3. **A2 raises false positives** on benign controls whose `EXTERNAL` span contains
   security prose, because it now scores exactly that span in isolation with no
   surrounding context to moderate it. Plausible and specifically measured.
4. **The oracle problem** — locating the embedded span uses knowledge of the
   authoring pools. A real gateway learns the boundary from a cooperating
   integration, not from a pool lookup. This experiment therefore measures the
   *ceiling* available to a perfectly cooperating integration, not what an
   arbitrary deployment would obtain. This is the single most important limitation
   and belongs in every summary of the result.
5. **`complicit_directive` is only n=40** — a framing comparison against
   `innocent_processing` (n=480) has very different precision on each side.

## Production safety

Unchanged and asserted in tests: registry, `injection.heuristic`, threshold 0.85,
no `by_trust` overlay in the shipped policy, blocking closed, warn/shadow only.
The experimental detector lives in `eval/`, is never registered, and Phase E
(production policy change) is not started.
