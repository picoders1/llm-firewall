# ADR-019 decision

**FAILURE** — by the pre-registered ladder, on a regression criterion, despite the
primary hypothesis being confirmed decisively.

## The criteria, applied unchanged

| # | Criterion | Bound | Measured | Verdict |
|---|---|---|---|---|
| 1a | retrieval_poisoning Wilson lower | ≥ 0.50 | **0.6099** | **MET** |
| 1b | tool_use_manipulation Wilson lower | ≥ 0.50 | **0.6099** | **MET** |
| 1c | safety_bypass Wilson lower | ≥ 0.50 | **0.8864** | **MET** |
| 2 | legitimate-request FPR upper | ≤ 0.10 | **0.0211** | **MET** |
| 3 | document-carried legitimate FPR upper | ≤ 0.10 | **0.0409** | **MET** |
| 4a | holdout-v3 benign FPR | no worse | +0.0069 | MET |
| 4b | holdout-v3 quoted_attack FPR | no worse | +0.0142 | MET |
| 5a | holdout-v3 attack recall | within 5 pt | **−0.0534** | **NOT MET** |
| 5b | holdout-v3 extraction recall | within 5 pt | **−0.0912** | **NOT MET** |

ADR-019: FULL SUCCESS needs all primary **and** all secondary. PARTIAL needs at
least one primary **and** all secondary. Two secondary criteria failed, so the
result is **FAILURE**.

## Why the label understates what happened

The label is correct and is not being softened. But a reader who sees only
"FAILURE" would draw the wrong lesson, so both halves belong in the same sentence:

**The corpus worked.** Three mechanisms went from **exactly 0.0000** to 0.7333,
0.7333 and 0.9667 — with **zero false positives on all 178 controls**, including
all 90 document-carried ones. The single largest registered risk (R-43: the model
learns "mentions a tool → block" and rejects legitimate agent traffic) did not
materialise at all.

**The model forgot.** Extraction recall on holdout-v3 fell 0.8446 → 0.7534, and
attack recall 0.8174 → 0.7640. Adding 450 attacks in three new relations cost
capability in a relation that already worked. That is catastrophic forgetting, and
ADR-019 registered it in advance as expected failure mode 3.

**The trade is real and it is a trade, not a defect in the corpus.** ADR-019 chose
to fail the run on it deliberately: a detector that gains three mechanisms and
loses system-prompt extraction has not obviously improved, and deciding that after
the fact would have been exactly the reinterpretation the protocol forbids.

## The hypothesis that was wrong was mine

ADR-019 and OD-31 registered `safety_bypass` as the mechanism most likely to be
**unlearnable from text** — the argument being that "the moderation step has
already run" is a false claim about system state, indistinguishable in text from a
true statement in legitimate documentation.

It is the **best-performing** of the three: **0.9667 [0.8864, 0.9908]**, 58 of 60,
with zero false positives on the legitimate moderation documentation authored
specifically as its control.

The argument was wrong in an instructive way. The model did not need to evaluate
the claim's truth; it learned the **relation** — a claim about system state
*arriving inside retrieved content* is illegitimate regardless of whether it
happens to be true, because a document has no standing to make it. That was the
alternative reading recorded in OD-31, and the evidence supports it.

## Decision

**FAILURE**, and the corpus is retained. The next question is not whether these
mechanisms are learnable — they are — but whether they can be learned *without*
losing what already works.
