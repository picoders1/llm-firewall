# ADR-016: Indirect-injection detection requires provenance, not a better classifier

**Status:** Accepted (finding and constraint). **Nothing implemented.**
**Date:** 2026-08-17
**Evidence:** [`eval/results/20260817T130736Z__indirect-delivery-shape/report.md`](../../eval/results/20260817T130736Z__indirect-delivery-shape/report.md)
**Follows** [ADR-015](ADR-015-fine-tuning-strategy.md) **Strategy A.**

## Context

Strategy A fine-tuning fixed a real representational failure: the classifier could
not distinguish discussing an attack from performing one, and after fine-tuning it
can (quoted_attack FPR 0.875 → 0.0429 on independent data, recall retained).

Hold-out v3 then showed indirect-injection recall of 0.4000 on n=20 — too few
samples to attribute the failure to anything. A dedicated corpus
(`holdout-indirect-v1`, 820 samples, 12 delivery shapes × 8 attack mechanisms,
with benign controls in the same containers) was built to find out what was
actually happening.

## The measurement

Indirect-injection recall is **0.1423** (74/520, Wilson 95% [0.1149, 0.1750]).
**No delivery shape is reliably detected. Six score exactly zero** — prose
addressed to the assistant, JSON metadata fields, tool/retrieval metadata, hidden
markdown, YAML config and quoted prose recorded 0 detections in 240 attempts.

Two results identify the mechanism.

### 1. Recall depends on who is speaking, not on the payload

| User framing | n | Recall | Wilson 95% |
|---|---|---|---|
| `innocent_processing` — attacker planted the payload | 480 | **0.0938** | [0.0708, 0.1231] |
| `complicit_directive` — the user asks the model to obey the block | 40 | **0.7250** | [0.5717, 0.8389] |

A **7.7× difference on identical payloads**, varying only whether the override
request appears in the user's own turn or inside a document.

### 2. Where it does fire, it fires on syntax rather than intent

`system_marker` (`<|im_start|>system`, `### SYSTEM OVERRIDE ###`) is both the
best-detected attack shape (recall 0.5667) and the **only** shape with a nonzero
false-positive rate (**0.2000**, 5/25). All five false positives wrap *inert*
prose — text discussing security controls — in system-like markup, and all score
above 0.996. None contains an instruction.

Recall and FPR rising together in one shape is the signature of a detector keying
on form.

### It is not a threshold problem

`json_metadata` attacks have a **median score of 5.5e-05**. These are not
borderline cases cut off by a conservative operating point; they are scored as
clean. No operating point recovers them without classifying all traffic as
malicious.

## Decision

**Indirect-injection detection is a provenance judgement, and the current
detector contract discards provenance before the model sees the text.**

`DetectionContext` carries `raw_text` and `normalized_text` — a single flat string
per direction. The transformer classifies a 512-token window with no
representation of *which span came from the user* and *which arrived from a
retrieved document, a tool result, or an API field*. That distinction is precisely
what separates indirect injection from ordinary content: the same sentence is
benign as data and hostile as instruction, and only its origin tells them apart.

The measurements above are what that looks like from outside. The model has learned
system-looking markup as a **proxy** for untrusted provenance — which is why it
fires on the proxy whether or not an instruction is present, and why it is blind
when the payload arrives without the markup.

Therefore:

1. **Indirect-injection detection will not be solved by fine-tuning alone.** More
   indirect examples would teach better surface-form guessing, the mechanism that
   already produces the `system_marker` false positives. Recorded so it is not
   attempted as the obvious next step.
2. **A detector that is answerable for indirect injection needs provenance-tagged
   input.** The contract must express span origin (`user` / `tool` / `retrieved` /
   `system`), not merely message role at the API boundary.
3. **Blocking on the current detector is refused on severity grounds**, separately
   from ADR-015's criteria. See below.

## Consequences for blocking

FNR on indirect injection is **0.8577**. With this detector blocking:

* Roughly six in seven indirect injections pass.
* Six delivery shapes pass at a measured 100%.
* No evasion technique is required — a JSON metadata field or plain prose
  addressed to the assistant is sufficient, and both are the *natural* way to
  deliver the payload.
* The gateway would look healthy while doing nothing: FPR is 0.0167 and direct
  attacks are caught well, so dashboards and alert volumes would read normal.

That last point is the decisive one. **A control that fails silently on the threat
it was bought for is worse than a documented absence of the control**, because it
transfers risk to a customer who believes they are protected. Indirect injection
through retrieved content is the primary reason to place a firewall in front of a
RAG application; this detector does not provide it.

**Blocking stays closed. The fine-tuned model remains warn-only** — with the
recorded caveat that warn-mode alerts are themselves near-useless for this threat,
since ~86% never fire.

## Options considered

| Option | Assessment |
|---|---|
| **A** — more diverse fine-tuning data | **Rejected as sufficient.** Provenance is absent from the input, so more examples train better guessing. May help as a component of B/C. |
| **B** — context-aware gating: tag spans by origin before inspection, and apply a different policy to untrusted spans | **Required.** Supplies the signal the model cannot infer. Already recorded as OD-19 option C. |
| **C** — a specialised indirect-injection detector consuming provenance-tagged input | **Required.** What would consume B's output. Separate from the direct-injection classifier, which works. |
| **D** — layered detectors with independent failure modes | Plausible complement; not a substitute for provenance. |
| **E** — accept warn-only indefinitely | **Rejected as a resting place.** Honest today, but a warn signal that fires on 14% of the threat is not a control. |

**Chosen direction: B and C together**, because they address different halves —
gating supplies provenance, and a detector trained on provenance-tagged input is
what consumes it. Neither is implemented. Each requires its own protocol and its
own pre-registered criteria.

## What this ADR does not claim

* It does **not** claim DeBERTa-v3 is unsuitable as an architecture. The same
  checkpoint detects direct injection well and its fine-tuned false-positive
  behaviour is good. The unsuitability is of *this input representation* for
  *this task*.
* It does **not** claim a provenance-aware design would work. That is a
  hypothesis requiring its own experiment.
* It does **not** revise any prior result. ADR-015's Strategy A verdict
  (PARTIAL SUCCESS) stands, and v2 and v3 remain frozen.

## Verification

```bash
uv run python -m scripts.datasets.build_indirect_v1 --sizing   # sample-size basis
uv run python -m scripts.datasets.build_indirect_v1 --check    # integrity gates
uv run pytest -m evaluation -q                                 # corpus + guard tests
```

## Revisit when

A provenance-tagging design exists and can be evaluated against
`holdout-indirect-v1` — which, having been scored once, is now a frozen reference
point for exactly that comparison.
