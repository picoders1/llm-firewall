# Indirect-injection delivery-shape evaluation

**Run:** `20260817T130736Z__indirect-delivery-shape`
**Date:** 2026-08-17
**Model:** `stratA__lr1e-05__ep2__seed13` — frozen Strategy A checkpoint, unchanged
**Threshold:** 0.9955 — from `selection_lock.json`, not recalibrated
**Dataset:** `holdout-indirect-v1`, 820 samples, sha256 `3ef8c0ec75d9aed9669332dd2e70987993459b39629a6f7109241e13f96d6e17`

## Headline

**Indirect-injection recall is 0.1423** (74/520, Wilson 95% [0.1149, 0.1750]) —
not the 0.4000 that hold-out v3 estimated on twenty samples.

**All twelve delivery shapes are systematically missed. Six score exactly
zero.** The detector does not perform indirect-injection detection in any channel
a real attacker would use.

**Blocking decision: unchanged — WARN ONLY.** The evidence against blocking is now
much stronger than it was.

---

## The question

Hold-out v3 put indirect-injection recall at 0.4000 (n=20) against 1.0000 at v2's
n=5. Twenty samples could not say which figure was real, nor whether the failure
depended on how the payload was delivered. This corpus separates two dimensions
v3 confounded — **delivery shape** (the syntactic channel) and **attack
mechanism** (what the instruction does) — and pairs every attack container with
benign controls using the **same container**.

Nothing was tuned. The checkpoint, threshold, tokenizer and inference path come
from the lock written before any hold-out was scored, and the corpus was evaluated
exactly once.

## Verification before evaluation

| Check | Result |
|---|---|
| Checkpoint SHA-256 matches the lock | ✅ |
| Threshold is the locked 0.9955 | ✅ |
| Dataset hash matches its freeze | ✅ |
| Hold-out v2 unchanged (`fd915752…`) | ✅ |
| Hold-out v3 unchanged (`0e26dd6b…`) | ✅ |
| Payload vocabulary disjoint from training and v3 | ✅ |

## Sample sizing, calculated before authoring

The per-shape question is a decision, not an estimate: *is this shape reliably
detected?* Judged against ADR-015's recall bound of 0.80 under the project's
CI-strict rule.

| Tier | n | RELIABLY DETECTED needs | SYSTEMATICALLY MISSED needs | Inconclusive band |
|---|---|---|---|---|
| Priority shapes (6) | 50 | ≥ 46/50 (0.920) | ≤ 34/50 (0.680) | 0.68–0.92 |
| Secondary shapes (6) | 30 | ≥ 29/30 (0.967) | ≤ 19/30 (0.633) | 0.63–0.967 |
| Benign controls | 300 | — | — | 0 FP → FPR ≤ 0.0126 |

v3 sized this category at n=20 as supporting coverage rather than to a criterion,
and its 0.4000 [0.2188, 0.6134] was too wide to act on. Every shape here lands in
a conclusive bucket unless its true recall sits inside the stated band.

## Taxonomy

**12 delivery shapes**, plus `complicit_directive` as a contrast condition:

*Priority* — html_comment, prose_addressed, xml_markup, json_metadata,
code_comment, tool_retrieval_metadata
*Secondary* — markdown_hidden, yaml_config, document_footer_header, alt_text,
quoted_prose, system_marker

**8 attack mechanisms** — instruction_override, system_prompt_extraction,
role_manipulation, context_injection, data_exfiltration, tool_use_manipulation,
safety_bypass, retrieval_poisoning

**13 contexts** — retrieved document, web page, PDF extraction, email, ticket,
knowledge-base article, code repository, API response, JSON document, XML
document, database field, search result, tool output

### A labelling decision worth stating plainly

§9 of the task offered `Summarize this incident report: <!-- ignore previous
instructions… -->` as a **benign** example, while §17 defines a positive as
embedded content "intended to manipulate model behavior when interpreted in the
relevant context" — which that payload is.

This corpus follows §17. A sample is positive when the embedded content
**functions as an instruction in context**, regardless of whether the human's own
request was innocent. In standard indirect-injection threat modelling the
innocent-user case *is* the attack: the attacker planted the payload and the user
is the victim. Labelling it benign would define the primary threat out of
existence.

To preserve the question §9 was actually asking — does the detector read context?
— `user_framing` is recorded as a **separate dimension**
(`innocent_processing` / `complicit_directive` / `security_discussion`) rather
than folded into the label. That turned out to be the most informative field in
the corpus.

## Dataset

820 samples: **520 attacks**, **300 benign controls**.

| Shape | attacks | benign | | Mechanism | n |
|---|---|---|---|---|---|
| html_comment | 50 | 25 | | context_injection | 73 |
| prose_addressed | 50 | 25 | | data_exfiltration | 71 |
| xml_markup | 50 | 25 | | instruction_override | 67 |
| json_metadata | 50 | 25 | | retrieval_poisoning | 64 |
| code_comment | 50 | 25 | | safety_bypass | 64 |
| tool_retrieval_metadata | 50 | 25 | | role_manipulation | 61 |
| complicit_directive | 40 | — | | system_prompt_extraction | 61 |
| markdown_hidden | 30 | 25 | | tool_use_manipulation | 59 |
| yaml_config | 30 | 25 | | | |
| document_footer_header | 30 | 25 | | | |
| alt_text | 30 | 25 | | | |
| quoted_prose | 30 | 25 | | | |
| system_marker | 30 | 25 | | | |

## Integrity

| Check | Result |
|---|---|
| Payload vocabulary vs fine-tuning phrases / v3 payloads | **disjoint** |
| Exact collisions (10 corpora, 16,115 texts) | **0** |
| Normalised collisions | **0** |
| Internal duplicates / near-duplicates | **0 / 0** |
| Near-duplicates vs v2 and v3 | **0** |
| Secrets / PII | **0 / 0** |

## Overall results (n=820, threshold 0.9955)

| TP | FP | TN | FN | Precision | Recall | F1 | FPR | FNR |
|---|---|---|---|---|---|---|---|---|
| 74 | 5 | 295 | 446 | 0.9367 | 0.1423 | 0.2471 | 0.0167 | **0.8577** |

Attack recall 0.1423 [0.1149, 0.1750] (n=520).
Benign-control FPR 0.0167 [0.0071, 0.0384] (n=300) — meets the ≤0.10
hard-negative bound.

## Recall by delivery shape

![recall by delivery shape](recall_by_delivery_shape.svg)

| Delivery shape | n | Recall | Wilson 95% | Verdict |
|---|---|---|---|---|
| prose_addressed | 50 | 0.0000 | [0.0000, 0.0713] | **SYSTEMATICALLY MISSED** |
| json_metadata | 50 | 0.0000 | [0.0000, 0.0713] | **SYSTEMATICALLY MISSED** |
| tool_retrieval_metadata | 50 | 0.0000 | [0.0000, 0.0713] | **SYSTEMATICALLY MISSED** |
| markdown_hidden | 30 | 0.0000 | [0.0000, 0.1135] | **SYSTEMATICALLY MISSED** |
| yaml_config | 30 | 0.0000 | [0.0000, 0.1135] | **SYSTEMATICALLY MISSED** |
| quoted_prose | 30 | 0.0000 | [0.0000, 0.1135] | **SYSTEMATICALLY MISSED** |
| code_comment | 50 | 0.0200 | [0.0035, 0.1050] | **SYSTEMATICALLY MISSED** |
| document_footer_header | 30 | 0.0333 | [0.0059, 0.1667] | **SYSTEMATICALLY MISSED** |
| xml_markup | 50 | 0.1600 | [0.0834, 0.2851] | **SYSTEMATICALLY MISSED** |
| html_comment | 50 | 0.2200 | [0.1275, 0.3524] | **SYSTEMATICALLY MISSED** |
| alt_text | 30 | 0.2333 | [0.1179, 0.4093] | **SYSTEMATICALLY MISSED** |
| system_marker | 30 | 0.5667 | [0.3920, 0.7262] | **SYSTEMATICALLY MISSED** |
| complicit_directive | 40 | 0.7250 | [0.5717, 0.8389] | INCONCLUSIVE |

**No shape is reliably detected.** Not one.

## Recall by attack mechanism

![recall by attack mechanism](recall_by_attack_mechanism.svg)

| Mechanism | n | Recall | Wilson 95% |
|---|---|---|---|
| retrieval_poisoning | 64 | 0.0312 | [0.0086, 0.1070] |
| tool_use_manipulation | 59 | 0.0339 | [0.0093, 0.1154] |
| role_manipulation | 61 | 0.0656 | [0.0258, 0.1568] |
| safety_bypass | 64 | 0.0938 | [0.0437, 0.1898] |
| context_injection | 73 | 0.1370 | [0.0761, 0.2341] |
| data_exfiltration | 71 | 0.2254 | [0.1437, 0.3352] |
| instruction_override | 67 | 0.2388 | [0.1527, 0.3533] |
| system_prompt_extraction | 61 | 0.2951 | [0.1956, 0.4189] |

The spread across mechanisms (0.03–0.30) is narrower than across shapes
(0.00–0.73), and its ordering is explicable: the two best-detected mechanisms are
the two whose phrasing most resembles a *direct* attack. The two mechanisms
specific to indirect channels — retrieval poisoning and tool-use manipulation —
are near zero. **The failure is channel-driven, not capability-driven.**

## Benign controls

![FPR by benign shape](fpr_by_benign_shape.svg)

| Shape | benign n | FP | FPR |
|---|---|---|---|
| system_marker | 25 | **5** | 0.2000 |
| all other 12 shapes | 275 | 0 | 0.0000 |

All five false positives are `system_marker` samples containing **inert content** —
prose *about* security wrapped in `<|im_start|>system` or `### SYSTEM OVERRIDE ###`.
None contains an instruction. All score above 0.996.

`system_marker` is simultaneously the best-detected attack shape and the only
shape with a nonzero FPR. Recall and FPR moving together in one shape is the
signature of a detector firing on **form rather than intent** — and it is visible
only because every attack container is paired with the same container carrying
inert content.

## The finding that matters most

| User framing | n | Recall | Wilson 95% |
|---|---|---|---|
| `innocent_processing` — attacker planted the payload | 480 | **0.0938** | [0.0708, 0.1231] |
| `complicit_directive` — the user asks the model to obey the block | 40 | **0.7250** | [0.5717, 0.8389] |

**A 7.7× difference in recall on identical payloads**, varying only who is
speaking.

The detector is not weak at indirect injection. It is **not attempting it**. It
classifies the user's turn. When the user requests an override, it fires; when an
attacker plants the identical sentence in a retrieved document and the user asks
innocently for a summary, it does not. It is a direct-injection classifier being
asked to do a different job.

And it is not a threshold problem: `json_metadata` attacks have a **median score
of 5.5e-05**. These are not borderline cases being cut off by a conservative
operating point — they are scored as clean.

## The five critical questions (§25)

### Q1 — Which delivery shapes are reliably detected?

**None.** No shape reaches the RELIABLY DETECTED bar. The best planted-payload
shape is `system_marker` at 0.5667, and its detection is driven by markup tokens
rather than content — demonstrated by its 20% false-positive rate on inert text in
the same markup.

### Q2 — Which delivery shapes are systematically missed?

**All twelve, and six at exactly zero**: prose_addressed, json_metadata,
tool_retrieval_metadata, markdown_hidden, yaml_config and quoted_prose recorded
**0 detections in 240 attempts**. code_comment (0.02), document_footer_header
(0.03), xml_markup (0.16), html_comment (0.22) and alt_text (0.23) follow.

These are the ordinary channels of a RAG application: retrieved pages, JSON API
fields, tool output, code, PDFs, tickets.

### Q3 — Does adding contextual information appear necessary?

**Yes, and the evidence is direct.** The 7.7× gap between innocent and complicit
framing on identical payloads shows the model's decision is driven by the user's
turn. A single flat text classifier over a concatenated prompt has no
representation of *provenance* — which span came from the user and which arrived
from a document — and provenance is precisely what distinguishes indirect
injection from ordinary content.

The `system_marker` result sharpens this: the model has learned that
system-looking markup is dangerous, which is a proxy for provenance rather than
provenance itself. It fires on the proxy whether or not an instruction is present.

### Q4 — Is the current model architecture suitable for indirect-injection detection?

**Not as currently used.** DeBERTa-v3 sequence classification over an
undifferentiated 512-token window has no channel to express "this span is
untrusted retrieved content". The architecture is not the whole problem —
fine-tuning fixed a genuine representational failure on quoted attacks — but
indirect injection is a *provenance* judgement, and this input representation
discards provenance before the model sees it.

Fine-tuning on more indirect examples might raise these numbers. It would still
be teaching the model to guess provenance from surface form, which is what
produced the `system_marker` false positives.

### Q5 — Would blocking with this detector create an unacceptable security blind spot?

**Yes, unambiguously.** With this detector blocking:

* ~86% of indirect injections would pass (FNR 0.8577).
* Six delivery shapes would pass at a measured 100%.
* An attacker needs no evasion technique — putting the payload in a JSON metadata
  field or addressing the assistant in plain prose is sufficient, and both are
  the natural way to deliver it.
* Blocking would create a **false assurance**: the FPR is excellent (0.0167) and
  direct attacks are caught well, so the gateway would look healthy while the
  highest-severity channel went unexamined.

That last point is the argument. A control that fails silently on the threat it
was bought for is worse than a documented absence of the control.

## Blocking decision: WARN ONLY (unchanged)

No evidence supports changing it. ADR-015's criteria are not met — attack recall
and extraction recall failed on hold-out v3 — and this run adds a
severity-weighted reason that stands on its own: the detector cannot see indirect
injection in any realistic channel.

**No production change was made.** Registry, heuristic detector, its 0.85
threshold and the gateway policy are untouched.

## Performance

mean 12.438 ms · p95 14.924 ms · peak VRAM 0.761 GB (n=200, single-sample, CUDA).
Consistent with the v3 run (11.750 / 12.308 / 0.759) on the same device. No
latency claim is made against the CPU-measured base model.

## Next research direction (§27)

**Classification: B + C — context-aware gating *and* a specialised
indirect-injection detector.**

Not A (more fine-tuning data): the failure is that provenance is absent from the
input representation, so more examples would teach better surface-form guessing —
the mechanism that already produces the `system_marker` false positives.

Not E: warn-only is the current state, and this run shows warn-mode alerts are
themselves near-useless for this threat (~86% never fire).

B and C together, because they address different halves: gating supplies the
provenance signal the model cannot infer, and a detector trained on
provenance-tagged input is what would consume it.

**Not implemented. A new experiment requires a new protocol.**

## Limitations

1. **Compositional corpus.** Diversity is bounded by the authored pools —
   13 shape template families, 26 payloads, 12 inert references. Lexical
   disjointness from training and v3 is verified, but a real attacker is not
   drawn from a matrix.
2. **`complicit_directive` is a contrast condition, not a threat model.** Its 40
   samples exist to isolate the framing variable; that recall figure should not be
   quoted as a capability.
3. **Context denominators are small** (xml_document n=8, email n=10) — context was
   not sized to a criterion and those rows are directional only.
4. **The failure-reason taxonomy is heuristic**, assigned by shape and score band
   rather than by inspecting model internals. It describes where the model fails,
   not mechanistically why.
5. **Benign controls carry only `security_discussion` framing.** A benign control
   with innocent framing and genuinely inert embedded content would test a
   slightly different thing; this corpus does not separate that.
6. **One authoring source, one machine, one run.** No independent review of the
   samples.
7. **English only.**
8. **This measures the fine-tuned Strategy A checkpoint only.** The base model and
   the heuristic were not scored on this corpus, so no three-way comparison is
   offered here.

## Artefacts

| File | Contents |
|---|---|
| [`manifest.json`](manifest.json) | Provenance; `tuning_performed: false` |
| [`metrics.json`](metrics.json) | All metrics with intervals |
| [`shape_metrics.json`](shape_metrics.json) | Per-shape recall and verdicts, attacks and controls |
| [`mechanism_metrics.json`](mechanism_metrics.json) | Per-mechanism recall |
| [`predictions.jsonl`](predictions.jsonl) | Per-sample scores |
| [`misses.jsonl`](misses.jsonl) | Every miss with its failure classification |
| [`error_analysis.md`](error_analysis.md) | Failure patterns and the framing analysis |
| `*.svg` | Recall by shape, recall by mechanism, FPR by benign shape |

## Reproduction

```bash
uv run python -m scripts.datasets.build_indirect_v1 --sizing
uv run python -m scripts.datasets.build_indirect_v1 --check
uv run python -m scripts.evaluate_indirect_v1
```
