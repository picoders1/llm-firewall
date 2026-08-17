# 21 — Open Decisions

Decisions genuinely requiring future validation. Everything settled is in `adr/`; anything
here is **not** settled, and no document should read as though it is.

Rule: an item leaves this list only by becoming an ADR (or an amendment to one) with the
evidence that resolved it. "We just did it that way" is not a resolution.

| ID | Decision | Needed by | Blocked on |
|---|---|---|---|
| OD-1 | Injection/jailbreak model selection | — | **VALIDATED** → [ADR-014](adr/ADR-014-detector-selection.md) |
| OD-2 | spaCy model size for Presidio | Phase 2 | PII benchmark |
| OD-3 | Threshold values per detector | — | **VALIDATED** for `injection.heuristic` (0.85 retained); OPEN for layer 2 |
| OD-4 | Score fusion across detectors | Phase 4+ | Calibration data |
| OD-5 | Benign corpus source | — | **VALIDATED** — oasst1 + dolly, 9,065 samples; enterprise-shaped corpus still OPEN |
| OD-6 | ONNX int8 quantisation | Phase 2 | Accuracy/latency measurement |
| OD-7 | Streaming window size | Phase 6 | TTFT vs detection measurement |
| OD-8 | Circuit breaker for upstream failure | Phase 1 | Retry behaviour under load |
| OD-9 | Kubernetes at all | Phase 7 | Whether anything deploys |
| OD-10 | Worker/thread-pool topology | Phase 4/6 | GIL ceiling measurement |
| OD-11 | Optional cloud-DLP detector | Post-P3 | Demand; privacy review |
| OD-12 | Multi-turn detection approach | Unscheduled | Evidence it is tractable |
| OD-13 | Rule weights are judgement, not measurement | Phase 2/4 | Per-rule evaluation data |
| OD-17 | PII and indirect-injection categories are not evaluable | Phase 4 | A corpus with enough samples |
| OD-19 | Hard-negative FPR makes the classifier undeployable as-is | — | **RESOLVED: WARN/SHADOW now, FINE-TUNING required for blocking** |
| OD-20 | Will fine-tuning fix the quoted-attack failure? | Phase 2 | The experiment in [ADR-015](adr/ADR-015-fine-tuning-strategy.md) |
| OD-21 | Is the synthetic corpus diverse enough to generalise? | Phase 2 | Dev vs hold-out divergence in the same experiment |
| OD-18 | Layer-2 promotion from warn to block | Phase 2 | Shadow-mode FPR on real traffic |
| OD-14 | Custom PII patterns are not validated at startup | Phase 2 | Decide the failure mode |
| OD-15 | Audit writes are synchronous and on the request path | Phase 4/5 | Measured share of overhead |
| OD-16 | Oversized requests (413) produce no audit row | Phase 1 | Where the limit should live |

---

## OD-1 — Which injection/jailbreak model — **RESOLVED**

**Resolved 2026-08-17 by [ADR-014](adr/ADR-014-detector-selection.md)** on measured
evidence: `protectai/deberta-v3-base-prompt-injection-v2` selected as the layer-2
candidate, in `warn` mode, with `injection.heuristic` retained as layer 1. Arch-Guard
was rejected despite better headline recall because it scores ~0.00 on system-prompt
extraction. Four candidates were not measurable (gated or unlicensed) and no number was
estimated for them.

*Original framing, retained for the record:*

## OD-1 (original) — Which injection/jailbreak model

**Question.** DeBERTa-v3-based injection classifier, a Llama-Guard-class safety model, a
smaller distilled classifier, or a fine-tune of our own?

**Why unresolved.** Model cards report performance on the publisher's benchmark, tuned by the
publisher. That number does not transfer to our splits, our thresholds or our latency budget —
and several public corpora are likely in these models' training data, so their published
figures are optimistically biased for exactly the data we would evaluate on.

**Resolution.** Measure the shortlist on our dev split, on the reference machine, with latency
recorded. Criteria: licence (must permit commercial use), size, CPU latency, and measured
delta over the heuristic baseline. Becomes an ADR.

**Fallback.** If nothing beats the heuristic meaningfully, that is the published finding
([19](19-implementation-roadmap.md), Phase 2 gate) — not a reason to ship a model anyway.

---

## OD-2 — spaCy model size for Presidio

**Question.** `en_core_web_sm` (~12 MB), `lg` (~560 MB), or `trf` (~430 MB + torch)?

**Why unresolved.** The recall difference on *our* PII categories is unknown, and the image-size
and latency costs are large enough that guessing is expensive in both directions.

**Resolution.** Run all three on the PII benchmark; report per-entity recall, p95 latency and
image size; default to the smallest model whose recall is adequate for the documented entity
set ([08](08-pii-security.md)).

---

## OD-3 — Threshold values

**Question.** What threshold for each detector?

**Why unresolved.** A threshold without a precision/recall curve is a guess. **Phase 0
deliberately does not tune** — the `0.85` in the sample policy is a placeholder and is labelled
as one.

**Resolution.** Sweep on `dev`, choose from the published curve, report on `test`. The chosen
operating point must state the FPR it accepts, because that is the number an operator lives
with.

---

## OD-4 — Score fusion across detectors

**Question.** Should multiple weak signals combine into one strong one? Currently the engine
takes the most severe action and never fuses.

**Why unresolved.** Scores are not comparable across detectors and not calibrated
([06](06-policy-engine.md)), so any weighting today would be arithmetic on incommensurable
numbers.

**Resolution.** Only if Phase 4 produces per-detector calibration curves. Even then, fusion
adds a decision surface that the truth-table test cannot cover exhaustively — the cost must be
weighed against the measured benefit, not assumed.

---

## OD-5 — Benign corpus source

**Question.** Where does a large, realistic, licensed benign corpus come from?

**Why unresolved.** This is the hardest sourcing problem in the project (R-02). Attack corpora
are easy to find; a benign set that resembles real application traffic and is licensed for
benchmark use is not. Instruction-tuning datasets are the obvious candidate and are not
representative of production LLM traffic.

**Resolution.** Licence review of candidates in [14](14-dataset-strategy.md); if none is
adequate, author a documented benign set and **state the limitation in every report that uses
it** rather than quietly reporting a weak FPR denominator.

---

## OD-6 — ONNX int8 quantisation

**Question.** Quantise the classifier for latency, or keep fp32 for accuracy?

**Resolution.** Measure both on the same split: accuracy delta versus p95 latency delta.
Quantise only if the accuracy cost is negligible against the latency gain, and publish both
numbers.

---

## OD-7 — Streaming window size

**Question.** How many tokens of lookahead before emitting?

**Why unresolved.** It is a direct trade: larger window → better detection, worse TTFT. The
exchange rate is unknown until measured.

**Resolution.** Phase 6 measures detection delta and TTFT cost across window sizes and
publishes the curve, so operators choose their own point rather than inheriting ours
([03](03-request-response-flow.md)).

---

## OD-8 — Circuit breaker for upstream failure

**Question.** Should the gateway trip a breaker when the upstream is failing, or keep retrying
within its bounded policy?

**Why unresolved.** A breaker prevents retry amplification (R-17) and adds a failure mode of
its own — a wrongly-tripped breaker denies service the upstream could have served.

**Resolution.** Decide from Phase 1 retry behaviour under induced upstream failure using the
mock's error triggers. If bounded retries with jitter are sufficient, skip the breaker.

---

## OD-9 — Kubernetes at all

**Question.** Do we write manifests?

**Why unresolved.** Compose is the reference deployment and covers the demonstrable use case.
Manifests that nothing runs are decoration, and manifests are also the most common way a
portfolio project signals inexperience by adding infrastructure it does not need (PM-7).

**Resolution.** Only if there is a real target to deploy to. Otherwise a documented deployment
architecture with the NetworkPolicy requirement stated (T-14) is the more honest artefact.

---

## OD-10 — Worker and thread-pool topology

**Question.** How many uvicorn workers, and how large a detector thread pool per worker?

**Why unresolved.** The interaction between the GIL, model memory (each worker holds its own
copy) and thread-pool contention cannot be reasoned out; it has to be measured
([ADR-001](adr/ADR-001-technology-stack.md)).

**Resolution.** Phase 4 concurrency benchmarks and Phase 6 soak testing produce the
recommendation, with memory-per-worker measured alongside.

---

## OD-11 — Optional cloud-DLP detector

**Question.** Offer Google DLP / AWS Comprehend as an optional PII detector?

**Why unresolved.** Better recall, and it sends every inspected prompt to a third party —
inverting the product's premise. Defensible only for operators who already have that processor
relationship.

**Resolution.** Post-Phase 3, if there is demand. It would ship **off by default**, with an
explicit privacy warning, and never as a default detector
([ADR-005](adr/ADR-005-pii-detection-strategy.md)).

---

## OD-12 — Multi-turn detection

**Question.** How do we detect an attack assembled across several messages, currently out of
scope (T-11)?

**Why unresolved.** It requires conversation state, which the gateway deliberately does not
hold — stateless instances are what make it horizontally scalable (NFR-017). Adding state
changes the deployment model, the privacy posture (conversation history must live somewhere)
and the threat model simultaneously.

**Resolution.** Unscheduled. Any proposal must address all three consequences, not just the
detection question. Until then it is documented as a limitation rather than hinted at as
future work.

---

## OD-13 — Rule weights

**Question.** The baseline detectors combine named rules with a noisy-OR over hand-assigned
weights (0.30 for fictional framing, 0.90 for an explicit instruction override). Those
numbers are engineering judgement about how unambiguous a phrasing is in isolation. They have
never been fitted to data.

**Why unresolved.** Fitting them requires a labelled corpus, which is Phase 4 work. Doing it
sooner would mean fitting to the 31-case smoke fixture — the exact tuning-on-test mistake the
methodology forbids.

**Resolution.** Phase 4 reports per-rule precision on a real corpus. Rules that never fire, or
that fire mostly on benign text, are removed rather than reweighted — a rule that cannot be
justified by data is a liability in a security control.

---

## OD-14 — Custom PII pattern validation

**Question.** Operator-supplied `custom_patterns` are compiled at detector construction. An
invalid regex is currently skipped so one bad pattern cannot take the detector down.

**Why unresolved.** Skipping is the safe runtime behaviour but it is also silent: an operator
who typos a pattern gets no PII detection for that entity and no signal. The alternative —
failing startup, consistent with every other configuration error (NFR-009) — is arguably more
correct but turns a typo into an outage.

**Resolution.** Phase 2: validate custom patterns at policy-load time alongside the other
startup checks, so a bad pattern is a startup failure. Also consider a complexity bound, since
an operator-supplied regex is a ReDoS surface.

---

## OD-15 — Synchronous audit writes

**Question.** The audit write currently happens inside the request path.

**Why unresolved.** ADR-012 already plans a bounded queue and background writer for Phase 5,
but the decision to *accelerate* that should rest on a measurement, not on discomfort. The
`audit_ms` stage timing is recorded on every request precisely so the question can be answered
with data.

**Resolution.** Phase 4 reports `audit_ms` as a share of `gateway_overhead_ms`. If it is
material, the Phase 5 queue moves earlier.

---

## OD-16 — Oversized requests are not audited

**Question.** `BodyLimitMiddleware` rejects an oversized body before the handler runs, so no
`request_trace` row is written. Every other rejection — malformed, unsupported, blocked,
upstream failure — is audited.

**Why unresolved.** The middleware must sit outside the handler to reject a body before
reading it, and the handler is what owns auditing. Fixing it means either moving the limit
into the handler (which defeats the point) or giving the middleware its own audit path
(duplicating the write logic).

**Impact.** A flood of oversized requests is invisible in the audit trail. It is visible in
access logs and would be visible in `firewall_request_bytes` once Prometheus metrics land, so
this is a gap in one signal rather than in all of them.

**Resolution.** Phase 1, when the metrics endpoint exists: either emit a minimal trace from
the middleware, or accept the gap and cover it with a metric. Documented rather than silently
tolerated.

---

## OD-17 — PII and indirect injection are not evaluable

**Question.** The benchmark contains 6 PII samples and 5 indirect-injection samples,
all from the internal hold-out. No public corpus in the registry supplies either.

**Why it matters.** `pii.regex` scored recall 1.0000 on the dev split — from a
single-digit denominator. That number is meaningless and is **not** reported
anywhere as a result. Indirect injection is, per the threat model, the category
that matters most in RAG and agent deployments, and it is exactly the one we
cannot currently measure.

**Resolution.** Phase 4: author a substantial indirect-injection set (public data
is thin), and generate synthetic PII at volume with known spans so entity-level
recall and span accuracy become measurable (docs/08-pii-security.md).

---

## OD-19 — **RESOLVED 2026-08-17: warn/shadow only; fine-tuning required for blocking**

**Resolved by a dev-calibrated, frozen-threshold sweep validated on the independent
hold-out** (`eval/results/20260817T102936Z__threshold-deployability/decision.md`).

Two findings settled it:

1. **Dev FPR does not predict hold-out FPR** — a 5x to 24x gap. The tightest point
   measured 0.28% on public dev and 6.78% on the hold-out.
2. **The threshold cannot fix the failure.** At 0.9995 — effectively maximum
   confidence — the model still fires on 87.5% of incident reports quoting an
   attacker payload and 41.2% of incident-response traffic. These are 0.99+
   predictions, not borderline scores: the failure is representational, not a
   calibration problem.

The security value is nonetheless real (recall 0.3167 → 0.8833; extraction recall
0.2667 → 0.8444), so rejection was also wrong. **Option B now, Option D as the path
to blocking.** Options A, C and E rejected, with reasons recorded in the decision.

*Original framing, retained:*

## OD-19 (original) — The classifier's hard-negative FPR blocks deployment

**Finding.** On 457 independent benign samples the selected classifier
false-positives at **12.0%** overall and **28.8%** on hard negatives, concentrated
in incident response (47%) and security operations (28%). Incident reports that
quote an attacker payload are blocked **93.8%** of the time.

**Why this is decisive.** The organisations most likely to deploy an LLM firewall
are the ones whose staff discuss attacks all day. A detector that cannot separate
*describing* an attack from *performing* one is not deployable in blocking mode at
any threshold visible in the sweep — and raising the threshold to fix FPR trades
away the recall that justified the model in the first place.

**Options, none yet chosen:**

1. **Keep layer 2 in `warn` indefinitely** and use it only as a signal for
   review. Cheap, honest, and gives up the security benefit.
2. **Context-aware gating** — do not run layer 2 on content from trusted roles or
   from tenants tagged as security teams. Reduces exposure without touching the
   model, but is a policy hack rather than a fix.
3. **Fine-tune on hard negatives.** The most likely real fix, and it needs a much
   larger hard-negative corpus than 170 samples, plus a training pipeline the
   project does not have.
4. **Two-stage: classifier proposes, a second check confirms.** Adds latency to
   an already 120 ms layer.
5. **Reject the classifier entirely** and invest in the heuristic layer, whose
   FPR is 2.4% and whose failures are the same category but five times rarer.

**Resolution.** Requires evidence option 3 can work, or a decision to accept 1.
Explicitly *not* resolved by raising the threshold until the FPR looks acceptable —
that is tuning to the hold-out, which this phase exists to prevent.

---

## OD-18 — Promoting layer 2 from warn to block

**Question.** ADR-014 ships the classifier in `warn`. What evidence promotes it?

**Why unresolved.** Its measured FPR on uncontaminated data is **12.0%**
[9.4%, 15.3%] over 457 benign samples — no longer a small-sample artefact, and far
too high to gate on. Production shadow-mode traffic remains the only source of an
FPR estimate on a *realistic* distribution (the hold-out is deliberately weighted
toward hard cases, so its FPR is an upper bound, not a forecast).

**Resolution.** Promotion is now blocked on OD-19's fine-tuning outcome, not on
data volume: the sweep in `eval/results/20260817T102936Z__threshold-deployability/` proves no threshold reaches an
acceptable FPR. Shadow-mode traffic remains necessary but is no longer sufficient.

---

## OD-20 — Will fine-tuning fix the quoted-attack failure?

**Question.** Can domain-specific training reduce `quoted_attack` FPR from 0.875
to ≤ 0.15 without regressing attack recall below 0.80?

**Status.** Protocol pre-registered in
[ADR-015](adr/ADR-015-fine-tuning-strategy.md); corpus built and integrity-checked;
**no training performed**. Success and failure criteria were fixed before any run.

**Resolution.** Strategies A→C in sequence, checkpoint selected on dev, hold-out
scored once per experiment. "Unsuccessful" is an acceptable, publishable outcome.

---

## OD-21 — Is the synthetic corpus diverse enough to generalise?

**Question.** The training corpus is compositional and synthetic (near-duplicate
rate 0.0000, but that measures surface overlap, not structural variety). Will a
model fine-tuned on it generalise to the independently authored hold-out, or fit
the generator?

**Why it cannot be answered now.** Only training answers it. The diagnostic is
pre-registered: **dev improves and hold-out does not** ⇒ the corpus is being
memorised, and the corpus (not the model) is the thing to fix.

**Resolution.** Falls out of the ADR-015 experiment. If it fails this way, the
next step is corpus diversification — more authored frames, and human-written
rather than composed hard negatives — not more epochs.

---

## Assumptions to validate during implementation

Not decisions, but beliefs the plan rests on. Each is cheap to check early and expensive to
discover late.

| # | Assumption | How it gets validated |
|---|---|---|
| A-1 | A base-size transformer classifier runs in acceptable CPU latency | Phase 2 measurement on the reference machine |
| A-2 | Per-character normalisation cost is negligible vs detection cost | Phase 0 micro-benchmark, confirmed in Phase 4 |
| A-3 | Postgres synchronous audit writes are not a material share of overhead | Phase 4 condition C decomposition |
| A-4 | The mock upstream is faithful enough that tests transfer to real providers | Phase 1 opt-in real-provider contract test |
| A-5 | `tool`-role inspection does not cause unacceptable false positives on legitimate RAG content | Phase 4 FPR on a RAG-shaped benign set |
| A-6 | Redaction preserves enough meaning that completions stay useful | Manual review during Phase 3 |
