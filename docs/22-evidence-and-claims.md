# 22 — Evidence Ledger: Claims and Their Proof

Every claim this project may ever make — in the README, in a CV, in an interview — is listed
here with the artefact that must exist first, how that artefact is produced, and where it
lives.

**The rule:** if the artefact does not exist, the claim is not made. Not softened, not
hedged — not made.

Status: **Pending** (no artefact yet) · **Produced** (artefact committed, claim permitted).

Every **detection-quality and performance** row is Pending, because no evaluation and no
benchmark has been run. Several **engineering** rows moved to Produced with the vertical
slice — those are claims about how the system is built, verifiable by running the suite, and
they are the only claims currently permitted.

---

## Detection quality

| Claim | Evidence required | How produced | Status |
|---|---|---|---|
| Injection detection recall | Per-category recall, `n`, split, threshold, Wilson interval | `python -m eval run --split test --frozen` | **Produced** — internal only |
| FPR on benign traffic | FPR over a benign corpus with stated size and source | Same run (9,065 benign samples) | **Produced** — internal only |
| **FPR on independent benign traffic** | FPR over an authored, never-published corpus with a Wilson interval | `python -m scripts.validate_holdout` (457 benign, 170 hard negatives) | **Produced** — the strongest FPR evidence the project has |
| **Hard-negative FPR** | FPR restricted to legitimate text resembling an attack | Same run | **Produced** |
| **No threshold makes the classifier deployable** | Frozen dev-selected sweep evaluated on the hold-out | `python -m scripts.threshold_analysis` | **Produced** — `eval/results/20260817T102936Z__threshold-deployability/decision.md` |
| **Fine-tuning reduces the enterprise FPR problem** | Hold-out FPR before/after, scored once behind a pre-hold-out lock | `python -m scripts.finetune_strategy_a --holdout` | **Produced** — `eval/results/finetune/20260817T122701Z__strategy-a/report.md` |
| **Attack recall is retained after fine-tuning** | Per-category recall with denominators, same 60 in-scope attacks | Same run | **Produced** — 0.8833 → 0.8833; the 7 misses differ by one sample |
| Fine-tuning makes the classifier block-ready | All six ADR-015 criteria met simultaneously | Same run | **NOT produced — the claim is refused.** Four criteria unmet; two of them unachievable at their denominators |
| The fine-tuned model is faster | Like-for-like latency on one device | — | **NOT produced.** The two measurements are CPU vs GPU and are not comparable |
| **The FPR improvement generalises to independent data** | Same metrics on a second, independently authored hold-out sharing no text and using different attack vocabulary | `python -m scripts.evaluate_holdout_v3` | **Produced** — `eval/results/20260817T125002Z__holdout-v3-validation/report.md` |
| **quoted_attack and incident_response FPR meet their bounds** | Wilson interval clearing the bound at an adequate denominator | Same run | **Produced** — 0.0429 [0.0147, 0.1186] n=70; 0.0000 [0.0000, 0.0337] n=110 |
| Blocking readiness | All six ADR-015 criteria met simultaneously | Same run | **NOT produced — the claim is refused.** Both recall criteria fail on the model's merits |
| **Indirect-injection detection is inadequate** | Per-delivery-shape recall with adequate n, benign controls in the same containers | `python -m scripts.evaluate_indirect_v1` | **Produced** — 0.1423 (n=520); no shape reliably detected; `eval/results/20260817T130736Z__indirect-delivery-shape/report.md` |
| **The detector classifies the user's turn, not retrieved content** | Recall split by user framing on identical payloads | Same run | **Produced** — 0.0938 (n=480) planted vs 0.7250 (n=40) user-requested |
| **It fires on system-like markup regardless of content** | Benign controls sharing the attack container | Same run | **Produced** — `system_marker` recall 0.5667 with FPR 0.2000 (5/25 inert samples) |
| The firewall protects RAG applications | Indirect-injection recall meeting a stated bound | — | **NOT produced — the claim is refused and must not be made.** FNR 0.8577 |
| **The firewall can carry and act on content provenance** | Provenance model, gateway assignment and monotone policy overlay, with tests | `pytest -m "unit or security"` | **Produced** — [ADR-017](adr/ADR-017-provenance-aware-detection-context.md) Phases A+B+C; 892 tests pass |
| The firewall uses provenance in production | A calibrated overlay enabled in the shipped policy | — | **NOT produced.** The capability ships **off**; no threshold is calibrated (OD-3) |
| **Provenance-aware detection improves indirect-injection recall** | Paired same-corpus comparison, text held constant, provenance varied, McNemar test | `python -m scripts.evaluate_provenance` | **Produced** — 0.1423 → 0.5365 (n=520, p ≈ 0); `eval/results/provenance/20260817T141551Z__provenance-secondary/report.md` |
| **It improves precision at the same time** | Benign-control FPR under both arms | Same run | **Produced** — 0.0167 → 0.0000, precision 1.0000 |
| **The effect depends on provenance, not on shorter inputs** | Ablations with provenance removed and inverted, same spans | Same run | **Produced** — 0.0000 and 0.0981 against 0.5365 |
| Provenance makes the detector blocking-ready | Indirect recall ≥ 0.80 per ADR-015 | — | **NOT produced — the claim is refused.** 0.5365; 46% still pass |
| The measured 0.5365 is what a deployment would obtain | The untrusted boundary declared by a real integration, not an oracle | — | **NOT produced.** The split used an oracle over the authoring pools; 0.5365 is a **ceiling for a perfectly cooperating integration** (OD-30) |
| **Coverage exists for the three undetected mechanisms** | A frozen training corpus and a disjoint hold-out, with contamination gates | `python -m scripts.datasets.build_mechanism_coverage --check` | **Produced** — `finetune-v2` (4,922) and `mechanisms-v1` (358); [ADR-019](adr/ADR-019-mechanism-coverage-fine-tuning.md) |
| **The three unseen mechanisms are learnable from text** | Per-mechanism recall on a disjoint hold-out, scored once | `python -m scripts.finetune_mechanisms --holdout` | **Produced** — 0.0000 → 0.7333 / 0.7333 / 0.9667; `eval/results/finetune/mechanisms/20260817T164552Z__adr019-strategy-a/report.md` |
| **The corpus did not teach it to block legitimate traffic** | Two benign-control families incl. document-carried | Same run | **Produced** — 0 FP on 178 controls, 0/90 document-carried, precision 1.0000 |
| **Extending the corpus caused catastrophic forgetting** | Rescored baseline on a prior hold-out under pre-registered bounds | Same run | **Produced** — extraction recall 0.8446 → 0.7534 (−0.0912) |
| The ADR-019 model is an improvement overall | All ADR-019 criteria met simultaneously | — | **NOT produced — the claim is refused.** Two regression criteria failed; the run is a FAILURE |
| **The ADR-019 regression is not a threshold artefact** | Recall and FPR moved in opposite directions, so the model is dominated at every operating point | Published aggregates in `holdout_metrics.json` | **Produced** — argument is threshold-free; requires no re-scoring |
| **Extraction's absolute training count never changed** | Per-sub-category counts in both frozen corpora | `eval/results/finetune/ADR-020-protocol/baseline_manifest.json` | **Produced** — 288 samples in v1 and v2; only its share of attack mass moved, 38.92% → 24.20% |
| The cause of the ADR-019 regression is known | An ablation separating composition, adaptation budget, capacity and seed variance | — | **NOT produced — the claim is refused.** Seven candidate causes; one eliminated, six live ([ADR-020](adr/ADR-020-retention-preserving-training.md)) |
| A retention-preserving successor works | ADR-020's retention, mechanism, benign and performance criteria met together | — | **NOT produced.** ADR-020 is a protocol; nothing has been trained |
| **Seed variance has been measured, once** | Three seeds per family scored on a common disjoint corpus | `python -m scripts.validate_proxy --report` | **Produced** — families fully disjoint; permutation p = 0.0500, the floor at 3v3 |
| **The ADR-019 regression is not explained by seed noise** | Between-condition gap exceeding within-condition spread across seeds | Same run | **Produced** — gap 0.0594 vs spread 0.0230 |
| Seed variance is now fully characterised | More than three runs per condition | — | **NOT produced — the claim is refused.** n=3 bounds run-level variance no more tightly than p = 0.0500 |
| **A disjoint public corpus can rank two fine-tunes of the same base** | Reproduction of a known effect on that corpus, by paired test | Same run | **Produced** — Strategy A > ADR-019, McNemar p < 1e-6 |
| **Dev-selected thresholds are arbitrary when dev separates perfectly** | Thresholds chosen under identical methodology across checkpoints | `eval/results/finetune/ADR-020-steps-0-1/metrics.json` | **Produced** — span 0.0694–0.9955 |
| Public-corpus scores are capability | An uncontaminated corpus | — | **NOT produced — the claim is refused.** Used in ADR-014 and plausibly in the base model's pretraining; admissible only to rank fine-tunes of the same base |

| Provenance adds negligible overhead | Baseline vs provenance-aware path, same workload, machine metadata | — | **NOT produced.** No numeric overhead may be quoted before implementation |
| **Dev FPR understates hold-out FPR by 5–24x** | Same run, six operating points | Same | **Produced** |
| Jailbreak detection recall | Reported separately from injection | Same run | **Produced** — internal only |
| The ML classifier beats the baseline by X | Both detectors, same split, same machine | `python -m eval compare` | **Produced** — internal only |
| System-prompt-extraction recall | Per-category recall with a real denominator | Same run (45 authored extraction attacks) | **Produced** |
| PII detection recall | **Per-entity** recall, never a single average | — | **Blocked: only 6 PII samples exist (OD-17)** |
| Indirect injection detection | Its own category row | — | **Blocked: only 5 samples exist (OD-17)** |

**"Internal only" is a real distinction, not hedging.** These results are measured and
committed, and they are not yet publishable as project metrics: the public corpora are
probably contaminated into both classifiers' training data, the uncontaminated hold-out has
32 benign samples, and no result has been reproduced on a second machine. They are good
enough to *decide with* ([ADR-014](adr/ADR-014-detector-selection.md)) and not good enough to
*advertise with*.

**Phrasing that is permitted once produced:** *"Recall 0.NN (95% CI a–b, n=N) on the held-out
test split of `<dataset>`, at threshold T, with FPR 0.NN on N benign samples — report:
`eval/reports/detect-<id>.md`."*

**Phrasing that is never permitted:** "94% accurate", "blocks prompt injection",
"state-of-the-art detection".

**Permitted for the fine-tuning result:** *"Standard supervised fine-tuning reduced
hard-negative false positives from 17.1% to 1.2% (n=170, Wilson 95% [0.3%, 4.2%]) on
an independently authored hold-out, with attack recall unchanged at 0.8833 (n=60).
Pre-registered blocking criteria were not met; the model remains in warn mode."*

**Never permitted:** "fine-tuning fixed the false-positive problem", "the model is now
production-ready for blocking", "93% improvement" without its denominator and interval,
or any latency comparison between the CPU and GPU measurements.

**Permitted for the v3 validation:** *"On a second, independently authored hold-out
(n=792) sharing no text with the first and using deliberately different attack
vocabulary, false positives on security-domain traffic met all four pre-registered
bounds — quoted_attack 4.3% (n=70, 95% CI [1.5%, 11.9%]), incident_response 0.0%
(n=110, [0.0%, 3.4%]). Attack recall did not meet its bound and the model remains in
warn mode."*

**Never permitted:** "validated for blocking", "the model generalises" without naming
which half (FPR generalised; recall failed), any indirect-injection recall figure from
either hold-out version, or an aggregate attack-recall comparison between v2 and v3 —
their attack mixes differ by construction.

**Permitted for the indirect-injection result:** *"On a dedicated 820-sample corpus
crossing twelve delivery shapes with eight attack mechanisms, the fine-tuned detector
recalled 14.2% of indirect injections (n=520, 95% CI [11.5%, 17.5%]). No delivery shape
was reliably detected and six recorded zero detections. The detector is not deployed in
blocking mode."*

**Never permitted:** any statement implying the firewall defends against indirect
injection or protects retrieval-augmented applications; quoting the aggregate 0.1423
without noting that six shapes are at zero; quoting `complicit_directive` recall
(0.7250) as an indirect-injection capability — it is a contrast condition measuring the
opposite thing.

**Permitted for ADR-017:** *"The architecture for provenance-aware detection is
designed and documented ([ADR-017](adr/ADR-017-provenance-aware-detection-context.md)),
including the trust model, normalisation compatibility, detector-compatibility
semantics and a migration plan. It is not implemented."*

**Permitted for the Phase D result:** *"On a paired comparison over 820 samples with
the model, weights and threshold held fixed, declaring which span was untrusted raised
indirect-injection recall from 14.2% to 53.7% (n=520, McNemar exact p < 0.001) while
benign-control false positives fell from 1.7% to 0.0%. The detector is not deployed in
blocking mode: 46% of indirect injections are still missed, and the measurement used
oracle segmentation, so it is a ceiling for a perfectly cooperating integration."*

**Permitted for ADR-019:** *"A pre-registered corpus extension took three previously
undetected attack mechanisms from 0% to 73%, 73% and 97% recall (n=60 each) with zero
false positives on 178 controls. The run was recorded as a FAILURE because
system-prompt-extraction recall regressed 9.1 points on a prior hold-out, outside the
bound fixed before training. The model is not deployed."*

**Never permitted for ADR-019:** quoting the mechanism recalls without the regression;
describing the run as a success; claiming the model is better than Strategy A; or
citing `safety_bypass` at 0.9667 without noting that 29 of 34 residual misses sit just
below a conservative frozen threshold, which is diagnostic and was excluded from the
decision.

**Permitted for ADR-020:** *"The regression was diagnosed from existing artefacts
without further training: it is a genuine loss of discrimination rather than a
threshold artefact, because recall fell while false positives rose. Seven candidate
causes were identified and one eliminated. A successor protocol is pre-registered and
has not been run."*

**Never permitted for ADR-020:** describing any cause as established — the ablation
that would separate them has not been run; quoting any number from the public proxy
corpora as capability; calling the layered detector a decision when it is an open
question (OD-34); or implying that ADR-019's regression is known to reproduce across
seeds, which is exactly what Step 1 exists to find out.

**Never permitted:** describing the firewall as provenance-aware, RAG-aware or
context-aware **in production** — the capability ships off; quoting 53.7% without both
the "46% still pass" and the oracle caveat; attributing the recall gain to the trust
*labels* (segmentation carries most of it, and arm A3 is the evidence); quoting
`complicit_directive` figures as indirect-injection performance; or presenting the
policy-ablation numbers as a detector result.

---

## Performance

| Claim | Evidence required | How produced | Stored at | Status |
|---|---|---|---|---|
| Gateway overhead of X ms p50 / Y ms p99 | Conditions A–D, warm-up, `n` ≥ 1000, machine metadata, concurrency level stated | `eval/runners/benchmark.py` | `eval/reports/bench-<run_id>.md` | Pending |
| Detection adds X ms | Condition C − B, per-detector histogram | Same | Same | Pending |
| Per-detector latency of X ms | Condition D | Same | Same | Pending |
| Sustained throughput of X req/s | Throughput **with error rate**, at a stated concurrency | Same | Same | Pending |
| Overhead is negligible relative to model latency | Both `MOCK_LATENCY_MS=0` and a realistic value | Same | Same | Pending |

Every performance claim must carry its conditions. *"XX ms overhead"* alone is not a claim,
it is a rumour — see [15-performance-benchmarking.md](15-performance-benchmarking.md) for the
definition of overhead and the required metadata block.

---

## Engineering

| Claim | Evidence required | How produced | Stored at | Status |
|---|---|---|---|---|
| OpenAI-compatible gateway | An unmodified OpenAI SDK client works end to end | `tests/integration/test_end_to_end.py` covers the request/response shape; the SDK test itself is Phase 1 | Test suite | **Partial** |
| Pluggable detector architecture | A detector added with one registry line and no changes elsewhere | Demonstrated: three stubs were replaced by real detectors with no caller changes | `tests/unit/test_layer_boundaries.py`, git history | **Produced** |
| Policy engine independent of detectors | Import-boundary test; truth table runs with no models loaded | `tests/unit/test_layer_boundaries.py`, `tests/unit/test_policy_engine.py` | Test suite | **Produced** |
| Fail-closed detector semantics | Timeout and exception both produce `503` + `detector_failure`, upstream not called | `tests/security/test_slice_invariants.py` | Test suite | **Produced** |
| Prompts never logged | Canary absent from every log record, driven through the full request path | `tests/security/test_log_leakage.py`, `test_slice_invariants.py` | Test suite | **Produced** |
| Evasion resistance | One test per evasion class, same verdict as the plain form | `tests/unit/test_normalize.py`, `tests/unit/test_baseline_detectors.py` | Test suite | **Produced** |
| Auditable security decisions | Blocked request persists trace + detector results + event with `policy_version`; verified in PostgreSQL | `tests/security/test_slice_invariants.py`, manual psql verification | Test suite | **Produced** |
| Runs with one command, no credentials | `docker compose up` → three healthy services, benign request returns a completion | `tests/integration/` | Test suite | **Produced** |
| CI enforces lint, types, tests, security scanning | Green pipeline with all jobs blocking | `.github/workflows/ci.yml` | CI history | Pending (not yet run on a remote) |

---

### Evaluation-methodology claims

| Claim | Evidence | Status |
|---|---|---|
| Thresholds are never tuned on the test split | `require_tunable` raises below the CLI; verified by test and by a refused command | **Produced** |
| Splits are deterministic and leak-free | Content-derived keys; integrity check reports 0 leaks and 0 duplicates on 11,009 samples | **Produced** |
| Dataset licences are verified, not assumed | Registry records the licence, gating and verification date read from the HF API; the loader refuses non-commercial sources | **Produced** |
| Metrics are correct | Verified against hand-computed matrices and against scikit-learn | **Produced** |
| Every result is reproducible | Reports refuse to write without commit, dataset checksum and machine metadata | **Produced** |
| Candidates are compared like-for-like | Identical data, splits, preprocessing and machine; unmeasurable candidates recorded as unmeasured, never estimated | **Produced** |

### Additional engineering claims produced by the vertical slice

| Claim | Evidence required | How produced | Status |
|---|---|---|---|
| A blocked prompt never reaches the model | Upstream **call counter** at zero for every blocked request — asserted in-process and across a real network boundary, not inferred from a 403 | `tests/security/test_slice_invariants.py`, `tests/integration/test_end_to_end.py` | **Produced** |
| PII is redacted before it leaves the gateway, in both directions | Forwarded payload and returned body both checked for the value | `tests/api/test_chat_completions.py`, `tests/integration/test_end_to_end.py` | **Produced** |
| The audit trail cannot hold prompt content | Schema asserted against a forbidden-substring list and a reviewed allowlist of free-text columns | `tests/security/test_audit_privacy.py` | **Produced** |
| Gateway overhead is measurable separately from model latency | Per-stage timings recorded per request and exposed as headers | `tests/integration/test_end_to_end.py`, `app/observability/timing.py` | **Produced** (the mechanism; **no figure is claimed**) |
| Detection quality of the baseline heuristics | — | — | **Not claimed. Unmeasured.** |

### Fine-tuning claims — none yet permitted

| Claim | Evidence required | Status |
|---|---|---|
| Fine-tuning reduces enterprise false positives | Hold-out evaluation at a dev-frozen checkpoint against the pre-registered criteria in ADR-015 | **Not claimed — no training performed** |
| The training corpus is uncontaminated | Build-time abort, pinned hold-out hash, 4 CI tests | **Produced** |
| The corpus is not near-duplicate slop | Jaccard ≥ 0.90 rate of 0.0000 against a 0.02 ceiling | **Produced** |
| The corpus forces context learning | Same 22 attack phrases on both label sides, asserted by test | **Produced** |

## Claims that will never be made

Regardless of what any artefact shows:

* "Prevents prompt injection" — no system does. The permitted form is a measured detection
  rate with its residual, on a named dataset.
* Any regulatory compliance status (GDPR, HIPAA, SOC 2, PCI-DSS, EU AI Act).
* "Production-ready" — until something is actually in production, and then it is a fact about
  a deployment, not a property of the repository.
* "Enterprise-grade", "military-grade", "state-of-the-art".
* Complete PII detection in any language.
* Any figure carried over from a model card or a third-party leaderboard as though it
  described this system.
* Performance extrapolated from the laptop-class reference machine to production capacity.

---

## Interview defence map

For each likely question, where the answer is written down. If a row cannot be answered from
the repository, that is a gap in the repository, not in the preparation.

| Likely question | Answer lives in |
|---|---|
| Why FastAPI/Python and not Go? | [ADR-001](adr/ADR-001-technology-stack.md) — and the GIL cost is named, not hidden |
| Why not build on LiteLLM? | [ADR-001](adr/ADR-001-technology-stack.md) |
| How do detectors plug in? | [05](05-detector-architecture.md), [ADR-002](adr/ADR-002-detector-plugin-architecture.md) |
| Two detectors disagree — what happens? | [06](06-policy-engine.md), "Conflict resolution" |
| Why not weighted score fusion? | [06](06-policy-engine.md), [21](21-open-decisions.md) OD-4 |
| What happens when a detector times out? | [ADR-007](adr/ADR-007-detector-failure-semantics.md) — including the availability cost accepted |
| Isn't fail-closed dangerous? | [ADR-007](adr/ADR-007-detector-failure-semantics.md), PM-9 in [20](20-risk-register.md) |
| Why no streaming? | [07](07-openai-compatible-api.md), [03](03-request-response-flow.md) — three strategies and their real costs |
| How is overhead measured? | [15](15-performance-benchmarking.md) — definition, four conditions, required metadata |
| Why does a mock upstream exist? | [ADR-009](adr/ADR-009-mock-upstream.md) — it is what makes the benchmark valid |
| How do you avoid tuning on test? | [13](13-evaluation-strategy.md) — content-derived splits |
| What's your false-positive rate? | The FPR row above — reported with its denominator, or "not yet measured" |
| How do you stop the firewall leaking prompts? | [10](10-security-model.md) — sink-level redaction, schema constraint, canary test |
| What does this NOT protect against? | [09](09-threat-model.md) — the scope table, including multi-turn and adaptive evasion |
| Why Presidio and not a cloud DLP API? | [ADR-005](adr/ADR-005-pii-detection-strategy.md), [21](21-open-decisions.md) OD-11 |
| Why OTel instead of the Langfuse SDK? | [ADR-008](adr/ADR-008-observability-and-privacy.md) — and why Langfuse's headline features are unusable here |
| Why is there no prompt in the audit trail? | [ADR-012](adr/ADR-012-persistence-and-retention.md) — with the investigation cost accepted |
| What would you do differently at scale? | [ADR-001](adr/ADR-001-technology-stack.md) revisit triggers, [21](21-open-decisions.md) OD-10 |
| What's the weakest part? | [20](20-risk-register.md) — the pre-mortem is the answer, and it is written down |

The last row matters most. A candidate who has written their own pre-mortem can answer
"what's weak about this" with specifics instead of modesty.

---

## Maintenance

* A row moves to **Produced** only when the artefact is committed and its path is filled in.
* If an artefact is regenerated, the claim is re-checked against the new numbers — including
  downward.
* Any README or CV text making a claim not in this table is a defect.
