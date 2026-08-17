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
