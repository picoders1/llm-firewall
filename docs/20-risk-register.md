# 20 — Risk Register and Pre-Mortem

## Pre-mortem

**Premise, taken seriously:** it is six months from now. The project failed technically *and*
failed to impress an experienced AI/GenAI interviewer. What went wrong?

Below are the causes ranked by how likely they are to be the actual cause, with the
mitigation now embedded in the design. Where a mitigation changed the architecture, the change
is named.

---

### PM-1 — "The evaluation is theatre." *(highest risk)*

**How it fails.** The repository has an `eval/` directory. It contains a script that ran once
on 200 samples, half of them written by the author, with thresholds tuned on the same data it
reports. The README says "94% recall". The interviewer asks: *what was the false-positive rate
on benign traffic, and how large was the benign set?* There is no answer.

**Why it is the top risk.** It is the failure mode of nearly every project in this category,
and it is invisible to the author — the numbers look great precisely because the methodology
is broken.

**Mitigations now in the design**
* Tune on `dev`, report on `test`; splits are content-derived (`sha256(sample_id) % 100`) so
  they cannot drift or be gamed ([13](13-evaluation-strategy.md)).
* FPR on a large benign corpus is the **headline** metric, not recall.
* Baselines mandatory: always-benign, always-attack, and the Phase 0 heuristic as the control.
* `n` printed next to every metric; Wilson intervals on the headline figures.
* The harness **refuses to emit a report** without dataset checksum, git commit and machine
  metadata.
* Validity threats printed in every report — including that public corpora are likely
  contaminated into published models' training data.
* Negative results published; Phase 2 does not pass by shipping a model that lost to the
  baseline ([19](19-implementation-roadmap.md)).

**Residual.** Sourcing a genuinely representative benign corpus is hard; if we fail, the FPR
denominator is weak and we say so rather than hiding it.

---

### PM-2 — "The security is a regex list wearing a lab coat."

**How it fails.** The detector is 40 patterns. It catches `ignore previous instructions` and
nothing an attacker would actually send. The interviewer types `ıgnore previous instructions`
and it passes.

**Mitigations**
* Index-preserving normalisation as a **first-class component**, defeating zero-width,
  confusable, fullwidth, case and whitespace evasion for *every* detector at once, with a test
  per evasion class ([ADR-010](adr/ADR-010-normalization-strategy.md)).
* Base64 payload surfacing so hidden instructions are inspected by content.
* The heuristic detector is **named a baseline** in its docstring, its metadata, and every
  document — and its explicit purpose is to be beaten by Phase 2 and measured against.
* Layered architecture where the cheap layer may short-circuit to BLOCK but **never to ALLOW**
  — so a heuristic miss cannot suppress the classifier.

**Residual.** T-04 lists what normalisation does *not* cover (rot13, custom ciphers,
token-splitting, image-embedded text). Named, not implied away.

---

### PM-3 — "It's a FastAPI tutorial with a `detect()` function."

**How it fails.** Everything lives in one route handler. There is one detector, one threshold
constant, and the "policy engine" is an `if`. Nothing about it is a *system*.

**Mitigations (these shaped the architecture)**
* Detector protocol + registry + `GuardedDetector`; `Action` is not importable in
  `app/detectors/` and the constraint is enforced by test
  ([ADR-002](adr/ADR-002-detector-plugin-architecture.md)).
* Policy engine is a **pure function** with no I/O, no clock, no logging — which is what makes
  the entire security decision surface an exhaustive truth table
  ([06](06-policy-engine.md)).
* Layering rules with an explicit dependency table, enforced by import tests
  ([02](02-system-architecture.md)).
* `SyncDetectorAdapter` exists in Phase 0 — *before* the first blocking model — because
  retrofitting it means retrofitting after the first production incident.

---

### PM-4 — "It leaks the prompts it exists to protect."

**How it fails.** `logger.info("blocked", prompt=text)` during debugging. Or Langfuse wired in
with default prompt capture. Or a `prompt` column added "temporarily". The security tool is
now the largest sensitive-data store in the architecture.

**Mitigations**
* Redaction is a **structlog processor at the sink**, so a future contributor's debug line is
  harmless by construction — not a rule people must remember
  ([10](10-security-model.md)).
* `content_logging=full` is **downgraded to `hash` in production, in code**.
* **No audit column can hold prompt content**; adding one requires a visible migration
  ([ADR-012](adr/ADR-012-persistence-and-retention.md)).
* OTel-first rather than the Langfuse SDK, spans content-free, tracing **off by default**
  ([ADR-008](adr/ADR-008-observability-and-privacy.md)).
* A canary test asserts a known prompt string appears in **no** log record, and it blocks CI.

---

### PM-5 — "The latency claim doesn't survive one question."

**How it fails.** README says "<60 ms overhead". *Measured how?* Against what baseline? On
what machine? Through a real model whose variance is 100× the effect? Warm-up? p99? The claim
evaporates.

**Mitigations**
* Overhead **defined**: `total − measured_upstream`, recorded per request in production, not
  only in a rig ([15](15-performance-benchmarking.md)).
* Four benchmark conditions (A–D) isolating proxy cost from detection cost.
* The **mock upstream with fixed configurable latency** exists largely so this measurement is
  valid at all ([ADR-009](adr/ADR-009-mock-upstream.md)).
* Warm-up mandatory, p99 and max mandatory, `n` mandatory, machine metadata mandatory,
  concurrency levels never averaged together.
* The reference machine is a laptop and the docs say its figures characterise **relative
  overhead**, never production capacity.

---

### PM-6 — "It claims things it hasn't earned."

**How it fails.** "Production-ready", "enterprise-grade", "GDPR compliant", "prevents prompt
injection". One follow-up question and the credibility of everything else goes with it.

**Mitigations**
* Standing rule in [README.md](README.md): no unverified metric, no unearned claim.
* [00](00-project-overview.md) and [09](09-threat-model.md) both carry explicit **non-claims**
  sections — including that the system does *not* prevent prompt injection.
* Every threat carries an honest status: Protected / Partial / Out of scope / Planned.
* [22-evidence-and-claims.md](22-evidence-and-claims.md) ties every future claim to the
  artefact that must exist before it may be made.

---

### PM-7 — "Overengineered."

**How it fails.** Four microservices, a plugin discovery system, a rules DSL, Kubernetes on day
one, a message bus — for a service handling no traffic. The interviewer reads it as
inexperience, not sophistication.

**Mitigations**
* Explicitly rejected in ADRs, each with a revisit trigger: entry-point plugin discovery
  ([ADR-002](adr/ADR-002-detector-plugin-architecture.md)), OPA/Rego DSL
  ([ADR-003](adr/ADR-003-policy-engine-design.md)), Kafka
  ([ADR-012](adr/ADR-012-persistence-and-retention.md)), microservices
  ([ADR-001](adr/ADR-001-technology-stack.md)).
* Twelve runtime dependencies; heavy stacks behind extras.
* Kubernetes is Phase 7 **and conditional**; Compose is the reference deployment.
* Directories exist only when they have content.

---

### PM-8 — "Slow enough that nobody would deploy it."

**How it fails.** A transformer detector runs synchronously on the event loop. Under
concurrency the gateway adds seconds. Nobody would put it in front of production.

**Mitigations**
* `SyncDetectorAdapter` with a **bounded** semaphore — unbounded thread offload turns a 20 ms
  model into a 2 s one via CPU oversubscription.
* Detectors run concurrently: stage cost is `max`, not `sum`.
* ONNX (not torch) for inference; per-detector timeouts bound the worst case.
* Model warm-up at startup, gated by `/ready`.
* Phase 4 measures it before Phase 6 optimises anything.

---

### PM-9 — "Fail-closed took production down."

**How it fails.** A detector bug blocks 100% of traffic. The mitigation for a security risk
became an availability incident.

**This is a real accepted cost, not a solved problem** ([ADR-007](adr/ADR-007-detector-failure-semantics.md)).

**Mitigations**
* Per-detector timeouts bound the failure.
* `/ready` fails on warm-up failure, so a broken instance leaves the load balancer rather than
  blocking every request it receives.
* `firewall_detector_errors_total` is an alerting metric — the response is *fix the detector*,
  not survive it.
* `503` not `403`, so client retry logic can distinguish outage from block.
* `fail_open` is available per detector, visible in config, and named in a startup warning.

**Residual.** Under sustained load, detector timeouts could cascade into broad blocking.
Belongs in the Phase 5 runbook and is measured in Phase 6 soak testing.

---

### PM-10 — "Vendor-coupled."

**How it fails.** Built on one provider's SDK and one observability vendor. Portability is a
rewrite; the interviewer asks how it would run against internal vLLM and the answer is "it
wouldn't".

**Mitigations**
* OpenAI-compatible HTTP contract, upstream swappable by env var
  ([ADR-004](adr/ADR-004-openai-compatible-contract.md)).
* OTel API rather than a vendor SDK; Langfuse is one exporter among several
  ([ADR-008](adr/ADR-008-observability-and-privacy.md)).
* No provider SDK on the request path — plain `httpx`.

---

### PM-11 — "Untested where it matters."

**How it fails.** 85% coverage, all of it on serialisation helpers. The block path, the
fail-closed path and the redaction offsets have no tests.

**Mitigations**
* A dedicated `tests/security/` suite with an enumerated, non-negotiable contents list
  ([16](16-testing-strategy.md)).
* The policy truth table covers every threshold/action/error combination.
* Every FR and NFR in [01-requirements.md](01-requirements.md) **names its test**, and the name
  must resolve.
* Coverage treated as a smoke detector, not a goal.

---

### PM-12 — "The documentation contradicts the code."

**How it fails.** Docs describe an architecture the code abandoned three weeks in. Worse than
no docs, because now the author cannot be trusted about anything.

**Mitigations**
* Every ADR has a **Verification** section naming how a reader checks the code matches it.
* Layer boundaries are enforced by import tests, not by prose.
* Documentation-consistency rules in [README.md](README.md); ADRs are superseded, never
  silently edited.
* [21-open-decisions.md](21-open-decisions.md) exists so unresolved items are visibly
  unresolved rather than quietly wrong.

---

## Risk register

Likelihood × Impact, both High / Medium / Low. **Owner** is the phase that must have
addressed it.

| ID | Risk | L | I | Mitigation | Owner |
|---|---|---|---|---|---|
| R-01 | Evaluation methodology not credible | M | **H** | PM-1 controls; harness refuses unstamped reports | P0/P4 |
| R-02 | No licensed benign corpus of adequate size | L | **H** | **Closed for the hold-out**: 457 authored benign samples, 0 contamination. Public benign denominator is 9,065. Enterprise-representative production traffic still absent | P4 |
| R-03 | Public benchmark contamination inflates Phase 2 results | **H** | M | Hold-out hand-authored set; stated validity threat | P2/P4 |
| R-04 | Detection quality genuinely poor | M | **H** | Publish it; layered design lets layer 2 be replaced | P2 |
| R-05 | Prompt content leaks into logs/DB/traces | L | **H** | Sink-level redaction, schema constraint, canary test | P0 |
| R-06 | Fail-closed causes an availability incident | M | **H** | Timeouts, `/ready` gating, alerting, `503`, per-detector override | P0/P5 |
| R-07 | Gateway overhead unacceptably high | M | M | Measure in P4 before optimising; ONNX; concurrency | P4 |
| R-08 | Streaming absence blocks real adoption | **H** | M | Documented refusal + committed P6 design with measured cost | P6 |
| R-09 | Scope creep / never finishing | **H** | M | Phase gates with acceptance criteria; stubs stay stubs | all |
| R-10 | Over-engineering | M | M | ADR-recorded rejections with revisit triggers | all |
| R-11 | Dataset licensing violation | L | **H** | Registry with verified licence; nothing committed; drops recorded | P4 |
| R-12 | Model licence or weights integrity issue | L | M | Digest pinning, `safetensors` only, checksum verification | P2 |
| R-13 | Docs drift from implementation | M | M | ADR Verification sections; import tests; open-decisions log | all |
| R-14 | 4 GB VRAM insufficient for the chosen model | **H** | L | **Materialised during Strategy A training**: default AdamW OOM'd all 18 runs. Resolved with fused AdamW + 4x4 gradient accumulation, proven equivalent to batch 16 (`scripts/verify_accumulation.py`). Inference is unaffected (0.767 GB peak) | P2 |
| R-15 | Presidio dependency weight (spaCy, ~600 MB) | M | L | Optional extra; `sm` default; size/recall trade measured | P2 |
| R-16 | Audit loss during a database outage | M | L | Documented default; `require_audit` flag; failure metric | P0/P5 |
| R-17 | Retry amplification during upstream failure | L | M | Bounded attempts, jitter; blocked requests never retried | P1 |
| R-18 | Rate limiting absent before P6 | M | M | README states: deploy behind a rate-limiting ingress | P6 |
| R-19 | False-positive compounding across detectors | M | M | `WARN` shadow mode; per-detector FPR measured; system FPR reported | P4 |
| R-21 | **The selected classifier is undeployable on security-domain traffic** | **H** | **H** | **Substantially mitigated, not closed**: Strategy A fine-tuning cut quoted-attack FPR 0.875 → 0.0625 and hard-negative FPR 0.1706 → 0.0118 with recall unchanged. Blocking stays closed — attack recall 53/60 against 55/60 required ([ADR-015](adr/ADR-015-fine-tuning-strategy.md)) | P2 |
| R-24 | **A pre-registered criterion is unsatisfiable at its denominator** | **H** | M | **Materialised, then closed**: hold-out v3 sized from an explicit calculation; both criteria now met with power. Sizing rules recorded in docs/13 (OD-22 resolved) | P2/P4 |
| R-25 | Fine-tuning degrades calibration on traffic unlike the corpus | L | M | **Not reproduced**: 0 FP across 166 ordinary/short-form v3 samples. Downgraded, kept open at low priority (OD-24) | P2/P4 |
| R-27 | **Indirect injection is largely undetected** | **H → M** | **H** | **Materially reduced but not closed.** Provenance-aware split scoring raises recall 0.1423 → **0.5365** with FPR → 0.0000; the six zero-recall shapes now score 0.47–0.58 ([ADR-018](adr/ADR-018-provenance-aware-detector-evaluation.md)). **46% still pass**, so blocking stays refused. Residual failure is now mechanism-specific, not delivery-specific | P2/P4 |
| R-29 | **A detector that fails silently creates false assurance** | M | **H** | **Materialised**: indirect FPR is 0.0167 and direct-attack recall is good, so a blocking gateway would look healthy while ~86% of indirect injections passed. Recorded in [ADR-016](adr/ADR-016-provenance-aware-detection.md) as the decisive argument against promotion | P2/P5 |
| R-30 | **Detector keys on syntax rather than intent** | M | M | **Materialised**: `system_marker` shows recall 0.5667 *and* FPR 0.2000 — it fires on `<|im_start|>system` regardless of content. Only detectable because benign controls share the attack containers | P2/P4 |
| R-31 | **Spoofed provenance is believed** | M | **H** | Design-level: inline claims ignored unless the channel is configured-trusted; claims may lower trust, never raise it; loosening rejected at policy load ([ADR-017](adr/ADR-017-provenance-aware-detection-context.md)) | P2 |
| R-32 | **Source classification is simply wrong** — integration mislabels a retrieved document as user input | **H** | M | Cannot be prevented by the gateway: the application is the only component that knows. Mitigated by direction — a mislabel can only *lose* tightening, never gain trust. Argues for connector-level assignment over application-level | P2 |
| R-33 | **Provenance lost during a transformation** | M | M | Attaches to the whole message part, so there is no per-span map to desynchronise; `DetectionContext` is already `frozen=True`. Test: provenance survives normalisation with the offset invariant intact | P2 |
| R-34 | **Mixed-provenance flattening raises false positives** | **H** | L | Accepted and documented: a flattened part degrades to the lowest trust of its constituents, so the user's instruction inherits the document's treatment. Fail-safe direction chosen deliberately; cost is real and will be visible in FPR | P2/P4 |
| R-35 | **Provenance-aware detector ignores provenance in practice** | L | M | **Closed by measurement**: the M2 (removed) and M4 (inverted) ablations use the same spans and score 0.0000 and 0.0981 against A2's 0.5365, so the effect provably depends on the labels ([ADR-018](adr/ADR-018-provenance-aware-detector-evaluation.md)) | P2/P4 |
| R-36 | **Policy trusts provenance too much** | M | **H** | Structural: provenance may only tighten, and a loosening overlay fails at config load rather than at request time. The tempting relaxation ("relax for authenticated users") is exactly the forgeable one and is unexpressible | P2 |
| R-37 | **Provenance metadata leaks source detail** | L | M | `source_ref` validated to reject URLs, paths and >64 chars; caller strings barred from metric labels; source content never recorded ([10](10-security-model.md)) | P2/P5 |
| R-38 | **Backward-compatibility regression** — existing requests change behaviour | M | **H** | `UNKNOWN` tightens nothing, so missing provenance reproduces current decisions. Guarded by a golden-file test comparing decisions before and after | P2 |
| R-39 | **Provenance plumbing adds latency for no measured benefit** | M | L | Four enum/string fields on a frozen model and one extra policy argument; no model call added. Overhead to be measured (baseline vs provenance-aware path, same workload) before any claim — no figure asserted now | P4 |
| R-40 | **Three attack mechanisms are undetectable at any provenance** | **H → L** | **H** | **Closed as a learnability question**: ADR-019 took all three from 0.0000 to 0.7333/0.7333/0.9667 with zero false positives. The mechanisms are learnable; the run failed on retention instead (R-46) | P2 |
| R-41 | **Provenance depends on a cooperating integration** | M | **H** | The Phase D result used oracle segmentation from the authoring pools; a real gateway learns the boundary from the integration. The measured 0.5365 is a **ceiling for a perfect integration**, not a deployment forecast. Mislabelling degrades toward the 0.1423 baseline (R-32) | P2/P5 |
| R-42 | A pre-registered criterion accepts a degradation | M | M | **Materialised in ADR-018 criterion 3**, which read "significant on recall or FPR" without stating direction. Verdict unchanged; rule added to docs/13 that every comparative criterion must state its direction | P4 |
| R-43 | **Training on tool-use attacks blocks legitimate agent traffic** | **L** | **H** | **Did not materialise.** ADR-019 measured **0 false positives on 178 controls**, including 0/90 document-carried. The contrastive corpus design held; precision 1.0000 | P2 |
| R-44 | **A corpus shortcut makes a model look good and behave badly** | M | **H** | **Materialised and closed during authoring**: every attack in a document carrier and every negative a direct request made the carrier a perfect label predictor. A model could have scored 100% by detecting the wrapper, then flagged all retrieved content. Fixed with document-carried legitimate content; asserted in CI | P2/P4 |
| R-45 | **A new corpus version leaks the prior version's training data into its dev split** | M | **H** | **Materialised and closed**: a split rule differing from v1 by one digest slice moved v1 samples between splits. Caught by a round-trip test before any training; artefacts rebuilt | P2 |
| R-46 | **Catastrophic forgetting when extending the training corpus** | **CONFIRMED** | **H** | **Materialised in ADR-019**: adding 450 attacks in three new relations cost 9.1 points of system-prompt-extraction recall (0.8446 → 0.7534) and 5.3 of attack recall — the capability ADR-014 chose this base model for. Caught only because regression criteria were pre-registered with numeric bounds (OD-32) | P2 |
| R-47 | An experiment succeeds at its objective and ships a net regression | M | **H** | **Prevented in ADR-019** by criteria 4–5 and a rescored baseline. Any corpus-extension experiment must measure prior capability against a rescored baseline under bounds fixed in advance (docs/13) | P2/P4 |
| R-28 | A small category reports a flattering rate that later reverses | **H** | M | Indirect injection moved 1.00 -> 0.40 on a bigger denominator with no model change. Single-digit denominators are now reported as "not evaluated" rather than as a rate | P4 |
| R-26 | A saturated dev split silently stops selecting | **CONFIRMED** | **H** | **Materialised twice, and now blocking.** All 18 Strategy A runs tied on v1 dev; on the *expanded* v2 dev the ADR-019 winner scores perfectly on all nine attack categories and 0/798 benign, so more data did not fix it. Nothing can rank checkpoints, and the dev-selected threshold is underdetermined (OD-23 → OD-33) | P2 |
| R-23 | Public-corpus FPR understates real FPR by 5–24x | **H** | M | Measured across six frozen operating points. Thresholds may never be set from public data alone | P2 |
| R-24 | Fine-tuning corpus is synthetic; model may fit the generator | **H** | M | Near-duplicate rate 0.0000; independently authored hold-out is the check; dev/hold-out divergence pre-registered as the failure diagnostic (OD-21) | P2 |
| R-25 | Training could contaminate the frozen hold-out, voiding all evaluation | L | **H** | Build aborts on collision; content hash pinned in CI; separate directory trees; four boundary tests | P2 |
| R-22 | Hold-out authored by one person encodes one view of enterprise traffic | M | M | Stated in docs/14; production shadow-mode data is the corrective | P2 |
| R-20 | Truth-table test becomes unmaintainable | L | L | Parametrised over the matrix, not enumerated | P0 |
| R-53 | **A dev-selected threshold is arbitrary when the dev split separates perfectly** | **CONFIRMED** | **H** | Six checkpoints, identical methodology, thresholds spanning **0.0694–0.9955**; one seed chose 0.0694 where its sibling chose 0.9954. Every historical threshold in this project was selected this way. Mitigated for comparisons by the matched-FPR analysis (docs/13); the underlying need for a non-saturating dev split is unresolved (OD-23, OD-33) | P2 |
| R-48 | **Seed variance was never measured, so a condition effect may be a run effect** | **M → L** | **H** | **Measured 2026-08-17 with no training.** Three seeds per family on the proxy: the two are fully disjoint (every Strategy A run beats every ADR-019 run), gap 0.0594 against a largest within-family spread of 0.0230. Exact permutation p = 0.0500 — the *floor* at 3v3, so suggestive rather than decisive. ADR-019's verdict stands; run-level variance is now bounded, not eliminated | P2 |
| R-49 | **A replay mixture starves the capability it was built to add** | M | M | The 90/10 mixture roughly halves mechanism exposure (~389 vs ~875 samples/epoch). Registered as ADR-020's central risk; the unweakened Wilson bound (≥ 38/60) is the instrument that detects it. ADR-019's margin (44, 44, 58) makes it survivable but not assured | P2 |
| R-50 | **Oversampling a small pool teaches memorisation, and dev is too saturated to notice** | M | M | Drawing 3,006 v1 rows at 90% for 486 steps repeats samples far more often than natural-order training. Registered as an ADR-020 failure mode in advance; the hold-out is the only instrument that can see it, and it is scored once | P2 |
| R-51 | **A substitute selection signal is contaminated and flatters the comparison** | M | **H** | Public corpora were used in ADR-014 and are plausibly in the base model's pretraining. Bounded, not ignored: absolute numbers are unclaimable, use is restricted to ranking fine-tunes of the same base, and the proxy is admitted only if it reproduces a known effect by exact McNemar (docs/13) | P2/P4 |
| R-52 | **Hold-out-informed design leaks through the diagnosis rather than the training** | M | M | ADR-020's causal analysis reasoned from ADR-019's *published* holdout-v3 aggregates. Bounded — per-sample v3 scores for that checkpoint were never persisted, so no finer information existed — and declared in the ADR rather than concealed | P2/P4 |

## Review cadence

The register is reviewed at every phase gate. A risk is closed only with evidence (a report, a
test, a committed artefact), never because it stopped feeling likely. New risks discovered
during implementation are added with the same discipline.
