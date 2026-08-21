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
| R-46 | **Catastrophic forgetting when extending the training corpus** | **CONFIRMED** | **H** | **Materialised in ADR-019**: adding 450 attacks in three new relations cost 9.1 points of system-prompt-extraction recall (0.8446 → 0.7534) and 5.3 of attack recall — the capability ADR-014 chose this base model for. Caught only because regression criteria were pre-registered with numeric bounds. **ADR-020 then failed to reverse it**: replay recovered 15% and reduced adaptation 41%, both at the cost of the new mechanisms (OD-32) | P2 |
| R-47 | An experiment succeeds at its objective and ships a net regression | M | **H** | **Prevented in ADR-019** by criteria 4–5 and a rescored baseline. Any corpus-extension experiment must measure prior capability against a rescored baseline under bounds fixed in advance (docs/13) | P2/P4 |
| R-28 | A small category reports a flattering rate that later reverses | **H** | M | Indirect injection moved 1.00 -> 0.40 on a bigger denominator with no model change. Single-digit denominators are now reported as "not evaluated" rather than as a rate | P4 |
| R-26 | A saturated dev split silently stops selecting | **CONFIRMED** | **H** | **Materialised twice, and now blocking.** All 18 Strategy A runs tied on v1 dev; on the *expanded* v2 dev the ADR-019 winner scores perfectly on all nine attack categories and 0/798 benign, so more data did not fix it. Nothing can rank checkpoints, and the dev-selected threshold is underdetermined (OD-23 → OD-33) | P2 |
| R-23 | Public-corpus FPR understates real FPR by 5–24x | **H** | M | Measured across six frozen operating points. Thresholds may never be set from public data alone | P2 |
| R-24 | Fine-tuning corpus is synthetic; model may fit the generator | **H** | M | Near-duplicate rate 0.0000; independently authored hold-out is the check; dev/hold-out divergence pre-registered as the failure diagnostic (OD-21) | P2 |
| R-25 | Training could contaminate the frozen hold-out, voiding all evaluation | L | **H** | Build aborts on collision; content hash pinned in CI; separate directory trees; four boundary tests | P2 |
| R-22 | Hold-out authored by one person encodes one view of enterprise traffic | M | M | Stated in docs/14; production shadow-mode data is the corrective | P2 |
| R-20 | Truth-table test becomes unmaintainable | L | L | Parametrised over the matrix, not enumerated | P0 |
| R-56 | **An observability API becomes the leak the audit schema prevents** | L | **H** | Two independent layers: no audit column can hold content, and every response passes an explicit DTO that lists its fields, so a new column cannot reach the API automatically. Asserted by driving secrets through the gateway and scanning every endpoint plus `/metrics` | P5 |
| R-57 | **A client-supplied metric label causes unbounded cardinality** | M | M | `model` arrives from the caller. `bounded_label` caps distinct values at 32 and collapses the rest to `other`; a security test drives 80 distinct model names and asserts the series count stays bounded. docs/12's 'bounded sets' assumption is now enforced rather than trusted | P5 |
| R-58 | **A dashboard renders an unavailable dependency as zero traffic** | M | M | `status` is `ok` / `empty` / `degraded`, and percentiles are `null` (not 0) when `n` is 0. The contract requires the frontend to render these differently | P5/P8 |
| R-73 | **An audit-store outage used to empty the fleet** | **RESOLVED (P13)** | M | `/ready` failed whenever PostgreSQL was unreachable, which contradicted ADR-012: with `require_audit=false` the security decision is unaffected and only the record is lost. Every instance leaving rotation turned an audit outage into a traffic outage. The requirement level now follows `require_audit` ([ADR-027](adr/ADR-027-readiness-contract.md)) | P0/P13 |
| R-59 | **The dashboard API is unauthenticated** | **RESOLVED (P9)** | M | Was deliberate while the console was API-only. Closed by [ADR-023](adr/ADR-023-operator-authentication.md): identity is terminated at a reverse proxy or ingress and enforced by `app/middleware/auth.py`, unknown paths default to operator-only, and `console_auth_mode=disabled` is refused in production. The exposure it described — thresholds plus block rates by category, which is a recipe for tuning an evasion (T-13) — was real | P5/P9 |
| R-60 | **The gateway itself is an open proxy to a paid upstream** | **RESOLVED (P10)** | **H** | Closed by [ADR-024](adr/ADR-024-llm-caller-authentication.md): `/v1/**` requires a service API key verified in middleware ahead of detector inference, and `caller_auth_mode=disabled` is refused in production. Every negative test asserts `upstream.call_count == 0` — a 401 alone would not prove the model was never reached | P9/P10 |
| R-62 | **A leaked caller key stays live until a deployment** | **M** | M | There is no expiry and no disabled flag: revocation is deleting the entry from `FIREWALL_CALLER_API_KEYS`, which requires a config change and a restart. Accepted deliberately — a revocation API means a credential store, a CRUD surface and an admin path on a security gateway (ADR-024 alternative A). The per-caller rate limit bounds the damage in the interval; a database-backed model becomes correct past roughly a dozen independently managed callers | P10 |
| R-63 | **A per-process rate limit reads as a global one** | M | M | `FIREWALL_CALLER_RATE_LIMIT_PER_MINUTE` is enforced in each worker, so N replicas allow N times the configured value. Stated in the ADR, the deployment doc, the metric description and the settings comment rather than hidden behind a plausible number — an operator who believes the limit is global will size it wrong by exactly the replica count. An exact global ceiling belongs at the ingress | P10 |
| R-65 | **The authentication-failure throttle punishes shared addresses** | **M** | M | It throttles by client address and runs *before* the credential comparison, so a legitimate caller behind the same NAT or egress gateway as an attacker is refused for the window and cannot clear its own count. Moving the check after authentication would remove the collateral damage and the protection together. Mitigated by shipping it **off by default**, by a 60-second window rather than a ban, and by making the edge the primary defence. Reproduced in miniature by the edge integration suite, which is why `compose.edge.yaml` leaves it off | P11 |
| R-66 | **The operator console proxy still has no rate limiting** | M | M | `deploy/docker/console-proxy` gained no `limit_req`, `limit_conn` or timeouts in Phase 11 — the edge work targeted the gateway, which is where the upstream credential and the expensive inference are. The console is authenticated (ADR-023) so an anonymous flood there costs a 401, but nothing bounds that flood. Deliberately out of scope, recorded rather than left implicit | P11 |
| R-68 | **The edge to firewall hop is plaintext** | M | M | Deliberate, not an omission: the two share an isolated network carrying only them, and the edge was moved onto that network *exclusively* in P12 — which also fixed a latent P11 bug where a second interface made the gateway see the wrong source address and silently disabled every peer-address control. mTLS was **not** added automatically; it becomes right when the internal network is shared with workloads outside this trust boundary (OD-39). `/metrics` is scraped over the same hop | P12 |
| R-69 | **A certificate that expires while running is not caught** | M | M | The edge validates expiry at start-up and refuses to start on an expired pair, but nginx holds a loaded certificate until reload — so one that lapses mid-run keeps being served until something restarts it. No expiry metric is exposed by the application, which holds no certificate. Monitoring belongs to whatever issues them; stated rather than papered over with a check that would only ever fire at restart | P12 |
| R-80 | **A queued audit writer loses records on an ungraceful stop** | **M** | M | Measured: `SIGKILL` after a burst wrote 49/300 records, against 300/300 synchronously — the queue holds roughly one write-latency of throughput, about 2.5 s here. A graceful stop loses nothing (300/300, bounded drain). Accepted in exchange for ~10 ms per request, with the code default left at `sync` so no deployment inherits the window by upgrading, and `require_audit=true` refusing the queue outright ([ADR-029](adr/ADR-029-audit-write-architecture.md)) | OD-42 |
| R-81 | **Backpressure that blocks is worse than backpressure that drops** | **RESOLVED (OD-42)** | **H** | A blocking queue was proposed in Phase 15 as the safe option and was **refuted by measurement**: against a stalled database it hung the request path until all 120 clients timed out, where dropping served all 120 and counted the loss. It converted a degraded dependency into a total outage — the failure ADR-012 rejected an unbounded queue for, in a different shape. The mode was deleted rather than left selectable with a warning | OD-42 |
| R-77 | **`gateway_overhead_ms` understates what a caller waits for** | **M** | M | `total_ms` is frozen by `timings.finish()` before the audit write, so the metric docs/15 says latency claims must rest on excludes ~10 ms p50 of client-visible time. Worse until Phase 15: the log line emitted `audit_ms` *before* the block that measures it, so every request reported `audit_ms: 0.000`. Ordering fixed (no behaviour change); the exclusion is deliberate and now documented rather than silently true. Any published overhead figure must say which definition it uses | P15 |
| R-78 | **The synchronous audit write dominates per-request latency** | **ADDRESSED (OD-42)** | M | Measured at **10.5 ms p50 / 14.4 ms p95** on the reference machine — six times the entire rest of the gateway span (1.7 ms p50). ADR-012 chose synchronous writes for Phase 0 and an async writer has been listed as outstanding since; this is the first measurement that says what it would be worth. Not fixed here: Phase 15 is a measurement phase, and changing the audit path on the strength of one benchmark is the "optimise until green" the brief forbids | P15 |
| R-79 | **Above concurrency 4 the harness is the bottleneck, not the gateway** | L | M | Condition A — client to mock with no gateway — degrades from 4 ms p50 at concurrency 1 to 206 ms at 64 on this laptop, so client-observed figures at concurrency 16 and 64 characterise the mock and the loopback. The server-measured span stays valid there. Stated in the run README so a reader does not mistake a saturated harness for a saturated gateway | P15 |
| R-74 | **No rolling-update semantics** | M | M | Plain Compose restarts a container; it cannot drain one, so a single-node reference deployment has a brief outage on restart. Compose was chosen over an orchestrator deliberately — no measured sizing exists and no cluster is available to validate manifests against ([ADR-028](adr/ADR-028-production-deployment-manifests.md), OD-41) — and the cost is stated rather than hidden behind manifests nobody could check | P14 |
| R-75 | **Secret files may be world-readable on the host** | M | M | The application container runs as uid 10001 with every capability dropped, so it cannot read a mode-600 file it does not own. `init_prod_secrets.sh` chowns to that uid where it has the privilege and otherwise falls back to 0444 inside a 0700 directory, printing exactly what it did. The directory is what protects them: another unprivileged user cannot traverse it. Granting the container `DAC_OVERRIDE` was rejected — that is the power to bypass every file permission, to read three files | P14 |
| R-76 | **Rotating a database secret does not rotate the database password** | L | M | `POSTGRES_PASSWORD` initialises the data directory on first run only, so replacing the secret file against an existing volume produces `InvalidPasswordError` on every connection. Found by rotating it during Phase 14 verification. Readiness stayed *ready* throughout, correctly — with `require_audit=false` an audit outage is advisory (ADR-027). Rotation needs an `ALTER ROLE` as well as a new file; recorded in docs/17 | P14 |
| R-71 | **Readiness re-asserts startup invariants it cannot independently discover** | L | M | Most security-boundary checks restate something the process refuses to start without, so they cannot fail in a correctly built process. Stated rather than dressed up as detection: their value is a machine-readable contract at the load balancer and a regression net for the day a startup check is relaxed. `test_readiness_contract.py` walks one shared list twice — refused at startup, and reported unready by an independently assembled state — so the two cannot drift apart silently | P13 |
| R-72 | **The schema check is exact equality** | L | M | With `require_audit=true` a rollout that ran expand/contract migrations would fail readiness on the intermediate revision, taking new instances out of rotation for a state the deployment doc actually prescribes. Bounded today: the project runs migrations as a separate step before rollout and uses no expand/contract split, and the check is advisory whenever audit is best-effort. Tracked as OD-40 rather than solved speculatively | P13 |
| R-70 | **The edge will not start if its backend name does not resolve** | L | M | `proxy_pass http://firewall-api:8000` uses a literal hostname, which nginx resolves at configuration load — so `nginx -t` in the entrypoint fails outright when the backend is not yet in DNS. Correct under compose (`depends_on: service_healthy`) and a real consideration in Kubernetes, where a Service can briefly have no endpoints during a rollout. Found by the fail-closed test suite rather than in production | P12 |
| R-67 | **Every shipped limit value is a development default** *(partially measured, P20)* | M | M | The edge rate, burst, connection cap and the application ceilings were chosen to be observable by hand, not measured. An operator who adopts them unchanged gets a limit that is either far too tight or decorative. Labelled as development defaults in the config, the ADR and the deployment doc, with an example production column and no recommended value — publishing one without traffic data would be exactly the unbacked claim docs/22 refuses. **Phase 20 run 2 measured two of them behaving exactly as documented** — edge `limit_req` admitted 11 of 60 as predicted, and the in-process ceiling admitted exactly 64 of 120 with the counter matching the refusals — so the defaults are now known to be *deterministic and correctly implemented*. Whether the numbers are right for real traffic is still unanswerable from loopback ([eval/results/shadow/20260821T171500Z__phase20-run2-limits-alerts-runbook/report.md](eval/results/shadow/20260821T171500Z__phase20-run2-limits-alerts-runbook/report.md)) | P11/P20 |
| R-64 | **The ceiling counts requests, not tokens** | M | M | A caller sending very large prompts outspends one sending many small prompts while staying inside the same limit, so the control bounds request volume rather than cost. `usage` is recorded per request and would be the basis for a real budget; no budget is claimed today (T-28) | P10 |
| R-61 | **A misconfigured proxy silently reintroduces spoofable identity** | M | **H** | `proxy_set_header` overwrites only the headers it names, so an identity header the application reads but the proxy does not set would pass through from the client. Two independent controls, either sufficient: the application refuses every identity header from an untrusted peer, and a test asserts the reference proxy's header list matches the three the application reads. What is **not** verified is a third-party proxy an operator brings themselves | P9 |
| R-55 | **A single classifier cannot hold both capabilities at this model size** | **CONFIRMED** | **H** | ADR-019 learned the mechanisms and lost extraction; ADR-020's two arms recovered extraction only by losing the mechanisms. Two independent interventions slide along one trade-off curve — a capacity signature, not a corpus defect. Mitigation is architectural (OD-34), not more training | P2 |
| R-54 | **A split that discriminates overall can be flat on the decision metric** | **CONFIRMED** | **H** | ADR-020 Step 2's dev separates T2 from T3 on F1, FPR and two mechanisms — but extraction recall is 1.0000 for all six runs, and extraction is what the experiment protects. A headline metric that finally moves can disguise a flat line on the one that decides. Per-metric saturation is now reported instead of a single verdict (docs/13) | P2/P4 |
| R-53 | **A dev-selected threshold is arbitrary when the dev split separates perfectly** | **CONFIRMED** | **H** | Six checkpoints, identical methodology, thresholds spanning **0.0694–0.9955**; one seed chose 0.0694 where its sibling chose 0.9954. Every historical threshold in this project was selected this way. Mitigated for comparisons by the matched-FPR analysis (docs/13); the underlying need for a non-saturating dev split is unresolved (OD-23, OD-33) | P2 |
| R-48 | **Seed variance was never measured, so a condition effect may be a run effect** | **M → L** | **H** | **Measured 2026-08-17 with no training.** Three seeds per family on the proxy: the two are fully disjoint (every Strategy A run beats every ADR-019 run), gap 0.0594 against a largest within-family spread of 0.0230. Exact permutation p = 0.0500 — the *floor* at 3v3, so suggestive rather than decisive. ADR-019's verdict stands; run-level variance is now bounded, not eliminated | P2 |
| R-49 | **A replay mixture starves the capability it was built to add** | **MATERIALISED** | **H** | Confirmed on mechanisms-v1: retrieval_poisoning 0.7333 → **0.3167** (T2) / 0.1167 (T3), tool_use 0.7333 → **0.3500** / 0.0500. Two of three mechanisms lost their Wilson bound. Registered in advance as ADR-020's central risk and it decided the outcome | P2 |
| R-50 | **Oversampling a small pool teaches memorisation, and dev is too saturated to notice** | M | M | Drawing 3,006 v1 rows at 90% for 486 steps repeats samples far more often than natural-order training. Registered as an ADR-020 failure mode in advance; the hold-out is the only instrument that can see it, and it is scored once | P2 |
| R-51 | **A substitute selection signal is contaminated and flatters the comparison** | M | **H** | Public corpora were used in ADR-014 and are plausibly in the base model's pretraining. Bounded, not ignored: absolute numbers are unclaimable, use is restricted to ranking fine-tunes of the same base, and the proxy is admitted only if it reproduces a known effect by exact McNemar (docs/13) | P2/P4 |
| R-52 | **Hold-out-informed design leaks through the diagnosis rather than the training** | M | M | ADR-020's causal analysis reasoned from ADR-019's *published* holdout-v3 aggregates. Bounded — per-sample v3 scores for that checkpoint were never persisted, so no finer information existed — and declared in the ADR rather than concealed | P2/P4 |
| R-82 | **The retention job needs `DELETE`, which ADR-012's least-privilege model withheld** | **M** | M | ADR-012 granted the application `SELECT/INSERT/UPDATE` and no `DROP`, so an application-level SQL flaw could not destroy the audit trail. An in-process sweeper needs `DELETE` on the three audit tables, and that protection is genuinely weaker for it ([ADR-030](adr/ADR-030-audit-retention.md)). Bounded rather than dismissed: every retention statement is parameterised, no user input reaches the path, the delete predicate is an id list produced by one function that filters on `created_at` alone, and the grant split was **never implemented in any manifest** — the application connects as the table owner today, so the model this weakens was aspirational. An external job holding its own credentials would preserve it (OD-43) | P16 |
| R-83 | **Retention deletes; backups do not** | M | M | A 30-day period in the database against a 90-day backup rotation means the data survives 90 days, and the gateway cannot see that, let alone enforce it. Listed as a deployment obligation in docs/10 rather than implied away. It also means a restore reintroduces rows the policy had removed, which the next sweep will remove again — correct, but only if retention is enabled on the restored instance | P16 |
| R-84 | **Retention is off by default, so an upgrade does not fix the growth** | **M** | M | Deliberate ([ADR-030](adr/ADR-030-audit-retention.md)): deletion is irreversible and an upgrade must not start removing an operator's audit trail because a default moved. The cost is that a deployment which never reads its startup log keeps growing exactly as before. Mitigated by a startup **warning** naming the consequence, the periods printed whether it is on or off, and `compose.prod.yaml` enabling it. Not mitigated by a startup refusal, which was considered and rejected — the failure is accumulation, not an open boundary | P16 |
| R-85 | **A sweep competes with the request path for the connection pool** | L | L | One connection, bounded batches, at most hourly, against a default pool of 5. No measurement of its impact under load has been taken, so this is stated rather than characterised. Bounded by the same 5-second command timeout as everything else, and by the per-sweep row ceiling | P16 |
| R-86 | **Nothing enforced retention; the audit store grew without bound** | **RESOLVED (P16)** | **H** | ADR-012 specified retention in Phase 0 and named the job that would enforce it. Four phases later nothing deleted, and the reference development store held 55 MB written over 2.4 days with no mechanism that would ever have removed any of it. Closed by [ADR-030](adr/ADR-030-audit-retention.md) with the periods unchanged. The lesson repeats one this register already carries: a documented intention with no artefact behind it is not a control | P16 |
| R-87 | **`/metrics` could not be scraped by Prometheus at all** | **RESOLVED (P17)** | **H** | The endpoint declared `application/openmetrics-text` while `generate_latest` emitted the Prometheus text format. Prometheus trusts the declared type, parsed the body as OpenMetrics and rejected every scrape for lacking the mandatory `# EOF` terminator. **Every metric in the catalogue was unreachable, so no alert could ever have fired and no dashboard could have been built.** Found by pointing a real Prometheus at the gateway in Phase 17, not by any test — `tests/api/test_metrics_endpoint.py` asserted the exposition against docs/12 and passed, because it is not a Prometheus. Fixed by one import; `tests/integration/test_alerting.py` now scrapes with the real server ([ADR-031](adr/ADR-031-alerting-and-incident-response.md)) | P17 |
| R-88 | **Almost every alert threshold is a guess** | M | M | Same problem as the rate limits (R-67) and the same treatment: each unmeasured threshold carries `calibration: unvalidated` in the rule file **and** in the runbook, enforced by test so it cannot be presented as measured in one place and as a guess in the other. This project has no production traffic; publishing tuned-looking numbers without traffic to tune against would be the unbacked claim docs/22 refuses. Expect to rewrite most of them in the first weeks of real use | P17 |
| R-89 | **`FirewallBlockRateStepChange` is silent on a deployment younger than a day** | L | M | It compares against `offset 1d`, which returns nothing before then — so a new deployment has no block-rate alerting at all and nothing says so. Accepted deliberately: the alternative is a fixed block-rate threshold, and nobody knows the right block rate for a deployment they have not seen. Stated in the ADR rather than discovered | P17 |
| R-90 | **Two alerts re-assert startup invariants and cannot fire in a correct process** | L | L | `FirewallHTTPSEnforcementDisabled` and `FirewallRetentionDisabled` describe states production refuses to start in or ships enabled. The same honest limitation as the readiness security checks (R-71): their value is catching a relaxed startup check or a mislabelled instance in the scrape pool, which is real but narrower than the alert name suggests | P17 |
| R-91 | **The rules assume a single Prometheus scrapes every replica** | L | M | Every expression aggregates for that topology. A federated or sharded setup silently changes what `min()` and `sum()` mean, and nothing detects that the assumption was broken. Documented in the runbook's preamble rather than encoded, because encoding it would mean shipping a scrape topology this project does not own | P17 |
| R-92 | **An exclude-list build context ships artefacts invented after it was written** | **RESOLVED (P18)** | M | `.dockerignore` excluded `predictions*`, `*.csv` and `*.svg` and claimed the image carried "~200K of result.json". Phase 15 then wrote `raw_results.jsonl`, matching none of them, and **17 MB of per-request rows shipped in the production image for four phases**. No content risk here — the rows are synthetic benchmark timings — but identical drift on an artefact holding real payloads would have been a disclosure and nothing would have noticed. Replaced with an allow-list of the one filename the dashboard opens, bound to the code by `tests/security/test_image_build_context.py` ([ADR-032](adr/ADR-032-release-candidate-readiness.md)) | P18 |
| R-93 | **Two CI scanners have never been observed to run** | M | M | Trivy (image vulnerabilities) and gitleaks (secrets) are defined in `.github/workflows/ci.yml` and neither is installed locally, so **no result from either has ever been seen by anyone** — CI has not executed on a remote. A manual `git grep` for DSNs, `sk-` keys, bearer tokens and absolute paths found nothing, which is weaker and not a substitute. Recorded rather than implied away, because "we scan for that" is the easiest unearned claim in security work | P18 |
| R-94 | **The readiness matrix is a snapshot and nothing keeps it current** | L | M | `docs/release-readiness.md` is accurate at Phase 18 and will be wrong the first time a capability changes without someone editing it. Mitigated only by being dated and phase-stamped rather than presented as continuously true. A test that regraded capabilities automatically would be a test that graded documentation, which is the thing this audit refused to do | P18 |
| R-95 | **Thirteen capabilities ship PARTIAL and the status column flatters them** | M | M | A reader who skims `docs/release-readiness.md` will overestimate readiness: heuristic-only enforcement, unvalidated limits, a console never viewed on a display, retention off by default and a runbook never used in an incident all read as "PARTIAL". The limitation column is not optional reading, and the document says so in its own summary | P18 |
| R-96 | **Both release scanners failed the first time they were run** | **RESOLVED (P19)** | **H** | Trivy and gitleaks had been defined in CI since Phase 0 and never executed anywhere. Run locally in Phase 19: **36 HIGH** in the application image (util-linux, four CVEs, fix available), **21 HIGH** in the edge (musl, zlib, libxml2, libexpat, libpng, c-ares, nghttp2), and **7 gitleaks findings**. Every one investigated and classified; zero real credentials; both images now scan clean under the unchanged policy ([ADR-033](adr/ADR-033-release-scanning-and-base-image-patching.md)). The lesson is the project's own recurring one: a control nobody has executed is not a control | P19 |
| R-97 | **The edge image is pinned by a mutable tag while the application image is pinned by digest** | M | M | `Dockerfile.edge` uses `nginx:1.27-alpine`; the application Dockerfile pins by digest with a comment explaining exactly why a tag is unsafe. The inconsistency was found in Phase 19 and deliberately **not** fixed in the same change as the patching, so that neither is attributable to the other. `apk upgrade` addresses the vulnerability exposure; the pin addresses build determinism, and they are different problems | P19 |
| R-98 | **`apt-get upgrade`/`apk upgrade` make two builds from the same pin non-identical** | M | L | Accepted deliberately: the fix for four HIGH CVEs was in the Debian archive and not in the upstream base image, and refreshing the pinned digest was tried and did not help. The pin still fixes which base a build starts from; CI now records the built image's identity so a release is traced by what was actually built ([ADR-033](adr/ADR-033-release-scanning-and-base-image-patching.md)) | P19 |
| R-99 | **Base-image CVEs will recur and nothing watches for them** | M | M | Phase 19 fixed today's. No subscription, no scheduled scan and no dependabot equivalent exists for base images, so the next unpatched HIGH surfaces only when CI next runs — which, on a repository whose CI has never been observed to run, could be a long time | P19 |
| R-100 | **The console's tests never ran in CI, and their documented invocation was broken** | **RESOLVED (P19)** | L | There was no frontend job at all, and `node --test tests/frontend/` — the command in the test file's own docstring — has resolved the directory as a module and exited 1 since Node 22. Thirteen tests over the formatters and `safeHref` had therefore never run in the pipeline, while reading locally as a failing suite. Both fixed | P19 |
| R-101 | **The shipped heuristics block ~1 in 3 legitimate security-adjacent messages** | **M → H** | **H** | **Measured through the deployment for the first time** (Phase 20, [ADR-034](adr/ADR-034-shadow-traffic-validation.md)): hard-negative block rate **0.3153** [0.2767, 0.3566] on 517 dev cases, against **0.0010** [0.0002, 0.0056] on 1,000 independent public benign samples. Ordinary traffic is clean; text that *quotes* an attack — incident tickets, abuse reports, security documentation — is refused about a third of the time. `jailbreak` accounts for more of it than `prompt_injection`. A **calibration item**, not a defect: the heuristics do what they were written to do, and docs/22 has never called them injection detection. It is now a number instead of an intuition ([eval/results/shadow/20260821T163000Z__phase20-controlled-traffic/report.md](eval/results/shadow/20260821T163000Z__phase20-controlled-traffic/report.md)) | P20 |
| R-102 | **Attack recall through the deployment is 0.4706** | M | **H** | 72/153 dev attacks blocked, 95% CI [0.3932, 0.5494] — **53% pass**. Consistent with every prior statement that enforcement is heuristic and misses rewordings; recorded here because it is the first measurement taken over a socket through the real policy engine rather than against detectors offline. Not a regression and not a release blocker: it is the residual the README already refuses to call prevention | P20 |
| R-103 | **Phase 20 measured decision behaviour only; capacity, alerts and the runbook remain unexercised** | M | M | ADR-034 registered six measurements and run 1 executed two. The development-default limits (R-67), the alert thresholds against real conditions (R-88) and the runbook dry run (the reason it is PARTIAL) are still outstanding, and are recorded as not produced rather than assumed fine | P20 |
| R-104 | **Three alerts could not fire on the first occurrence of their condition** | **RESOLVED (post-RC)** | **H** | **Root cause, established by inspection of a freshly started process:** `firewall_concurrency_rejections_total{scope}`, `firewall_detector_errors_total{detector,error_kind}` and `firewall_retention_sweeps_total{outcome}` are **labelled**, so prometheus_client creates no child series until the first event. The series appears already positive with no prior zero, and `increase()` over a flat series is 0. `firewall_audit_events_dropped_total` is **unlabelled**, exists at 0 from registry construction, and was verified unaffected — the contrast is the proof. **Fix:** each rule now also matches a series that is positive now and absent one window ago; no application metric, label or threshold changed, so cardinality is untouched. The concurrency rule uses a 15m lookback because its `for: 5m` needs the clause to outlast the hold. **Verified live on a virgin state** (fresh app + renewed Prometheus volume): first-ever burst of 56 rejections gave `increase[5m] = 0` — the old expression would not have fired — while the new clause read 56 and the alert went PENDING then FIRING. Four promtool cases pin it, and they fail against the old expressions | P20 |
| R-105 | **A documented runbook command did not work as written** | **RESOLVED (post-RC)** | M | `uv run python scripts/purge_audit.py`, quoted in three runbook entries and in docs/17, exits with *"No audit database is configured"* unless `FIREWALL_DATABASE_URL` and `FIREWALL_PERSIST_EVENTS` are in the environment — present inside the container, absent in an operator's shell. Found by executing the runbook rather than reading it, which is why it was graded PARTIAL. Every occurrence now carries the prerequisite with a placeholder credential, never a real one, and the corrected procedure was dry-run successfully | P20 |
| R-106 | **`firewall_audit_queue_capacity` documented as absent; it is 0** | **RESOLVED (post-RC)** | L | Traced configuration → settings → runtime → docs → tests. The gauge is **unlabelled**, so it is created with the registry and can never be absent; `set_audit_queue_capacity` is called only in the queued branch, leaving it at 0 under `sync`. **The implementation is correct and was not changed**: depth is 0 there too and `0 / 0` is NaN, which no comparison satisfies, so the saturation alert is silent. ADR-031, the `main.py` comment and the metric HELP text all claimed *absence* and were wrong; all three corrected. The promtool case that modelled absence now models the real 0/0 state, so the silence is a tested property rather than an incidental one | P20 |

## Review cadence

The register is reviewed at every phase gate. A risk is closed only with evidence (a report, a
test, a committed artefact), never because it stopped feeling likely. New risks discovered
during implementation are added with the same discipline.
