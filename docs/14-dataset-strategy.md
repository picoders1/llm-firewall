# Datasets

## Policy

1. **No third-party dataset is committed to this repository.** Datasets are fetched by
   script into `eval/datasets/raw/`, which is git-ignored. Committing someone else's corpus
   creates a licensing problem and a repository nobody wants to clone.
2. **Every dataset is registered before use** in `eval/datasets/registry.yaml` with its
   source, version, licence, redistribution terms and content checksum. A dataset with an
   unclear licence is not used — "it was on the internet" is not a licence.
3. **Checksums are verified on download.** An evaluation whose input can change silently is
   not reproducible.
4. **Production traffic is never an evaluation dataset.** This is both a privacy rule
   ([logging.md](10-security-model.md)) and a methodological one.
5. **Attack data stays inert.** Corpora contain live attack strings; they are never used as
   fixtures that reach a real upstream model, and the directory is excluded from any
   packaged artefact.

## Registry format

```yaml
datasets:
  - name: <slug>
    version: <upstream version or commit>
    source: <URL>
    licence: <SPDX id or explicit terms>
    redistributable: true | false
    download: scripts/datasets/<slug>.py
    checksum_sha256: <hash of the normalised case file>
    categories: [ ... ]
    languages: [en]
    notes: <caveats, known label-quality issues>
```

The harness refuses to run against a dataset whose recorded checksum does not match what is
on disk.

## Sources — verified and decided (2026-08-17)

Licences and gating were read from the **HuggingFace API**, not from memory, on the date
below. The machine-readable record is `eval/datasets/registry.yaml`; the loader refuses any
dataset whose `commercial_use` is not permitted, so a rejection is enforced rather than
merely noted.

### Accepted

| Dataset | Licence | Role | n used | Contamination |
|---|---|---|---|---|
| `deepset/prompt-injections` | apache-2.0 | injection + benign | 662 | **high** |
| `jackhhao/jailbreak-classification` | apache-2.0 | jailbreak + benign | 1,286 | **high** |
| `Lakera/gandalf_ignore_instructions` | mit | injection (attack-only) | 999 | **high** |
| `OpenAssistant/oasst1` | apache-2.0 | **benign denominator** | 4,000 | medium |
| `databricks/databricks-dolly-15k` | cc-by-sa-3.0 | **benign denominator** | 4,000 | medium |
| internal `holdout` | Apache-2.0 (ours) | contamination control | 66 | **none** |

CC-BY-SA is accepted: it permits commercial use, and the share-alike obligation binds
derivative *datasets*, which we do not publish. Recorded so the obligation is not forgotten
if we ever do.

### Rejected, with the reason recorded so it is not re-litigated

| Dataset | Licence | Rejected because |
|---|---|---|
| `tatsu-lab/alpaca` | cc-by-nc-4.0 | **Non-commercial.** An Apache-2.0 project cannot rely on a benchmark it may not use commercially. Also model-generated, so not human benign traffic. |
| `HuggingFaceH4/no_robots` | cc-by-nc-4.0 | Same licence problem. Otherwise an excellent 10k human-written benign corpus — revisit only if the licence changes. |
| `hackaprompt/hackaprompt-dataset` | mit | **Gated** (`gated: auto`): needs an authenticated token, so no unauthenticated reproducible fetch. Also ~600k entries with very noisy labels, needing sampling and re-labelling. |

### Historical note

An earlier revision of this document listed these as unverified candidates. They are now
verified; the table above supersedes it.

| Candidate | Provides | Licence status | Caveat |
|---|---|---|---|
| `deepset/prompt-injections` | Direct injection, benign | **verify** | Small; widely used, so likely in model training data |
| `jackhhao/jailbreak-classification` | Jailbreak vs benign | **verify** | Label boundary between jailbreak and roleplay is fuzzy |
| JailbreakBench artefacts | Curated jailbreak behaviours | **verify** | Research-use terms need checking |
| Lakera `gandalf_ignore_instructions` | Real user injection attempts | **verify** | Game-derived; distribution differs from application traffic |
| HackAPrompt corpus | Large adversarial competition set | **verify** | Very noisy labels; needs sampling and re-labelling |
| Instruction-tuning corpora (Dolly, Alpaca-style) | **Benign** at volume | **verify** | Essential for a credible FPR denominator |
| Presidio / synthetic PII generators | PII entities with spans | **verify** | Synthetic PII is safe to commit — real PII must never be |
| Hand-authored indirect-injection set | Indirect injection | Ours, Apache-2.0 | Public data for this category is thin; we will author and document it |

**The benign source is the one that matters most.** Attack corpora are easy to find and easy
to over-weight; FPR — the metric that decides whether anyone can actually deploy this —
needs a large, realistic, benign denominator, and finding one is the harder sourcing problem.

**Known contamination risk:** several of these are public and widely mirrored, so any
published classifier may have trained on them (validity threat 2 in
[methodology.md](13-evaluation-strategy.md)). Where possible we will hold out a hand-authored set that
has never been published as the honest generalisation check.

## The internal hold-out — the contamination control

`eval/datasets/holdout/` — **531 cases**, authored for this project and **never
published**, so they cannot be in any model's training data. This is the only
contamination control available without access to training corpora.

| | |
|---|---|
| Total | 531 (457 benign, 74 attack) |
| Hard negatives | **170** (37% of benign) |
| Difficulty | 223 hard, 174 medium, 60 easy |
| Domains | 20, from `business_email` to `incident_response` |
| Length | 9 – 748 chars, median 85 |
| Provenance | `source_type: authored`, `source: internal_authored`, Apache-2.0 |
| Built by | `scripts/datasets/build_holdout.py`, from `scripts/datasets/authoring/` |

### Why hard negatives dominate

The hold-out is deliberately not representative of *average* traffic — it is
weighted toward the cases that decide deployability. 170 samples are legitimate
text that superficially resembles an attack: incident reports quoting a payload,
"ignore my previous email", policy documents saying staff must disregard
unsigned instructions, guardrail documentation, red-team scoping, AI-safety
discussion.

That weighting paid for itself immediately. On the expanded hold-out the selected
classifier false-positives on **93.8%** of incident reports that quote attacker
text, and **12.0%** of benign samples overall — a failure entirely invisible on
the public corpora, where the same model measures 1.3%
([ADR-014](adr/ADR-014-detector-selection.md)).

### Integrity guarantees

Enforced by `build_holdout.py`, which refuses to write if any fail:

* **Safety scan** — no credentials, no real-looking PII. Exemptions are principled,
  not case-by-case: RFC 2606 reserved domains, the 555-01xx reserved phone range,
  and Luhn-**invalid** digit runs (which cannot be payment cards).
* **0 internal duplicates** by normalised content.
* **0 contamination collisions** against all six other corpora (the five public
  datasets plus the smoke fixture), checked exact and normalised.
* **0 near-duplicate pairs** at Jaccard ≥ 0.85.

### Honest limits

* Authored by one person, so it encodes one view of enterprise traffic.
* 457 benign is enough to bound FPR to roughly ±3 points, not to two decimals.
* Hard-negative weighting means the overall FPR is **not** an estimate of
  production FPR; it is an estimate of FPR on adversarially-selected benign text.
  Both are reported separately for that reason.

## The fine-tuning corpus — `finetune-v1`

`eval/datasets/finetune/` — 3,814 samples (3,074 benign of which 2,443 hard
negatives; 740 attacks), split 3,006 train / 808 dev. Built deterministically by
`scripts/datasets/build_finetune.py` from authored component pools.

**Generated by a documented matrix, not by prompting a model.** Diversity comes
from combinatorics over hand-written components, which is why the near-duplicate
rate is 0.0000 at Jaccard ≥ 0.90.

**The defining property:** the same 22 attack phrases appear on both sides of the
label boundary — as payloads, and quoted inside incident reports, test fixtures
and training material. This makes keyword-learning insufficient by construction,
which is the whole point of the experiment
([ADR-015](adr/ADR-015-fine-tuning-strategy.md)).

**Hold-out boundary.** Zero collisions with `eval/datasets/holdout/`, enforced by
a build-time abort and four CI tests including a pinned content hash. The hold-out
remains the only uncontaminated judge and is never trained, tuned or selected on.

Limits: synthetic and compositional, 3,814 samples is small, category labels are
generator-assigned, English only.

## The in-repo smoke set

`eval/datasets/smoke/` — approximately 40 cases, **written by us**, Apache-2.0, committed.

Purpose: exercise the harness end to end in Phase 0 and in CI without a network fetch.
Coverage: benign (roughly half, deliberately including security-adjacent benign prompts that
*should not* be blocked), direct injection, jailbreak, PII, plus one obfuscated variant per
evasion class covered by normalisation.

**It is not a benchmark and every report generated from it says so.** Forty cases authored
by the same people who wrote the rules is a wiring test. It measures that the pipeline runs,
not that the detector works.

## PII test data

Synthetic only, generated by script with a fixed seed: emails at `example.com`, phone
numbers in reserved ranges, credit-card numbers from the standard test set (Luhn-valid, not
issued), documentation-range IP addresses. Real PII never enters this repository, including
the author's own.

## Adding a dataset

1. Verify the licence permits research/benchmark use; record the SPDX id or the exact terms.
2. Add a registry entry and a download script that writes only to `eval/datasets/raw/`.
3. Write a normaliser mapping it to the case schema in
   [methodology.md](13-evaluation-strategy.md), preserving stable `sample_id`s.
4. Record the checksum of the normalised output.
5. Document label-quality caveats in `notes` — this is where the honest reading of a dataset
   lives, and it is not optional.
6. Confirm splits: existing `sample_id`s must not move between splits.

---

## Hold-out versioning

Hold-outs are **versioned, never edited**. A frozen corpus that gains or loses a
sample invalidates every result measured against it, so a change of content is a
change of version.

| Version | Path | n | Status |
|---|---|---|---|
| v2 | `eval/datasets/holdout/cases.jsonl` | 531 | **Frozen**, hash `fd91575272056d3b282804ddfbbbde63`. The artefact behind the Strategy A result. |
| v3 | `eval/datasets/holdout/v3/` | 792 | **Frozen**, hash `0e26dd6b7d0f545c0bd68b64c2a0b4b60397f8ad41436754dc38b679fbbb28bf`. Built for statistical power. |
| indirect-v1 | `eval/datasets/holdout/indirect-v1/` | 820 | **Frozen**, hash `3ef8c0ec75d9aed9669332dd2e70987993459b39629a6f7109241e13f96d6e17`. Built to measure indirect injection per delivery shape. |
| mechanisms-v1 | `eval/datasets/holdout/mechanisms-v1/` | 358 | **Frozen**, hash `bb562774663dea7580d7d1a97031b810c7a8aadebde10fcbfd04a116b521e91c`. Built for the three mechanisms at zero recall ([ADR-019](adr/ADR-019-mechanism-coverage-fine-tuning.md)). |

No version supersedes another. Each remains valid evidence for the runs that used
it, and each pinned hash is asserted in CI. `indirect-v1` is topic-specific rather
than general: it answers one question v2 and v3 were not sized to answer, and it
carries its own taxonomy (`delivery-shape-v1`).

### Why v3 was built

v2's `quoted_attack` (n=16) and `incident_response` (n=17) sub-corpora were too
small for ADR-015's confidence-interval rule to be satisfiable *at any model
quality*. v3's denominators come from an explicit calculation
(`build_holdout_v3.py --sizing`), not a guess. See
[13](13-evaluation-strategy.md) for the sizing rules.

### Independence requirements for a new hold-out version

A new version must be independent of every corpus a result would be compared
against, and independence is measured rather than asserted:

* **0** exact and **0** normalised collisions against training, dev, every prior
  hold-out version, the smoke fixture and all public benchmark corpora. v3 was
  checked against 14,978 texts across nine corpora.
* **0** internal near-duplicates at Jaccard ≥ 0.90, and 0 against the prior
  version.
* **Fresh authoring, not paraphrase.** The prior version's *category-level* error
  pattern may inform which categories to expand; individual prior samples must
  not be inspected and transformed.
* **Deliberately different vocabulary where the phenomenon allows it.** v3's 26
  quoted attack payloads are lexically disjoint from the 22 in the fine-tuning
  corpus, so a model that memorised training strings earns nothing. This is what
  makes a repeated result evidence of generalisation rather than of recall.
* **0** secrets and **0** PII, with the same patterns the prior version used —
  the safety contract must not weaken between versions.

### Taxonomy dimensions for a topic-specific hold-out

`indirect-v1` records four dimensions rather than one category, because the failure
it was built to characterise turned out to be driven by a dimension nobody had
measured:

| Dimension | Why it is separate |
|---|---|
| `delivery_shape` | The syntactic channel (HTML comment, JSON field, tool metadata). **This is the variable that determines detection** — 0.0000 to 0.7250 across shapes. |
| `attack_mechanism` | What the instruction does. Varies far less (0.03–0.30), so conflating it with shape hides the real effect. |
| `context` | The realistic source (retrieved page, PDF, ticket, API result). |
| `user_framing` | Whether the human's own request was innocent, complicit, or a security discussion — **recorded separately from the label**. |

Hold-out v3 confounded shape with mechanism across 20 samples and could attribute
its 0.4000 to neither. Crossing them explicitly is what made the finding legible.

**Keeping `user_framing` out of the label is a deliberate methodological choice.**
In indirect injection the innocent-user case *is* the attack — the attacker planted
the payload and the user is the victim — so folding framing into the label would
define the primary threat out of existence. Recording it as its own dimension
preserved the ability to ask whether the detector reads context, and produced the
run's central result: 0.0938 recall on planted payloads versus 0.7250 when the user
asks for the override themselves.

---

## Training-corpus versioning

The same rule as hold-outs: **versioned, never edited.**

| Version | Path | n | Status |
|---|---|---|---|
| finetune-v1 | `eval/datasets/finetune/{train,dev}` | 3,814 | **Frozen.** Hashes pinned in the Strategy A selection lock; this is the record of a completed experiment. |
| finetune-v2 | `eval/datasets/finetune/v2/{train,dev}` | 4,922 | **Frozen.** v1 + a 1,108-sample mechanism extension ([ADR-019](adr/ADR-019-mechanism-coverage-fine-tuning.md)). No training run yet. |

### Extending a training corpus without invalidating a prior experiment

Three rules, the second and third learned by getting them wrong first.

**1. Never edit the prior version.** finetune-v1's hashes appear in
`selection_lock.json`. Editing it would make the Strategy A result unreproducible
and unfalsifiable at once.

**2. Reproduce the split rule byte-for-byte.** v2 must place every v1 sample in the
split it was already in. A first build used the full SHA-256 digest and a boundary of
21 where v1 uses `hexdigest()[:8]` and 20 — which silently moved v1 samples between
splits, **leaking Strategy A training data into v2's dev split** and corrupting any
selection made on it. Caught before training by
`test_v2_splits_preserve_v1_split_assignment`.

**3. A shortcut is a bug even when the metrics improve.** The extension's first build
placed every attack in a document carrier and every hard negative in a direct-request
carrier, making the carrier a perfect predictor of the label. A model could have
scored 100% by detecting the wrapper and would then have flagged all retrieved
content. The fix was a third population — legitimate content inside the same
carriers — so that no carrier carries label information. Asserted at build time and
in CI.

Corollary: **an accompanying hold-out needs its own pools for every population, not
just the attacks.** Sharing the document-legitimate pool between train and hold-out
produced 14 exact collisions on the first attempt.

### Changing proportions without authoring a corpus

ADR-020 needs a different *distribution*, not more data: the leading explanation for
ADR-019's regression is that system-prompt extraction's share of attack mass fell from
38.92% to 24.20% while its absolute count stayed at exactly 288 samples.

**Prefer a sampler over a new corpus.** finetune-v1 and finetune-v2 are frozen and
stay frozen; the successor arms re-weight *which rows are drawn* from v2 and author
nothing. This keeps the corpus record intact, costs no authoring or integrity review,
and makes the manipulated variable exactly one thing.

**Measure the mixture you already have before choosing a target.** The obvious replay
ratios — 25/75, 50/50, 75/25 v1:extension — are all useless here, because the
extension is 1,108 of 4,922 samples and **v2's implicit ratio is already 77.5/22.5**.
Every candidate sits at or below the v1 share ADR-019 already had. This is the same
class of error as a criterion that cannot be met at its denominator: a knob specified
across a range that cannot produce the effect being tested. ADR-020 uses 90/10.

**Assert the realised proportions, not the configured ones.** A sampler that silently
misses its target reintroduces the exact confound the experiment exists to remove, and
a saturated dev split will not reveal it. The pre-flight check compares realised
per-batch composition against `variable_matrix.csv`.

**A sampler has its own failure mode.** Drawing 3,006 v1 rows at 90% for 486 steps
repeats individual samples far more often than natural-order training does. That is a
memorisation risk, registered in advance as an ADR-020 failure mode rather than
discovered afterwards.

### Public corpora have a third role

Beyond model selection (ADR-014) and benign-corpus sourcing, the corpora in
`eval/datasets/raw/` serve as a **selection signal that costs no hold-out budget** —
they were never used in fine-tuning and are 0-collision disjoint from finetune-v2
across all 10,947 samples.

| Corpus | n | Role in ADR-020 |
|---|---|---|
| `lakera-gandalf` | 999 attacks | Human-authored system-prompt extraction — the regressed capability |
| `deepset-prompt-injections` | 263 / 399 | Second attack family, multilingual |
| `dolly-benign`, `oasst1-benign` | 8,000 benign | FPR signal and matched-FPR calibration pool |

They are **contaminated for absolute claims** and usable only for ranking fine-tunes
of the same base model. See docs/13, "When nothing left can rank checkpoints", for the
admissibility rule and the gate that makes it falsifiable.
