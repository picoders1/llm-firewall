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
