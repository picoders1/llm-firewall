# Hold-out v3 — independent evaluation corpus

**Frozen 2026-08-17.** `dataset_sha256` `0e26dd6b7d0f545c0bd68b64c2a0b4b60397f8ad41436754dc38b679fbbb28bf`

**Read-only.** Do not append, relabel, or regenerate. A change here invalidates
every result measured against it.

## Why v3 exists

v2 could not answer the question it was built for. ADR-015 requires that a
criterion whose Wilson 95% interval straddles its bound counts as **not met**.
Combined with v2's sub-corpus sizes, two criteria were unsatisfiable by any
model:

| Criterion | v2 n | Best possible | Wilson upper at best case | Required |
|---|---|---|---|---|
| quoted_attack FPR ≤ 0.15 | 16 | 0 FP | 0.1936 | ≤ 0.15 |
| incident_response FPR ≤ 0.10 | 17 | 0 FP | 0.1843 | ≤ 0.10 |

Strategy A measured a perfect **0/17** on `incident_response` and was still
recorded as failing it. A third criterion, extraction recall ≥ 0.80, was
reachable in principle but needed n≈292 at the observed 0.8444 — against v2's 45.

**v3 fixes the denominators. It does not touch the criteria.**

## Sizing — calculated, not guessed

Each target is the smallest n whose Wilson interval, *evaluated at the rate
Strategy A actually achieved on v2*, falls entirely on the satisfying side of the
bound. Sizing against a hypothetical perfect result would produce a corpus that
fails the moment the model makes one mistake.

| Category | Criterion | Observed on v2 | Minimum n | v3 n | Margin |
|---|---|---|---|---|---|
| quoted_attack | FPR ≤ 0.15 | 0.0625 | 55 | **70** | +15 |
| incident_response | FPR ≤ 0.10 | 0.0333 * | 69 | **110** | +41 |
| hard negatives (all) | FPR ≤ 0.10 | 0.0118 | 35 | **240** | +205 |
| benign (overall) | FPR ≤ 0.0241 | 0.0066 | 299 | **436** | +137 |
| attacks in scope | recall ≥ 0.80 | 0.8833 | 81 | **356** | +275 |
| system_prompt_extraction | recall ≥ 0.80 | 0.8444 | 292 | **296** | +4 |

\* `incident_response` measured 0/17 on v2. Zero cannot be assumed to hold at a
larger n, so it is sized against a conservative non-zero rate.

Reproduce: `uv run python -m scripts.datasets.build_holdout_v3 --sizing`

## Composition

792 samples: **436 benign** (240 hard negatives, 196 ordinary) and **356
attacks**, all in the injection detector's scope.

| Category | n |
|---|---|
| benign | 436 |
| system_prompt_extraction | 296 |
| direct_prompt_injection | 40 |
| indirect_prompt_injection | 20 |

Difficulty: 416 hard, 173 medium, 203 easy. Benign domains are led by
incident_response (110), software_engineering (43) and security_operations (41).

Generated from a documented matrix — context × document type × security topic ×
payload/reference × linguistic style × difficulty — over independently authored
pools in `scripts/datasets/authoring/holdout_v3_pools.py`. Deterministic:
seed 20260818.

## Independence

Nothing here is copied, paraphrased, or transformed from a v2 sample or a
training sample. Two design choices make this substantive rather than asserted:

* **The quoted attack payloads are deliberately disjoint from the 22 phrases in
  the fine-tuning corpus.** Each is semantically equivalent to something the
  model trained on and lexically distinct from all of it. A model that memorised
  the training strings earns nothing here.
* **The quoting frames are new document shapes** — SOC tickets, forensic
  timelines, detection-rule commentary, threat-intel digests, nested escalation
  quotes — not variants of v2's frames.

The v2 *category-level* error pattern informed which categories to expand. No
individual v2 text was inspected and transformed.

## Integrity (measured at build time)

| Check | Result |
|---|---|
| Exact collisions vs v2, training, dev, smoke, 5 public corpora | **0** |
| Normalised collisions vs the same | **0** |
| Internal near-duplicates (Jaccard ≥ 0.90) | **0** (4 pruned deterministically) |
| Cross-version near-duplicates vs v2 | **0** |
| Secrets | **0** |
| PII | **0** |
| Internal duplicates removed | 0 |

Corpora checked: hold-out v2 (531), fine-tuning train (3,006) and dev (808),
smoke (31), deepset-prompt-injections (662), dolly-benign (4,000),
jackhhao-jailbreak (1,286), lakera-gandalf (999), oasst1-benign (4,000).

All identifiers, ticket numbers, hostnames and names are synthetic. No real
customer, employee, or credential material appears anywhere.

## Relationship to v2

**v2 is not superseded and not modified.** It remains at
`eval/datasets/holdout/cases.jsonl` under its pinned hash
`fd91575272056d3b282804ddfbbbde63`, and it remains the artefact behind the
Strategy A result. v3 is an *additional* independent hold-out with adequate
statistical power.

## Schema

```json
{"sample_id": "holdout3-b-0001", "text": "...", "label": 0,
 "category": "benign", "sub_category": "quoted_attack",
 "domain": "incident_response", "difficulty": "hard", "language": "en",
 "source": "internal_authored", "source_type": "synthetic",
 "created_at": "2026-08-17", "generation_method": "matrix: ...",
 "holdout_version": "v3", "notes": "hard_negative"}
```

## Limitations

1. **Compositional, like the training corpus.** Diversity is bounded by the
   authored pools. This is the same weakness the fine-tuning corpus has, and it
   is why the *lexical disjointness* from training matters more than the sample
   count.
2. **English only.**
3. **`system_prompt_extraction` carries 296 of 356 attacks**, because that is what
   the recall criterion required. Aggregate attack recall on v3 is therefore
   dominated by extraction and is not comparable to v2's attack mix.
4. **Sized against Strategy A's v2 rates.** If the true rates differ materially,
   the margins shrink — the `system_prompt_extraction` margin of +4 is thin.
5. **One authoring source.** No second author reviewed these samples
   independently.
