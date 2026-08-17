# Smoke fixture — NOT a benchmark

**Nothing in this directory may be reported as a project result.**

31 hand-authored cases, written by the same people who wrote the detection rules.
Its only job is to prove that the evaluation plumbing works:

* the case schema parses and carries stable `sample_id`s,
* detectors run deterministically over a labelled set,
* labels are handled correctly (positive = attack),
* per-category grouping works,
* the harness can be extended without redesign in Phase 4.

## Why its numbers are meaningless

* **n = 31.** Any metric computed here has confidence intervals wider than the
  metric.
* **Authored by the rule author.** The detectors were written knowing these cases
  exist. This is the textbook definition of tuning on the test set.
* **No realistic benign distribution.** The false-positive rate that decides
  whether this product is deployable needs a large, independent benign corpus —
  the hardest sourcing problem in the project (docs/14-dataset-strategy.md, R-02).

Real evaluation — licensed public corpora, deterministic `sha256(sample_id) % 100`
splits, precision/recall/F1/FPR/FNR with Wilson intervals, per-category recall and
published threats to validity — is Phase 4
(docs/13-evaluation-strategy.md, docs/19-implementation-roadmap.md).

## Licence

Authored for this repository, Apache-2.0, same as the project. All PII values are
**synthetic**: `example.com` addresses, the reserved `555-01xx` phone range, the
standard Luhn-valid test card, private/documentation IP ranges, and the standard
IBAN test value. No real personal data exists anywhere in this repository.

## Schema

One JSON object per line:

| Field | Meaning |
|---|---|
| `sample_id` | Stable identifier; determines the split, so it never changes |
| `category` | `benign`, `direct_prompt_injection`, `indirect_prompt_injection`, `jailbreak`, `pii`, `system_prompt_extraction` |
| `prompt` | The input under test |
| `expected_label` | `true` = attack (positive class) |
| `difficulty` | `easy` / `medium` / `hard` — author-assigned, for stratified reporting |
| `source` | Provenance |
| `language` | ISO code |
| `notes` | Why a case is interesting, especially near-miss benign cases |

The `hard` benign cases are the important ones: security-adjacent text
("explain how prompt injection works"), legitimate role assignment, and a
Luhn-invalid order number. A detector suite that fires on those is unusable no
matter how good its recall is.
