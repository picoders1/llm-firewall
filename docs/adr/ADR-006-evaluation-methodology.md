# ADR-006: Evaluation as a First-Class Component

**Status:** Accepted
**Date:** 2026-08-17
**Phase:** 0 (harness skeleton), Phase 4 (benchmarks)

## Context

Every LLM security product makes numerical claims, and most of them are unfalsifiable: no
dataset named, no split discipline, no denominator, no machine, no code. The claim
"blocks 95% of prompt injections" is compatible with a detector that blocks 95% of
*everything*.

For this project the evaluation methodology **is** the credibility. A gateway whose
detection quality is unmeasured is a gateway whose detection quality is unknown, and the
difference between this repository and a weekend demo is entirely in whether the numbers can
be reproduced by a stranger.

## Decision

**The evaluation harness is a first-class component with its own package, its own tests, and
its own CI job** — not a notebook, not a script that produced the README's numbers once.

Binding rules, enforced by the harness rather than by good intentions:

1. **No metric without a committed report.** Reports live in `eval/reports/` as JSON +
   Markdown, stamped with dataset checksum, git commit, configuration and machine metadata.
   Documentation cites the report file. Until a report exists the text reads
   `pending benchmark execution`.
2. **No metric without `n`.** Printed next to every figure.
3. **Deterministic, content-derived splits.** `sha256(sample_id) % 100` — no RNG, no shuffle
   order, no reshuffling when cases are added.
4. **Tune on `dev`, report on `test`.** Reporting a number after tuning thresholds on the
   same split is the field's most common self-deception.
5. **Baselines always.** Always-benign, always-attack, and the Phase 0 heuristic detector as
   the control condition. A new detector's value is its measured delta, not its absolute
   score.
6. **Precision, recall, F1, FPR and FNR reported together**, plus per-category recall. FPR on
   a large benign corpus is the headline, because it is what decides whether the thing is
   deployable.
7. **Threats to validity printed in every report**, including static-dataset bias, benchmark
   contamination of published models, and benign-corpus representativeness.
8. **Negative results are published** in the same report as positive ones.
9. **The harness never touches production traffic**, in either direction.
10. **LLM-as-judge is offline only**, never in the request path, and any judge used must have
    its agreement rate against human labels reported.

**Two runners**, because the two questions are different: `InProcessRunner` for detection
quality (no HTTP noise), `HttpRunner` for latency and throughput (measures what a client
actually experiences). Benchmark design is in
[performance-benchmarking.md](../15-performance-benchmarking.md).

Phase 0 builds the harness skeleton and runs it on ~40 hand-authored cases. That run is
labelled a **wiring test, not a benchmark**, in the report itself.

## Alternatives considered

| Alternative | Rejected because |
|---|---|
| **Evaluate later, ship features first** | Detection thresholds cannot be chosen without measurement, so "later" means shipping arbitrary thresholds and rationalising them afterwards. The harness is also what tells us whether Phase 2's model is worth its 400 MB. |
| **A notebook** | Not reproducible, not testable, not runnable in CI, and its outputs drift from the code that produced them. |
| **Reuse someone's published leaderboard number** | Measures their configuration, their thresholds and their machine — not this system. Useful as context, never as a claim about this gateway. |
| **Test on the training split for convenience** | The specific mistake rule 4 exists to prevent. |
| **Report accuracy as the headline** | With 90% benign traffic, "always allow" scores 90% accuracy. Accuracy is reported only alongside the confusion matrix. |
| **LLM judge in the production path for hard cases** | Doubles latency and cost, adds non-determinism to a security decision, and creates a second injectable surface. Offline only. |
| **Evaluate through the HTTP API only** | Adds network noise to detection-quality measurement for no benefit; and it would make CI evaluation require a running stack. |

## Consequences

### Positive
* Every claim in the repository is checkable by running one command.
* Threshold selection becomes an evidence-based decision with a published curve.
* Phase 2's model upgrade produces a number, not an assertion, and a model that fails to beat
  the heuristic baseline is caught before it ships.
* Regression detection: a committed report history makes "did that rule change hurt FPR"
  answerable.
* The validity-threats section forces honesty about what the numbers do not mean.

### Negative / accepted costs
* Real engineering effort spent on something that ships no user-facing feature.
* Dataset sourcing and licence verification is slow and genuinely unglamorous
  ([datasets.md](../14-dataset-strategy.md)).
* Split discipline means visible early numbers will be worse than tuned-on-test numbers
  would be. That is the point, and it must be said out loud when someone asks why the
  numbers are not higher.
* Latency benchmarks on a laptop-class machine characterise relative overhead only; they
  cannot be presented as production capacity.
* Public attack corpora are likely contaminated into published models' training data, so
  Phase 2 numbers on them are optimistically biased — reported as a known limitation rather
  than resolved.

### Revisit when
An adaptive/red-team evaluation loop is added (attacks generated against *this* deployment
rather than replayed from a static corpus) — the single most valuable methodological upgrade
available, and correctly a later phase.

## Verification

* `tests/evaluation/` — split determinism, metric correctness against hand-computed
  confusion matrices, report schema validity.
* The harness refuses to emit a report without machine metadata, dataset checksum and `n`.
* The harness refuses to emit latency metrics below the configured minimum iteration count.
* CI runs the smoke evaluation on every push, so the harness cannot rot.
* Any documentation change adding a numeric claim must cite a report path — enforced at
  review.
