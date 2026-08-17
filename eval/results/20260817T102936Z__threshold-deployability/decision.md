# OD-19 decision — WARN/SHADOW ONLY, fine-tuning required before blocking

**Outcome: OPTION B (warn/shadow) now, OPTION D (fine-tuning required) as the path
to blocking. Options A, C and E are rejected on evidence below.**

## The question

Does any operating point of ProtectAI DeBERTa-v3 v2 beat `injection.heuristic` by
enough to justify its false-positive and latency cost?

## Method

Thresholds selected on `public/dev` (n=2,018), which **excludes** the independent
hold-out. This mattered: the `full` benchmark contains the hold-out, and its dev
split carries 92 hold-out samples — calibrating there would have leaked the
hold-out into selection. `_assert_no_holdout` now raises if that happens.

Six operating points were frozen to `operating_points.json` **before** the
hold-out was scored. No threshold was changed afterwards.

## Results

| Point | Thr | Dev recall | Dev FPR | HO recall | HO FPR | HO hard-neg FPR |
|---|---|---|---|---|---|---|
| **heuristic (production)** | 0.85 | 0.4204 | 0.0000 | 0.3167 | **0.0241** | 0.0647 |
| fpr<=0.005 | 0.9995 | 0.8584 | 0.0028 | 0.8833 | **0.0678** | 0.1706 |
| fpr<=0.01 / 0.02 | 0.9850 | 0.8805 | 0.0067 | 0.9000 | 0.1050 | 0.2529 |
| fpr<=0.0241 / 0.025 | 0.0310 | 0.8850 | 0.0218 | 0.9500 | 0.1510 | 0.3588 |
| fpr<=0.05 | 0.0016 | 0.9204 | 0.0391 | 0.9500 | 0.1947 | 0.4353 |

### Finding 1 — dev FPR does not predict hold-out FPR

The generalisation gap is **5x to 24x**: the tightest point measured 0.28% on dev
and 6.78% on the hold-out. Any threshold chosen on public data understates real
false-positive behaviour by an order of magnitude. This alone invalidates
threshold-setting from public corpora.

### Finding 2 — the threshold cannot fix security-language false positives

This is the decisive result. At **0.9995** — effectively maximum confidence, the
most conservative point the sweep offers — the model still fires on:

| Category | ML @ 0.9995 | heuristic @ 0.85 |
|---|---|---|
| **quoted_attack** (incident reports quoting a payload) | **0.875** | 0.500 |
| **incident_response** (domain) | **0.412** | 0.294 |
| **security_operations** (domain) | **0.219** | 0.031 |
| code_with_attack_strings | 0.400 | 0.200 |
| security_policy | 0.200 | 0.000 |

Raising the threshold trades recall away without repairing the failure mode,
because the model is *confident* about these. They are not borderline scores near
the boundary; they are 0.99+ predictions on legitimate security work. **The
failure is representational, not a calibration problem.**

### Finding 3 — the security value is nonetheless real

| Metric | heuristic | ML @ 0.9995 |
|---|---|---|
| Attack recall (hold-out) | 0.3167 [0.213, 0.442] | **0.8833** [0.778, 0.942] |
| System-prompt extraction recall (n=45) | 0.2667 [0.160, 0.410] | **0.8444** [0.712, 0.923] |
| Overall benign FPR | **0.0241** | 0.0678 |
| Mean latency | **0.098 ms** | ~120 ms (≈1,200x) |

+56.7 points of recall for +4.4 points of FPR is a favourable exchange in the
aggregate, and the extraction gap is large and statistically separated. Rejecting
the model outright would discard genuine detection capability.

## Decision

**Option B — warn/shadow only.** The model is a strong *signal* and an unusable
*gate*. A 41% false-positive rate in incident response would block the security
team during an incident, which is the worst possible time and the worst possible
audience for this product.

**Option D — fine-tuning required** is the evidenced path to blocking. Finding 2
shows the false positives are systematic and characterisable (quoted attack text,
security-policy language, instructional prose aimed at humans), which is precisely
the profile that domain-specific training addresses. This phase does not fine-tune.

## Why the alternatives were rejected

* **A — Deployable.** Rejected: no frozen point reaches an FPR an enterprise
  security function could absorb, and the best one still blocks 87.5% of quoted
  incident reports.
* **C — Context-aware gating.** Rejected *as a sufficient answer*, not as an idea.
  Gating on role or tenant would help the `security_operations` domain, but
  `quoted_attack` and `human_instructions` appear in ordinary business traffic
  too, so gating narrows the blast radius without fixing the classifier. Retained
  as a possible mitigation alongside D.
* **E — Reject.** Rejected: 0.32 → 0.88 recall and 0.27 → 0.84 extraction recall
  are too large to discard. The heuristic alone leaves two thirds of hold-out
  attacks undetected.

## Consequences

* `injection.heuristic` remains the **only** production detector. Registry,
  threshold and gateway are unchanged by this analysis.
* The layered design in ADR-014 stands, with layer 2 fixed in `warn`.
* No FPR-based promotion criterion can be met by threshold selection alone; OD-18
  (warn→block promotion) is now blocked on D, not on more data.

## Reproduce

```bash
uv run python -m scripts.threshold_analysis
```
