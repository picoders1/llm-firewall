# ADR-021: Integrating the layer-2 transformer detector, warn-only

**Status:** Accepted. **Implemented 2026-08-18.**
**Date:** 2026-08-18
**Phase:** 2
**Follows** [ADR-014](ADR-014-detector-selection.md) (selection),
[ADR-015](ADR-015-fine-tuning-strategy.md) (fine-tuning),
[ADR-020](ADR-020-retention-preserving-training.md) (closed: no better model is coming).

> **The gap this closes is not a research gap.** Seven ADRs measured, fine-tuned,
> hold-out-validated and honestly failed a succession of models — and `app/`
> contained no ML detector at all. Every request was still decided by Phase 0
> heuristics. This integrates the selected checkpoint as **layer 2 in warn mode**.
>
> **It ships disabled.** Default behaviour is byte-identical to before.
> **It can never block.** Promotion needs OD-18, which needs the data this produces.

## Context

ADR-014 selected `protectai/deberta-v3-base-prompt-injection-v2` on measured
evidence. ADR-015 fine-tuned it, cutting quoted-attack FPR 0.875 → 0.0429, and
validated it on holdout-v3 where **all four FPR criteria were met**. ADR-020 then
established that no materially better single model is available at this size.

That checkpoint has never run in the gateway. The registry comment has said
`injection.heuristic → injection.transformer (Phase 2)` since Phase 0, and the
`SyncDetectorAdapter` thread-offload was built in Phase 0 *specifically* for this,
before any blocking detector existed. The integration point was designed and left
unused.

Meanwhile OD-18 — promoting layer 2 from warn to block — is blocked on
"shadow-mode FPR on real traffic", which cannot exist while the detector does not
run. The dependency is circular until something runs in warn mode.

## Decision

Register `injection.transformer` as a **layer-2, input-only, warn-only** detector,
**disabled in the default policy**.

Layer 2 does **not replace** layer 1. Both run, cheap first, per
docs/05-detector-architecture.md. The heuristic keeps threshold 0.85 and `block`;
nothing about it changes.

### Warn, not block

| evidence | why it forbids blocking |
|---|---|
| ADR-015 | four of six blocking criteria met; two recall criteria genuinely fail |
| ADR-016 | indirect-injection recall **0.1423** — 86% of indirect attacks pass |
| ADR-018 | provenance lifts that to 0.5365, but 46% still pass, and it used oracle segmentation |
| OD-3 | no threshold in this repository is calibrated against production traffic |

`action: warn` is recorded in policy, and a test asserts it is not `block`.
Promotion is a separate ADR that must cite shadow-mode false-positive data.

### Disabled, not enabled

Three independent reasons, any one sufficient:

1. **The weights are not in this repository and never will be.** Model weights are
   not committed (docs/14). `model_path` must point outside `app/`.
2. **The `ml` extra is not in the default install.** transformers and torch are
   optional dependencies.
3. **Latency, measured rather than assumed.** Every published figure for this model
   is CUDA. Production containers have no GPU.

### CPU latency — measured for this ADR

200 samples, single-sample, warm, tokenisation included, on the reference machine:

| | CPU (this ADR) | CUDA (published) |
|---|---|---|
| mean | 96.61 ms | 11.75 ms |
| p50 | 95.38 ms | 11.96 ms |
| p95 | 108.26 ms | 12.31 ms |
| p99 | 163.95 ms | 14.79 ms |
| max | 597.34 ms | 16.79 ms |
| throughput, single-threaded | **10.4/s** | 85.1/s |

**CPU is ~8× slower.** `timeout_ms` is set to 2000, which leaves ~12× headroom over
the measured p99 — sized for CPU, not for the CUDA numbers in the reports. The
throughput figure is the operationally significant one: 10.4/s single-threaded is a
capacity constraint an operator must plan for, and it is a further reason this
ships off. No gateway-overhead claim is made from these detector-only numbers.

### Failure semantics: fail-open, deliberately

Layer 2 is the only detector in this repository configured `fail_open`, which
inverts the ADR-007 default. The reasoning: **layer 1 inspects every request
regardless**, so a layer-2 outage costs *evidence*, not *enforcement*. Fail-closed
here would convert a model outage into a service outage while adding no security,
because the blocking decision does not depend on layer 2 in warn mode. It is named
in the startup warning like any fail-open detector.

A different failure is treated differently: **enabled but unavailable is a startup
error, not a per-request 503.** A missing `model_path`, a missing checkpoint, or a
missing `ml` extra raises `ConfigurationError` from `warmup()`. A security control
that cannot load should stop a deployment rather than quietly degrade one.

`detect()` before `warmup()` also raises rather than returning 0.0 — a silent zero
is indistinguishable from "no attack found".

## Consequences

**Unblocks OD-18.** Warn-mode operation is exactly the shadow-mode data collection
that promotion to blocking requires.

**Builds the path OD-34 needs.** ADR-020 concluded that mechanism coverage and
extraction retention do not fit in one model, promoting the layered-detector
question. A layered architecture needs precisely this: a second same-category
detector in the registry, running through the guarded pipeline, aggregated by
policy. That plumbing now exists and is exercised.

**Makes provenance exercisable.** ADR-017/2P-C shipped `consumes_provenance` and
the `by_trust` overlay with no detector using either. A real layer-2 detector is
the first candidate consumer, though this one declares `consumes_provenance: False`
— the fine-tuned checkpoint was trained and evaluated without provenance, and
claiming otherwise would be unfounded.

**Truncation becomes visible.** Text beyond the 512-token window is unseen by the
model. That is a detection gap, not a performance detail, so it is reported on
every result that hits it (`input_truncated_to_model_window`).

## What this ADR does not claim

* Not that the model is ready to block — it is not, and `warn` enforces that.
* Not that indirect injection is handled — 0.1423 stands (ADR-016).
* Not any production-traffic performance figure. The latency above is detector-only
  on one machine with one corpus; gateway overhead is unmeasured.
* Not that enabling it is advisable yet. It ships off, and turning it on is a
  reviewable policy edit an operator makes with the throughput number in hand.

## Verification

```bash
uv run pytest tests/unit/test_transformer_detector.py -q
uv run pytest -m "unit or api or security" -q
```

The registry, default-disabled state, warn action, locked threshold, absence of
weights from `app/` and from the container image, and the layer-boundary rule are
all asserted in `tests/unit/test_transformer_detector.py`.

## Revisit when

Shadow-mode false-positive data exists on real traffic (OD-18), or when OD-34's
layered-detector experiment needs a second registered detector.
