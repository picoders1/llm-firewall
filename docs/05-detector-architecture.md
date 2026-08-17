# Detector Layer

## The contract

```python
class Detector(Protocol):
    name: str
    category: Category
    directions: frozenset[Direction]

    async def detect(self, ctx: DetectionContext) -> DetectionResult: ...
    async def warmup(self) -> None: ...  # load models at startup, not on request 1
    async def aclose(self) -> None: ...
```

A detector answers **one question about one piece of text and returns evidence**. It does
not decide, does not log content, does not touch the database, and cannot import
`app.policy`. That constraint is what makes the security decision surface testable in
isolation.

`DetectionResult` carries `detected`, `score`, `category`, `reasons`, `spans`, `metadata`,
`latency_ms`, and the failure fields `errored` / `error_kind`.

## Score semantics — stated because it is routinely got wrong

* A score is **detector-local**. `0.9` from the heuristic baseline and `0.9` from a DeBERTa
  classifier mean different things and are not comparable.
* A score is **not a calibrated probability** unless the detector's own documentation says
  so and a calibration curve exists in an evaluation report.
* Therefore thresholds are configured **per detector**, and a threshold change is only
  meaningful next to a precision/recall curve for that detector on a named dataset.

The Phase 0 heuristic detector returns a weighted rule-coverage score and says in its
docstring, in its `metadata`, and in [ADR-002](adr/ADR-002-detector-plugin-architecture.md)
that it is uncalibrated. That honesty is the point: it is a baseline to be beaten in
Phase 2, not a security claim.

## Guarding — timeouts and failure semantics in exactly one place

Every registered detector is wrapped:

```
GuardedDetector(inner, timeout_ms, on_error) 
    ├─ start monotonic timer
    ├─ await asyncio.wait_for(inner.detect(ctx), timeout)
    ├─ on success        → result with latency_ms attached
    ├─ on TimeoutError   → DetectionResult(errored=True, error_kind="timeout")
    └─ on Exception      → DetectionResult(errored=True, error_kind=type name)
                            (exception logged with traceback, never the content)
```

`GuardedDetector` **never decides**; it records the failure. The policy engine, reading
`errored=True` plus that detector's configured `on_error`, is what converts a failure into
`BLOCK` (`fail_closed`, the default) or into nothing (`fail_open`). Keeping the conversion
in the engine keeps the "what happens on failure" logic in the one place that is
exhaustively unit-tested.

Why this is centralised rather than left to each detector: the failure mode we most need to
prevent is a security component that stops inspecting without anyone noticing. If each
detector implemented its own `try/except`, one `except Exception: return no_finding` would
disable that protection permanently and silently. See
[ADR-007](adr/ADR-007-detector-failure-semantics.md).

## Synchronous models on an async server

Transformers, ONNX Runtime and Presidio are synchronous and CPU-bound. Awaiting them
directly would block the event loop for every concurrent request for the duration of the
inference.

```python
class SyncDetectorAdapter(Detector):
    """Bridges a blocking detector onto the event loop.

    Dispatches to a bounded thread pool. The semaphore matters: without it, N
    concurrent requests create N concurrent inferences, and CPU oversubscription
    turns a 20 ms model into a 2 s one under load.
    """

    async def detect(self, ctx):
        async with self._semaphore:
            return await anyio.to_thread.run_sync(self._detect_sync, ctx)
```

This exists in Phase 0 even though Phase 0 has no ML detector, because retrofitting it
after a blocking detector ships means retrofitting it after the first production incident.

Detectors also implement `warmup()`, called during lifespan startup, so model loading (~1–3 s
for a DeBERTa-class model) is paid once at boot and `/ready` does not report ready until it
has completed.

## Registry and pipeline

The registry is a dictionary from detector name to factory. Instances are constructed at
startup from `PolicyConfig`, wrapped in `GuardedDetector`, warmed up, and grouped by
direction. Adding a detector is: implement the protocol, register the name, add a policy
block. No discovery magic, no entry points.

The pipeline runs all enabled detectors for a direction concurrently:

```python
results = await asyncio.gather(*(d.detect(ctx) for d in detectors))
```

Wall-clock cost of the detection stage is the **slowest** detector, not the sum — which is
why per-detector latency, not just total latency, is recorded on every event.

## Layered detection strategy

The architecture supports cheap-first layering, and Phase 0 wires the ladder even though
only the first rung is built:

| Layer | Mechanism | Measured cost | Status |
|---|---|---|---|
| 1 | Deterministic heuristics over normalised text | **0.098 ms mean** (measured) | **Built** |
| 2 | Fine-tuned transformer classifier (DeBERTa-class) | **~120 ms mean, CPU, fp32** (measured) | **Selected**, not integrated ([ADR-014](adr/ADR-014-detector-selection.md)) |
| 3 | Stronger semantic guardrail model, sampled or on-escalation | not measured | Phase 6, evidence-gated |
| 4 | Policy decision | microseconds | **Built** |

The layer-2 latency is an order of magnitude worse than the ~10–40 ms this table
originally estimated, because it is fp32 on CPU. ONNX export and int8 quantisation
(OD-6) are the mitigation, and the estimate has been replaced with the measurement.

### Measured, on the frozen held-out split (n=2,051; 1,800 benign)

| Detector | Recall | Precision | FPR | mean ms |
|---|---|---|---|---|
| `injection.heuristic` (layer 1) | 0.4183 | **1.0000** | **0.0000** | **0.098** |
| ProtectAI DeBERTa v2 (layer 2 candidate) | 0.9283 | 0.9066 | 0.0133 | 119.99 |
| Arch-Guard (rejected) | 0.9402 | 0.9255 | 0.0106 | 124.38 |

Internal benchmark results; see [ADR-014](adr/ADR-014-detector-selection.md) for the
contamination caveat and the hold-out numbers that actually drove the decision. **This
is why layer 1 is retained**: zero false positives on 1,800 benign samples at 1/1200th
the cost is not something the classifier replaces.

Two rules govern the ladder:

1. **Layer 1 may short-circuit to BLOCK, never to ALLOW.** A cheap rule firing with high
   confidence can skip expensive layers. A cheap rule *not* firing proves nothing and must
   not suppress layer 2 — that would be an evasion primitive.
2. **No LLM judge in the request path.** Calling a model to guard a model doubles latency,
   doubles cost, and adds a second injectable surface. LLM-based judging belongs in the
   offline evaluation harness, clearly separated. See
   [ADR-006](adr/ADR-006-evaluation-methodology.md).

## Detectors planned

| Detector | Category | State | Target |
|---|---|---|---|
| `injection.heuristic` | `prompt_injection` | **Built** — 10 weighted rules over normalised text, raw text and decoded base64 | remains as layer 1 |
| `injection.transformer` | `prompt_injection` | — | Phase 2, ONNX-exported classifier |
| `jailbreak.heuristic` | `jailbreak` | **Built** — 8 rules, deliberately conservative weights | Phase 2 |
| `pii.regex` | `pii` | **Built** — email, phone, credit card (Luhn), IPv4, IBAN, custom patterns; emits spans | remains as layer 1 |
| `pii.presidio` | `pii` | — | Phase 2, replaces `pii.regex` behind the same interface |
| `output.policy` | `output_policy` | registered stub, disabled | Phase 3 |

`output.stub` is **registered and wired**, returning `detected=False`, so the pipeline,
config, event schema and tests exercise the real multi-detector path and Phase 3 is a
substitution rather than an integration.

### Scoring: noisy-OR over named rules

The two heuristic detectors combine rule weights as ``1 - Π(1 - w)``. Chosen over a sum
(which needs arbitrary clamping) and over a max (which ignores corroboration): it is bounded
in ``[0, 1)``, monotone in every input, and has an honest reading — each rule is an
independent weak signal, and agreement raises confidence without any single weak rule
reaching certainty.

Two consequences worth stating:

* Weights encode **how unambiguous a phrasing is in isolation**. Only a rule that is hard to
  write innocently (`ignore all previous instructions`, a forged `<|im_start|>` marker) earns
  enough weight to cross the default threshold alone. Fictional framing sits at 0.30 and can
  only ever corroborate.
* Hits are **deduplicated by rule id before scoring**, so repeating one phrase ten times is
  one piece of evidence repeated, not ten independent signals.

The score is **not a calibrated probability**, and the detectors say so in their own
`metadata` (`calibrated: false`, `baseline: true`) as well as in this document.

## What the heuristic baseline actually does

Weighted rules over normalised text, each contributing to a bounded score, with the
matched rule names returned in `reasons` for the audit record:

* instruction override (`ignore (all )?previous instructions`, `disregard the above`)
* role reassignment (`you are now`, `act as`, `pretend to be`, DAN-style framings)
* system-prompt extraction (`repeat your (system )?prompt`, `what are your instructions`)
* delimiter/scope injection (`### system`, `<|im_start|>`, fake chat-template markers)
* exfiltration framing (`send it to`, `output the above`, markdown-image exfil patterns)
* encoded-payload signal (a decoded base64 segment that itself matches any rule above)

It is a **baseline**, and the documentation says so everywhere it appears. Its purpose is
to be the control condition in Phase 4's evaluation: the transformer detector's value is
the delta over this on the same dataset, on the same machine, with the same harness. A
project that ships only this and calls it prompt-injection defence is doing the thing this
repository explicitly refuses to do.

---

## Provenance-aware detectors — capability shipped, no consumer yet

[ADR-017](adr/ADR-017-provenance-aware-detection-context.md), Phase C. The protocol
is **extended, not forked**, and **no shipped detector consumes provenance** —
asserted by `test_no_shipped_detector_claims_to_consume_provenance`. A detector
that starts reading provenance is a deliberate, separately evaluated change.

Legacy behaviour is pinned rather than assumed:
`test_legacy_detectors_score_identically_regardless_of_provenance` runs every
registered detector over the same text under five different
provenance/trust pairs and asserts identical score, spans and reasons.

```python
class Detector(Protocol):
    name: str
    category: Category
    directions: frozenset[Direction]
    emits_spans: bool
    consumes_provenance: bool = False  # NEW — advertisement, not a requirement
```

| Detector kind | `consumes_provenance` | Behaviour |
|---|---|---|
| Legacy — `injection.heuristic`, `pii.regex`, the stubs | `False` | Unchanged. Reads text, ignores provenance. Must produce byte-identical results. |
| Provenance-aware | `True` | May read `ctx.provenance` / `ctx.trust` and score differently |
| "Requires provenance" | — | **Deliberately not a supported category** |

Two decisions worth the reasoning:

**No parallel interface.** A second detector protocol would double the
`GuardedDetector`, pipeline and registry surface, and split the policy truth table
that [ADR-003](adr/ADR-003-policy-engine-design.md) depends on. One flag on the
existing protocol costs a line.

**No `requires_provenance`.** A detector that cannot function on `UNKNOWN`
provenance would fail on every legacy request, and the only safe response —
fail-closed per [ADR-007](adr/ADR-007-detector-failure-semantics.md) — would block
ordinary traffic. A capability mismatch must not become an outage. A detector that
wants provenance must degrade gracefully without it; one that genuinely cannot is
disabled by configuration.

**The detector still does not decide.** Provenance reaches the policy engine as its
own explicit input rather than through detector metadata, so a provenance-driven
change of action is declared in the policy file and visible in
`PolicyDecision.reasons`. Detector-specific policy behaviour stays impossible.
