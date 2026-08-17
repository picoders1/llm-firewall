# ADR-002: Pluggable Detector Architecture

**Status:** Accepted
**Date:** 2026-08-17
**Phase:** 0

## Context

Detection is the part of this system guaranteed to change. Today's best open prompt-injection
classifier will be superseded; the right PII engine differs by deployment; some operators
will want a cheap heuristic and others a 400 MB transformer. Meanwhile the surrounding
machinery — timeouts, failure handling, concurrency, audit records, metrics — must be
identical for every detector, because that machinery is where the security guarantees
actually live.

A gateway coupled to one model is a gateway that gets replaced instead of upgraded.

## Decision

A minimal `Detector` protocol, and everything cross-cutting lives outside it.

```python
class Detector(Protocol):
    name: str
    category: Category
    directions: frozenset[Direction]

    async def detect(self, ctx: DetectionContext) -> DetectionResult: ...
    async def warmup(self) -> None: ...
    async def aclose(self) -> None: ...
```

**A detector answers one question about one piece of text and returns evidence.** It must
not: choose an action, log content, touch the database, read global configuration, or import
`app.policy`.

Supporting pieces:

1. **`GuardedDetector`** wraps every registered detector with timeout, error capture and
   latency measurement (ADR-007). Detectors contain no `try/except` around their own work.
2. **`SyncDetectorAdapter`** bridges blocking, CPU-bound detectors onto the event loop via
   `anyio.to_thread.run_sync` behind a bounded semaphore.
3. **Registry** — an explicit dict of name → factory. Instances are built at startup from
   `PolicyConfig`, wrapped, warmed up, and grouped by direction.
4. **Pipeline** — runs a direction's detectors concurrently under `asyncio.gather`.
5. **Layering** — cheap deterministic checks may short-circuit to BLOCK, **never to ALLOW**.

Phase 0 registers stub detectors for jailbreak and output policy that return
`detected=False`, so the multi-detector path, config, events and tests are exercised from
day one and Phase 2/3 is substitution rather than integration.

## Score semantics

A score is detector-local, not comparable across detectors, and not a calibrated probability
unless that detector's documentation and an evaluation report say otherwise. Thresholds are
therefore per detector. The Phase 0 heuristic detector declares itself uncalibrated in its
docstring, its `metadata`, and its documentation — it is a benchmark control, not a security
claim.

## Alternatives considered

| Alternative | Rejected because |
|---|---|
| **One `SecurityService` with methods per check** | Simplest thing that works, and it works until the second implementation of anything. Adding a detector then means editing the class every caller depends on; testing a detector means constructing the whole service. |
| **Detectors return an action** | Collapses detection and policy. Threshold and action then live inside detector code, so changing "block" to "redact" is a code change and a redeploy, and the decision logic cannot be tested without the models. Explicitly forbidden (ADR-003). |
| **Entry-point / setuptools plugin discovery** | Real extensibility, real cost: implicit load order, dependency conflicts, and — for a security product — **a supply-chain hole where an installed package silently becomes part of the security decision**. A dict is enough until third-party detectors are an actual requirement. |
| **Chain of responsibility (each detector calls the next)** | Serialises what should be concurrent, and lets one detector suppress another. Fan-out plus a central decision is both faster and safer. |
| **Sync protocol with the pipeline handling threading** | Forces every I/O-bound detector (a future remote classifier) into a thread. Async protocol plus an adapter for sync implementations covers both without penalty. |
| **Per-detector timeout handling inside each detector** | Guarantees inconsistency, and one `except Exception: return clean` silently disables a control forever. |

## Consequences

### Positive
* Swapping heuristic → transformer is a registry line and a policy block; no caller changes.
* Detectors are trivially unit-testable: construct a `DetectionContext`, assert on a
  `DetectionResult`. No app, no database, no HTTP.
* Timeout and failure semantics are uniform and provable, in one file.
* The blocking-model hazard is handled before the first blocking model exists.
* Detectors are independently benchmarkable, which is what makes ADR-006's baseline
  comparison meaningful.

### Negative / accepted costs
* More indirection than a single service. Justified by the second detector, not the first.
* Fan-out means every enabled detector runs on every request, including after another has
  already found a blocking issue. This is deliberate — the audit record wants all scores,
  and the threshold-tuning data in `detector_results` depends on scores from detectors that
  did not fire. Short-circuit is available for the cheap layer where the cost is real.
* Uniform `DetectionResult` is a lowest common denominator; detector-specific richness lives
  in `metadata`, which is untyped.
* A dict registry means no third-party detectors without a code change. Accepted, and
  recorded as the revisit trigger.

### Revisit when
A third party genuinely needs to ship a detector out-of-tree; or `metadata` starts carrying
structure that the policy engine needs to interpret (which would mean the result contract is
wrong and should be extended properly).

## Verification

* `app/policy` contains no import of `app.detectors` and vice versa — checked by an
  import-boundary test.
* `Action` is not importable in any file under `app/detectors/` — checked by test.
* A detector added in a test fixture requires no changes outside its own module and one
  registry entry.
* `tests/unit/test_guarded_detector.py` proves timeout and exception paths produce
  `errored=True` results rather than propagating.
