# ADR-007: Fail-Closed by Default

**Status:** Accepted
**Date:** 2026-08-17
**Phase:** 0

## Context

Detectors fail. A model file is missing after a bad deploy, an ONNX session throws on a
pathological input, a thread pool saturates under load, a remote classifier times out.

The question is what the gateway does at that moment — and it is the most consequential
default in the system, because the failure mode nobody notices is a firewall that has
quietly stopped inspecting. Every request still returns `200`. Dashboards look healthy.
Protection is gone.

There is a real tension: fail-closed converts a detector bug into an outage of the protected
application. That is not a small cost, and pretending otherwise would be dishonest.

## Decision

**`fail_closed` is the default for every security-critical detector**, configurable per
detector.

Mechanism, split deliberately across two components:

* `GuardedDetector` **records** the failure — timeout or exception becomes
  `DetectionResult(errored=True, error_kind=...)`, with the exception logged server-side
  (traceback, never content). It does not decide.
* The **policy engine converts** it: `fail_closed` contributes `BLOCK` with
  `category=detector_failure`; `fail_open` contributes nothing but is still recorded.

Keeping conversion in the engine means "what happens on failure" is part of the exhaustively
tested truth table rather than scattered through the detector layer.

Supporting requirements, without which the default is not survivable:

1. **Per-detector timeouts** (default 250 ms) so a hang is bounded and detection cannot
   consume the request budget.
2. **`firewall_detector_errors_total{detector, error_kind}`** — an alerting metric. The
   correct response to a failing detector is to fix it, not to survive it.
3. **A separate error category.** `detector_failure` blocks are never counted as attacks;
   conflating them would corrupt every security metric in the system.
4. **`/ready` fails** when a detector cannot warm up, so a broken instance is removed from
   the load balancer instead of blocking every request it receives.
5. **Fail-open is loud.** Every `fail_open` detector is logged with a warning at startup,
   naming it. An operator should never discover it by reading YAML during an incident.
6. **Distinct client error.** A `detector_failure` block returns `503`, not `403` — this is
   the gateway being unavailable, not the user being malicious, and a client's retry logic
   should be able to tell the difference.

## Alternatives considered

| Alternative | Rejected because |
|---|---|
| **Fail-open by default** | The failure nobody notices. Protection silently disappears while every signal says healthy, and an attacker who can induce detector errors (large inputs, pathological Unicode, load) gets a universal bypass (threat T-12). For a security control this is the wrong default even though it is the more available one. |
| **Fail-open with an alert** | Depends on someone reading the alert during the window. The window is the exposure, and it is unbounded. |
| **Global fail mode rather than per detector** | Too coarse. An experimental output detector and the primary injection classifier do not warrant the same posture. |
| **Retry the detector before failing** | Retrying a timeout under load makes the load worse, and doubles the latency budget of the failure path. |
| **Degrade to the cheap heuristic when the ML detector fails** | Superficially attractive, and it silently changes the security posture to something weaker while continuing to report success. Detection quality would differ from what the policy claims, invisibly. Rejected for the same reason as fail-open. |

## Consequences

### Positive
* Protection cannot silently disappear. The system's worst failure mode is loud.
* Inducing detector errors is not a bypass primitive.
* Detector bugs surface as incidents with a metric and an alert, so they get fixed.
* Failure handling is uniform, in one place, and covered by the truth-table tests.

### Negative / accepted costs
* **A detector bug becomes an application outage.** This is the real cost. It is accepted
  because a security control that fails silently is worse than one that fails loudly, and
  because timeouts plus `/ready` bound the blast radius.
* Under sustained load, detector timeouts could cascade into broad blocking. Mitigated by
  bounded thread pools, conservative timeouts, and the fact that `/ready` will drop a
  saturated instance — but the risk is real and belongs in the runbook.
* Operators unfamiliar with the default will be surprised by `503`s during a bad deploy.
  Documented in the README, the hardening guide and the startup logs.
* `fail_open` remains available, so a deployment can reintroduce the risk. Deliberate: the
  right posture for an experimental detector differs from a primary one, and the choice is
  visible in config and in startup warnings.

### Revisit when
Production data shows detector failures are common enough that fail-closed causes more harm
than the exposure it prevents — which would be evidence that the detectors need fixing
first, not that the default is wrong.

## Verification

* `tests/security/test_fail_closed.py` — a detector that raises, and one that hangs past its
  timeout, both produce `503` with `category=detector_failure`.
* `tests/security/test_fail_open.py` — a `fail_open` detector's failure does not block and is
  recorded with `errored=true`.
* `tests/unit/test_policy_engine.py` — error handling in the truth table.
* `tests/unit/test_startup_warnings.py` — every `fail_open` detector is named in a startup
  warning.
* `/ready` returns `503` when a detector's `warmup()` fails — API test.
