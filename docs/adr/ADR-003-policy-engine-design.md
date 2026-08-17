# ADR-003: Policy Engine as a Pure Function

**Status:** Accepted
**Date:** 2026-08-17
**Phase:** 0

## Context

Something must convert "the injection detector scored 0.91" into "return 403". That
conversion is the security behaviour of the product: it is what an auditor asks about, what
an operator tunes, and what must be provable.

If it is scattered — a threshold in the detector, an `if` in the route handler, an action
constant in a config file read three layers down — then nobody can state what the system
does without reading all of it, and it cannot be tested without booting all of it.

## Decision

One component decides, and it is a **pure function**:

```python
def evaluate(results: Sequence[DetectionResult], config: PolicyConfig) -> PolicyDecision
```

No I/O. No clock. No logging. No global state. Same inputs, same output, always.

**Algorithm:**

1. Drop results from detectors disabled in `config`.
2. For each result: if `errored`, apply that detector's `on_error`
   (`fail_closed` → contributes `BLOCK` with `category=detector_failure`; `fail_open` →
   contributes nothing, but is recorded). Otherwise it triggers when `score >= threshold`.
3. Each triggering detector contributes its configured action.
4. The decision is the **most severe** contributed action:
   `BLOCK > REDACT > WARN > ALLOW`.
5. `REDACT` collects spans from every redacting detector; overlapping spans are merged.
6. The decision carries the full result set, the triggering detector, the category and the
   reasons — so the audit record explains itself.

**Configuration** is declarative YAML, per detector:

```yaml
policies:
  prompt_injection:
    enabled: true
    threshold: 0.85
    action: block
    on_error: fail_closed
    timeout_ms: 250
```

**Startup validation** rejects incoherent policy before serving traffic: `action: redact` on
a detector that cannot produce spans, a threshold outside `[0, 1]`, an unknown detector name,
or an unknown action. A policy error is a startup failure, never a runtime surprise.

Input and output are **separate evaluations** with separate configuration, because the right
action differs by direction (see [output-inspection.md](../03-request-response-flow.md)).

## Alternatives considered

| Alternative | Rejected because |
|---|---|
| **Detectors return actions** | Buries policy in detector code. Changing an action becomes a code change; the decision surface cannot be tested without loading models; and two detectors disagreeing has no defined resolution. |
| **Decision logic in the route handler** | Where it always ends up by default. Requires an HTTP client and a running app to test one boolean, and it duplicates across the input and output paths — which is precisely how the two drift apart. |
| **Rules DSL / OPA / Rego** | Genuinely powerful and the right call for complex multi-tenant authorisation. Here it adds a language, a runtime and a debugging surface to express `score >= threshold → action`. Revisit if per-tenant or conditional policy becomes a requirement. |
| **First-match-wins ordering** | Makes the outcome depend on detector order, which is invisible in config and easy to get wrong. Severity precedence is order-independent and explainable in one sentence. |
| **Weighted score fusion across detectors** | Statistically attractive, but scores from different detectors are not comparable or calibrated (ADR-002), so a weighted sum would be arithmetic on incommensurable numbers. Revisit only after calibration data exists from Phase 4. |
| **Impure engine (logs, emits metrics, writes events)** | Convenient, and it destroys the property that makes this component trustworthy. The caller logs; the engine decides. |

## Consequences

### Positive
* The entire security decision surface is one function, testable as an exhaustive truth
  table: every combination of detector × threshold × action × error state, in milliseconds,
  with no models loaded. This is the single highest-value test in the repository.
* An operator can change a threshold or an action by editing YAML and restarting — no
  redeploy, no code review of security-critical logic.
* Explaining a block is mechanical: the decision object carries its own reasoning, and
  `policy_version` on the audit row ties it to the exact policy that produced it.
* Severity precedence means adding a detector cannot silently weaken an existing decision.

### Negative / accepted costs
* Expressiveness is limited to per-detector threshold and action. No "block only if
  injection *and* PII", no per-tenant policy, no time-based rules. This is a real limitation
  and the named revisit trigger.
* Purity means the engine cannot log its own reasoning; callers must persist the decision
  object or the reasoning is lost. Mitigated by making the decision object self-describing
  and by testing that it is persisted.
* Severity precedence can be surprising: one detector configured to `warn` and another to
  `block` yields a block. Correct, but it must be documented for operators.

### Revisit when
Cross-detector conditions or per-tenant policy become a real requirement; or Phase 4
produces calibration data that makes score fusion defensible.

## Verification

* `tests/unit/test_policy_engine.py` — the truth table, including every `on_error` path.
* `app/policy/engine.py` imports nothing from `app.detectors`, `app.database`,
  `app.gateway`, `logging` or `time` — checked by an import test.
* `tests/unit/test_policy_config.py` — invalid policies fail at load, with the specific
  cases enumerated above.
* `policy_version` appears on every persisted decision — integration test.
