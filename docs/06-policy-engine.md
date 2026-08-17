# 06 — Policy Engine

Decision record: [ADR-003](adr/ADR-003-policy-engine-design.md).
Failure semantics: [ADR-007](adr/ADR-007-detector-failure-semantics.md).

## Position in the system

```
DetectionResult[]  ──►  PolicyEngine.evaluate(results, config, direction)  ──►  PolicyDecision
                              (pure function)
```

The engine is the **only** component that decides. Detectors produce evidence; the handler
executes the decision. Neither decides.

```python
def evaluate(
    results: Sequence[DetectionResult],
    config: PolicyConfig,
    direction: Direction,
) -> PolicyDecision: ...
```

**Pure:** no I/O, no clock, no logging, no global state, no randomness. Same inputs → same
output, always. This is not stylistic — it is what makes the entire security decision surface
testable as a truth table in milliseconds with no models, no HTTP and no database
([16-testing-strategy.md](16-testing-strategy.md)).

## Actions

| Action | Meaning | Effect |
|---|---|---|
| `ALLOW` | Nothing triggered | Forward / return unchanged |
| `WARN` | Triggered, but observe only | Forward unchanged; record `warned=true`; increment metric. **Shadow-mode for a new detector** |
| `REDACT` | Triggered, content is repairable | Replace spans, then forward / return |
| `BLOCK` | Triggered, request or response must not proceed | `403` (or `503` for detector failure); not forwarded |

`WARN` is what makes a detector deployable at all: a new classifier runs in shadow mode
against production traffic, its false-positive rate is measured on real data, and only then is
it promoted to `BLOCK`. Without it, every threshold change is a gamble on live traffic.

## Algorithm

```
1. filter    drop results whose detector is disabled in config
2. classify  for each result:
                errored and on_error == fail_closed  → contributes BLOCK (detector_failure)
                errored and on_error == fail_open    → contributes nothing, recorded
                score >= threshold                   → contributes its configured action
                otherwise                            → contributes ALLOW
3. select    action = max(contributions, key=ACTION_PRECEDENCE)
4. attribute triggering_detector, category, reasons from the winning contribution
5. spans     if REDACT: union of spans from every redacting detector, overlaps merged
6. return    PolicyDecision(action, category, triggering_detector, reasons, results, spans)
```

### Precedence

```
BLOCK  >  REDACT  >  WARN  >  ALLOW
```

**Severity precedence, not detector priority and not ordering.** Two properties follow:

* **Order-independent.** The outcome does not depend on the order detectors ran or were
  configured. First-match-wins would make the result depend on invisible ordering.
* **Monotone.** Adding a detector can only make a decision more severe, never less. A new
  detector cannot silently weaken an existing protection.

### Conflict resolution — the question people ask

> One detector says ALLOW, another says BLOCK. What happens?

**BLOCK.** There is no voting, no averaging, no confidence-weighted fusion. An ALLOW is not
evidence of safety — it is the *absence* of evidence of one particular attack. A PII detector
returning ALLOW says nothing about injection. Treating absence of evidence as evidence of
absence, and letting it outvote a positive finding, is the bug this rule exists to prevent.

The cost is honest: **false positives compound.** With N detectors each at 1% FPR, the system
FPR approaches 1−(0.99)^N. This is why per-detector FPR is measured and reported, why
thresholds are chosen from published curves, and why `WARN` exists as the staging state
([13-evaluation-strategy.md](13-evaluation-strategy.md)).

> Two detectors both say BLOCK. Which is attributed?

The first in a deterministic order (registration order), with **all** results carried on the
decision. Attribution affects the audit record's `triggering_detector`, never the outcome.

> Why not weighted score fusion?

Scores from different detectors are not comparable and not calibrated
([05-detector-architecture.md](05-detector-architecture.md)). Summing them would be arithmetic
on incommensurable numbers. Revisit only if Phase 4 produces calibration curves —
[21-open-decisions.md](21-open-decisions.md) OD-4.

### Threshold semantics

Trigger is `score >= threshold`. Inclusive, so `threshold: 0.0` means "always trigger" and
`threshold: 1.0` means "only at maximum confidence" — both useful and both unsurprising.

Thresholds are **per detector** because scores are detector-local. A threshold is only
meaningful next to a precision/recall curve for that detector on a named dataset; choosing one
without that is guessing, and Phase 0 explicitly does not tune.

### Error handling

`GuardedDetector` records failures; the engine converts them. Keeping conversion here means
"what happens when a detector breaks" is part of the tested truth table rather than scattered
through the detector layer.

| Condition | `fail_closed` (default) | `fail_open` |
|---|---|---|
| Timeout | BLOCK, `category=detector_failure`, HTTP `503` | Contributes nothing; recorded `errored=true` |
| Exception | BLOCK, `category=detector_failure`, HTTP `503` | Same |

`detector_failure` is a **separate category** and is never counted as an attack — conflating
availability failures with detections would corrupt every security metric in the system.
`503` rather than `403` because this is the gateway being unavailable, not the user being
malicious, and client retry logic should be able to tell the difference.

## Configuration

Declarative YAML, validated at startup. Secrets are structurally rejected
([ADR-011](adr/ADR-011-configuration-model.md)).

```yaml
# config/policies/default.yaml
version: 1
policy_name: default

# Which message roles are inspected. `tool` is the indirect-injection surface:
# retrieved documents and tool output are attacker-controlled in any RAG system.
# `system` is trusted by default — enable it if you template user data into it.
inspect_roles: [user, tool]

input:
  prompt_injection:
    detector: injection.heuristic     # → injection.transformer in Phase 2
    enabled: true
    threshold: 0.85
    action: block
    on_error: fail_closed
    timeout_ms: 250

  jailbreak:
    detector: jailbreak.stub          # → jailbreak.transformer in Phase 2
    enabled: true
    threshold: 0.85
    action: warn                      # shadow mode: a stub must not block traffic
    on_error: fail_open               # a stub failing must not take the service down
    timeout_ms: 250

  pii:
    detector: pii.regex               # → pii.presidio in Phase 2
    enabled: true
    threshold: 0.50
    action: redact
    on_error: fail_closed
    timeout_ms: 100
    entities: [EMAIL, PHONE, CREDIT_CARD, IPV4, IBAN]
    custom_patterns:                  # enterprise identifiers; no secrets permitted here
      - name: EMPLOYEE_ID
        pattern: 'EMP-[0-9]{6}'

output:
  pii:
    detector: pii.regex
    enabled: true
    threshold: 0.50
    action: redact                    # redact on output; blocking a paid-for completion is worse
    on_error: fail_closed
    timeout_ms: 100
    entities: [EMAIL, PHONE, CREDIT_CARD]

  output_policy:
    detector: output.stub             # → Phase 3
    enabled: false
    threshold: 0.90
    action: block
    on_error: fail_closed
    timeout_ms: 250

redaction:
  style: labelled                     # <EMAIL_REDACTED>, not fixed-width masking
  template: "<{entity}_REDACTED>"

limits:
  max_inspect_chars: 100000
  max_messages: 200
  base64_segments: 8
```

Note the asymmetry between `input.pii` (redact) and `output.pii` (redact but fewer entities),
and between input-side `block` and output-side preference for `redact`. Input inspection is
prevention and blocking is cheap; output inspection is containment and the completion has
already been paid for ([03-request-response-flow.md](03-request-response-flow.md)).

### Startup validation

Every one of these prevents the process from starting:

| Rejected | Why |
|---|---|
| Secret-shaped key anywhere in the document | Secrets belong to the environment only |
| `threshold` outside `[0, 1]` | Silently unreachable policy |
| Unknown detector name | A typo would silently disable a control |
| Unknown action or `on_error` value | |
| `action: redact` on a detector that cannot emit spans | Would degrade to a no-op at runtime |
| Unknown role in `inspect_roles` | Would silently inspect less than intended |
| `enabled: true` with a detector that failed to construct | |

A policy error must never be a runtime surprise. Every `fail_open` detector is additionally
named in a startup **warning**, so an operator never discovers it mid-incident.

### Policy versioning

`policy_version = sha256(policy file bytes)`, recorded on every persisted decision. Without
it, "why was this blocked in March" is unanswerable after any config change
([11-data-model.md](11-data-model.md)).

Policy files live in git and change through review — a threshold change is a security-relevant
change and should appear as a diff. Hot-reload arrives in Phase 6 with an atomic swap and the
version change recorded in the audit trail.

## What the engine does not do

* It does not log — the caller persists the decision object, which is self-describing.
* It does not emit metrics.
* It does not know what a detector is, or what produced a score.
* It does not express conditions across detectors ("block only if injection **and** PII").
  This is a real limitation and the named revisit trigger in
  [ADR-003](adr/ADR-003-policy-engine-design.md).
* It does not vary by tenant, user or time of day.

## Verification

| Property | Test |
|---|---|
| Truth table: detector × score/threshold × action × error × `on_error` | `tests/unit/test_policy_engine.py` (parametrised) |
| Purity — no forbidden imports | `tests/unit/test_policy_purity.py` |
| Precedence is order-independent | Shuffled-input property test |
| Startup validation rejects each invalid case above | `tests/unit/test_policy_config.py` |
| `policy_version` matches file hash and changes with the file | `tests/unit/test_policy_version.py` |
| Redaction span merge on overlapping spans | `tests/unit/test_redaction.py` |

---

## Provenance as a policy input (ADR-017, Phase C)

`evaluate()` takes a fourth argument:

```python
evaluate(results, config, direction, provenance: ProvenanceContext | None = None)
```

`ProvenanceContext` carries `(provenance, trust)` and **nothing else**. Passing the
whole `DetectionContext` was rejected: it would hand the engine `raw_text`, which
breaks the property that makes the truth table enumerable and puts prompt content
one attribute access away from a decision path that must never log it.

`None` means "no provenance-conditional adjustment" — identical to the behaviour
before provenance existed, which is what keeps every prior caller correct.

### The overlay may only tighten

```yaml
input:
  prompt_injection:
    detector: injection.heuristic
    threshold: 0.85
    action: warn
    by_trust:
      untrusted:
        threshold: 0.60      # lower  = stricter → allowed
        action: block        # severer = stricter → allowed
```

A higher threshold or a less severe action **fails at policy load**, so a policy
that could weaken a decision cannot start. An operator learns from a failed
deployment, not from an incident review.

This inherits the engine's existing monotonicity: adding a detector can only make
a decision more severe, and now so can declaring an origin. The accepted cost is
that **provenance can never reduce false positives** — the obvious feature
("relax the threshold for authenticated users") is exactly the one an attacker
would forge, so it is unexpressible rather than discouraged.

### Two things provenance deliberately does not touch

**Detector failure.** `on_error: fail_closed` produces a BLOCK regardless of
trust. Failing closed is about availability of inspection, not about trust in a
source, and making it trust-conditional would let a policy author accidentally
turn a fail-closed detector into a fail-open one for some origins (ADR-007).

**Which messages are inspected.** `inspect_roles` gates on `role`, not provenance.
A caller cannot claim a provenance that skips inspection.

### Escalations are never silent

A provenance-driven change appends its cause to the contribution reason:

```
injection.heuristic:score=0.5500>=threshold=0.3000:trust=untrusted:threshold=0.3000:action=block
```

so it reaches `PolicyDecision.reasons` and the audit record. An operator reading a
block can always see that origin, not score, was what changed.
