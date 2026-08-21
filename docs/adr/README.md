# Architecture Decision Records

Each ADR records one decision that was expensive to make and would be expensive to reverse.
Decisions that are obvious, reversible, or purely stylistic do not get an ADR — a directory
full of trivia is where real decisions go to hide.

Unresolved questions are **not** here; they are in
[21-open-decisions.md](../21-open-decisions.md).

## Index

| ADR | Decision | Status | Primary doc |
|---|---|---|---|
| [001](ADR-001-technology-stack.md) | Technology stack and packaging | Accepted | [02](../02-system-architecture.md) |
| [002](ADR-002-detector-plugin-architecture.md) | Pluggable detector architecture | Accepted | [05](../05-detector-architecture.md) |
| [003](ADR-003-policy-engine-design.md) | Policy engine as a pure function | Accepted | [06](../06-policy-engine.md) |
| [004](ADR-004-openai-compatible-contract.md) | OpenAI-compatible contract; streaming deferred | Accepted | [07](../07-openai-compatible-api.md) |
| [005](ADR-005-pii-detection-strategy.md) | PII: regex baseline → Presidio | Accepted | [08](../08-pii-security.md) |
| [006](ADR-006-evaluation-methodology.md) | Evaluation as a first-class component | Accepted | [13](../13-evaluation-strategy.md) |
| [007](ADR-007-detector-failure-semantics.md) | Fail-closed by default | Accepted | [06](../06-policy-engine.md) |
| [008](ADR-008-observability-and-privacy.md) | OpenTelemetry-first; Langfuse as exporter | Accepted | [12](../12-observability.md) |
| [009](ADR-009-mock-upstream.md) | Ship a mock upstream service | Accepted | [15](../15-performance-benchmarking.md) |
| [010](ADR-010-normalization-strategy.md) | Index-preserving normalisation | Accepted | [05](../05-detector-architecture.md) |
| [011](ADR-011-configuration-model.md) | Split env settings from YAML policy | Accepted | [06](../06-policy-engine.md) |
| [012](ADR-012-persistence-and-retention.md) | Audit persistence and retention | Accepted, amended by 029 | [11](../11-data-model.md) |
| [013](ADR-013-deployment-strategy.md) | Compose first, Kubernetes conditionally | Accepted | [17](../17-deployment-architecture.md) |
| [014](ADR-014-detector-selection.md) | Layered detector selection; baseline retained as layer 1 | Accepted | [13](../13-evaluation-strategy.md) |
| [015](ADR-015-fine-tuning-strategy.md) | Fine-tuning strategy, pre-registered | **Executed → PARTIAL** | [13](../13-evaluation-strategy.md) |
| [016](ADR-016-provenance-aware-detection.md) | Indirect injection needs provenance, not a better classifier | Accepted | [09](../09-threat-model.md) |
| [017](ADR-017-provenance-aware-detection-context.md) | Provenance-aware `DetectionContext` | Accepted | [05](../05-detector-architecture.md) |
| [018](ADR-018-provenance-aware-detector-evaluation.md) | Provenance-aware evaluation protocol | **Executed → PARTIAL** | [13](../13-evaluation-strategy.md) |
| [019](ADR-019-mechanism-coverage-fine-tuning.md) | Mechanism-coverage fine-tuning protocol | **Executed → FAILURE** | [13](../13-evaluation-strategy.md) |
| [020](ADR-020-retention-preserving-training.md) | Retention-preserving successor training | **Executed → FAILURE** | [13](../13-evaluation-strategy.md) |
| [021](ADR-021-layer2-transformer-integration.md) | Layer-2 transformer integrated, warn-only, disabled | Accepted | [05](../05-detector-architecture.md) |
| [022](ADR-022-dashboard-frontend-architecture.md) | A browser console from the gateway, without a framework | Accepted | [23](../23-dashboard-frontend.md) |
| [023](ADR-023-operator-authentication.md) | Operator identity terminated at the ingress, enforced in-process | Accepted, amended by 024 | [17](../17-deployment-architecture.md) |
| [024](ADR-024-llm-caller-authentication.md) | Service API key for `/v1`, plus a per-caller ceiling | Accepted | [17](../17-deployment-architecture.md) |
| [025](ADR-025-edge-abuse-protection.md) | Volumetric limits at the edge, admission control in-process | Accepted | [17](../17-deployment-architecture.md) |
| [026](ADR-026-secure-transport.md) | TLS at the edge; the application verifies rather than assumes | Accepted | [17](../17-deployment-architecture.md) |
| [027](ADR-027-readiness-contract.md) | `/ready` as a security contract, with required vs advisory checks | Accepted | [17](../17-deployment-architecture.md) |
| [028](ADR-028-production-deployment-manifests.md) | Compose as the reference production target; topology asserted by test | Accepted | [17](../17-deployment-architecture.md) |
| [029](ADR-029-audit-write-architecture.md) | Audit writes move to a bounded drop-on-full queue | Accepted | [11](../11-data-model.md) |
| [030](ADR-030-audit-retention.md) | Audit retention: a batched, age-only deletion job with no aimable predicate | Accepted | [11](../11-data-model.md), [12](../12-observability.md) |
| [031](ADR-031-alerting-and-incident-response.md) | Alerting policy, incident runbook, and the conditions deliberately not alerted | Accepted | [12](../12-observability.md), [runbook](../runbook.md) |
| [032](ADR-032-release-candidate-readiness.md) | Release-candidate readiness audit: 46 capabilities graded against evidence | Accepted | [release-readiness](../release-readiness.md) |
| [033](ADR-033-release-scanning-and-base-image-patching.md) | Scanner allow-lists, base-image patching, and edge image scanning | Accepted | [release-ci-evidence](../release-ci-evidence.md) |

**Numbering note.** ADRs are numbered in the order the decisions were made and are never
renumbered — cross-references would rot. The brief's suggested ordering (ADR-007
Observability, ADR-008 Deployment) maps here to ADR-008 and ADR-013 respectively; ADR-007
covers failure semantics, which turned out to be a larger decision than anticipated and
earned its own record.

Model selection became **ADR-014** once Phase 2 produced the measurements, resolving OD-1.
Several later ADRs are *pre-registered protocols* rather than architecture decisions: their
status records the outcome of the experiment they registered, and a **FAILURE** there is a
result the project keeps, not a document to revise.

## Template

```markdown
# ADR-NNN: Title

**Status:** Proposed | Accepted | Superseded by ADR-XXX
**Date:** YYYY-MM-DD
**Phase:** N

## Context
The forces at play. What makes this hard.

## Decision
What we are doing, stated so it can be checked against the code.

## Alternatives considered
Each with the reason it was rejected. An ADR with no rejected
alternatives is a description, not a decision.

## Consequences
### Positive
### Negative / accepted costs
### Revisit when
The concrete trigger that should reopen this.

## Verification
How a reader confirms the code matches this ADR.
```

## Rules

* **Supersede, never edit.** A decision that changed gets a new ADR; the old one is marked
  `Superseded by ADR-XXX`. The history is the point.
* **Every ADR names the cost it accepts.** A decision with no downside was not a decision.
* **Every ADR names its revisit trigger**, so it can be retired on evidence rather than on
  feeling.
* **Every ADR has a Verification section.** An ADR nobody can check against the code becomes
  fiction within a month.
