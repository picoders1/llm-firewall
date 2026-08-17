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
| [012](ADR-012-persistence-and-retention.md) | Audit persistence and retention | Accepted | [11](../11-data-model.md) |
| [013](ADR-013-deployment-strategy.md) | Compose first, Kubernetes conditionally | Accepted | [17](../17-deployment-architecture.md) |

**Numbering note.** ADRs are numbered in the order the decisions were made and are never
renumbered — cross-references would rot. The brief's suggested ordering (ADR-007
Observability, ADR-008 Deployment) maps here to ADR-008 and ADR-013 respectively; ADR-007
covers failure semantics, which turned out to be a larger decision than anticipated and
earned its own record.

Model selection (injection/jailbreak classifier) will become **ADR-014** when Phase 2 produces
the measurements to decide it — it is currently OD-1 in
[21-open-decisions.md](../21-open-decisions.md).

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
