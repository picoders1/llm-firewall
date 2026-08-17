# 00 — Project Overview

## What this is

**LLM Firewall** is a drop-in security gateway that sits between an application and any
OpenAI-compatible LLM endpoint. It inspects requests before they reach the model and
responses before they reach the user, applies a configurable policy, and produces an
auditable record of every decision.

Adoption is one line:

```python
client = OpenAI(base_url="http://localhost:8000/v1", api_key="...")
```

## The problem

An application that calls an LLM has no natural place to enforce security. Detection logic
gets duplicated into every service, coupled to one provider's SDK, untested and unmeasured.
Meanwhile the attacks that matter — an injection arriving inside a retrieved document, PII
leaking outward in a completion — cross the boundary between the application and the model,
which is exactly where nobody is looking.

Three consequences follow, and the design responds to each:

| Problem | Response |
|---|---|
| Security logic scattered across services | One inspected boundary, one policy, one audit trail |
| Detection quality unknown | An evaluation harness that is a first-class component, not a script |
| Guardrail latency claimed, never measured | Gateway overhead defined precisely and measured in production, not only in a rig |

## What it does

```
Client application
      │
      ▼
┌─────────────────────────────────────────────────────────────┐
│ LLM Firewall                                                │
│   validate → normalise → input detectors → policy           │
│   ├─ BLOCK  → 403, never forwarded                          │
│   └─ ALLOW/REDACT → forward                                 │
└──────────────────────────┬──────────────────────────────────┘
                           ▼
              OpenAI-compatible LLM upstream
                           │
┌──────────────────────────▼──────────────────────────────────┐
│   output detectors → policy → redact / block / allow        │
│   → security event + metrics + trace                        │
└──────────────────────────┬──────────────────────────────────┘
                           ▼
                    Client application
```

Capabilities, and their honest state:

| Capability | State |
|---|---|
| Prompt-injection detection | Heuristic baseline (Phase 0) → transformer classifier (Phase 2) |
| Jailbreak detection | Phase 2 |
| PII detection and redaction | Regex baseline (Phase 0) → Presidio (Phase 2) |
| Output policy enforcement | Path in Phase 0, detectors in Phase 3 |
| ALLOW / BLOCK / REDACT / WARN | Phase 0 |
| Security event logging and audit | Phase 0 |
| Observability (logs, metrics, traces) | Phase 0; exporters Phase 5 |
| Red-team evaluation with real metrics | Harness Phase 0, benchmarks Phase 4 |
| Latency and throughput benchmarking | Phase 4 |
| Docker / Compose deployment | Phase 0 |
| CI/CD | Phase 0 |
| Streaming | **Phase 6** — rejected with `400` until then, deliberately |
| Rate limiting | **Phase 6** — deploy behind a rate-limiting ingress until then |

## Design principles

1. **Detectors detect; the policy engine decides.** No detector returns a business action.
   This is what makes the entire security decision surface testable as a truth table with no
   models loaded. ([06](06-policy-engine.md), [ADR-003](adr/ADR-003-policy-engine-design.md))
2. **Fail closed, loudly.** A detector that times out or crashes blocks by default. A
   security control that fails silently is worse than one that fails visibly.
   ([ADR-007](adr/ADR-007-detector-failure-semantics.md))
3. **Never log the prompt.** The firewall sees every sensitive prompt in the system; storing
   them would make the security control the largest liability in the architecture.
   ([10](10-security-model.md), [ADR-012](adr/ADR-012-persistence-and-retention.md))
4. **No number without a run.** Every metric cites a committed report with its dataset
   checksum, git commit and machine metadata. Until then the text reads
   `pending benchmark execution`. ([13](13-evaluation-strategy.md))
5. **Refuse rather than fake.** Streaming returns `400` because inspecting a stream honestly
   is hard; shipping uninspected streaming while advertising protection would be a false
   security claim. ([07](07-openai-compatible-api.md))
6. **No provider lock-in.** OpenAI-compatible contract, swappable upstream, OTel rather than a
   vendor SDK. ([ADR-004](adr/ADR-004-openai-compatible-contract.md),
   [ADR-008](adr/ADR-008-observability-and-privacy.md))

## What it explicitly does not do

Stated up front, because a guardrail product that will not name its limits is not
trustworthy. Full analysis in [09-threat-model.md](09-threat-model.md).

* It does not **prevent** prompt injection. No current system does. It raises cost, provides
  visibility, and publishes its measured residual rate.
* It does not detect attacks assembled across multiple conversation turns — each message is
  inspected independently.
* It does not defend against an attacker who knows the detectors and adapts (white-box
  evasion).
* It does not authenticate callers, terminate TLS, or rate-limit (before Phase 6).
* It does not stop the application from bypassing it — if the app can reach the model
  directly, this gateway is advisory. Enforcing that is a network task.
* It makes no regulatory compliance claim of any kind.

## Current state

**Phase 0 — planning complete, implementation not started.**

No evaluation has been run. Every metric in this repository reads
`pending benchmark execution`. See [19-implementation-roadmap.md](19-implementation-roadmap.md).

## Reference machine

Recorded because every latency number this project ever publishes must name its machine.

| | |
|---|---|
| OS | Ubuntu 24.04.4 LTS, kernel 7.0.0 |
| CPU / RAM | 16 logical cores / 31 GiB |
| GPU | NVIDIA RTX 3050 Laptop, 4 GiB VRAM, driver 580.173 |
| Python | 3.12.3 |
| Docker | 29.7.2, Compose v5.4.0 |
| Occupied host ports | 5432 (local Postgres), 3000 — project uses **5434** and **3001** |

Laptop-class. Its figures characterise **relative overhead**, never production capacity.

## Document map

| Range | Contents |
|---|---|
| 00–01 | Overview, requirements |
| 02–04 | Architecture, flows, component design |
| 05–08 | Detectors, policy, API contract, PII |
| 09–12 | Threat model, security model, data model, observability |
| 13–15 | Evaluation, datasets, performance methodology |
| 16–18 | Testing, deployment, CI/CD |
| 19–22 | Roadmap, risks, open decisions, evidence ledger |
| `adr/` | ADR-001 … ADR-013 |

Index and reading order: [README.md](README.md).
