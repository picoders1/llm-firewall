# LLM Firewall — Documentation

This directory is the **single source of truth** for what is being built, why, and how it will
be verified. Code that contradicts these documents is a bug in one of the two.

**Current stage: release candidate — Phase 18 readiness audit complete
([ADR-032](adr/ADR-032-release-candidate-readiness.md), [release-readiness.md](release-readiness.md):
26 PASS, 13 PARTIAL, 6 DEFERRED, 1 SUPERSEDED, 0 BLOCKED).**
Enforcement is still entirely heuristic. A fine-tuned classifier is measured and integrated as
layer 2 but **ships disabled and can never block** ([ADR-021](adr/ADR-021-layer2-transformer-integration.md)).
Evaluation has been run: ADR-014 through ADR-021 record executed experiments — including two
recorded **failures** — each traceable to a committed report. Blocking on ML findings is
refused on evidence (indirect recall 0.1423, ADR-016).

A read-only Security Operations console ships at `/dashboard`
([ADR-022](adr/ADR-022-dashboard-frontend-architecture.md)). Since Phase 9 it and its APIs
require an operator identity terminated at a reverse proxy or ingress
([ADR-023](adr/ADR-023-operator-authentication.md)); the boundary is off outside production
and refused-at-startup within it. Since Phase 10 `/v1/**` requires a **caller** credential too
— a service API key on `Authorization: Bearer`, a separate boundary with its own setting and
principal type ([ADR-024](adr/ADR-024-llm-caller-authentication.md)). Port 8000 should still
not be published. Phase 11 added the layer that bounds anonymous *arrival*: a reference nginx
edge doing connection, rate and body limits ([ADR-025](adr/ADR-025-edge-abuse-protection.md)),
exercised against real nginx in CI, with a small in-process safety net behind it. Phase 12
added TLS to that edge ([ADR-026](adr/ADR-026-secure-transport.md)): certificates are runtime
mounts, the edge refuses to start on unusable material, and the application refuses operator
and gateway requests unless a trusted proxy asserts the client hop was HTTPS. Production
refuses to start plaintext. Phase 13 made `/ready` a contract over those boundaries rather
than over the process alone ([ADR-027](adr/ADR-027-readiness-contract.md)), and Phase 14 turned
the documented topology into `compose.prod.yaml` — enforced by test rather than by prose
([ADR-028](adr/ADR-028-production-deployment-manifests.md)).

`docs/19-implementation-roadmap.md` and the ADRs carry current state; prefer them over any
summary elsewhere.

## Reading order

| # | Document | Answers |
|---|---|---|
| 1 | [00-project-overview.md](00-project-overview.md) | What is this, and what does it deliberately not do? |
| 2 | [02-system-architecture.md](02-system-architecture.md) | How is it decomposed, and what are the layering rules? |
| 3 | [09-threat-model.md](09-threat-model.md) | What is defended, against whom, and what is out of scope? |
| 4 | [01-requirements.md](01-requirements.md) | What must it do, and which test proves each claim? |
| 5 | [adr/](adr/) | Why is it built this way, and what was rejected? |
| 6 | [13-evaluation-strategy.md](13-evaluation-strategy.md) | How do we know whether it works? |
| 7 | [19-implementation-roadmap.md](19-implementation-roadmap.md) | What gets built, in what order, and when is it done? |
| 8 | [20-risk-register.md](20-risk-register.md) | How could this fail, and what was changed to prevent it? |

## Contents

### Foundation
| Doc | Contents |
|---|---|
| [00-project-overview.md](00-project-overview.md) | Problem, capabilities, principles, non-claims, reference machine |
| [01-requirements.md](01-requirements.md) | FR-001…075, NFR-001…017, each naming its verifying test |

### Architecture
| Doc | Contents |
|---|---|
| [02-system-architecture.md](02-system-architecture.md) | Components, layering rules, dependency direction, concurrency model |
| [03-request-response-flow.md](03-request-response-flow.md) | Inbound path stage by stage; response path and the streaming problem |
| [04-component-design.md](04-component-design.md) | Module-by-module surface, dependencies, failure modes, object lifetimes |
| [05-detector-architecture.md](05-detector-architecture.md) | Detector protocol, guarding, concurrency, layered strategy, score semantics |
| [06-policy-engine.md](06-policy-engine.md) | Pure-function engine, precedence, conflict resolution, policy YAML |
| [07-openai-compatible-api.md](07-openai-compatible-api.md) | Supported surface, error contract, upstream config, streaming refusal |
| [08-pii-security.md](08-pii-security.md) | Entity coverage, redaction representation, false-positive controls |

### Security
| Doc | Contents |
|---|---|
| [09-threat-model.md](09-threat-model.md) | Assets, trust boundaries, attacker capabilities, T-01…T-23, scope table |
| [10-security-model.md](10-security-model.md) | Content-logging modes and retention; hardening baseline and delegated controls |

### Data and operations
| Doc | Contents |
|---|---|
| [11-data-model.md](11-data-model.md) | Six tables, indexes, retention, why no prompt column exists |
| [12-observability.md](12-observability.md) | Logs, metric catalogue, span structure, health vs readiness |
| [runbook.md](runbook.md) | Incident runbook: one entry per alert — meaning, evidence, mitigation, escalation, resolution — and the conditions deliberately not alerted |
| [release-readiness.md](release-readiness.md) | Phase 18 audit: every capability graded PASS/PARTIAL/DEFERRED/SUPERSEDED against implementation, tests, live evidence and docs |
| [release-ci-evidence.md](release-ci-evidence.md) | What each scanner and pipeline control actually produced, and in which environment |
| [release-checklist.md](release-checklist.md) | The gate between a release candidate and a tag |

### Evaluation
| Doc | Contents |
|---|---|
| [13-evaluation-strategy.md](13-evaluation-strategy.md) | Labels, splits, metric definitions, baselines, validity threats |
| [14-dataset-strategy.md](14-dataset-strategy.md) | Registry format, candidate sources, licensing policy |
| [15-performance-benchmarking.md](15-performance-benchmarking.md) | Overhead definition, conditions A–D, protocol, required metadata |

### Delivery
| Doc | Contents |
|---|---|
| [16-testing-strategy.md](16-testing-strategy.md) | Suite taxonomy, the two tests that matter most, conventions |
| [17-deployment-architecture.md](17-deployment-architecture.md) | Local environment; production topology, obligations, migrations |
| [18-ci-cd-strategy.md](18-ci-cd-strategy.md) | Eight blocking jobs, caching, what is deliberately not in CI |

### Planning
| Doc | Contents |
|---|---|
| [19-implementation-roadmap.md](19-implementation-roadmap.md) | Phases 0–7: objective, files, tasks, tests, acceptance, DoD, risks |
| [20-risk-register.md](20-risk-register.md) | Pre-mortem PM-1…PM-12 and risk register R-01…R-20 |
| [21-open-decisions.md](21-open-decisions.md) | OD-1…OD-12 genuinely unresolved, plus assumptions to validate |
| [22-evidence-and-claims.md](22-evidence-and-claims.md) | Every future claim, its required artefact, and the interview defence map |

### Decisions
[adr/](adr/) — ADR-001 … ADR-028, with index, template and numbering note.

## Standing rules

1. **No fabricated numbers.** Any latency, precision, recall or throughput figure must come
   from a committed evaluation report and must cite that report and its machine metadata.
   Where no such report exists the number is not written at all — see
   [22](22-evidence-and-claims.md), which lists both the claims that are supported and the
   ones this project refuses to make.
2. **No unearned claims.** "Production-ready", "enterprise-grade" and any regulatory
   compliance claim are prohibited. See [22](22-evidence-and-claims.md).
3. **Detectors do not decide.** Any code path where a detector returns a business action is a
   design violation ([ADR-003](adr/ADR-003-policy-engine-design.md)).
4. **Security-critical code fails closed.** A new `fail_open` default requires an ADR
   ([ADR-007](adr/ADR-007-detector-failure-semantics.md)).
5. **Prompts are not logged.** Any change that can emit inspected content at default
   configuration must be rejected ([10](10-security-model.md)).
6. **Every requirement names its test.** A requirement with no verification hook is a wish.
7. **Unresolved is stated, not implied.** Open questions belong in
   [21](21-open-decisions.md), not in hedged prose elsewhere.

## Conventions

* **Terminology is fixed.** *Detector* produces evidence; *policy engine* decides; *action* is
  one of ALLOW/WARN/REDACT/BLOCK; *direction* is input or output; *upstream* is the LLM
  endpoint; *gateway* is this system. These words are not used loosely.
* **Identifiers are stable and cross-referenced**: FR-/NFR- (requirements), T- (threats),
  ADR-, PM-/R- (pre-mortem, risks), OD- (open decisions), A- (assumptions).
* **Phase references** always mean the phases in [19](19-implementation-roadmap.md).
