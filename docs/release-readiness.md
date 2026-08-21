# Release Readiness Matrix

The Phase 18 audit. Every capability was verified **against the code and against a
running system**, not against the document that describes it. Where the two
disagreed, this audit changed the document — or, twice, the code.

**Status vocabulary**

| | Meaning |
|---|---|
| **PASS** | Implemented, covered by automated tests, and observed working in an integration or live check. |
| **PARTIAL** | Implemented and tested, with a named limitation that a deployment must know about. |
| **BLOCKED** | Cannot be marked ready. Nothing here is blocked at the time of writing. |
| **DEFERRED** | Deliberately not built, with the evidence or decision that deferred it. |
| **SUPERSEDED** | An earlier roadmap item replaced by a better implemented equivalent. |

**PASS requires all four of**: implementation, automated tests, integration or live
evidence, and documentation that matches. Documentation alone never earns a PASS —
this project has now found four capabilities that were fully documented and
partially or never enforced, and one (`/metrics`) that was documented, tested, and
broken.

Test counts are collected counts from `uv run pytest --collect-only`, at
**1676 passing / 42 skipped** for the suite as a whole.

---

## Request path

| Capability | Implementation | Automated tests | Integration / live evidence | Docs | Status | Known limitation |
|---|---|---|---|---|---|---|
| OpenAI-compatible gateway | `app/api/v1/chat.py`, `app/gateway/upstream.py` | `test_chat_completions.py` (24), `test_end_to_end.py` (11) | Live: benign → 200 with upstream +1 | [07](07-openai-compatible-api.md) | **PASS** | No SDK-level conformance test against the real `openai` package |
| Normalisation preserving offsets | `app/core/normalize.py` | `test_normalize.py` (51), `test_redaction.py` (15) | Redaction spans map back to raw bodies end to end | [ADR-010](adr/ADR-010-normalization-and-offsets.md) | **PASS** | — |
| Detector pipeline, concurrent + guarded | `app/detectors/pipeline.py`, `GuardedDetector` | `test_pipeline.py` (10), `test_guarded_detector.py` (11) | — | [05](05-detector-architecture.md) | **PASS** | — |
| Fail-closed on detector error/timeout | `GuardedDetector`, policy `on_error` | `test_slice_invariants.py` (21) | Live: 503 `detector_failure`, upstream not called | [05](05-detector-architecture.md) | **PASS** | A detector configured `fail_open` passes traffic uninspected; named in a startup warning, not prevented |
| Policy engine decides; detectors do not | `app/policy/engine.py` | `test_policy_engine.py` (43), `test_layer_boundaries.py` (50, AST-based) | — | [06](06-policy-engine.md) | **PASS** | — |
| Streaming inspection | — | — | — | [07](07-openai-compatible-api.md) | **DEFERRED** | `stream: true` returns `400`. Inspecting a token stream requires buffering decisions this project has not designed; refusing is honest, silently passing it through would not be |

## Detection

| Capability | Implementation | Automated tests | Integration / live evidence | Docs | Status | Known limitation |
|---|---|---|---|---|---|---|
| Heuristic injection / jailbreak | `app/detectors/heuristics/` | `test_baseline_detectors.py` (51) | Live: injection → 403, upstream +0 | [05](05-detector-architecture.md) | **PARTIAL** | **They recognise published phrasings and miss anything reworded.** This is the entire enforcement path today |
| PII redaction (structured identifiers) | `app/detectors/pii/` | `test_redaction.py` (15) | Live: `EMAIL`/`PHONE`/`CREDIT_CARD` counted in `security_events.details` with no values | [08](08-pii-security.md) | **PARTIAL** | Structured identifiers only — no names, addresses or organisations |
| Presidio-based PII | — | — | — | [08](08-pii-security.md) | **DEFERRED** | The regex baseline covers the identifier classes; adding spaCy plus two Presidio packages to the runtime image needs evidence that has not been produced |
| Layer-2 transformer detector | `app/detectors/transformer.py` | `test_transformer_detector.py` (17) | Registered, **disabled**, warn-only | [ADR-021](adr/ADR-021-layer2-transformer-integration.md) | **PARTIAL** | **Ships off and cannot block.** Blocking is refused on evidence: indirect recall 0.1423 ([ADR-016](adr/ADR-016-indirect-injection-delivery-shape.md)) |
| Provenance-aware context | `app/core/provenance.py`, persisted columns | `test_provenance*.py` (134+65+16+11 unit, 12+15 security) | Recorded on every audit row | [ADR-017](adr/ADR-017-provenance-aware-detection-context.md) | **PARTIAL** | Carried, recorded and **never consulted by a decision**: `by_trust` overlays are absent from the shipped policy and no threshold is calibrated (OD-3) |
| Output disclosure / exfiltration detectors | `output.stub` registered, disabled | — | — | [03](03-request-response-flow.md) | **DEFERRED** | Not built. The output direction currently carries PII redaction only |

## Identity and abuse

| Capability | Implementation | Automated tests | Integration / live evidence | Docs | Status | Known limitation |
|---|---|---|---|---|---|---|
| Operator authentication | `app/middleware/auth.py`, `app/auth/identity.py` | `test_operator_auth.py` (35), `test_auth_identity.py` (34), `test_auth_boundary.py` (13) | Manual: nginx strips a client-supplied identity header | [ADR-023](adr/ADR-023-operator-authentication.md) | **PASS** | Verified against the reference proxy only; a third-party identity proxy has never been integrated (R-61) |
| Caller authentication (`/v1/**`) | `app/middleware/caller_auth.py`, `app/auth/caller.py` | `test_caller_auth.py` (43), `test_caller_boundary.py` (14) | Every negative asserts `upstream.call_count == 0` | [ADR-024](adr/ADR-024-llm-caller-authentication.md) | **PASS** | Enforced per process; a fleet shares no state |
| Upstream credential isolation | `app/gateway/upstream.py` | `test_upstream_credential_isolation.py` (16) | Signature asserted on Protocol and implementation | [ADR-024](adr/ADR-024-llm-caller-authentication.md) | **PASS** | — |
| Edge rate/connection limiting | `deploy/docker/edge/`, `compose.edge.yaml` | `test_edge_abuse_protection.py` (14) | `test_edge_proxy.py` (10) drives real nginx in CI | [ADR-025](adr/ADR-025-edge-abuse-protection.md) | **PARTIAL** | **Every shipped limit is a development default, not measured** (R-67) |
| In-process admission control | `app/middleware/admission.py`, `app/auth/admission.py` | `test_admission.py` (19) | — | [ADR-025](adr/ADR-025-edge-abuse-protection.md) | **PARTIAL** | Off by default; per-process, so an N-replica ceiling is N× the configured one |
| Transport (HTTPS) enforcement | `app/middleware/transport.py`, `app/auth/transport.py` | `test_secure_transport.py` (26) | `test_tls_edge.py` (19), `test_tls_failure_modes.py` — real TLS handshakes | [ADR-026](adr/ADR-026-secure-transport.md) | **PASS** | The application verifies TLS; it never terminates it. Certificate expiry mid-run is not detected (R-69) |

## Audit and data lifecycle

| Capability | Implementation | Automated tests | Integration / live evidence | Docs | Status | Known limitation |
|---|---|---|---|---|---|---|
| Audit persistence | `app/database/repository.py` | `test_audit_integrity.py` (16), `test_audit_privacy.py` | Live: both rows written for a block and an allow | [ADR-012](adr/ADR-012-persistence-and-retention.md) | **PASS** | An audit-write failure does not fail the request unless `require_audit=true` — deliberate |
| No content columns anywhere | `app/database/models.py` | `test_audit_privacy.py` (metadata-asserted) | Live canary: prompt, email, card and API key absent from every audit row | [11](11-data-model.md) | **PASS** | Hashes prove sameness, not secrecy |
| Bounded async audit writer | `QueuedAuditRepository` | `test_audit_queue.py` | Measured: 500/500 healthy, 109 dropped-and-counted against a stalled database | [ADR-029](adr/ADR-029-audit-write-architecture.md) | **PASS** | A `SIGKILL` loses what is queued — 49/300 measured (R-80). Code default stays `sync` |
| Audit retention | `app/database/retention.py` | `test_retention_policy.py` (18), `test_retention_safety.py` | `test_retention.py` — 9 tests against real PostgreSQL | [ADR-030](adr/ADR-030-audit-retention.md) | **PARTIAL** | **Off by default** (R-84). Backups outlive retention and the gateway cannot see them (R-83) |
| Purge safety (no aimable predicate) | `_eligible_ids`, one `DELETE` | `test_retention_safety.py` | Compiled SQL asserted against the PostgreSQL dialect | [ADR-030](adr/ADR-030-audit-retention.md) | **PASS** | — |
| Least-privilege database role | — | — | — | [ADR-012](adr/ADR-012-persistence-and-retention.md) | **DEFERRED** | **The role split was never implemented in any manifest**; the application connects as the table owner and since Phase 16 needs `DELETE` (R-82). Restoring it is OD-43 |

## Observability and operations

| Capability | Implementation | Automated tests | Integration / live evidence | Docs | Status | Known limitation |
|---|---|---|---|---|---|---|
| Prometheus metrics | `app/observability/metrics.py` | `test_metrics_endpoint.py` (16) | **A live Prometheus reports the target `up`** — it did not until Phase 18 fixed R-87 | [12](12-observability.md) | **PASS** | Counters are per process; every fleet threshold must aggregate |
| Bounded label cardinality | `bounded_label` | security test drives 80 model names | — | [12](12-observability.md) | **PASS** | — |
| Alert rules | `deploy/alerts/firewall.rules.yaml` | `test_alert_rules.py` (88) | `promtool test rules`: 24 cases, all 16 alerts; `FirewallHTTPSEnforcementDisabled` observed **firing** live | [ADR-031](adr/ADR-031-alerting-and-incident-response.md) | **PARTIAL** | **Most thresholds are unvalidated development defaults** (R-88), labelled as such in both the rules and the runbook |
| Incident runbook | `docs/runbook.md` | `test_alert_rules.py` binds it to the rules in both directions | — | [runbook](runbook.md) | **PARTIAL** | Written from the code and the design; **no entry has been followed through a real incident** |
| Readiness contract | `app/api/readiness.py` | `test_readiness.py` (23), `test_readiness_contract.py` (16) | Live `/ready` breakdown | [ADR-027](adr/ADR-027-readiness-contract.md) | **PASS** | Most security-boundary checks re-assert startup invariants and cannot fail in a correct process (R-71) |
| Security Operations API | `app/api/dashboard/` | `test_dashboard_api.py` (34), `test_dashboard_privacy.py` (29) | Live canary: no leakage on any of 8 routes | [contract](dashboard-api-contract.md) | **PASS** | Read-only by construction; non-`GET` refused at the boundary |
| Security console | `dashboard/` | `test_dashboard_frontend_safety.py` (63), `test_dashboard_static.py` (13), node tests | — | [ADR-022](adr/ADR-022-dashboard-frontend-architecture.md) | **PARTIAL** | **Never visually reviewed on a real display**; verified structurally |
| OTLP / Langfuse exporter | — | — | — | [ADR-008](adr/ADR-008-tracing-and-telemetry.md) | **DEFERRED** | Nothing has asked for distributed traces, and shipping telemetry to a third party is a decision a security gateway should not make by default |
| Grafana dashboards as code | — | — | — | [19](19-implementation-roadmap.md) §5.4 | **SUPERSEDED** | The console answers "what is happening" from the audit trail, and Phase 17's rules answer "should someone act". A third view of the same data, in a tool this deployment does not run, would be maintained by nobody |

## Deployment and supply chain

| Capability | Implementation | Automated tests | Integration / live evidence | Docs | Status | Known limitation |
|---|---|---|---|---|---|---|
| Production topology | `compose.prod.yaml` | `test_deployment_topology.py` (43) | `test_prod_topology.py` (12) probes a running stack | [ADR-028](adr/ADR-028-production-deployment-manifests.md) | **PASS** | No rolling updates in plain Compose (R-74) |
| Non-root, capability-dropped image | `deploy/docker/Dockerfile` | `test_container.py` | Verified: `uid=10001(app)`, read-only rootfs, no compilers, no weights, no secrets | [17](17-deployment-architecture.md) | **PASS** | The **edge** container's master process runs as root — standard nginx — mitigated by `cap_drop: ALL` plus four named capabilities |
| Build context hygiene | `.dockerignore` | `test_image_build_context.py` (11) | Image `/app/eval` reduced 21 MB → 264 KB in this phase | [ADR-032](adr/ADR-032-release-candidate-readiness.md) | **PASS** | — |
| Secret handling | file mounts, `SecretStr` | `test_settings.py` (28), `test_deployment_topology.py` | No secret in any image layer or env | [ADR-011](adr/ADR-011-configuration-model.md) | **PASS** | Rotating a database secret does not rotate the database password (R-76) |
| Kubernetes manifests | — | — | — | [OD-41](21-open-decisions.md) | **DEFERRED** | No measured sizing and no cluster to validate against. Writing manifests nobody can run is how fictional infrastructure enters a repository |
| Frontend tests | `tests/frontend/*.test.mjs` | 13 node tests | **Now run in CI** — there was no frontend job until Phase 19, and the documented invocation had been broken since Node 22 | [ADR-022](adr/ADR-022-dashboard-frontend-architecture.md) | **PASS** | — |
| Dependency audit | `uv.lock` | CI `security` job | `pip-audit --skip-editable`: **No known vulnerabilities found** | [18](18-ci-cd-strategy.md) | **PASS** | `torch` is not on PyPI in its CUDA build and cannot be audited by `pip-audit`; it is not a runtime dependency of the application |
| Image vulnerability scan | CI `trivy-action`, both images | `test_image_build_context.py` | **Executed locally (Phase 19), Trivy 0.58.2**: application 36 HIGH → **0**, edge 21 HIGH → **0**. Remote CI result **still unobserved** | [ADR-033](adr/ADR-033-release-scanning-and-base-image-patching.md) | **PARTIAL** | Local scan, not the CI-built artefact. The edge had never been scanned by anything before this phase |
| Secret scanning | CI `gitleaks-action`, `.gitleaks.toml` | — | **Executed locally (Phase 19), gitleaks v8.30.1** over 24 commits: 7 findings, all classified, **0 real credentials**; 0 after a per-finding allow-list, negative-controlled with two planted keys | [ADR-033](adr/ADR-033-release-scanning-and-base-image-patching.md) | **PARTIAL** | Local scan; the remote CI result is **still unobserved**. Each allow-list entry is a standing assertion nothing re-checks |

## Evaluation discipline

| Capability | Implementation | Automated tests | Integration / live evidence | Docs | Status | Known limitation |
|---|---|---|---|---|---|---|
| Frozen corpora, pinned hashes | `eval/datasets/` | `test_holdout_integrity.py` (21), `test_finetune_corpus.py` (20) | Hashes asserted per run | [14](14-dataset-strategy.md) | **PASS** | — |
| Pre-registered protocols | ADR-014 → ADR-020 | `test_adr019_experiment.py` (20), `test_adr020_*.py` (60) | Two experiments recorded as **FAILURE** and not promoted | [13](13-evaluation-strategy.md) | **PASS** | — |
| Hold-out scoring budget | `eval/schema.py:require_tunable` | `test_eval_framework.py` (49) | Enforced at the library boundary | [13](13-evaluation-strategy.md) | **PASS** | — |
| Performance benchmark | `eval/runners/benchmark.py` | `test_benchmark_isolation.py` | Phase 15 matrix committed with machine metadata | [15](15-performance-benchmarking.md) | **PARTIAL** | Laptop-class reference machine; **no SLO is claimed and none may be derived** |
| Evidence ledger | `docs/22-evidence-and-claims.md` | — | Every claim names the artefact required first | [22](22-evidence-and-claims.md) | **PASS** | — |

---

## What this audit changed

Two code defects, both found by checking a running system rather than reading a
document:

1. **`/metrics` could not be scraped by any Prometheus** (R-87, found in Phase 17,
   recorded here for the release record). The endpoint declared
   `application/openmetrics-text` while emitting the Prometheus text format. Two
   tests asserted the wrong content type and passed. Fixed; a live scrape now
   guards it.
2. **The production image shipped 17 MB of per-sample benchmark data** (Phase 18).
   The `.dockerignore` excluded `predictions*`, `*.csv` and `*.svg` and claimed to
   ship "~200K of result.json"; Phase 15 then began writing `raw_results.jsonl`,
   which none of those patterns match. Replaced with an allow-list of the single
   filename the dashboard opens, bound to the code by test. Image 238 MB → 217 MB.

Documentation corrected in this phase: the "Phase 0 — implementation not started"
banner in the project overview, the "does not authenticate callers, terminate TLS,
or rate-limit" limitation, seven "Not started" phase rows in the README, the
threat model's "designed, not implemented" provenance heading and its B4 row
asserting a least-privilege role split that was never built, and CLAUDE.md's
description of the detector registry.

## The honest summary

Everything an operator would touch is built, tested, and observed working. What
remains genuinely weak is stated plainly and is not a matter of engineering
completeness:

* **Enforcement is heuristic.** The detectors that decide every request recognise
  published phrasings. The measured classifier that would do better is disabled,
  because the evidence says it should be.
* **Almost every operational number is a guess.** Rate limits, admission ceilings
  and alert thresholds are development defaults (R-67, R-88). They are labelled
  everywhere they appear.
* **Nothing here has served production traffic.** Every runbook entry, every
  threshold and every capacity figure is derived from the design and from a
  laptop, and the first week of real traffic should be expected to change them.

This is a defensible release candidate, not a system with a production track
record, and the two should not be confused.
