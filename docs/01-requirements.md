# Requirements

Every requirement names the test that verifies it. A requirement with no verification hook is
a wish, and is not accepted into this document.

Status: **Specified** (agreed, not built) · **Implemented** (built and verified) ·
**Deferred** (scheduled, phase named).

---

## Functional requirements

### API contract

| ID | Requirement | Phase | Verified by | Status |
|---|---|---|---|---|
| FR-001 | The gateway shall accept OpenAI-compatible chat-completion requests at `POST /v1/chat/completions` such that an unmodified OpenAI SDK client can use it by changing `base_url` only. | 1 | `tests/api/test_chat_completions.py`, `tests/integration/test_openai_sdk.py` | Specified |
| FR-002 | The gateway shall forward unrecognised request fields to the upstream unchanged rather than dropping them. | 1 | `tests/api/test_passthrough.py` | Specified |
| FR-003 | The gateway shall return errors in the OpenAI error envelope, including a `request_id`. | 0 | `tests/api/test_error_envelope.py` | Specified |
| FR-004 | The gateway shall reject `stream: true` with `400 unsupported_feature` until streaming inspection is implemented. | 0 | `tests/api/test_streaming_rejected.py` | Specified |
| FR-005 | The gateway shall expose `GET /v1/models`, proxied from the upstream. | 1 | `tests/api/test_models.py` | Specified |
| FR-006 | The gateway shall expose `GET /health` (liveness, no external dependencies) and `GET /ready` (readiness, dependency-checked). | 0 | `tests/api/test_health.py` | Specified |
| FR-007 | `GET /ready` shall return 503 when policy is invalid, a detector failed to warm up, or the database is unreachable while `persist_events` is enabled. | 0 | `tests/api/test_readiness.py` | Specified |

### Detection

| ID | Requirement | Phase | Verified by | Status |
|---|---|---|---|---|
| FR-010 | The gateway shall execute all enabled input detectors before forwarding a request upstream. | 0 | `tests/api/test_pipeline_order.py` | Specified |
| FR-011 | Input detectors shall run concurrently, so detection-stage latency is the maximum, not the sum, of detector latencies. | 0 | `tests/unit/test_pipeline_concurrency.py` | Specified |
| FR-012 | The gateway shall inspect only messages whose role is in the configured `inspect_roles`, defaulting to `user` and `tool`. | 0 | `tests/unit/test_role_filter.py` | Specified |
| FR-013 | Text shall be normalised before inspection (invisible-character removal, confusable folding, NFKC, casefolding, whitespace collapse) with a preserved source-offset map. | 0 | `tests/unit/test_normalize.py`, `test_normalize_offsets.py` | Specified |
| FR-014 | Base64-encoded payloads within inspected text shall be decoded and made available to detectors, bounded by a configured segment cap. | 0 | `tests/unit/test_normalize.py` | Specified |
| FR-015 | The gateway shall provide a prompt-injection detector. | 0 (heuristic baseline) / 2 (classifier) | `tests/unit/test_injection_heuristic.py`, Phase 4 eval report | Specified |
| FR-016 | The gateway shall provide a jailbreak detector. | 2 | `tests/unit/test_jailbreak.py` | Deferred (P2) |
| FR-017 | The gateway shall provide a PII detector emitting character spans against the original text. | 0 (regex) / 2 (Presidio) | `tests/unit/test_pii_regex.py` | Specified |
| FR-018 | Each detector shall emit a structured result carrying detector name, detected flag, score, category, reasons, spans, latency and error state. | 0 | `tests/unit/test_detection_result.py` | Specified |
| FR-019 | Detectors shall not determine business action; `Action` shall not be importable within `app/detectors/`. | 0 | `tests/unit/test_layer_boundaries.py` | Specified |
| FR-020 | The gateway shall inspect model output before returning it to the client. | 0 (path) / 3 (detectors) | `tests/api/test_output_pipeline.py` | Specified |
| FR-021 | Output inspection shall cover tool-call arguments and markdown link/image URLs. | 3 | `tests/security/test_output_exfiltration.py` | Deferred (P3) |

### Policy

| ID | Requirement | Phase | Verified by | Status |
|---|---|---|---|---|
| FR-030 | A single policy engine shall map detection results to exactly one action per direction. | 0 | `tests/unit/test_policy_engine.py` | Specified |
| FR-031 | The policy engine shall be a pure function: no I/O, no clock, no logging, no global state. | 0 | `tests/unit/test_policy_purity.py` | Specified |
| FR-032 | The engine shall select the most severe contributed action, ordered `BLOCK > REDACT > WARN > ALLOW`. | 0 | `tests/unit/test_policy_engine.py` | Specified |
| FR-033 | A detector shall trigger when its score meets or exceeds its configured threshold. | 0 | `tests/unit/test_policy_engine.py` | Specified |
| FR-034 | The gateway shall block a request when a triggering detector's configured action is BLOCK, returning `403` and not forwarding upstream. | 0 | `tests/security/test_block.py` | Specified |
| FR-035 | The gateway shall redact matched spans and forward the modified content when the action is REDACT, on both directions. | 0 | `tests/security/test_redaction.py` | Specified |
| FR-036 | The gateway shall forward unchanged and record the finding when the action is WARN. | 0 | `tests/unit/test_policy_engine.py` | Specified |
| FR-037 | Policy shall be loaded from validated YAML; invalid policy shall prevent startup. | 0 | `tests/unit/test_policy_config.py` | Specified |
| FR-038 | Policy YAML containing keys resembling secrets shall be rejected at load. | 0 | `tests/unit/test_policy_config.py` | Specified |
| FR-039 | Input and output directions shall be independently configurable. | 0 | `tests/unit/test_policy_config.py` | Specified |

### Failure handling

| ID | Requirement | Phase | Verified by | Status |
|---|---|---|---|---|
| FR-040 | Each detector shall be bounded by a configured timeout. | 0 | `tests/unit/test_guarded_detector.py` | Specified |
| FR-041 | A detector timeout or exception shall produce a recorded error result, never propagate to the handler. | 0 | `tests/unit/test_guarded_detector.py` | Specified |
| FR-042 | Detector failure shall default to `fail_closed`, blocking with `category=detector_failure` and status `503`. | 0 | `tests/security/test_fail_closed.py` | Specified |
| FR-043 | `fail_open` shall be configurable per detector, and every fail-open detector shall be named in a startup warning. | 0 | `tests/security/test_fail_open.py`, `tests/unit/test_startup_warnings.py` | Specified |
| FR-044 | Upstream failures shall map to `502`/`504` without reflecting the upstream response body. | 1 | `tests/api/test_upstream_failures.py` | Specified |
| FR-045 | Audit-write failure shall not fail the request by default, shall log at ERROR and increment a metric; `require_audit=true` shall invert this. | 0 | `tests/integration/test_audit_failure.py` | Specified |

### Observability and audit

| ID | Requirement | Phase | Verified by | Status |
|---|---|---|---|---|
| FR-050 | Every request shall have a correlation ID, reusing a valid client `X-Request-ID` or generating one, echoed on every response. | 0 | `tests/api/test_request_id.py` | Specified |
| FR-051 | Client-supplied correlation IDs shall be validated for length and character set before use. | 0 | `tests/security/test_log_injection.py` | Specified |
| FR-052 | The gateway shall emit a structured security event per request, carrying decision, category, detector scores, latencies and status. | 0 | `tests/unit/test_security_event.py` | Specified |
| FR-053 | Inspected content shall not appear in logs at the default configuration. | 0 | `tests/security/test_log_leakage.py` | Specified |
| FR-054 | `content_logging=full` shall be downgraded to `hash` when the environment is production. | 0 | `tests/unit/test_settings.py` | Specified |
| FR-055 | Secrets shall never appear in logs, spans, audit records or error responses. | 0 | `tests/security/test_secret_leakage.py` | Specified |
| FR-056 | Security events shall persist to PostgreSQL via Alembic-managed schema, with no column capable of holding full prompt content (except the gated preview). | 0 | `tests/integration/test_audit_persistence.py`, `tests/unit/test_no_content_columns.py` | Specified |
| FR-057 | Each persisted decision shall record the `policy_version` and the threshold in force at decision time. | 0 | `tests/integration/test_audit_persistence.py` | Specified |
| FR-058 | The gateway shall expose Prometheus metrics at `/metrics`, with no label derived from user content. | 0 | `tests/api/test_metrics.py` | Specified |
| FR-059 | Gateway overhead shall be measurable per request, separately from upstream latency. | 0 | `tests/api/test_latency_fields.py` | Specified |

### Limits

| ID | Requirement | Phase | Verified by | Status |
|---|---|---|---|---|
| FR-060 | Requests exceeding `max_request_bytes` shall be rejected with `413` before the body is fully read. | 0 | `tests/security/test_body_limit.py` | Specified |
| FR-061 | Inspected text shall be truncated at `max_inspect_chars`, and truncation shall be recorded on the event. | 0 | `tests/unit/test_truncation.py` | Specified |
| FR-062 | Malformed requests shall be rejected with `400` and shall not reach the upstream. | 0 | `tests/api/test_malformed.py` | Specified |
| FR-063 | Block responses shall disclose category and request ID only — never score, rule name, or matched content. | 0 | `tests/security/test_block_response.py` | Specified |

### Evaluation

| ID | Requirement | Phase | Verified by | Status |
|---|---|---|---|---|
| FR-070 | An evaluation harness shall run a labelled dataset through detectors and policy without production traffic. | 0 (skeleton) / 4 | `tests/evaluation/test_runner.py` | Specified |
| FR-071 | The harness shall compute precision, recall, F1, FPR, FNR and per-category recall, reporting `n` with every metric. | 4 | `tests/evaluation/test_metrics.py` | Specified |
| FR-072 | Dataset splits shall be deterministic and content-derived, stable across machines and across dataset growth. | 0 | `tests/evaluation/test_splits.py` | Specified |
| FR-073 | Every report shall record dataset checksum, git commit, configuration and machine metadata; the harness shall refuse to emit a report without them. | 0 | `tests/evaluation/test_report.py` | Specified |
| FR-074 | The harness shall measure latency and throughput with the gateway enabled and disabled, isolating overhead from upstream latency. | 4 | `tests/evaluation/test_benchmark.py` | Deferred (P4) |
| FR-075 | No third-party dataset shall be committed; datasets shall be registered with source, licence and checksum. | 0 | Review + `tests/evaluation/test_registry.py` | Specified |

---

## Non-functional requirements

No numeric SLO appears below, because none has been measured. Each performance NFR names the
measurement that will establish its target.

| ID | Requirement | Verified by | Status |
|---|---|---|---|
| NFR-001 | Gateway overhead shall be measured and published under stated conditions, separately from upstream latency. **Target: to be set from the Phase 4 baseline.** | `eval/reports/bench-*.md` | Deferred (P4) |
| NFR-002 | Detection-stage latency shall be bounded by per-detector timeouts, so worst-case added latency is `max(timeouts)` per direction. | `tests/unit/test_guarded_detector.py` | Specified |
| NFR-003 | No blocking call shall execute on the event loop; CPU-bound detectors shall run in a bounded thread pool. | `tests/unit/test_sync_adapter.py`, ruff `ASYNC` rules | Specified |
| NFR-004 | Throughput shall be measured at multiple concurrency levels with error rates reported. | `eval/reports/bench-*.md` | Deferred (P4) |
| NFR-005 | Detector failures shall be observable via metric and alertable. | `tests/api/test_metrics.py` | Specified |
| NFR-006 | The security decision surface shall be unit-testable without models, HTTP or a database. | `tests/unit/test_policy_engine.py` runtime | Specified |
| NFR-007 | Security-critical behaviour shall have dedicated tests in `tests/security/`, and CI shall fail on any failure. | CI configuration | Specified |
| NFR-008 | The default configuration shall be the safe configuration (fail-closed, no content logging, tracing off). | `tests/unit/test_defaults.py` | Specified |
| NFR-009 | Configuration errors shall prevent startup rather than surfacing at request time. | `tests/unit/test_policy_config.py` | Specified |
| NFR-010 | The system shall run as a non-root container with a read-only root filesystem and dropped capabilities. | `tests/integration/test_container.py`, compose config | Specified |
| NFR-011 | Dependencies shall be pinned in a committed lockfile and scanned for known vulnerabilities in CI. | CI jobs | Specified |
| NFR-012 | The full stack shall start with `docker compose up` with no credentials and no network egress. | `tests/integration/test_end_to_end.py` | Specified |
| NFR-013 | Evaluation results shall be reproducible: identical dataset checksum, configuration and commit shall produce identical classification metrics. | `tests/evaluation/test_determinism.py` | Specified |
| NFR-014 | The gateway shall not depend on any single LLM provider; the upstream shall be swappable by configuration. | `tests/integration/test_upstream_swap.py` | Specified |
| NFR-015 | Type checking (`mypy --strict` on `app/`) and linting shall pass with no suppressions outside documented exceptions. | CI jobs | Specified |
| NFR-016 | Audit storage shall hold no prompt or completion content at production configuration. | `tests/unit/test_no_content_columns.py` | Specified |
| NFR-017 | Horizontal scalability shall be preserved: no request-scoped state outside the process, so instances are interchangeable. | Review; `tests/unit/test_no_global_state.py` | Specified |

---

## Explicit non-requirements

Stated so that absence is understood as a decision, not an oversight:

* The gateway does not authenticate or authorise callers — that belongs to the ingress.
* It does not terminate TLS.
* It does not rate-limit before Phase 6 — deploy behind a rate-limiting ingress.
* It does not detect attacks assembled across multiple conversation turns.
* It does not moderate benign-but-undesirable content, evaluate factuality, or detect
  hallucination.
* It does not inspect non-text modalities.
* It does not claim to prevent prompt injection — it raises cost, provides visibility, and
  publishes its measured residual rate.
