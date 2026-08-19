# Threat Model

Scope: the LLM Firewall gateway itself and the traffic that flows through it. This document
states what the system defends, what it partially defends, and — most importantly — what it
does not defend. A guardrail product that will not name its own limits is not trustworthy.

Method is lightweight STRIDE-informed asset/boundary analysis. It is intended to be short
enough that people actually read it.

---

## 1. Assets

| # | Asset | Why an attacker wants it | Where it lives |
|---|---|---|---|
| A1 | End-user prompt content | Often contains PII, credentials, business data | In flight; hashed in audit |
| A2 | System prompt / instructions | Reveals business logic, enables targeted bypass | Client request, `system` role |
| A3 | Model completions | May contain PII or restricted content | In flight |
| A4 | Upstream API key | Direct financial cost; impersonation of the tenant | `Settings`, env only |
| A5 | Audit trail | Deleting it hides an attack; reading it maps defences | PostgreSQL |
| A6 | Policy configuration | Knowing thresholds enables tuned evasion; changing it disables defence | YAML + env |
| A7 | Gateway availability | Denial of the protected application | Process |
| A8 | Detector behaviour | Knowing what fires enables systematic bypass | Model weights, rules |

## 2. Trust boundaries

```
   ┌─ UNTRUSTED ─────────────────────────────────────────────┐
   │  End users of the client application                    │
   │  Retrieved documents, tool output, web content  ◄── the │
   │  most commonly underestimated boundary in LLM systems   │
   └────────────────────────┬────────────────────────────────┘
                            │ B1
   ┌─ SEMI-TRUSTED ─────────▼────────────────────────────────┐
   │  Client application (authored by the operator, but      │
   │  relays untrusted content and may be compromised)       │
   └────────────────────────┬────────────────────────────────┘
                            │ B2  ◄── the firewall's inspection point
   ┌─ TRUSTED (this system) ▼────────────────────────────────┐
   │  Gateway process · policy · detectors · audit sink      │
   └────────────────────────┬────────────────────────────────┘
                            │ B3
   ┌─ EXTERNAL ─────────────▼────────────────────────────────┐
   │  Upstream LLM provider (availability, confidentiality   │
   │  and integrity are all outside our control)             │
   └─────────────────────────────────────────────────────────┘
```

### 2a. Provenance and the B1/B2 boundary — designed, not implemented

The diagram above already places retrieved documents and tool output in
**UNTRUSTED**, and the client application in **SEMI-TRUSTED**. The gap this
project measured is that the firewall, sitting at B2, **cannot see the B1
crossing**: by the time bytes reach it, a retrieved document concatenated into a
`user` message is indistinguishable from something the human typed.

[ADR-017](adr/ADR-017-provenance-aware-detection-context.md) designs a channel for
the semi-trusted application to *declare* that crossing. Two consequences must be
stated in the threat model rather than in the design doc, because they bound what
the mechanism can ever achieve:

* **Provenance is a cooperation mechanism, not an authentication mechanism.** The
  caller *is* the semi-trusted application. The firewall cannot distinguish a
  correct claim from a compromised application's lie, and no cryptographic scheme
  fixes that while the application holds the key.
* **This is acceptable only because provenance may only *tighten*.** A hostile or
  compromised integration can decline to declare provenance and receive today's
  behaviour; it cannot declare provenance to obtain anything weaker, because
  loosening is not expressible in the policy schema. A design that allowed
  provenance to relax a threshold would convert B2 from an inspection point into a
  bypass.

**New threat, in scope:** T-21 below. The mechanism is implemented as of Phase
A+B; what it can achieve is bounded by the two points above, not by the quality of
the implementation.

| Boundary | Crossing | Controls |
|---|---|---|
| B1 | User/document content → application | Outside our control; the reason B2 must assume hostile input |
| B2 | Application → gateway | Size limits, schema validation, normalisation, detection, policy, audit |
| B3 | Gateway → upstream | Egress to a configured base URL only; key never logged; timeouts; response body never reflected to the client |
| B4 | Gateway → PostgreSQL | Least-privilege role, no `DROP`, no raw content columns |

**The critical observation:** content arriving in the `tool` role has crossed B1 without
ever being seen by a human, and the application relays it with the same syntactic status as
the user's own words. That is why `tool` is inspected by default
([request-flow.md §3](03-request-response-flow.md)).

## 3. Attacker capabilities (assumed)

| Attacker | Can | Cannot |
|---|---|---|
| **T1 — End user** | Send arbitrary prompts, observe responses and status codes, iterate rapidly, encode/obfuscate payloads | Read the audit trail, read policy config, reach the gateway's internal network |
| **T2 — Content supplier** (owns a page/document/tool the app ingests) | Plant instructions in content the model will read, target the app's known tools | Send requests directly, observe responses |
| **T3 — Malicious insider / compromised app** | Send crafted requests, alter the client-side call | Alter gateway policy or code (separate deploy path) |
| **T4 — Network observer** | See traffic if TLS is terminated incorrectly | Read plaintext under correct TLS |
| **T5 — Compromised upstream** | Return arbitrary, hostile completions | Reach the gateway's other dependencies |

We deliberately assume T1 and T2 are **adaptive**: they will observe which of their payloads
are blocked and iterate. Any defence evaluated only on a static dataset is evaluated against
a weaker attacker than the real one. This is stated in
[13-evaluation-strategy.md](13-evaluation-strategy.md) as a named validity threat.

---

## 4. Threats and treatment

Status legend: **Mitigated** — controls exist and are tested · **Partial** — meaningfully
reduced, not eliminated · **Out of scope** — architecturally not our job · **Planned** —
the control is designed but not yet built.

### Injection and manipulation

| ID | Threat | Status | Control | Residual risk |
|---|---|---|---|---|
| T-01 | Direct prompt injection ("ignore previous instructions") | **Partial** | Heuristic layer (P0) + transformer classifier (P2), threshold-gated BLOCK | No classifier is complete; novel phrasings and adaptive rewording evade. Measured, not assumed — see eval reports |
| T-02 | Indirect prompt injection via retrieved content | **Largely undetected — measured** | `tool`-role content is inspected, but recall is **0.1423** (n=520) and **no delivery shape is reliably detected** ([ADR-016](adr/ADR-016-provenance-aware-detection.md)) | The gap is now quantified rather than described. Six delivery shapes recorded **zero** detections. Blocking is refused on this basis. The structural cause is that provenance is absent from the detector's input; [ADR-017](adr/ADR-017-provenance-aware-detection-context.md) designs the fix but nothing is implemented |
| T-21 | **Spoofed provenance metadata** — a client asserts `trust=operator` on attacker-controlled content | **Mitigated (Phase A+B)** | No trust value is ever read from the wire; inline provenance claims are ignored unless `FIREWALL_TRUST_INLINE_PROVENANCE_CLAIMS` is enabled, and even then a claim may only **lower** trust | Enforced by `tests/security/test_provenance_spoofing.py` and an exhaustive monotonicity test over every role x claim pair. Loosening via policy is Phase C and is rejected at config load |
| T-03 | Jailbreak / persona escape (DAN-style) | **Partial** | Dedicated jailbreak detector (P2) | Long-tail, and multi-turn attacks are largely undetected — see T-11 |
| T-04 | Obfuscated payload (base64, homoglyph, zero-width, fullwidth) | **Mitigated** for the covered encodings | Index-preserving normalisation + base64 surfacing, with unit tests per evasion class | Rot13, custom ciphers, token-level splitting, image-embedded text are not covered |
| T-05 | System-prompt extraction | **Partial** | Input rules on extraction phrasing; output-side disclosure detection (P3) | Paraphrased or piecemeal extraction is hard to detect |

### Data protection

| ID | Threat | Status | Control | Residual risk |
|---|---|---|---|---|
| T-06 | PII sent to a third-party model | **Partial** | Input PII detection → REDACT/BLOCK; regex baseline (P0) → Presidio (P2) | Names, addresses and free-text identifiers are recall-limited; non-English coverage is weak. Never claimed as complete |
| T-07 | PII leaked in a completion | **Partial** | Output PII detection → span redaction (P3) | Same recall limits, plus paraphrased leakage |
| T-08 | The firewall itself leaking prompts via logs | **Mitigated** | Sink-level redaction processor, `content_logging=none` default, `full` refused in production, no prompt columns in the schema, dedicated leak test | A future contributor could add a new sink; mitigated by test, not by architecture alone |
| T-09 | Exfiltration via markdown image/link URL in output | **Planned (P3)** | Output URL inspection | Currently undetected — stated plainly |
| T-10 | Exfiltration via tool-call arguments | **Planned (P3)** | `tool_calls` argument inspection | Currently undetected |

### Evasion and defeat of the control

| ID | Threat | Status | Control | Residual risk |
|---|---|---|---|---|
| T-11 | Multi-turn / conversational attack split across messages | **Out of scope (P0–P5)** | — | Each message is inspected independently. A payload assembled across turns is not detected. Named explicitly because per-message inspection is the standard, rarely-disclosed limitation of this product category |
| T-12 | Detector failure or timeout used as a bypass (flood to induce timeouts) | **Mitigated** | `fail_closed` default, per-detector timeouts, `firewall_detector_errors_total` alerting | `fail_open` configurations reintroduce this by choice |
| T-13 | Threshold probing / oracle attack | **Partial** | Block responses reveal category only — never score, rule, or matched span | Status codes still leak one bit per request; rate limiting (P6) raises the cost |
| T-14 | Bypassing the gateway entirely | **Out of scope** | Network policy — the app must not be able to reach the upstream directly | Deployment concern, documented in [hardening.md](10-security-model.md); the gateway cannot enforce it |
| T-15 | Adaptive white-box evasion by an attacker who knows the detectors | **Out of scope** | — | Open-source detectors are inspectable. Defence-in-depth, not detection, is the answer |

### Infrastructure

| ID | Threat | Status | Control | Residual risk |
|---|---|---|---|---|
| T-16 | Oversized request → memory exhaustion | **Mitigated** | `max_request_bytes` enforced during body read; `max_inspect_chars` bounds detector work | |
| T-17 | Slowloris / connection exhaustion | **Partial** | Server timeouts; connection limits belong to the reverse proxy | Ingress responsibility |
| T-18 | Request flood / cost amplification | **Planned (P6)** | Rate-limit architecture designed, not implemented | Deploy behind a rate-limiting ingress until then — stated in README |
| T-19 | Upstream API key theft | **Mitigated** | Env-only, `SecretStr`, never logged or persisted, not in YAML (structurally rejected), not in the image | Process memory access implies host compromise |
| T-20 | Compromised or hostile upstream | **Out of scope** | Output inspection catches *some* hostile content | A compromised model provider is not a threat a proxy can solve |
| T-21b | Audit-trail tampering | **Partial** | Append-only usage, least-privilege DB role without `DROP` | No cryptographic chaining; a DB-level compromise defeats it. *(Numbering note: `T-21` was assigned twice — to spoofed provenance metadata above and to this row. Both IDs are cited elsewhere, so renumbering either would break those citations; this row is disambiguated as `T-21b` and new threats start at T-24.)* |
| T-24 | **Unauthenticated access to the Security Operations console** | **Mitigated (P9)** | Operator identity terminated at a reverse proxy or ingress and enforced by `app/middleware/auth.py`; access classes assigned by path and defaulting to operator-only; `console_auth_mode=disabled` refused in production ([ADR-023](adr/ADR-023-operator-authentication.md)) | The console exposes no content, but thresholds plus block rates by category describe how to tune an evasion — this is T-13 without the guesswork, which is why an internal-network assumption was not sufficient |
| T-25 | **Spoofed operator identity** — a client sets `X-Auth-Request-User` itself | **Mitigated (P9)** | No identity header is read until the socket's peer falls inside `FIREWALL_TRUSTED_PROXIES`. `X-Forwarded-For` is never consulted: it is client-supplied, so trusting it would let the attacker write their own permission slip. Malformed subjects are refused, not sanitised | The proxy must overwrite inbound copies of every identity header the application reads; that half runs in nginx and is asserted against the reference configuration, not executed (R-61). Structurally the same threat as T-21 provenance spoofing, and mitigated the same way — trust is derived, never received |
| T-26 | **Unauthenticated use of the gateway itself** | **Mitigated (P10)** | A service API key on `Authorization: Bearer`, verified against configured SHA-256 digests in middleware ahead of the handler, so a refusal costs no detector inference and never reaches the upstream ([ADR-024](adr/ADR-024-llm-caller-authentication.md)). `caller_auth_mode=disabled` is refused in production | Revocation requires a deployment: there is no expiry and no disabled flag, so a leaked key is live until the configuration changes. Rate limits bound the damage but are per process |
| T-27 | **Spoofed caller identity** — a client asserts `X-Firewall-Caller` itself | **Mitigated (P10)** | In proxy mode no caller header is read until the socket's peer falls inside `FIREWALL_CALLER_TRUSTED_PROXIES`; `X-Forwarded-For` is never consulted. A caller id the gateway does not recognise is refused even from the trusted peer | Same residual as T-25: the ingress must overwrite inbound copies, and that half is asserted against configuration rather than executed (R-61) |
| T-28 | **Budget exhaustion by an authenticated caller** | **Partial (P10)** | Per-caller sliding-window rate limit and concurrency ceiling, both off by default until a deployment has traffic to size them from | **Per process**: N replicas allow N times the limit. And the ceiling counts *requests*, not tokens — one caller sending very large prompts can outspend one sending many small ones inside the same limit |
| T-29 | **Audit trail used as a denial-of-service vector** | **Mitigated (P10)** | Failed caller authentication writes no database row; refusals are counted (`firewall_caller_auth_failures_total`) and logged instead | An authenticated caller can still generate rows at its rate limit, which is the intended behaviour |
| T-22 | Supply-chain compromise of a dependency | **Partial** | Pinned lockfile, `pip-audit` and image scanning in CI, minimal dependency count | Not eliminated by any control at this scale |
| T-23 | Malicious model weights (Phase 2) | **Partial** | Pinned model revision by digest, `safetensors` only, checksum verified at download | Trusting a model publisher is unavoidable when using a published model |

---

## 5. Scope summary

**Protected (controls exist and are tested)**
Oversized requests · malformed requests · known-pattern direct injection · covered
obfuscation classes · structured PII in single messages · secrets never logged or persisted ·
detector failure not silently degrading protection · full auditability of decisions.

**Partially protected (real reduction, measured, incomplete)**
Novel prompt injection · indirect injection · jailbreaks · system-prompt extraction ·
unstructured PII · threshold probing · audit integrity.

**Out of scope (stated, not solved)**
Multi-turn attack assembly · adaptive white-box evasion · attacks that bypass the gateway
at the network level · compromised upstream providers · model-level alignment and
truthfulness · hallucination · content moderation of benign-but-undesirable output ·
authentication and authorisation of the calling application (belongs to the ingress) ·
non-text modalities.

---

## 6. Explicit non-claims

The project does not claim, and no document in this repository may claim:

* that it prevents prompt injection — no current system does; it *raises cost and provides
  visibility*, and the residual rate is published;
* any regulatory compliance status (GDPR, HIPAA, SOC 2, EU AI Act);
* completeness of PII detection in any language;
* protection against attackers who can modify the gateway's configuration or code;
* that a passing evaluation on a benchmark predicts performance against an adaptive
  attacker.

## 7. Review triggers

Revisit this document when: a new detector or category is added; the inspected role set
changes; a new egress or storage destination is introduced; streaming inspection ships; or
an evaluation reveals a bypass class not listed above. Each triggers an update here **in the
same change**, not afterwards.
