# 08 — PII Detection and Redaction

Decision record: [ADR-005](adr/ADR-005-pii-detection-strategy.md).

## Two problems under one name

PII detection is the most immediately valuable feature of an LLM gateway and the one most
often overclaimed. It is really two problems with different achievable accuracy:

| | Structured identifiers | Unstructured identifiers |
|---|---|---|
| Examples | email, phone, credit card, IBAN, IP, employee ID | person name, address, employer, identifying free text |
| Method | patterns + checksums | NER |
| Precision | High — Luhn and mod-97 eliminate most false positives | Moderate |
| Recall | High within covered formats | **Structurally limited, in every system that exists** |
| Language sensitivity | Low | High |

The standard false claim is "we detect PII", demonstrated on an email address. This project
separates the two, reports them separately, and says which one it is doing.

## Pipeline position

```
raw message
     │
     ▼  normalise (offset map preserved)
DetectionContext
     │
     ▼  PII detector → spans against raw_text + entity labels
DetectionResult
     │
     ▼  PolicyEngine
   ALLOW ──────────────► forward unchanged
   REDACT ─────────────► replace spans → forward
   BLOCK ──────────────► 403, never forwarded
```

Spans are computed against `raw_text` using the normalisation offset map
([ADR-010](adr/ADR-010-normalization-strategy.md)). This is what allows confusable-resistant
matching and byte-correct redaction of the forwarded text at the same time — without the
offset map they are mutually exclusive.

**PII detection runs on both directions.** Input: stop PII reaching a third-party model.
Output: stop PII reaching the user. Same detector, different configuration.

## Phase 0 — `pii.regex` (built)

Deterministic, span-emitting, no heavy dependencies.

| Entity | Method | Note |
|---|---|---|
| `EMAIL` | RFC-pragmatic pattern | High precision |
| `CREDIT_CARD` | Pattern + **Luhn** | Luhn is what stops order numbers and IDs matching |
| `PHONE` | E.164 + common national formats | **Highest false-positive source** — a long digit run is not a phone number. `.` is deliberately **not** accepted as a separator: it made dotted-quad strings such as `999.999.999.999` match. The recall lost on the `555.123.4567` style is the cheaper side of that trade |
| `IPV4` / `IPV6` | Pattern + range validation | Private/documentation ranges configurable |
| `IBAN` | Pattern + **mod-97** | |
| Custom | Operator patterns from policy YAML | Employee/account/case IDs — the PII an organisation actually cares about, and only they know the format |

Explicitly **not** detected: names, addresses, organisations, dates of birth, national IDs
outside configured patterns. Documented in the docstring, the policy comments, and the README.

## Phase 2 — `pii.presidio`

Microsoft Presidio replaces it behind the same `Detector` interface: mature, Apache-2.0,
span-based by design, combines pattern recognisers with spaCy NER and context enhancement, and
supports custom recognisers.

**The spaCy model choice is a real trade and will be decided by measurement, not by default:**

| Model | Size | Trade |
|---|---|---|
| `en_core_web_sm` | ~12 MB | Fast, small image, weaker NER recall |
| `en_core_web_lg` | ~560 MB | Better recall, materially larger image and memory |
| `en_core_web_trf` | ~430 MB + torch | Best recall, transformer latency |

Default `sm`, `lg` configurable, and the **recall / latency / image-size difference measured
on the PII benchmark and published** rather than asserted. Presidio and spaCy live in the
`pii` extra, so operators who do not enable it carry neither.

Entity coverage expands to `PERSON`, `LOCATION`, `ORGANIZATION`, `DATE_TIME`, `NRP`, plus
locale-specific recognisers — each reported with its own recall, never averaged into a single
"PII recall" number.

## Redaction representation

Labelled tokens, not fixed-width masks:

```
before:  Contact me at alice@example.com or +1-555-0142.
after:   Contact me at <EMAIL_REDACTED> or <PHONE_REDACTED>.
```

Rationale: the completion stays readable, the model retains the *structure* of the sentence
(a masked-out blob changes meaning), and the downstream application can see what was removed.
`XXXXX` masking loses all three.

Mechanics:

* Spans are merged when overlapping; the outermost span wins, longest-first.
* Replacement is applied right-to-left so earlier offsets stay valid.
* The template is configurable (`redaction.template`); the entity label is interpolated.
* Redaction is recorded on the audit event as **entity types and offsets, never the redacted
  values** — an audit record of what was redacted must not itself contain the PII.

## False positives

The operational reality: at 100 req/s, a 1% false-positive rate is 3 600 wrongly-modified
requests per hour. FPR is therefore the headline PII metric, not recall
([13-evaluation-strategy.md](13-evaluation-strategy.md)).

| Control | Effect |
|---|---|
| Checksum validation (Luhn, mod-97) | Removes the largest structured-identifier FP class |
| Per-entity enable/disable | Deployments that do not need `PHONE` can drop its FP contribution entirely |
| Per-entity threshold (Presidio confidence) | Tune recall/precision per entity, not globally |
| `WARN` before `REDACT` | Shadow-measure FPR on real traffic before modifying it |
| Context enhancement (Presidio) | "card 4111..." scores higher than a bare digit run |
| Allowlist patterns | Suppress known-benign matches (test fixtures, `example.com`, internal doc IPs) |
| **Overlap resolution** | A card number also matches the phone pattern. The detector keeps the higher-confidence entity, so a card is never mislabelled `<PHONE_REDACTED>` |
| **Threshold as an entity filter** | Entities below the configured threshold are not reported at all, so raising `threshold` to 0.7 disables phone matching without editing the entity list |

**Redact rather than block by default.** "Summarise this customer email" is the application,
not the attack. Blocking on PII presence breaks legitimate traffic constantly; blocking is
available for deployments where PII must not reach a third-party model at all.

## Custom enterprise entities

The highest-value organisation-specific case, supported with no code:

```yaml
custom_patterns:
  - name: EMPLOYEE_ID
    pattern: 'EMP-[0-9]{6}'
  - name: CASE_REF
    pattern: '[A-Z]{2}-[0-9]{4}-[0-9]{5}'
    validator: mod11        # Phase 2: optional checksum validators
```

Phase 2 adds Presidio custom recognisers, allowing context words and score adjustment rather
than bare patterns. Patterns are policy, so they are reviewable in a diff — and the
secret-key validator applies, so nobody can smuggle a credential in as a "pattern".

## Privacy of the PII pipeline itself

A PII detector that logs what it found is a PII leak with extra steps.

* Detected values never appear in logs, spans, error responses or audit rows — only entity
  types, offsets, counts and scores ([10-security-model.md](10-security-model.md)).
* Test fixtures are **synthetic**: `example.com` addresses, reserved-range phone numbers,
  standard Luhn-valid test card numbers, documentation-range IPs. Real PII never enters this
  repository, including the author's own.
* Evaluation PII datasets are synthetic or licensed benchmark data
  ([14-dataset-strategy.md](14-dataset-strategy.md)).

## Non-claims

* No claim of complete PII detection in any language.
* No claim of GDPR, HIPAA, PCI-DSS or any other compliance status. Redacting a card number is
  not PCI compliance.
* Phase 0 detects **no names or addresses**, which for many deployments is the majority of
  their PII risk.
* Non-English recall will be weak and will be reported per language rather than averaged away.

## Verification

| Property | Test |
|---|---|
| Per-entity positives and negatives; exact span offsets | `tests/unit/test_pii_regex.py` |
| Luhn rejects invalid card numbers | `tests/unit/test_pii_regex.py` |
| Redaction on request and response; surrounding text intact | `tests/security/test_redaction.py` |
| Correct offsets after normalisation folding | `tests/security/test_redaction.py` |
| Overlapping spans merge correctly | `tests/unit/test_redaction.py` |
| Detected values absent from logs and audit rows | `tests/security/test_log_leakage.py` |
| Phase 2: `pii.regex` vs `pii.presidio`, per-entity recall, `sm` vs `lg` | Committed evaluation report |
