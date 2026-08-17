# ADR-005: PII Detection Strategy

**Status:** Accepted
**Date:** 2026-08-17
**Phase:** 0 (regex baseline), Phase 2 (Presidio)

## Context

PII detection is the most immediately valuable feature of an LLM gateway and the one most
often overclaimed. Two very different problems hide under one name:

* **Structured identifiers** — email, phone, credit card, IBAN, national ID, IP. Regular,
  often checksum-verifiable, high precision achievable with pattern matching.
* **Unstructured identifiers** — person names, addresses, employers, free-text descriptions
  that identify someone in combination. These require NER, are recall-limited in every
  system that exists, and are heavily language- and locale-dependent.

Conflating them produces the standard false claim: "we detect PII", demonstrated on an
email address.

There is also a functional constraint: PII actions are usually `REDACT`, not `BLOCK`, so the
detector must return **precise character spans against the original text**, not just a
boolean.

## Decision

**Two implementations behind one interface, introduced in sequence.**

### Phase 0 — `pii.regex`

Deterministic patterns with validation, emitting spans:

| Entity | Method | Note |
|---|---|---|
| Email | RFC-pragmatic pattern | High precision |
| Credit card | Pattern + **Luhn check** | Luhn removes most false positives; order numbers stop matching |
| Phone | E.164 and common national formats | Highest FP source — a long digit run is not a phone number |
| IPv4 / IPv6 | Pattern + range validation | Private/documentation ranges configurable |
| IBAN | Pattern + mod-97 check | |
| Custom enterprise IDs | Operator-supplied patterns from policy YAML | Employee/account/case IDs are the PII an organisation actually cares about, and only they know the format |

No names, no addresses, no organisations. **Documented as covering structured identifiers
only**, in the docstring, the policy comments, and the README.

### Phase 2 — `pii.presidio`

Microsoft Presidio replaces it behind the same `Detector` interface: mature, actively
maintained, Apache-2.0, span-based by design, extensible with custom recognisers, and it
combines pattern recognisers with spaCy NER and context enhancement rather than being
purely one or the other.

**spaCy model choice** is a genuine trade and will be decided on measurement, not on
default:

| Model | Size | Trade |
|---|---|---|
| `en_core_web_sm` | ~12 MB | Fast, smaller image, weaker NER recall |
| `en_core_web_lg` | ~560 MB | Better recall, materially larger image and memory |
| `en_core_web_trf` | ~430 MB + torch | Best recall, transformer-speed latency |

Default `sm`, with `lg` configurable, and the recall/latency/size difference **measured on
the PII benchmark and published** rather than asserted. Presidio and spaCy live in the `pii`
extra so operators who do not enable it do not carry ~600 MB and a torch dependency.

### Actions

Default `redact` on both directions. `block` is available for deployments where PII must not
reach a third-party model at all. Redaction uses labelled tokens (`<EMAIL_REDACTED>`), never
fixed-width masks — the completion stays readable and the application can see what was
removed.

Redaction spans are computed against `raw_text` using the normalisation offset map
(ADR-010), so confusable-resistant matching and correct redaction are simultaneously
possible.

## Alternatives considered

| Alternative | Rejected because |
|---|---|
| **Regex only, permanently** | Cannot detect names or addresses at all. Shipping it as "PII detection" is the overclaim this ADR exists to prevent. |
| **Presidio from Phase 0** | ~600 MB of dependencies and a NER model before the interface it plugs into has been validated. Phase 0's job is to prove the seam; a regex detector proves it in 100 lines. |
| **Cloud DLP APIs (Google DLP, AWS Comprehend)** | Better recall, and they require **sending every prompt to a third party** — inverting the product's premise. Available as an optional detector later for operators who already accept that processor relationship; never a default. |
| **LLM-based PII extraction** | Good recall, but adds a model call to the request path (doubling latency and cost), is non-deterministic, and introduces a second injectable surface. Belongs in the offline harness. |
| **Fine-tuned in-house NER** | Best possible fit, months of labelled data. Not a Phase 2 decision. |
| **Blocking rather than redacting by default** | Breaks legitimate traffic constantly. "Summarise this customer email" is the application, not the attack. |

## Consequences

### Positive
* Phase 0 ships something honest and genuinely useful — structured-identifier redaction with
  correct spans — without a heavy dependency.
* The Presidio upgrade is a substitution, benchmarked against the regex baseline on the same
  dataset, which turns "we upgraded PII detection" into a number.
* Custom enterprise patterns via policy YAML address the highest-value organisation-specific
  case with no code.
* Optional extras keep the default image slim and its CVE surface small.

### Negative / accepted costs
* **Phase 0 detects no names or addresses.** For many deployments that is the majority of
  their PII risk. Stated plainly wherever PII is mentioned.
* Presidio brings spaCy, a model download, and ~1–3 s of startup warm-up.
* Non-English coverage will remain weak, and per-language recall will be reported rather
  than averaged away.
* NER PII detection is inherently recall-limited; no configuration makes it complete, and
  the documentation will not imply otherwise.
* Phone-number patterns are the main false-positive source and will need threshold tuning
  against a benign corpus.

### Revisit when
Benchmarked Presidio recall is inadequate for a real deployment (consider fine-tuned NER or
an optional cloud DLP detector); or non-English traffic becomes a requirement.

## Verification

* `tests/unit/test_pii_regex.py` — per-entity positives and negatives, Luhn rejection of
  invalid card numbers, exact span offsets.
* `tests/security/test_redaction.py` — request- and response-side redaction replaces the
  entity and preserves surrounding text.
* Phase 2: a committed evaluation report comparing `pii.regex` and `pii.presidio` on the
  same split, including per-entity recall and the `sm`/`lg` comparison.
* No PII claim appears in the README without a report reference.
