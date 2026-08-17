# ADR-010: Index-Preserving Normalisation

**Status:** Accepted
**Date:** 2026-08-17
**Phase:** 0

## Context

Literal text matching is trivially evaded. `ignore previous instructions` becomes:

* `ig<ZWSP>nore previous instructions` — a zero-width space, invisible, defeats substring matching
* `іgnore previous instructions` — Cyrillic `і` (U+0456), visually identical
* `ｉｇｎｏｒｅ previous instructions` — fullwidth forms
* `aWdub3JlIHByZXZpb3VzIGluc3RydWN0aW9ucw==` — base64, which a model may well decode and act on
* `IGNORE   Previous\n\n\nInstructions` — case and whitespace noise

Every detector needs resistance to these. If each implements its own, they will differ, and
the weakest one becomes the bypass.

There is a second constraint that makes this non-trivial. PII redaction needs **exact
character spans in the original text**. Normalisation changes string length and offsets —
so the obvious implementation (normalise, match, return spans) returns spans that are wrong
against the text actually being forwarded. The naive fix (match only on raw text) gives up
evasion resistance entirely. These two requirements appear to be in conflict.

## Decision

**Normalise once, centrally, and carry an offset map back to the source.**

`DetectionContext` gives every detector three views of the same message:

| Field | Content | Used for |
|---|---|---|
| `raw_text` | Exactly what the client sent | Redaction spans, audit hashes, forwarding |
| `normalized_text` | Folded inspection form | Pattern matching |
| `decoded_segments` | Base64 payloads, decoded, with their source spans | Inspecting hidden instructions |

Normalisation pipeline, applied **per character** so the offset map stays exact:

1. Drop invisible characters (zero-width space/joiner/non-joiner, BOM, soft hyphen,
   bidi controls, Mongolian vowel separator).
2. Fold Unicode confusables via a **small, explicit, auditable table** (Cyrillic/Greek
   lookalikes, dash and quote variants).
3. NFKC compatibility folding (fullwidth, ligatures, superscripts).
4. Casefold.
5. Collapse whitespace runs to a single space.

`Normalized.offsets[i]` gives the source index that produced `normalized_text[i]`, so
`source_span(start, end)` converts any normalised match back into a valid `TextSpan` against
`raw_text`. **This is what lets confusable-resistant matching and correct redaction coexist.**

Base64 surfacing is bounded (8 segments per message) and gated: a candidate must decode
cleanly to ≥85% printable UTF-8, which keeps hashes, identifiers and binary blobs out.

**Normalised text is used only for inspection and is never forwarded.** The gateway must not
change the meaning of a request as a side effect of inspecting it.

## Alternatives considered

| Alternative | Rejected because |
|---|---|
| **No normalisation; each detector handles evasion** | Guarantees inconsistency; the weakest detector becomes the bypass; and the same logic gets debugged repeatedly. |
| **Whole-string NFKC** | Simpler and faster, but breaks the offset map — one input character can compose with its neighbour, so there is no reliable per-character correspondence. Per-character NFKC forgoes cross-character composition (a combining accent merging with its base letter), which does not affect instruction-phrase matching. The trade is stated in the module docstring. |
| **Full UTS-39 confusables table** | Thousands of mappings, real false-folding risk, and a large data dependency. A small curated table covers the classes actually seen in attacks and every entry can be justified in review. Expand on evidence from evaluation, not speculatively. |
| **Normalise and forward the normalised text** | Would silently rewrite user requests — casefolding names, stripping formatting, altering meaning. A proxy that mutates traffic to suit its own inspection is a bug generator. |
| **Aggressive de-leetspeak, homoglyph-to-ASCII for everything, vowel stripping** | Each broadening step raises false positives on legitimate non-English text. Folding Greek and Cyrillic aggressively would mangle genuine Greek and Russian prompts. |
| **Recursive decoding (base64 inside base64, rot13, hex, URL-encoding)** | Unbounded attacker-controlled work, and each layer adds false-positive surface. One level of base64 covers the observed cases; deeper nesting is itself a strong signal and can be scored as one rather than followed. |
| **Detect obfuscation and block on its presence alone** | Zero-width characters and base64 appear in legitimate traffic (code snippets, data payloads). Blocking on their presence is a false-positive machine; using them as a *feature* alongside content is correct. |

## Consequences

### Positive
* Every detector inherits the same evasion resistance for free, and it is tested once.
* Redaction spans remain exact against the forwarded text despite folding.
* Adding an evasion class means one change in one module plus a test, benefiting all
  detectors simultaneously.
* Decoded base64 is inspected by content rather than merely flagged as suspicious.

### Negative / accepted costs
* **Not complete, and cannot be.** Rot13, custom substitution ciphers, token-level splitting
  (`i g n o r e`), text embedded in images, and instructions expressed in another language
  are not handled. Listed as residual risk T-04 rather than implied away.
* Per-character normalisation is slower than whole-string; it scales linearly with input,
  which is why `max_inspect_chars` exists.
* Aggressive folding can create false positives — casefolding plus confusable folding could
  make a legitimate multilingual prompt resemble an attack pattern. Measured as part of FPR,
  not assumed away.
* The confusables table is a maintenance surface that will grow as evaluation finds gaps.
* Base64 decoding is attacker-triggerable work; bounded by the segment cap.

### Revisit when
Evaluation shows a specific uncovered evasion class producing false negatives at a
meaningful rate — the addition should be evidence-driven, with the FPR cost measured.

## Verification

* `tests/unit/test_normalize.py` — one case per evasion class (zero-width, Cyrillic
  confusable, fullwidth, case, whitespace, base64), each asserting the *same* detector verdict
  as the plain form.
* `tests/unit/test_normalize_offsets.py` — for randomised inputs, every
  `source_span` maps back to the correct substring of `raw_text`.
* `tests/unit/test_normalize_bounds.py` — segment cap and printable-ratio gate hold.
* `tests/security/test_redaction.py` — redaction on text containing folded characters
  replaces exactly the right source range.
