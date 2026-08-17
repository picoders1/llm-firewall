"""Structured-identifier PII detector — the Phase 0 baseline.

Covers **structured identifiers only**: email, phone, credit card, IPv4, IBAN, and
operator-supplied enterprise patterns. It detects **no names, addresses or
organisations**, which for many deployments is the majority of their PII risk.
That gap is the reason Presidio replaces this in Phase 2 behind the identical
interface (docs/08-pii-security.md, ADR-005).

Two properties make it more than a regex list:

* **Checksum validation.** Credit cards are Luhn-checked and IBANs mod-97 checked.
  This removes the largest false-positive class outright — order numbers and
  reference codes stop matching — which matters because at 100 req/s a 1% FPR is
  3 600 wrongly-modified requests an hour.
* **Normalisation-aware with exact source spans.** Matching happens on the folded
  text, so `4111​1111…` with zero-width spaces is still found, and the span maps
  back through the offset map to the exact source range so redaction replaces the
  right bytes including the hidden characters.

Detected values never enter logs, spans or audit records — only entity labels,
offsets and counts. A PII detector that logs what it found is a PII leak with
extra steps.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass

from app.config.policy import DetectorPolicy
from app.core.types import Category, DetectionContext, DetectionResult, TextSpan
from app.detectors.base import BOTH_DIRECTIONS, BaseDetector

MAX_ENTITIES = 64


@dataclass(frozen=True, slots=True)
class EntityRule:
    label: str
    pattern: re.Pattern[str]
    # Per-entity confidence. Not calibrated: it encodes how much structure and
    # validation stand behind a match, which is the honest basis available
    # without an evaluation corpus.
    confidence: float
    validator: str | None = None


def _luhn(digits: str) -> bool:
    total = 0
    for index, char in enumerate(reversed(digits)):
        value = int(char)
        if index % 2:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def _iban_mod97(candidate: str) -> bool:
    rearranged = candidate[4:] + candidate[:4]
    numeric = "".join(str(int(c, 36)) if c.isalpha() else c for c in rearranged)
    try:
        return int(numeric) % 97 == 1
    except ValueError:
        return False


def _valid_ipv4(candidate: str) -> bool:
    parts = candidate.split(".")
    return len(parts) == 4 and all(part.isdigit() and int(part) <= 255 for part in parts)


BUILTIN_ENTITIES: tuple[EntityRule, ...] = (
    EntityRule(
        "EMAIL",
        re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,63}"),
        0.90,
    ),
    EntityRule(
        "CREDIT_CARD",
        re.compile(r"\b(?:\d[ \-]?){12,18}\d\b"),
        0.95,
        validator="luhn",
    ),
    EntityRule(
        "IBAN",
        re.compile(r"\b[A-Za-z]{2}\d{2}[A-Za-z0-9]{11,30}\b"),
        0.95,
        validator="iban",
    ),
    EntityRule(
        "IPV4",
        re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
        0.70,
        validator="ipv4",
    ),
    EntityRule(
        # E.164 and common national forms. Deliberately requires a leading + or a
        # grouping separator: a bare run of digits is not a phone number, and
        # treating it as one is the single largest false-positive source here.
        #
        # `.` is NOT accepted as a separator. It made dotted-quad strings such as
        # "999.999.999.999" match as phone numbers — a false positive that costs
        # more than the recall lost on the "555.123.4567" writing style, given
        # that FPR is the headline metric (docs/13-evaluation-strategy.md).
        "PHONE",
        re.compile(r"(?:\+\d{1,3}[ \-]?)?(?:\(\d{2,4}\)[ \-]?|\d{2,4}[ \-])\d{2,4}[ \-]?\d{2,6}\b"),
        0.60,
        validator="phone",
    ),
)

_ENTITIES_BY_LABEL = {rule.label: rule for rule in BUILTIN_ENTITIES}


def _validate(rule: EntityRule, text: str) -> bool:
    if rule.validator is None:
        return True
    if rule.validator == "luhn":
        digits = re.sub(r"[ \-]", "", text)
        return 13 <= len(digits) <= 19 and _luhn(digits)
    if rule.validator == "iban":
        return _iban_mod97(text.upper())
    if rule.validator == "ipv4":
        return _valid_ipv4(text)
    if rule.validator == "phone":
        digits = re.sub(r"\D", "", text)
        return 7 <= len(digits) <= 15
    return True


def _resolve_overlaps(found: list[tuple[TextSpan, float]]) -> list[tuple[TextSpan, float]]:
    """Keep the best-supported entity when two patterns claim the same text.

    A credit-card number also matches the phone pattern. Reporting both would
    label the same characters twice and, after span merging, could redact a card
    as `<PHONE_REDACTED>` — a mislabelled audit record and a confusing redaction.
    Higher confidence wins; ties go to the longer span, which is the more specific
    match.
    """
    ordered = sorted(found, key=lambda item: (-item[1], -len(item[0]), item[0].start))
    kept: list[tuple[TextSpan, float]] = []
    for span, confidence in ordered:
        if any(span.overlaps(existing) for existing, _ in kept):
            continue
        kept.append((span, confidence))
    return sorted(kept, key=lambda item: item[0].start)


class RegexPiiDetector(BaseDetector):
    """Structured-identifier PII detection with exact source spans."""

    name = "pii.regex"
    category = Category.PII
    directions = BOTH_DIRECTIONS
    emits_spans = True

    def __init__(self, policy: DetectorPolicy | None = None) -> None:
        super().__init__(policy)
        options = policy.options if policy else {}
        self._rules = tuple(self._resolve_rules(options))
        self._threshold = policy.threshold if policy else 0.0

    def _resolve_rules(self, options: dict[str, object]) -> Iterator[EntityRule]:
        """Only the entities the operator asked for.

        Enabling every recogniser by default is how a PII detector becomes a
        false-positive generator; the entity set is explicit configuration.
        """
        requested = options.get("entities")
        if isinstance(requested, list) and requested:
            for label in requested:
                rule = _ENTITIES_BY_LABEL.get(str(label).upper())
                if rule is not None:
                    yield rule
        else:
            yield from BUILTIN_ENTITIES

        custom_patterns = options.get("custom_patterns") or []
        if not isinstance(custom_patterns, list):
            custom_patterns = []
        for custom in custom_patterns:
            if not isinstance(custom, dict) or "name" not in custom or "pattern" not in custom:
                continue
            try:
                # IGNORECASE because matching happens on casefolded text: a
                # pattern like `EMP-[0-9]{6}` would otherwise never match.
                compiled = re.compile(str(custom["pattern"]), re.IGNORECASE)
            except re.error:
                # A bad operator pattern must not take the detector down; it is
                # skipped and the rest still run. Startup validation of custom
                # patterns is tracked as future work.
                continue
            yield EntityRule(
                label=str(custom["name"]).upper(),
                pattern=compiled,
                confidence=float(custom.get("confidence", 0.85)),
            )

    def _find(self, ctx: DetectionContext) -> list[tuple[TextSpan, float]]:
        found: list[tuple[TextSpan, float]] = []
        for rule in self._rules:
            if len(found) >= MAX_ENTITIES:
                break
            for match in rule.pattern.finditer(ctx.normalized_text):
                if len(found) >= MAX_ENTITIES:
                    break
                if not _validate(rule, match.group(0)):
                    continue
                if rule.confidence < self._threshold:
                    # Below the configured threshold the entity is not reported at
                    # all, so a deployment that cannot tolerate phone-number false
                    # positives simply raises the threshold.
                    continue
                span = ctx.source_span(match.start(), match.end(), rule.label)
                if span is not None:
                    found.append((span, rule.confidence))
        return _resolve_overlaps(found)

    async def detect(self, ctx: DetectionContext) -> DetectionResult:
        found = self._find(ctx)
        if not found:
            return self._result(detected=False, score=0.0, metadata={"entities": {}})

        counts: dict[str, int] = {}
        for span, _ in found:
            counts[span.label] = counts.get(span.label, 0) + 1

        return self._result(
            detected=True,
            score=max(confidence for _, confidence in found),
            # Labels and counts only — never the matched values.
            reasons=tuple(sorted(counts)),
            spans=tuple(span for span, _ in found),
            metadata={"entities": counts, "baseline": True, "structured_only": True},
        )


def build(policy: DetectorPolicy) -> RegexPiiDetector:
    return RegexPiiDetector(policy)
