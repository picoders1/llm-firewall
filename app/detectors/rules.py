"""A small, explainable rule engine shared by the baseline heuristic detectors.

**These are baseline heuristics, not prompt-injection detection.** They exist to
prove the detector contract end to end and to give Phase 2's classifier a control
condition to be measured against (docs/05-detector-architecture.md,
docs/13-evaluation-strategy.md). Their recall against anything an adaptive
attacker writes is expected to be poor, and that expectation is the point: the
delta a real model achieves over this baseline is the number worth publishing.

Design constraints that keep this defensible rather than a keyword list:

* **Small and named.** Every rule has an id, a weight and a one-line rationale, so
  a block can be explained and a false positive can be attributed to a specific
  rule rather than to "the regex".
* **Normalisation-aware.** Rules match the folded text and map their spans back to
  the source through the offset map, so the whole evasion-resistance story in
  ADR-010 applies to every rule for free.
* **Encoded payloads inspected.** A rule that fires inside a decoded base64
  segment counts, because the model will decode it too.
* **Bounded.** Match work is capped so a long body cannot force unbounded regex
  execution.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

from app.core.types import DetectionContext, TextSpan

# A single rule never reaches the default block threshold on its own unless it is
# genuinely unambiguous; weaker signals must corroborate. See `combine`.
MAX_HITS_PER_RULE = 3
MAX_TOTAL_HITS = 24


@dataclass(frozen=True, slots=True)
class Rule:
    """One named, weighted pattern."""

    id: str
    pattern: re.Pattern[str]
    weight: float
    rationale: str
    # Rules that describe *structure* (chat-template markers, delimiters) are
    # matched against the raw text too, because normalisation can fold them.
    match_raw: bool = False


@dataclass(frozen=True, slots=True)
class RuleHit:
    rule_id: str
    weight: float
    source: str  # "normalized" | "raw" | "base64"
    span: TextSpan | None = None


@dataclass(frozen=True, slots=True)
class RuleSetResult:
    score: float
    hits: tuple[RuleHit, ...] = ()
    spans: tuple[TextSpan, ...] = field(default=())

    @property
    def reasons(self) -> tuple[str, ...]:
        """Rule ids only — never the matched text (docs/10-security-model.md)."""
        seen: dict[str, None] = {}
        for hit in self.hits:
            seen.setdefault(f"{hit.rule_id}@{hit.source}", None)
        return tuple(seen)


def compile_rule(
    rule_id: str,
    pattern: str,
    weight: float,
    rationale: str,
    *,
    match_raw: bool = False,
) -> Rule:
    return Rule(
        id=rule_id,
        pattern=re.compile(pattern, re.IGNORECASE),
        weight=weight,
        rationale=rationale,
        match_raw=match_raw,
    )


def combine(weights: Iterable[float]) -> float:
    """Combine independent rule weights with a noisy-OR.

    ``1 - Π(1 - w)``. Chosen over a sum (which needs arbitrary clamping) and over
    a max (which ignores corroboration) because it is bounded in ``[0, 1)``,
    monotone in every input, and has an honest reading: each rule is treated as an
    independent weak signal, and agreement raises confidence without any single
    weak rule ever reaching certainty.

    **This is not a calibrated probability.** It is a rule-coverage score,
    comparable only against this detector's own configured threshold
    (docs/05-detector-architecture.md).
    """
    product = 1.0
    for weight in weights:
        product *= 1.0 - max(0.0, min(1.0, weight))
    return 1.0 - product


def _scan(
    rules: Sequence[Rule],
    text: str,
    source: str,
    ctx: DetectionContext | None,
    budget: int,
) -> list[RuleHit]:
    hits: list[RuleHit] = []
    for rule in rules:
        if len(hits) >= budget:
            break
        for index, match in enumerate(rule.pattern.finditer(text)):
            if index >= MAX_HITS_PER_RULE or len(hits) >= budget:
                break
            span: TextSpan | None = None
            if source == "normalized" and ctx is not None:
                span = ctx.source_span(match.start(), match.end(), rule.id)
            elif source == "raw":
                span = TextSpan(start=match.start(), end=match.end(), label=rule.id)
            hits.append(RuleHit(rule_id=rule.id, weight=rule.weight, source=source, span=span))
    return hits


def apply_rules(rules: Sequence[Rule], ctx: DetectionContext) -> RuleSetResult:
    """Run a rule set over every view of the text a detector is given.

    The normalised text is the primary surface; raw text is scanned only by rules
    that describe structure; decoded segments are scanned because an instruction
    the model will decode is an instruction.
    """
    hits = _scan(rules, ctx.normalized_text, "normalized", ctx, MAX_TOTAL_HITS)

    raw_rules = [rule for rule in rules if rule.match_raw]
    if raw_rules and len(hits) < MAX_TOTAL_HITS:
        hits.extend(_scan(raw_rules, ctx.raw_text, "raw", ctx, MAX_TOTAL_HITS - len(hits)))

    for segment in ctx.decoded_segments:
        if len(hits) >= MAX_TOTAL_HITS:
            break
        for hit in _scan(rules, segment.decoded, "base64", None, MAX_TOTAL_HITS - len(hits)):
            # The span points at the *encoded* region in the source: that is the
            # text a redaction or an audit record has to refer to.
            hits.append(
                RuleHit(
                    rule_id=hit.rule_id,
                    weight=hit.weight,
                    source="base64",
                    span=segment.span,
                )
            )

    # Deduplicate by rule id before scoring. Ten matches of one rule is one piece
    # of evidence repeated, not ten independent signals — without this, repeating
    # a phrase would inflate the score arbitrarily.
    strongest: dict[str, float] = {}
    for hit in hits:
        strongest[hit.rule_id] = max(strongest.get(hit.rule_id, 0.0), hit.weight)

    spans = tuple(hit.span for hit in hits if hit.span is not None)
    return RuleSetResult(score=combine(strongest.values()), hits=tuple(hits), spans=spans)
