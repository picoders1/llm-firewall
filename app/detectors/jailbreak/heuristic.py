"""Baseline jailbreak detector.

**Baseline, not a jailbreak classifier.** Same caveats as the injection baseline:
small published-phrasing rule set, unmeasured recall, trivially evaded by
rewording. It exists to prove the contract and to be a control condition.

## Why this is a separate detector from prompt injection

The two are routinely conflated and they are not the same question:

| | Prompt injection | Jailbreak |
|---|---|---|
| Target | The **instruction hierarchy** — whose text counts as instruction | The model's **safety alignment** — what it is willing to produce |
| Succeeds when | The model follows attacker text as if it were operator policy | The model produces content it would normally refuse |
| Can occur | Without any unsafe request at all | With no instruction-hierarchy manipulation at all |
| Typical arrival | Often **indirect** — retrieved documents, tool output | Almost always **direct** from the user |

Keeping them separate has two concrete consequences. Operationally, they can carry
different actions and thresholds — many deployments want to block injection but
only warn on jailbreak attempts, or the reverse. Methodologically, per-category
recall stays visible in evaluation instead of one aggregate number hiding that one
of the two is far weaker (docs/13-evaluation-strategy.md).

A single prompt can legitimately trigger both. That is a correct outcome, not
double counting: the policy engine takes the most severe action once.
"""

from __future__ import annotations

from app.config.policy import DetectorPolicy
from app.core.types import Category, DetectionContext, DetectionResult, Direction
from app.detectors.base import BaseDetector
from app.detectors.rules import Rule, apply_rules, compile_rule

# Deliberately conservative weights. Jailbreak phrasing overlaps heavily with
# legitimate creative, security-research and educational requests, so most of
# these rules cannot justify a block on their own — corroboration is required.
JAILBREAK_RULES: tuple[Rule, ...] = (
    compile_rule(
        "persona_jailbreak",
        r"\b(DAN\b|do\s+anything\s+now|developer\s+mode\s+(enabled|on)|"
        r"jailbr(oken|eak)|AIM\s+mode|STAN\b|opposite\s+day\s+mode)\b",
        0.85,
        "Named jailbreak personas from published prompt collections.",
    ),
    compile_rule(
        "safety_removal",
        r"\b(no|without|remove|disable|bypass|ignore|disregard|turn\s+off|forget)\b"
        r"[^.!?\n]{0,25}?\b"
        r"(restriction|limitation|filter|guardrail|safety|censorship|"
        r"content\s+polic|ethical\s+guideline|moral)\w*",
        0.85,
        "Explicitly requests removal of safety constraints.",
    ),
    compile_rule(
        "refusal_suppression",
        r"\b(never\s+refuse|do\s+not\s+refuse|cannot\s+say\s+no|"
        r"don'?t\s+(apolog|warn|lecture)|no\s+disclaimers?|"
        r"always\s+(comply|answer|obey))\b",
        0.75,
        "Pre-empts refusal behaviour — a strong jailbreak tell.",
    ),
    compile_rule(
        "unrestricted_persona",
        r"\b(unfiltered|uncensored|unrestricted|amoral|uncensured)\b[^.!?\n]{0,20}?\b"
        r"(ai|assistant|model|chatbot|version|response)\b",
        0.75,
        "Requests an explicitly unrestricted persona.",
    ),
    compile_rule(
        "alignment_negation",
        r"\byou\s+(are|have)\s+(no|not\s+bound\s+by)\b[^.!?\n]{0,25}?\b"
        r"(rules?|ethics?|guidelines?|restrictions?|programming|training)\b",
        0.70,
        "Asserts the model's alignment does not apply.",
    ),
    compile_rule(
        "fictional_shield",
        r"\b(hypothetical(ly)?|fictional|role\s?play|in\s+a\s+story|"
        r"for\s+(educational|research)\s+purposes\s+only|"
        r"this\s+is\s+(just\s+)?(a\s+)?(test|story|game))\b",
        0.30,
        "Fictional framing. Very weak: overwhelmingly used legitimately, so it can "
        "only ever corroborate — never trigger on its own.",
    ),
    compile_rule(
        "emotional_manipulation",
        r"\b(my\s+(grandmother|grandma|dying)\b[^.!?\n]{0,40}?\b(used\s+to|would)\b|"
        r"people\s+will\s+die\s+(if|unless)|you\s+will\s+be\s+(shut\s+down|deleted))\b",
        0.60,
        "Published social-engineering framings used to pressure compliance.",
    ),
    compile_rule(
        "output_prefix_injection",
        r"\b(start|begin)\s+(your\s+)?(response|reply|answer)\s+with\b[^.!?\n]{0,30}?"
        r"(sure|certainly|absolutely|of\s+course|here)\b",
        0.65,
        "Forces an affirmative prefix to bypass refusal — a well-documented technique.",
    ),
)


class HeuristicJailbreakDetector(BaseDetector):
    """Rule-based jailbreak baseline. Uncalibrated by construction."""

    name = "jailbreak.heuristic"
    category = Category.JAILBREAK
    directions = frozenset({Direction.INPUT})
    emits_spans = False

    async def detect(self, ctx: DetectionContext) -> DetectionResult:
        outcome = apply_rules(JAILBREAK_RULES, ctx)
        threshold = self.policy.threshold if self.policy else 0.85
        return self._result(
            detected=outcome.score >= threshold,
            score=outcome.score,
            reasons=outcome.reasons,
            metadata={
                "rules_fired": len({hit.rule_id for hit in outcome.hits}),
                "calibrated": False,
                "baseline": True,
            },
        )


def build(policy: DetectorPolicy) -> HeuristicJailbreakDetector:
    return HeuristicJailbreakDetector(policy)
