"""Baseline prompt-injection detector.

**Scope, stated plainly: this is a baseline, not prompt-injection detection.**

It recognises a small set of *documented, published* attack phrasings. It will not
catch a rewording it has not seen, an attack in another language, an instruction
implied rather than stated, or anything an attacker produces after one round of
iterating against it. Its measured recall against a real corpus is unknown and
will be published in Phase 4 alongside the classifier that replaces it.

Its actual jobs are:

1. prove the detector contract carries a real detector end to end;
2. be the **control condition** in Phase 4 — the transformer's value is its
   measured delta over this, on the same split, on the same machine;
3. serve as layer 1 of the cheap-first ladder, where it may short-circuit to
   BLOCK but never to ALLOW (docs/05-detector-architecture.md).

Semantics: prompt injection is an attempt to manipulate the model's **instruction
hierarchy** — to make it treat attacker text as operator instruction. That is a
different question from jailbreak (see `app/detectors/jailbreak/heuristic.py`),
and the two are separate detectors with separate categories so that per-category
recall stays visible in evaluation rather than being averaged away.
"""

from __future__ import annotations

from app.config.policy import DetectorPolicy
from app.core.types import Category, DetectionContext, DetectionResult, Direction
from app.detectors.base import BaseDetector
from app.detectors.rules import Rule, apply_rules, compile_rule

# Weights are judgement, not measurement. They encode how unambiguous a phrasing
# is in isolation: only a rule that is hard to write innocently earns enough
# weight to trigger the default 0.85 threshold on its own. Everything weaker must
# be corroborated by another rule (see `app.detectors.rules.combine`).
INJECTION_RULES: tuple[Rule, ...] = (
    compile_rule(
        "instruction_override",
        r"\b(ignore|disregard|forget|override)\b[^.!?\n]{0,40}?\b"
        r"(previous|prior|above|earlier|preceding|all)\b[^.!?\n]{0,25}?\b"
        r"(instruction|prompt|rule|direction|command|guideline)s?\b",
        0.90,
        "Explicit instruction-hierarchy override; the canonical injection phrasing.",
    ),
    compile_rule(
        "instruction_replacement",
        r"\b(new|updated|revised|real|actual|true)\s+"
        r"(instruction|prompt|system\s+prompt|directive|rule)s?\b\s*[:\-]",
        0.75,
        "Presents attacker text as a replacement instruction set.",
    ),
    compile_rule(
        "system_prompt_extraction",
        r"\b(reveal|show|print|repeat|output|display|tell\s+me|what\s+(are|is|were))\b"
        r"[^.!?\n]{0,30}?\b(your|the)\b[^.!?\n]{0,20}?\b"
        r"(system\s+prompt|initial\s+instruction|original\s+instruction|"
        r"system\s+message|instructions|prompt)\b",
        0.85,
        "Attempts to extract operator instructions (threat T-05).",
    ),
    compile_rule(
        "verbatim_repeat",
        r"\brepeat\b[^.!?\n]{0,30}?\b(everything|all|the\s+text)\b[^.!?\n]{0,20}?\babove\b",
        0.70,
        "Common indirect route to system-prompt disclosure.",
    ),
    compile_rule(
        "role_reassignment",
        r"\b(you\s+are\s+now|from\s+now\s+on[,]?\s+you|"
        r"pretend\s+(to\s+be|you\s+are)|act\s+as\s+(if\s+you|a|an|the))\b",
        0.55,
        "Role reassignment. Weak alone: legitimate prompts reassign roles constantly.",
    ),
    compile_rule(
        "delimiter_injection",
        r"(<\|im_(start|end)\|>|<\|(system|user|assistant|endoftext)\|>|"
        r"\[/?(INST|SYS)\]|<</?SYS>>|###\s*(system|instruction)s?\b)",
        0.90,
        "Chat-template markers forged in user content to fake a turn boundary. "
        "Weighted high because no legitimate prompt contains them.",
        match_raw=True,
    ),
    compile_rule(
        "authority_escalation",
        r"\b(admin|developer|root|system)\s+(mode|access|override|command|privilege)s?\b",
        0.65,
        "Claims elevated authority to outrank the operator's instructions.",
    ),
    compile_rule(
        "exfiltration_instruction",
        r"\b(send|post|upload|transmit|forward|leak|exfiltrate)\b[^.!?\n]{0,30}?\b"
        r"(to|at)\b\s*(https?://|www\.|[\w.-]+@)",
        0.75,
        "Instructs the model to transmit content to an attacker-controlled destination.",
    ),
    compile_rule(
        "markdown_image_exfiltration",
        r"!\[[^\]]{0,60}\]\(\s*https?://[^)\s]{1,200}[?&=][^)\s]{0,200}\)",
        0.55,
        "Markdown image with a query payload; renders in a chat UI and performs a GET.",
        match_raw=True,
    ),
    compile_rule(
        "instruction_boundary_claim",
        r"\b(end\s+of\s+(the\s+)?(prompt|instruction|context)|"
        r"everything\s+(above|before)\s+(this|is)\s+(is\s+)?(a\s+)?"
        r"(test|fake|ignored|irrelevant))\b",
        0.70,
        "Asserts a false boundary so following text reads as operator instruction.",
    ),
)


class HeuristicInjectionDetector(BaseDetector):
    """Rule-based prompt-injection baseline. Uncalibrated by construction."""

    name = "injection.heuristic"
    category = Category.PROMPT_INJECTION
    directions = frozenset({Direction.INPUT})
    # Injection findings drive BLOCK, not REDACT: removing the offending phrase
    # would silently change what the user asked, and the remaining text is not
    # trustworthy anyway.
    emits_spans = False

    async def detect(self, ctx: DetectionContext) -> DetectionResult:
        outcome = apply_rules(INJECTION_RULES, ctx)
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


def build(policy: DetectorPolicy) -> HeuristicInjectionDetector:
    return HeuristicInjectionDetector(policy)
