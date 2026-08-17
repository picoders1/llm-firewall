"""Registered placeholder detectors for Phase 0.

These are **wired, not fake**: they are constructed from policy, guarded, warmed
up, run through the real pipeline, and their results flow through the real policy
engine. They simply never detect anything, because the detection logic is Phase 2
and Phase 3 work.

Their purpose is that the multi-detector path, policy validation, the event
schema and the tests exercise the genuine machinery from day one, so later phases
are a substitution rather than an integration
(docs/adr/ADR-002-detector-plugin-architecture.md).

A stub declares the *capabilities of the detector it stands in for* — notably
:attr:`emits_spans` for the PII slot — so that policy validation behaves the same
way now as it will once the real implementation lands.
"""

from __future__ import annotations

from app.config.policy import DetectorPolicy
from app.core.types import Category, DetectionContext, DetectionResult, Direction
from app.detectors.base import BaseDetector


class StubDetector(BaseDetector):
    """A detector that always reports "nothing found"."""

    async def detect(self, ctx: DetectionContext) -> DetectionResult:
        return self._result(
            detected=False,
            score=0.0,
            reasons=("stub_detector_not_implemented",),
            metadata={"phase": "0", "implemented": False},
        )


class OutputPolicyStub(StubDetector):
    """Placeholder for the Phase 3 output-policy detector."""

    name = "output.stub"
    category = Category.OUTPUT_POLICY
    directions = frozenset({Direction.OUTPUT})
    emits_spans = False


def build_output_stub(policy: DetectorPolicy) -> OutputPolicyStub:
    return OutputPolicyStub(policy)
