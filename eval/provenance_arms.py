"""Experimental detector arms for the Phase 2P-D provenance experiment.

ADR-018. These live in `eval/` and are **never registered** with the production
detector registry: the experiment must be able to fail without having touched the
gateway.

All arms share one model, one set of weights, one tokenizer, one threshold. The
only intended difference is whether a span's provenance is known and used, which
is what makes the comparison causal rather than merely suggestive.

The four arms and why each exists:

    A0 content_only_flat        control — replicates the ADR-016 run
    A1 provenance_aware_flat    provenance available but constant
    A2 provenance_aware_split   treatment — scores only untrusted spans
    A3 content_only_split       isolates segmentation from provenance

A3 is the arm that keeps the experiment honest. A2's advantage over A0 could come
entirely from segmentation — a short isolated span is an easier input than the same
payload buried in a document — and without A3 there would be no way to tell.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from app.core.types import Provenance, TrustLevel


class Segmentation(StrEnum):
    """How a sample's text is divided into parts. The characters never change."""

    FLAT = "flat"
    SPLIT = "split"


class ProvenanceMode(StrEnum):
    """Ablation over what provenance the parts are labelled with (ADR-018 §9)."""

    CORRECT = "correct"
    REMOVED = "removed"
    INVERTED = "inverted"


@dataclass(frozen=True, slots=True)
class Part:
    """One inspectable span, with the provenance the gateway would have assigned."""

    text: str
    provenance: Provenance
    trust: TrustLevel

    @property
    def untrusted(self) -> bool:
        return self.trust is TrustLevel.UNTRUSTED


@dataclass(frozen=True, slots=True)
class Arm:
    """One experimental configuration."""

    name: str
    segmentation: Segmentation
    consumes_provenance: bool
    provenance_mode: ProvenanceMode = ProvenanceMode.CORRECT
    description: str = ""
    is_control: bool = False
    diagnostic_only: bool = field(default=False)


ARMS: tuple[Arm, ...] = (
    Arm(
        name="A0_content_only_flat",
        segmentation=Segmentation.FLAT,
        consumes_provenance=False,
        description="Control. Scores the whole message; replicates the ADR-016 run.",
        is_control=True,
    ),
    Arm(
        name="A1_provenance_aware_flat",
        segmentation=Segmentation.FLAT,
        consumes_provenance=True,
        description=(
            "Provenance available but constant across classes. Tests whether the "
            "field's mere presence changes anything."
        ),
    ),
    Arm(
        name="A2_provenance_aware_split",
        segmentation=Segmentation.SPLIT,
        consumes_provenance=True,
        description=(
            "Treatment. Scores only spans the gateway marked UNTRUSTED: an "
            "instruction inside untrusted data is illegitimate, the user's own "
            "instruction is not."
        ),
    ),
    Arm(
        name="A3_content_only_split",
        segmentation=Segmentation.SPLIT,
        consumes_provenance=False,
        description=(
            "Isolates segmentation from provenance. Scores every span and takes "
            "the maximum. If A2 == A3, the benefit is segmentation."
        ),
    ),
    Arm(
        name="M2_provenance_removed",
        segmentation=Segmentation.SPLIT,
        consumes_provenance=True,
        provenance_mode=ProvenanceMode.REMOVED,
        description="Ablation: split spans labelled UNKNOWN. A2 should collapse.",
    ),
    Arm(
        name="M4_provenance_inverted",
        segmentation=Segmentation.SPLIT,
        consumes_provenance=True,
        provenance_mode=ProvenanceMode.INVERTED,
        description=(
            "Robustness: carrier tagged EXTERNAL, embedded span tagged USER_INPUT. "
            "Recall should collapse. Not a production scenario."
        ),
    ),
)


def locate_embedded(text: str, candidates: tuple[str, ...]) -> tuple[str, str] | None:
    """Split `text` into (carrier, embedded) at a known pool string.

    Returns None when no candidate is present. **This is an oracle**: it uses
    knowledge of how the corpus was authored, which a real gateway does not have.
    The experiment therefore measures the ceiling available to a perfectly
    cooperating integration, not what an arbitrary deployment obtains — the single
    most important limitation of the result (ADR-018).
    """
    for candidate in candidates:
        index = text.find(candidate)
        if index != -1:
            carrier = (text[:index] + text[index + len(candidate) :]).strip()
            return carrier, candidate
    return None


def build_parts(
    text: str,
    arm: Arm,
    embedded_candidates: tuple[str, ...],
) -> list[Part]:
    """The parts one arm sees for one sample.

    FLAT reproduces what the gateway derives from the corpus today: a single
    `user` part, `USER_INPUT`/`PRINCIPAL`. SPLIT reproduces what a cooperating
    integration would send: the carrier as the user's own words, the embedded span
    declared external.
    """
    if arm.segmentation is Segmentation.FLAT:
        return [Part(text, Provenance.USER_INPUT, TrustLevel.PRINCIPAL)]

    located = locate_embedded(text, embedded_candidates)
    if located is None:
        # No embedded span found: the sample is indivisible, so SPLIT degenerates
        # to FLAT rather than silently dropping the sample.
        return [Part(text, Provenance.USER_INPUT, TrustLevel.PRINCIPAL)]

    carrier, embedded = located
    if arm.provenance_mode is ProvenanceMode.REMOVED:
        carrier_tag = (Provenance.UNKNOWN, TrustLevel.UNKNOWN)
        embedded_tag = (Provenance.UNKNOWN, TrustLevel.UNKNOWN)
    elif arm.provenance_mode is ProvenanceMode.INVERTED:
        carrier_tag = (Provenance.EXTERNAL, TrustLevel.UNTRUSTED)
        embedded_tag = (Provenance.USER_INPUT, TrustLevel.PRINCIPAL)
    else:
        carrier_tag = (Provenance.USER_INPUT, TrustLevel.PRINCIPAL)
        embedded_tag = (Provenance.EXTERNAL, TrustLevel.UNTRUSTED)

    parts = []
    if carrier:
        parts.append(Part(carrier, *carrier_tag))
    parts.append(Part(embedded, *embedded_tag))
    return parts


def combine(scores: list[float], parts: list[Part], arm: Arm) -> float:
    """One score for the sample, from its per-part scores.

    A provenance-consuming arm scores **only untrusted spans**: it is answering
    "is there an instruction in data that should not contain one", and the user's
    own instruction is not evidence of that. An arm that ignores provenance takes
    the maximum over every span, which is the strongest content-only reading.

    When a provenance-consuming arm finds no untrusted span it returns 0.0 — not
    a failure but the correct answer to its question. That is exactly what makes
    the M2 ablation informative.
    """
    if not scores:
        return 0.0
    if not arm.consumes_provenance:
        return max(scores)
    untrusted = [score for score, part in zip(scores, parts, strict=True) if part.untrusted]
    return max(untrusted) if untrusted else 0.0
