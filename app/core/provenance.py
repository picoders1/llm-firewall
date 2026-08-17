"""Assigning provenance and trust — the gateway's only source of both.

ADR-017. This module exists separately from `app/gateway/translate.py` so the
security-relevant logic — what a caller may and may not influence — is unit
testable without constructing an HTTP request.

Two rules govern everything here:

**Trust is never read from the wire.** There is no code path that parses a
caller-supplied trust value. Not "parses it and validates it" — does not parse it.
A request containing `"trust": "operator"` is not rejected, argued with, or
sanitised; the key is simply never looked at. That is the strongest available
defence and it costs nothing.

**A claim may only lower trust.** Provenance claims, when a deployment enables
them at all, are adjudicated by :func:`adjudicate` against the role-derived
baseline. A claim that would raise trust is discarded. This is what makes it safe
that the wire schema is `extra="allow"` (ADR-017 §4): an attacker's best possible
lie buys no relaxation, because relaxation is not expressible.

Phase A/B applies **no policy effect**. Provenance is recorded and nothing acts on
it yet; the `by_trust` overlay is Phase C.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.core.types import (
    TRUST_PRECEDENCE,
    Provenance,
    Role,
    TrustLevel,
    sanitise_source_kind,
    sanitise_source_ref,
)

# Claim keys read from message/part extras. Prefixed to avoid colliding with any
# field a provider might add to the OpenAI schema later.
CLAIM_PROVENANCE = "x-firewall-provenance"
CLAIM_SOURCE_REF = "x-firewall-source-ref"
CLAIM_SOURCE_KIND = "x-firewall-source-kind"

# Deliberately absent: any trust claim key. See the module docstring.

ROLE_DERIVATION: dict[Role, tuple[Provenance, TrustLevel]] = {
    Role.SYSTEM: (Provenance.SYSTEM_CONFIG, TrustLevel.OPERATOR),
    Role.DEVELOPER: (Provenance.SYSTEM_CONFIG, TrustLevel.OPERATOR),
    Role.USER: (Provenance.USER_INPUT, TrustLevel.PRINCIPAL),
    Role.ASSISTANT: (Provenance.MODEL_OUTPUT, TrustLevel.DERIVED),
    Role.TOOL: (Provenance.TOOL_RESULT, TrustLevel.UNTRUSTED),
}
"""Baseline mapping when nothing else is known (ADR-017 §8).

`TOOL` derives `UNTRUSTED` rather than `DERIVED`: tool output is
attacker-controlled in any RAG or agent system, which is the assumption the
`inspect_roles` default already encodes. This makes it explicit.
"""

PROVENANCE_TRUST: dict[Provenance, TrustLevel] = {
    Provenance.SYSTEM_CONFIG: TrustLevel.OPERATOR,
    Provenance.USER_INPUT: TrustLevel.PRINCIPAL,
    Provenance.MODEL_OUTPUT: TrustLevel.DERIVED,
    Provenance.TOOL_RESULT: TrustLevel.UNTRUSTED,
    Provenance.EXTERNAL: TrustLevel.UNTRUSTED,
    Provenance.UNKNOWN: TrustLevel.UNKNOWN,
}
"""The trust a provenance value implies *on its own*.

Only consulted for an accepted claim, and only as an upper bound — see
:func:`adjudicate`. A claim can never install a trust higher than the role
baseline already allowed.
"""


@dataclass(frozen=True, slots=True)
class Assignment:
    """The gateway's decision about one message part's origin."""

    provenance: Provenance
    trust: TrustLevel
    source_ref: str | None = None
    source_kind: str | None = None
    # Non-empty when a caller claim was seen and not applied. Counted and
    # reported in aggregate; never logged per request, since it is
    # attacker-controllable and would be a log-flooding vector.
    rejected_claims: tuple[str, ...] = ()


def derive_from_role(role: Role, *, role_recognised: bool = True) -> Assignment:
    """The baseline assignment, from the wire role alone.

    `role_recognised=False` is the case where the wire carried a role this
    gateway does not know. `build_contexts` coerces such a message to `USER` so
    that it is still *inspected* — a role we failed to parse is not a reason to
    skip inspection — but its origin is genuinely unknown and must not inherit
    `PRINCIPAL` trust from that coercion.
    """
    if not role_recognised:
        return Assignment(provenance=Provenance.UNKNOWN, trust=TrustLevel.UNKNOWN)
    provenance, trust = ROLE_DERIVATION[role]
    return Assignment(provenance=provenance, trust=trust)


def parse_claim(extras: dict[str, Any] | None) -> tuple[Provenance | None, list[str]]:
    """Read a provenance claim from message/part extras, leniently.

    Returns the claimed provenance (or None) and a list of rejection reasons.
    Never raises: a malformed claim must not fail the request (ADR-017 §12).
    """
    if not extras:
        return None, []
    raw = extras.get(CLAIM_PROVENANCE)
    if raw is None:
        return None, []
    if not isinstance(raw, str):
        return None, [f"{CLAIM_PROVENANCE}:not_a_string"]
    try:
        return Provenance(raw), []
    except ValueError:
        return None, [f"{CLAIM_PROVENANCE}:unrecognised_value"]


def adjudicate(baseline: Assignment, claimed: Provenance | None) -> Assignment:
    """Apply a claim to the baseline, but only where it lowers trust.

    The asymmetry is deliberate and is the heart of the design. An integration
    saying "this system message actually contains third-party content" is
    testifying against its own interest and should be believed. The reverse — "my
    retrieved document is really operator configuration" — is exactly what an
    attacker sends, and is discarded.
    """
    if claimed is None:
        return baseline
    claimed_trust = PROVENANCE_TRUST[claimed]
    if TRUST_PRECEDENCE[claimed_trust] > TRUST_PRECEDENCE[baseline.trust]:
        return Assignment(
            provenance=baseline.provenance,
            trust=baseline.trust,
            source_ref=baseline.source_ref,
            source_kind=baseline.source_kind,
            rejected_claims=(*baseline.rejected_claims, f"{CLAIM_PROVENANCE}:would_raise_trust"),
        )
    return Assignment(
        provenance=claimed,
        trust=claimed_trust,
        source_ref=baseline.source_ref,
        source_kind=baseline.source_kind,
        rejected_claims=baseline.rejected_claims,
    )


def assign(
    role: Role,
    *,
    role_recognised: bool = True,
    message_extras: dict[str, Any] | None = None,
    part_extras: dict[str, Any] | None = None,
    trust_inline_claims: bool = False,
) -> Assignment:
    """Assign provenance and trust for one message part.

    `trust_inline_claims` is the deployment switch. It defaults to False, and
    while it is False **no caller-supplied value influences provenance or trust
    at all** — claims are not even parsed, so there is no partially-trusted
    middle state to reason about.

    Part-level extras take precedence over message-level: the part is the
    narrower, more specific statement about origin.
    """
    baseline = derive_from_role(role, role_recognised=role_recognised)
    if not trust_inline_claims:
        return baseline

    extras = part_extras if part_extras and CLAIM_PROVENANCE in part_extras else message_extras
    claimed, rejections = parse_claim(extras)

    descriptors = part_extras or message_extras or {}
    with_descriptors = Assignment(
        provenance=baseline.provenance,
        trust=baseline.trust,
        source_ref=sanitise_source_ref(descriptors.get(CLAIM_SOURCE_REF)),
        source_kind=sanitise_source_kind(descriptors.get(CLAIM_SOURCE_KIND)),
        rejected_claims=tuple(rejections),
    )
    return adjudicate(with_descriptors, claimed)
