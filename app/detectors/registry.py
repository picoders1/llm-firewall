"""Detector registry — an explicit dictionary of name → factory.

No entry-point discovery, no plugin scanning. For a security product, a mechanism
where an installed package silently becomes part of the security decision is a
supply-chain hole, and a dict is sufficient until third-party detectors are an
actual requirement (docs/adr/ADR-002-detector-plugin-architecture.md).

Adding a detector is: implement the protocol, register the name here, add a
policy block. Replacing one is a single line — which is the property Phase 2
depends on.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping

from app.config.policy import DetectorCapabilities, DetectorPolicy
from app.core.exceptions import ConfigurationError
from app.detectors.base import BaseDetector
from app.detectors.injection.heuristic import HeuristicInjectionDetector
from app.detectors.injection.heuristic import build as build_injection_heuristic
from app.detectors.injection.transformer import TransformerInjectionDetector
from app.detectors.injection.transformer import build as build_injection_transformer
from app.detectors.jailbreak.heuristic import HeuristicJailbreakDetector
from app.detectors.jailbreak.heuristic import build as build_jailbreak_heuristic
from app.detectors.pii.regex import RegexPiiDetector
from app.detectors.pii.regex import build as build_pii_regex
from app.detectors.stub import OutputPolicyStub, build_output_stub

DetectorFactory = Callable[[DetectorPolicy], BaseDetector]

# Phase 0 baselines, the ADR-021 layer-2 classifier, plus one remaining stub.
# Layer 2 does not *replace* layer 1: the ladder runs both, cheap first
# (docs/05-detector-architecture.md). Remaining Phase 2/3 replacements:
#   jailbreak.heuristic → jailbreak.transformer
#   pii.regex           → pii.presidio
#   output.stub         → the Phase 3 output-policy detector
_REGISTRY: dict[str, tuple[DetectorFactory, type[BaseDetector]]] = {
    HeuristicInjectionDetector.name: (build_injection_heuristic, HeuristicInjectionDetector),
    # Layer 2, ADR-021. Registered so it is configurable; the default policy
    # leaves it DISABLED, so a default install is unchanged by its presence.
    TransformerInjectionDetector.name: (build_injection_transformer, TransformerInjectionDetector),
    HeuristicJailbreakDetector.name: (build_jailbreak_heuristic, HeuristicJailbreakDetector),
    RegexPiiDetector.name: (build_pii_regex, RegexPiiDetector),
    OutputPolicyStub.name: (build_output_stub, OutputPolicyStub),
}


def registered_names() -> tuple[str, ...]:
    return tuple(sorted(_REGISTRY))


def capabilities() -> Mapping[str, DetectorCapabilities]:
    """Capability map for policy validation.

    Passed *into* :meth:`app.config.policy.PolicyConfig.validate_against_registry`
    so that ``app.config`` never imports ``app.detectors`` and the dependency
    direction stays one-way.
    """
    return {name: cls.capabilities() for name, (_, cls) in _REGISTRY.items()}


def create(name: str, policy: DetectorPolicy) -> BaseDetector:
    entry = _REGISTRY.get(name)
    if entry is None:
        raise ConfigurationError(
            f"unknown detector {name!r}; known detectors: {', '.join(registered_names())}"
        )
    factory, _ = entry
    return factory(policy)
