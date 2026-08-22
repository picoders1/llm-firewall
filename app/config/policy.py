"""Security policy schema — declarative YAML, validated before the app serves traffic.

The second half of the split configuration model
(docs/adr/ADR-011-configuration-model.md). Policy is declarative so that a
threshold or action change is a reviewable diff rather than a code change, and it
is validated strictly so that a misconfiguration fails at startup rather than
surfacing as a runtime surprise (NFR-009).

Two validation stages, deliberately separated:

* **Schema validation** (this module, at parse time) — structure, ranges, enums,
  duplicate detectors, and secret-shaped keys.
* **Registry validation** (:meth:`PolicyConfig.validate_against_registry`) —
  unknown detector names and ``redact`` configured on a detector that cannot emit
  spans. This takes the capability map as an *argument* rather than importing the
  detector registry, so ``app.config`` keeps its position at the bottom of the
  dependency graph (docs/02-system-architecture.md).
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Self

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_serializer, model_validator

from app.core.exceptions import ConfigurationError
from app.core.types import ACTION_PRECEDENCE, Action, Direction, ErrorPolicy, Role, TrustLevel

# Substrings that make a key look like a credential. Heuristic by nature — it is a
# safety net beneath the rule that secrets live in the environment, backed up by
# gitleaks in CI, not a guarantee (ADR-011).
SECRET_KEY_HINTS: tuple[str, ...] = (
    "secret",
    "password",
    "passwd",
    "token",
    "apikey",
    "api_key",
    "_key",
    "credential",
)

# Actions that require the detector to report character spans.
SPAN_REQUIRING_ACTIONS = frozenset({Action.REDACT})

# Identifies how `PolicyConfig.version_hash` canonicalises the model before
# hashing. It is hashed alongside the policy so that a value produced by this
# scheme can never be mistaken for one produced by the previous, defective one
# (R-115). Bump it whenever the canonical form changes for a reason other than
# the policy itself changing; every stored `policy_version` from before the bump
# then belongs unambiguously to the older scheme.
CANONICALISATION_SCHEME = "v2-sorted-sets"


class DetectorCapabilities(BaseModel):
    """What a registered detector can do, as declared by its implementation.

    Supplied to :meth:`PolicyConfig.validate_against_registry` so policy can be
    checked against reality without ``app.config`` importing ``app.detectors``.
    """

    model_config = ConfigDict(frozen=True)

    name: str
    emits_spans: bool = False
    directions: frozenset[Direction] = frozenset({Direction.INPUT, Direction.OUTPUT})
    # Reported so an operator can see which detectors actually read provenance;
    # policy validation does not require it (ADR-017).
    consumes_provenance: bool = False


class TrustOverlay(BaseModel):
    """A provenance-conditional adjustment to one detector's policy.

    **May only tighten.** A lower threshold or a more severe action is permitted;
    the reverse is rejected when the policy is loaded, not when a request arrives
    (ADR-017 §4/§11).

    That direction is the whole reason provenance is safe to accept from a
    semi-trusted integration: an attacker's best possible lie buys no relaxation,
    because relaxation is not expressible. The cost is that provenance can never
    be used to *reduce* false positives, which is deliberate — a relaxation is
    exactly what would be forged.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    threshold: float | None = Field(default=None, ge=0.0, le=1.0)
    action: Action | None = None


class DetectorPolicy(BaseModel):
    """Policy for one detector in one direction."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    detector: str
    enabled: bool = True

    # PLACEHOLDER VALUE. Thresholds are only meaningful next to a
    # precision/recall curve for that detector on a named dataset. Nothing in
    # this repository has been calibrated; these are chosen in Phase 2 from a
    # published sweep (docs/21-open-decisions.md, OD-3).
    threshold: float = Field(default=0.85, ge=0.0, le=1.0)

    action: Action = Action.BLOCK
    on_error: ErrorPolicy = ErrorPolicy.FAIL_CLOSED
    timeout_ms: int = Field(default=250, gt=0, le=60_000)

    # Provenance-conditional tightening, keyed by the gateway-derived trust level
    # (ADR-017). Absent or empty means provenance changes nothing, which is what
    # makes a request carrying no provenance behave exactly as it did before.
    by_trust: dict[TrustLevel, TrustOverlay] = Field(default_factory=dict)

    # Detector-specific settings (entity lists, custom patterns). Opaque here;
    # interpreted by the detector that owns them.
    options: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _overlays_may_only_tighten(self) -> Self:
        """Reject a loosening overlay at load time.

        Checked here rather than at request time so that a policy which could
        weaken a decision cannot start. An operator finds out from a failed
        deployment, not from an incident review.

        An overlay with neither field set is permitted and meaningful: it records
        that a trust level was considered and deliberately left alone.
        """
        for trust, overlay in self.by_trust.items():
            if overlay.threshold is not None and overlay.threshold > self.threshold:
                raise ValueError(
                    f"by_trust.{trust.value}.threshold {overlay.threshold} is higher than the "
                    f"base threshold {self.threshold}, which would make detection *less* "
                    "sensitive for that trust level. Provenance may only tighten (ADR-017)."
                )
            if overlay.action is Action.ALLOW:
                raise ValueError(
                    f"by_trust.{trust.value}.action 'allow' is not configurable; an overlay "
                    "exists to escalate, and ALLOW is the absence of a decision"
                )
            if (
                overlay.action is not None
                and ACTION_PRECEDENCE[overlay.action] < ACTION_PRECEDENCE[self.action]
            ):
                raise ValueError(
                    f"by_trust.{trust.value}.action '{overlay.action.value}' is less severe than "
                    f"the base action '{self.action.value}'. Provenance may only tighten "
                    "(ADR-017)."
                )
        return self

    def effective(self, trust: TrustLevel | None) -> tuple[float, Action, str | None]:
        """Threshold and action for this entry at a given trust level.

        Returns `(threshold, action, reason)` where `reason` is None when no
        overlay applied. The reason is surfaced in `PolicyDecision.reasons` so a
        provenance-driven escalation is never invisible to the operator reading an
        audit record.
        """
        if trust is None:
            return self.threshold, self.action, None
        overlay = self.by_trust.get(trust)
        if overlay is None:
            return self.threshold, self.action, None
        threshold = self.threshold if overlay.threshold is None else overlay.threshold
        action = self.action if overlay.action is None else overlay.action
        if threshold == self.threshold and action is self.action:
            return self.threshold, self.action, None
        return (
            threshold,
            action,
            f"trust={trust.value}:threshold={threshold:.4f}:action={action.value}",
        )

    @model_validator(mode="after")
    def _reject_allow_action(self) -> Self:
        # ALLOW is the absence of a decision, not something a detector requests.
        # Configuring it would silently make the entry a no-op that still costs
        # latency — disabling the entry is what the operator means.
        if self.action is Action.ALLOW:
            raise ValueError(
                "action 'allow' is not configurable; set 'enabled: false' to disable a detector"
            )
        return self


class RedactionSettings(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    # Labelled tokens rather than fixed-width masks: the text stays readable and
    # the caller can see what was removed (docs/08-pii-security.md).
    template: str = "<{entity}_REDACTED>"

    @model_validator(mode="after")
    def _template_has_placeholder(self) -> Self:
        if "{entity}" not in self.template:
            raise ValueError("redaction.template must contain the '{entity}' placeholder")
        return self


class Limits(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    max_inspect_chars: int = Field(default=100_000, gt=0)
    max_messages: int = Field(default=200, gt=0)
    base64_segments: int = Field(default=8, ge=0)


class PolicyConfig(BaseModel):
    """A complete, validated security policy."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    version: int = Field(default=1, ge=1)
    policy_name: str = "default"

    # `tool` is inspected by default because it is the indirect-injection
    # surface: retrieved documents and tool output are attacker-controlled in any
    # RAG or agent system (docs/03-request-response-flow.md).
    inspect_roles: frozenset[Role] = frozenset({Role.USER, Role.TOOL})

    @field_serializer("inspect_roles")
    def _serialise_inspect_roles(self, roles: frozenset[Role]) -> list[str]:
        """Sorted, because a set has no order and Python's is not stable (R-115).

        Pydantic renders a ``frozenset`` as a list in *set-iteration* order, which
        for strings depends on ``PYTHONHASHSEED`` — randomised per process. That
        made ``version_hash`` return one of two values at random for a byte-identical
        policy, so one policy appeared in the audit trail as two versions. Sorting
        here makes the serialised order a property of the values rather than of the
        interpreter that happened to load them.

        A new set-valued field on this model would reintroduce the defect silently;
        `tests/unit/test_policy_version.py` fails if one is added without a
        deterministic serialiser.
        """
        return sorted(role.value for role in roles)

    input: dict[str, DetectorPolicy] = Field(default_factory=dict)
    output: dict[str, DetectorPolicy] = Field(default_factory=dict)

    redaction: RedactionSettings = RedactionSettings()
    limits: Limits = Limits()

    @model_validator(mode="after")
    def _no_duplicate_detectors(self) -> Self:
        for direction, entries in (("input", self.input), ("output", self.output)):
            seen: dict[str, str] = {}
            for entry_name, entry in entries.items():
                if entry.detector in seen:
                    raise ValueError(
                        f"{direction}: detector {entry.detector!r} is configured twice "
                        f"({seen[entry.detector]!r} and {entry_name!r}); the policy that would "
                        "apply to its results is ambiguous"
                    )
                seen[entry.detector] = entry_name
        return self

    # --- Lookups -----------------------------------------------------------

    def section(self, direction: Direction) -> dict[str, DetectorPolicy]:
        # Explicit rather than `input if direction is Direction.INPUT else output`:
        # that form silently returns the OUTPUT section for any value that is not
        # the INPUT enum member — including the string "input" — which is a
        # wrong-section bug that looks like a configuration problem.
        if direction is Direction.INPUT:
            return self.input
        if direction is Direction.OUTPUT:
            return self.output
        raise ValueError(f"unknown direction: {direction!r}")

    def for_detector(self, direction: Direction, detector: str) -> DetectorPolicy | None:
        """Policy governing a detector's results in one direction, if configured."""
        for entry in self.section(direction).values():
            if entry.detector == detector:
                return entry
        return None

    def enabled_detectors(self, direction: Direction) -> tuple[str, ...]:
        return tuple(entry.detector for entry in self.section(direction).values() if entry.enabled)

    def fail_open_detectors(self) -> tuple[str, ...]:
        """Every detector configured to fail open, for the startup warning.

        An operator must never discover a fail-open detector while reading YAML
        during an incident (ADR-007).
        """
        names: list[str] = []
        for direction in (Direction.INPUT, Direction.OUTPUT):
            for entry in self.section(direction).values():
                if entry.enabled and entry.on_error is ErrorPolicy.FAIL_OPEN:
                    names.append(f"{direction.value}:{entry.detector}")
        return tuple(names)

    # --- Versioning --------------------------------------------------------

    def version_hash(self) -> str:
        """Deterministic fingerprint of the *effective* policy.

        Computed over the canonical serialisation of the validated model, not the
        raw file bytes, so it is stable across comments, key order and formatting
        and changes if and only if the effective policy changes. Recorded on
        every persisted decision, without which "why was this blocked in March"
        is unanswerable after any config change (docs/11-data-model.md).

        "Deterministic" includes *across processes*, which it was not until R-115:
        a set-valued field serialised in ``PYTHONHASHSEED``-dependent order, so a
        byte-identical policy hashed to one of two values at random and one policy
        reached the audit trail as two versions. Determinism is the entire point of
        the field, so it is asserted in a subprocess with a varied hash seed rather
        than in-process, where the seed is fixed and the defect is invisible.

        The canonicalisation scheme is hashed with the policy, so a value produced
        here cannot be confused with one produced before the fix. Values recorded
        by the defective scheme are not repairable and stay as they are.

        The policy contains no secrets by construction, so nothing secret enters
        the hash.
        """
        canonical = json.dumps(
            {"canonicalisation": CANONICALISATION_SCHEME, "policy": self.model_dump(mode="json")},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        return f"sha256:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()[:32]}"

    # --- Registry validation ----------------------------------------------

    def validate_against_registry(self, capabilities: Mapping[str, DetectorCapabilities]) -> None:
        """Check the policy against the detectors that actually exist.

        Raises :class:`ConfigurationError` listing every problem at once — an
        operator fixing a policy file should not have to rediscover the next
        error on each restart.
        """
        problems: list[str] = []

        for direction in (Direction.INPUT, Direction.OUTPUT):
            for entry_name, entry in self.section(direction).items():
                where = f"{direction.value}.{entry_name}"
                capability = capabilities.get(entry.detector)

                if capability is None:
                    known = ", ".join(sorted(capabilities)) or "<none registered>"
                    problems.append(
                        f"{where}: unknown detector {entry.detector!r}. Known detectors: {known}"
                    )
                    continue

                if direction not in capability.directions:
                    problems.append(
                        f"{where}: detector {entry.detector!r} does not support the "
                        f"{direction.value} direction"
                    )

                if entry.action in SPAN_REQUIRING_ACTIONS and not capability.emits_spans:
                    problems.append(
                        f"{where}: action {entry.action.value!r} requires character spans, but "
                        f"detector {entry.detector!r} does not emit them; it would silently "
                        "degrade to a no-op"
                    )

        if problems:
            raise ConfigurationError("invalid security policy:\n  - " + "\n  - ".join(problems))


def assert_no_secret_keys(data: Any, path: str = "") -> None:
    """Recursively reject secret-shaped keys anywhere in a policy document.

    Enforced as a startup failure rather than a review convention: this is the
    mechanism that makes it impossible to commit a credential through a policy
    file (ADR-011, threat T-19).
    """
    if isinstance(data, dict):
        for key, value in data.items():
            lowered = str(key).lower()
            if any(hint in lowered for hint in SECRET_KEY_HINTS):
                location = f"{path}.{key}" if path else str(key)
                raise ConfigurationError(
                    f"policy contains a secret-shaped key at {location!r}. "
                    "Secrets must be supplied as FIREWALL_* environment variables, "
                    "never in a policy file (ADR-011)."
                )
            assert_no_secret_keys(value, f"{path}.{key}" if path else str(key))
    elif isinstance(data, list):
        for index, item in enumerate(data):
            assert_no_secret_keys(item, f"{path}[{index}]")


def load_policy(path: Path) -> PolicyConfig:
    """Parse and schema-validate a policy file.

    Registry validation is a separate step performed once the detector registry
    is built; see :meth:`PolicyConfig.validate_against_registry`.
    """
    if not path.is_file():
        raise ConfigurationError(f"policy file not found: {path}")

    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigurationError(f"{path}: policy file is not valid YAML: {exc}") from exc

    if raw is None:
        raise ConfigurationError(f"{path}: policy file is empty")
    if not isinstance(raw, dict):
        raise ConfigurationError(f"{path}: expected a mapping at the top level")

    assert_no_secret_keys(raw)

    try:
        return PolicyConfig.model_validate(raw)
    except Exception as exc:  # pydantic ValidationError and friends
        raise ConfigurationError(f"{path}: invalid policy: {exc}") from exc
