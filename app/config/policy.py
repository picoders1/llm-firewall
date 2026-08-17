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
from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.core.exceptions import ConfigurationError
from app.core.types import Action, Direction, ErrorPolicy, Role

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


class DetectorCapabilities(BaseModel):
    """What a registered detector can do, as declared by its implementation.

    Supplied to :meth:`PolicyConfig.validate_against_registry` so policy can be
    checked against reality without ``app.config`` importing ``app.detectors``.
    """

    model_config = ConfigDict(frozen=True)

    name: str
    emits_spans: bool = False
    directions: frozenset[Direction] = frozenset({Direction.INPUT, Direction.OUTPUT})


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

    # Detector-specific settings (entity lists, custom patterns). Opaque here;
    # interpreted by the detector that owns them.
    options: dict[str, Any] = Field(default_factory=dict)

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

        The policy contains no secrets by construction, so nothing secret enters
        the hash.
        """
        canonical = json.dumps(
            self.model_dump(mode="json"),
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
