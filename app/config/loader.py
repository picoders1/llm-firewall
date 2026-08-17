"""Composition of the two configuration systems into one immutable object.

`AppConfig` is what the application factory holds for the process lifetime:
settings from the environment, policy from YAML, and the policy version hash that
every audit record will carry.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from app.config.policy import PolicyConfig, load_policy
from app.config.settings import Settings, get_settings
from app.core.types import Direction


@dataclass(frozen=True, slots=True)
class AppConfig:
    """Fully resolved configuration for one process."""

    settings: Settings
    policy: PolicyConfig
    policy_version: str
    policy_path: Path

    @property
    def fail_open_detectors(self) -> tuple[str, ...]:
        return self.policy.fail_open_detectors()

    def safe_summary(self) -> dict[str, object]:
        """Effective configuration for the startup log, with secrets masked."""
        return {
            **self.settings.safe_summary(),
            "policy_name": self.policy.policy_name,
            "policy_version": self.policy_version,
            "policy_path": str(self.policy_path),
            "inspect_roles": sorted(role.value for role in self.policy.inspect_roles),
            "input_detectors": list(self.policy.enabled_detectors(Direction.INPUT)),
            "output_detectors": list(self.policy.enabled_detectors(Direction.OUTPUT)),
            "fail_open_detectors": list(self.fail_open_detectors),
        }


def load_config(settings: Settings | None = None) -> AppConfig:
    """Load settings and policy together.

    Raises :class:`app.core.exceptions.ConfigurationError` if the policy is
    missing or invalid. Callers should let this propagate: an unusable policy
    must prevent startup rather than degrade silently into an unprotected
    gateway (NFR-009).
    """
    resolved = settings or get_settings()
    policy = load_policy(resolved.policy_file)
    return AppConfig(
        settings=resolved,
        policy=policy,
        policy_version=policy.version_hash(),
        policy_path=resolved.policy_file,
    )
