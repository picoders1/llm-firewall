"""Operator authentication for the Security Operations console (ADR-023)."""

from app.auth.identity import (
    AccessClass,
    AuthConfig,
    AuthOutcome,
    DenyReason,
    Principal,
    Role,
    classify_path,
)

__all__ = [
    "AccessClass",
    "AuthConfig",
    "AuthOutcome",
    "DenyReason",
    "Principal",
    "Role",
    "classify_path",
]
