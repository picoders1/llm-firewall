"""Application settings — deployment values and secrets, from the environment.

This is one half of a deliberately split configuration model
(docs/adr/ADR-011-configuration-model.md). Secrets and deployment-specific values
arrive as environment variables; declarative *security policy* lives in YAML and
is loaded by :mod:`app.config.policy`. The two never mix, and policy YAML
structurally rejects secret-shaped keys.

Precedence, lowest to highest::

    built-in defaults  <  config/environments/<env>.yaml  <  FIREWALL_* env vars
                       <  explicit runtime overrides (constructor kwargs)
"""

from __future__ import annotations

from enum import StrEnum
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import Field, SecretStr, field_validator
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
)

DEFAULT_ENVIRONMENTS_DIR = Path("config/environments")


class Environment(StrEnum):
    DEVELOPMENT = "development"
    TESTING = "testing"
    PRODUCTION = "production"


class ContentLogging(StrEnum):
    """How much inspected content may reach logs and the audit database.

    ``NONE`` is the default. ``FULL`` exists for local debugging and is refused
    in production — see :meth:`Settings.effective_content_logging` and
    docs/10-security-model.md.
    """

    NONE = "none"
    HASH = "hash"
    FULL = "full"


class LogFormat(StrEnum):
    JSON = "json"
    CONSOLE = "console"


class EnvironmentOverlaySource(PydanticBaseSettingsSource):
    """Loads ``config/environments/<environment>.yaml`` as a low-priority source.

    Placed *below* environment variables in the precedence chain so a deployment
    can always override a checked-in overlay. The environment name is read
    directly from ``FIREWALL_ENVIRONMENT`` because the overlay to load must be
    known before the settings object exists.

    Overlays carry non-secret deployment defaults only. A key that looks like a
    secret is rejected here for the same reason it is rejected in policy YAML:
    checked-in files must not be able to carry credentials.
    """

    _SECRET_HINTS = ("secret", "password", "token", "_key", "apikey", "api_key")

    def __init__(self, settings_cls: type[BaseSettings], environments_dir: Path) -> None:
        super().__init__(settings_cls)
        self._environments_dir = environments_dir
        self._data: dict[str, Any] | None = None

    def _load(self) -> dict[str, Any]:
        if self._data is not None:
            return self._data

        import os

        env_name = os.environ.get("FIREWALL_ENVIRONMENT", Environment.DEVELOPMENT.value)
        path = self._environments_dir / f"{env_name}.yaml"
        if not path.is_file():
            self._data = {}
            return self._data

        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if not isinstance(raw, dict):
            raise ValueError(f"{path}: expected a mapping at the top level")

        for key in raw:
            lowered = str(key).lower()
            if any(hint in lowered for hint in self._SECRET_HINTS):
                raise ValueError(
                    f"{path}: key {key!r} looks like a secret. "
                    "Secrets belong in environment variables only (ADR-011)."
                )

        self._data = {str(k): v for k, v in raw.items()}
        return self._data

    def get_field_value(self, field: Any, field_name: str) -> tuple[Any, str, bool]:
        data = self._load()
        return data.get(field_name), field_name, False

    def __call__(self) -> dict[str, Any]:
        return dict(self._load())


class Settings(BaseSettings):
    """Deployment configuration and secrets."""

    model_config = SettingsConfigDict(
        env_prefix="FIREWALL_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        validate_default=True,
    )

    # --- Environment -------------------------------------------------------
    environment: Environment = Environment.DEVELOPMENT
    environments_dir: Path = DEFAULT_ENVIRONMENTS_DIR

    # --- Logging -----------------------------------------------------------
    log_level: str = "INFO"
    log_format: LogFormat = LogFormat.JSON
    content_logging: ContentLogging = ContentLogging.NONE

    # --- Upstream LLM (used from Phase 1) ----------------------------------
    upstream_base_url: str = "http://localhost:8081/v1"
    upstream_api_key: SecretStr | None = None
    upstream_connect_timeout_s: float = Field(default=5.0, gt=0)
    upstream_read_timeout_s: float = Field(default=60.0, gt=0)
    upstream_max_connections: int = Field(default=100, gt=0)

    # --- Request limits ----------------------------------------------------
    max_request_bytes: int = Field(default=256 * 1024, gt=0)

    # --- Provenance (ADR-017) ----------------------------------------------
    # Whether an inline `x-firewall-provenance` claim on a message or content
    # part is honoured at all. **Off by default, and deliberately here rather
    # than in policy YAML**: this is a trust-boundary switch, so it belongs to
    # whoever deploys the process, not to a policy file that config management
    # may rotate independently.
    #
    # Even when enabled, a claim can only *lower* trust (app/core/provenance.py),
    # and no caller-supplied trust value is ever read.
    trust_inline_provenance_claims: bool = False

    # --- Detectors ---------------------------------------------------------
    policy_file: Path = Path("config/policies/default.yaml")
    detector_default_timeout_ms: int = Field(default=250, gt=0)
    detector_max_threads: int = Field(default=8, gt=0)

    # --- Persistence -------------------------------------------------------
    database_url: SecretStr | None = None
    database_pool_size: int = Field(default=5, gt=0)
    persist_events: bool = True
    require_audit: bool = False

    # --- Observability -----------------------------------------------------
    metrics_enabled: bool = True
    tracing_enabled: bool = False
    # Per-stage timings as response headers, for benchmarking. Off by default:
    # precise detector timings are a timing side channel an attacker could use to
    # infer which detector fired (docs/15-performance-benchmarking.md).
    expose_timing_headers: bool = False

    # --- Server ------------------------------------------------------------
    host: str = "0.0.0.0"  # noqa: S104 — binding in a container is intended
    port: int = Field(default=8000, gt=0, le=65535)

    @field_validator("log_level", mode="before")
    @classmethod
    def _validate_log_level(cls, value: Any) -> str:
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        upper = str(value).upper()
        if upper not in allowed:
            raise ValueError(f"log_level must be one of {sorted(allowed)}, got {value!r}")
        return upper

    @field_validator("upstream_base_url")
    @classmethod
    def _validate_upstream_url(cls, value: str) -> str:
        if not value.startswith(("http://", "https://")):
            raise ValueError("upstream_base_url must start with http:// or https://")
        return value.rstrip("/")

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        """Highest priority first.

        The environment overlay sits *below* env vars and dotenv so that a
        deployment can always override a checked-in file, and above the built-in
        defaults so an environment can shift them.
        """
        overlay_dir = Path(
            init_settings.init_kwargs.get("environments_dir", DEFAULT_ENVIRONMENTS_DIR)  # type: ignore[attr-defined]
        )
        return (
            init_settings,
            env_settings,
            dotenv_settings,
            file_secret_settings,
            EnvironmentOverlaySource(settings_cls, overlay_dir),
        )

    # --- Derived behaviour -------------------------------------------------

    @property
    def is_production(self) -> bool:
        return self.environment is Environment.PRODUCTION

    def effective_content_logging(self) -> ContentLogging:
        """Downgrade FULL content logging in production rather than trusting config.

        A misconfigured environment variable must not be able to turn the
        firewall into a prompt-leaking sink — and production is exactly when
        someone reaches for ``full`` during an incident.
        """
        if self.is_production and self.content_logging is ContentLogging.FULL:
            return ContentLogging.HASH
        return self.content_logging

    def safe_summary(self) -> dict[str, Any]:
        """Effective configuration for the startup log, with secrets masked.

        An operator should be able to see what is actually in force without
        guessing, and without any secret reaching the log.
        """
        return {
            "environment": self.environment.value,
            "log_level": self.log_level,
            "log_format": self.log_format.value,
            "content_logging": self.effective_content_logging().value,
            "content_logging_requested": self.content_logging.value,
            "upstream_base_url": self.upstream_base_url,
            "upstream_api_key_set": self.upstream_api_key is not None,
            "max_request_bytes": self.max_request_bytes,
            "policy_file": str(self.policy_file),
            "detector_default_timeout_ms": self.detector_default_timeout_ms,
            "detector_max_threads": self.detector_max_threads,
            "database_configured": self.database_url is not None,
            "persist_events": self.persist_events,
            "require_audit": self.require_audit,
            "metrics_enabled": self.metrics_enabled,
            "tracing_enabled": self.tracing_enabled,
        }


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Process-wide settings. Cached: re-reading the environment per request is
    both wasteful and a source of configuration drift within a single request."""
    return Settings()
