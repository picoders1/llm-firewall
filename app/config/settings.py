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

import ipaddress
import re
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

# Where a container runtime mounts secrets. Docker Compose `secrets:` and
# Kubernetes secret volumes both land here by convention, and pydantic-settings
# reads a file named for the prefixed setting — `/run/secrets/FIREWALL_UPSTREAM_API_KEY`.
#
# A FILE rather than an environment variable, because an environment variable is
# readable by anything that can run `docker inspect`, anything that can read
# `/proc/<pid>/environ`, and every crash reporter that dumps the environment. A
# mounted file is readable by the process and nothing else (ADR-028).
#
# Resolved at import and only when the directory exists: pydantic-settings warns
# on a missing `secrets_dir`, and every developer machine and CI runner would
# otherwise carry that warning for a path only containers have.
# The floor for every audit-retention period. Lives here rather than beside the
# sweeper because `app.database` imports this module and not the other way round.
# Zero would mean "delete everything on the next sweep", and a mistyped
# `FIREWALL_RETENTION_*` should not be recoverable only from a backup (ADR-030).
MINIMUM_RETENTION_DAYS = 1

DOCKER_SECRETS_DIR = Path("/run/secrets")
_SECRETS_DIR = str(DOCKER_SECRETS_DIR) if DOCKER_SECRETS_DIR.is_dir() else None


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


class AuditWriteMode(StrEnum):
    """How an audit record reaches PostgreSQL.

    ``SYNC`` is Phase 0's behaviour and the default: the record is written before
    the response is returned, so a served request always has a row. ADR-012
    registered a bounded queue as the Phase 5 successor and named the measurement
    that would justify it; Phase 15 supplied that measurement (10.5 ms p50).

    A third mode — block on a full queue, so saturation degrades to synchronous
    behaviour — was implemented, measured and **removed**. Against a stalled
    database it did not degrade to synchronous behaviour; it hung the request
    path indefinitely and turned a database stall into a total gateway outage,
    which is strictly worse than either surviving option
    (docs/adr/ADR-029-audit-write-architecture.md).
    """

    SYNC = "sync"
    QUEUE_DROP = "queue_drop"


class CallerAuthMode(StrEnum):
    """How an *application* calling `/v1/**` proves it is allowed to.

    Deliberately a different setting, a different header and a different
    principal type from :class:`ConsoleAuthMode`. Operators are people reading a
    console; callers are services spending a model budget. Sharing one mechanism
    between them would mean a stolen dashboard session could drive the model, or
    a service token could read the security event log — see
    docs/adr/ADR-024-llm-caller-authentication.md.

    ``API_KEY`` is the default in production because it is the only mode that
    needs no change to an OpenAI client: `OpenAI(base_url=..., api_key=...)`
    already sends `Authorization: Bearer`.
    """

    DISABLED = "disabled"
    API_KEY = "api_key"
    PROXY = "proxy"


class ConsoleAuthMode(StrEnum):
    """How operator identity reaches the Security Operations console.

    ``PROXY`` is the only mode that authenticates anything. ``DISABLED`` exists so
    the stack still starts with one command on a laptop, and is refused in
    production — see :meth:`Settings.effective_console_auth_mode` and
    docs/adr/ADR-023-operator-authentication.md.

    There is deliberately no ``password`` or ``token`` mode. Adding one would mean
    a credential store, a session mechanism and a reset path inside a security
    gateway, to duplicate something every deployment target already terminates.
    """

    DISABLED = "disabled"
    PROXY = "proxy"


# RFC 9110 field-name token. A header name is used to *read* attacker-adjacent
# input, so a malformed one is a configuration error, not something to sanitise
# at request time.
_HEADER_NAME = re.compile(r"^[A-Za-z0-9!#$%&\'*+.^_`|~-]{1,64}$")

IpNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

# A caller identifier reaches a metric label and an audit column, so it is
# constrained rather than sanitised: an operator picks these, and a malformed one
# is a configuration error to fail on at startup.
_CALLER_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")


def parse_caller_keys(raw: str) -> tuple[tuple[str, str], ...]:
    """``"web-app:<sha256>,batch:<sha256>"`` → ``(("web-app", "<sha256>"), ...)``.

    **Hashes, never raw credentials.** What a deployment puts in its secret store
    is the digest of the key, so an environment dump — the way this kind of
    secret actually leaks — yields nothing a caller can present. The raw key
    exists only in the caller's own configuration.

    SHA-256 without a salt or a work factor is correct *here* and would be wrong
    for a password: these keys are generated by `scripts/generate_caller_key.py`
    with 256 bits of entropy, so there is no dictionary to run and no rainbow
    table to build. A short hand-written key would break that assumption, which
    is why the helper generates rather than accepts one.
    """
    entries: list[tuple[str, str]] = []
    seen_ids: set[str] = set()
    seen_hashes: set[str] = set()
    for item in (part.strip() for part in raw.split(",")):
        if not item:
            continue
        caller_id, separator, digest = item.partition(":")
        if not separator:
            raise ValueError(f"caller_api_keys: {item!r} is not '<caller_id>:<sha256-hex>'")
        caller_id, digest = caller_id.strip(), digest.strip().lower()
        if not _CALLER_ID.match(caller_id):
            raise ValueError(
                f"caller_api_keys: {caller_id!r} is not a valid caller id "
                "(lowercase letters, digits, dot, dash, underscore; 64 chars max)"
            )
        if not _SHA256_HEX.match(digest):
            raise ValueError(
                f"caller_api_keys: the credential for {caller_id!r} is not a SHA-256 hex "
                "digest. Generate one with scripts/generate_caller_key.py — and note that "
                "the RAW key must never appear here."
            )
        if caller_id in seen_ids:
            raise ValueError(f"caller_api_keys: {caller_id!r} is configured twice")
        if digest in seen_hashes:
            # Two callers sharing a key makes the audit trail lie about who spent
            # the budget, which is most of the reason to have caller identity.
            raise ValueError("caller_api_keys: two callers share the same credential")
        seen_ids.add(caller_id)
        seen_hashes.add(digest)
        entries.append((caller_id, digest))
    return tuple(entries)


def parse_networks(raw: str, *, field: str) -> tuple[IpNetwork, ...]:
    """Comma-separated CIDRs → networks, with the field named on failure.

    Declared as a string rather than a ``tuple[str, ...]`` because these values
    arrive as environment variables and ``FIREWALL_TRUSTED_PROXIES=10.0.0.0/8``
    is what an operator will actually write. A list-typed setting would demand
    JSON and fail confusingly on the obvious input.
    """
    out: list[IpNetwork] = []
    for item in (part.strip() for part in raw.split(",")):
        if not item:
            continue
        try:
            out.append(ipaddress.ip_network(item, strict=False))
        except ValueError as exc:
            raise ValueError(f"{field}: {item!r} is not a valid IP network ({exc})") from None
    return tuple(out)


def parse_csv(raw: str) -> tuple[str, ...]:
    return tuple(item for item in (part.strip() for part in raw.split(",")) if item)


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
        # Environment variables still win, per the precedence chain ADR-011
        # documents. Files are an alternative source for the four SecretStr
        # settings, not a new layer above them.
        secrets_dir=_SECRETS_DIR,
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
    # Idle connections kept for reuse. Bounded separately from the total because
    # an unbounded keepalive pool holds file descriptors against a provider long
    # after a burst has passed (ADR-025 §13).
    upstream_max_keepalive_connections: int = Field(default=20, gt=0)

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

    # --- Operator authentication (ADR-023) ---------------------------------
    # Identity is terminated *outside* the process, at a reverse proxy or
    # ingress, and arrives as a header. Nothing here stores a password, issues a
    # token, or knows what a user is.
    #
    # `None` means "derive from the environment": PROXY in production, DISABLED
    # elsewhere. Written this way rather than as a plain default so that a
    # production deployment cannot inherit an unauthenticated console by
    # forgetting a variable — the same shape as `effective_content_logging`.
    console_auth_mode: ConsoleAuthMode | None = None

    # Comma-separated CIDRs. The peer address of the TCP connection must fall
    # inside one of these before ANY identity header is read. This is the whole
    # anti-spoofing mechanism: X-Forwarded-For is deliberately not consulted,
    # because a forwarded-for chain is client-supplied and proves nothing.
    trusted_proxies: str = ""

    # Optional second factor for the boundary itself: a value only the proxy
    # knows. Matters when the trusted CIDR is a whole pod network rather than a
    # single ingress address.
    proxy_shared_secret: SecretStr | None = None
    # A header *name*, not a credential.
    proxy_shared_secret_header: str = "X-Firewall-Proxy-Secret"  # noqa: S105

    # Header names the proxy injects. Defaults follow oauth2-proxy, which is the
    # most common thing sitting in this position.
    auth_subject_header: str = "X-Auth-Request-User"
    auth_roles_header: str = "X-Auth-Request-Groups"

    # Comma-separated group values that grant the OPERATOR role. Empty means any
    # authenticated subject is an operator — correct when the proxy is already
    # restricted to the operations team, which is the common case.
    operator_roles: str = ""

    # Comma-separated CIDRs allowed to scrape /metrics without an operator
    # identity. Empty means /metrics requires an operator once auth is enforced.
    metrics_networks: str = ""

    # Same-origin sign-out path published by the proxy (e.g. `/oauth2/sign_out`).
    # Same-origin only: the console never links to an external identity provider,
    # so an operator cannot be walked to an attacker-chosen host by a config typo.
    console_logout_path: str | None = None

    # Send HSTS. Explicit rather than inferred: TLS terminates at the ingress, so
    # the process cannot observe whether the browser hop was HTTPS, and guessing
    # wrong on plain HTTP locks a developer out of their own localhost.
    https_enforced: bool = False

    # --- Caller authentication (ADR-024) -----------------------------------
    # A DIFFERENT boundary from the operator console above, deliberately kept
    # apart: an operator session must never drive the model, and a service key
    # must never read the security event log.
    #
    # `None` derives from the environment: API_KEY in production, DISABLED
    # elsewhere. Setting DISABLED in production is refused at startup — the
    # process holds the upstream credential, so an open `/v1` is an open proxy
    # to a paid model.
    caller_auth_mode: CallerAuthMode | None = None

    # `<caller_id>:<sha256-hex>` pairs, comma separated. **Digests, not keys** —
    # the raw credential lives only in the caller's configuration, so an
    # environment dump here yields nothing presentable.
    caller_api_keys: str = ""

    # Proxy mode only. Same anti-spoofing rule as the operator boundary: the
    # peer address of the socket, never X-Forwarded-For.
    caller_trusted_proxies: str = ""
    caller_proxy_shared_secret: SecretStr | None = None
    caller_identity_header: str = "X-Firewall-Caller"

    # Abuse protection. Both are PER PROCESS: with N replicas the effective limit
    # is N times these values (ADR-024 records the scaling limitation rather than
    # reaching for Redis to hide it). 0 disables.
    caller_rate_limit_per_minute: int = Field(default=0, ge=0)
    caller_max_concurrent_requests: int = Field(default=0, ge=0)

    # --- Admission control (ADR-025) ---------------------------------------
    # The in-process safety net BEHIND the edge, not instead of it. Volumetric
    # abuse is the edge's job; these bound what one process will accept once a
    # request has already arrived.

    # Requests in flight at once, across every route. 0 disables. Guards the
    # process itself and, behind it, the detector thread pool and the upstream
    # connection pool. Over this, the answer is 503 + Retry-After: the server is
    # at capacity, which is a different fact from "you exceeded your quota" (429).
    max_concurrent_requests: int = Field(default=0, ge=0)

    # Failed caller authentications per minute per client address before that
    # client is refused *before* the credential comparison. 0 disables. The key
    # is the socket peer, or the trusted proxy's `client_ip_header` — never a
    # value the client chose, or it could evade the throttle by changing it.
    auth_failures_per_minute: int = Field(default=0, ge=0)

    # Read only when the peer is inside `trusted_proxies`. Deliberately a single
    # address header, not `X-Forwarded-For`: a forwarded-for chain is partly
    # client-supplied and picking "the right entry" is a class of bug avoided by
    # not having the feature.
    client_ip_header: str = "X-Real-IP"

    # --- Audit write path (ADR-012, ADR-029) --------------------------------
    # `sync` is Phase 0's behaviour: the row is written before the response is
    # returned, so a served request always has a record. The queued modes move
    # the write off the request path and accept a window in which a request has
    # been answered and its row has not been written.
    audit_write_mode: AuditWriteMode = AuditWriteMode.SYNC

    # Records held in memory awaiting a write. Bounded, always: an unbounded
    # queue in front of a failing database converts a database outage into an
    # out-of-memory kill (ADR-012). Dropping is visible in a metric; an OOM is
    # visible as an outage.
    audit_queue_size: int = Field(default=1000, gt=0)

    # How long shutdown waits for the queue to drain before abandoning what is
    # left. Bounded so a stuck database cannot hold a rolling deploy open.
    audit_drain_timeout_s: float = Field(default=5.0, gt=0)

    # --- Audit retention (ADR-012, ADR-030) --------------------------------
    # Off by default, and enabled explicitly in `compose.prod.yaml`. Deletion is
    # irreversible, so an upgrade must not start removing an operator's audit
    # trail because a default changed underneath them — the same reasoning that
    # keeps `audit_write_mode` at `sync` (ADR-029). Startup warns when it is off,
    # because a store that only grows is a liability that gets worse with time.
    retention_enabled: bool = False

    # `request_traces` (and, by cascade, `detector_results`). 30 days is the
    # operational tuning window from ADR-012, and it is also the console's
    # maximum query window, so retention never removes a row the console could
    # still have displayed.
    retention_trace_days: int = Field(default=30, ge=MINIMUM_RETENTION_DAYS)

    # `security_events`. Longer because an investigation usually starts well
    # after the event; the denormalised auditor table is meant to outlive the
    # operational one.
    retention_event_days: int = Field(default=180, ge=MINIMUM_RETENTION_DAYS)

    # A sweep at startup and then on this interval. Not a daily cron: there is no
    # scheduler in this deployment (OD-41), and a once-a-day job inside a process
    # that gets redeployed daily is a job that never runs.
    retention_interval_s: float = Field(default=3600.0, gt=0)

    # Rows removed per statement. Small on purpose: `Database` applies a 5-second
    # command timeout, so one unbounded DELETE against a backlog would time out,
    # roll back, and delete nothing — permanently.
    retention_batch_size: int = Field(default=1000, gt=0)

    # Ceiling per table per sweep, so a misconfiguration cannot empty the audit
    # trail in one pass unobserved. Reaching it is logged, never silent.
    retention_max_rows_per_sweep: int = Field(default=50_000, gt=0)

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

    @field_validator("retention_event_days")
    @classmethod
    def _validate_retention_ordering(cls, value: int, info: Any) -> int:
        """`security_events` must outlive `request_traces`.

        Not a taste preference: the console's event-detail endpoint LEFT JOINs an
        event to its trace precisely because events survive longer, and the
        contract documents null operational fields on an old event as normal.
        Inverting the order would make the longer-lived table the one that
        disappears first, which nothing in the design expects.
        """
        traces = info.data.get("retention_trace_days")
        if traces is not None and value < traces:
            raise ValueError(
                f"retention_event_days ({value}) must be >= retention_trace_days ({traces}): "
                "security_events is the record an investigation reads months later and is "
                "designed to outlive the request traces (ADR-012)"
            )
        return value

    @field_validator("log_level", mode="before")
    @classmethod
    def _validate_log_level(cls, value: Any) -> str:
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        upper = str(value).upper()
        if upper not in allowed:
            raise ValueError(f"log_level must be one of {sorted(allowed)}, got {value!r}")
        return upper

    @field_validator("caller_api_keys")
    @classmethod
    def _validate_caller_keys(cls, value: str) -> str:
        parse_caller_keys(value)
        return value

    @field_validator("trusted_proxies", "metrics_networks", "caller_trusted_proxies")
    @classmethod
    def _validate_networks(cls, value: str, info: Any) -> str:
        parse_networks(value, field=info.field_name)
        return value

    @field_validator(
        "proxy_shared_secret_header",
        "auth_subject_header",
        "auth_roles_header",
        "caller_identity_header",
        "client_ip_header",
    )
    @classmethod
    def _validate_header_name(cls, value: str) -> str:
        if not _HEADER_NAME.match(value):
            raise ValueError(f"{value!r} is not a valid HTTP header name")
        return value

    @field_validator("console_logout_path")
    @classmethod
    def _validate_logout_path(cls, value: str | None) -> str | None:
        """Same-origin absolute path, or nothing.

        `//evil.example` is a protocol-relative URL that browsers navigate
        off-origin, and it starts with `/` — so `startswith("/")` alone is the
        check people get wrong.
        """
        if value is None:
            return None
        if not value.startswith("/") or value.startswith("//"):
            raise ValueError(
                "console_logout_path must be a same-origin absolute path such as '/oauth2/sign_out'"
            )
        return value

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

    def effective_console_auth_mode(self) -> ConsoleAuthMode:
        """Configured mode, or the environment's default.

        Production defaults to PROXY and refuses DISABLED. The refusal is not a
        style preference: an unauthenticated console publishes block rates,
        detector configuration and thresholds — enough to tune an evasion
        against this gateway without ever tripping it (threat T-13).
        """
        if self.console_auth_mode is None:
            return ConsoleAuthMode.PROXY if self.is_production else ConsoleAuthMode.DISABLED
        if self.is_production and self.console_auth_mode is ConsoleAuthMode.DISABLED:
            raise ValueError(
                "console_auth_mode=disabled is refused when environment=production. "
                "Terminate operator authentication at the ingress and set "
                "FIREWALL_TRUSTED_PROXIES (docs/adr/ADR-023-operator-authentication.md)."
            )
        return self.console_auth_mode

    @property
    def trusted_proxy_networks(self) -> tuple[IpNetwork, ...]:
        return parse_networks(self.trusted_proxies, field="trusted_proxies")

    @property
    def metrics_scrape_networks(self) -> tuple[IpNetwork, ...]:
        return parse_networks(self.metrics_networks, field="metrics_networks")

    @property
    def operator_role_values(self) -> frozenset[str]:
        return frozenset(parse_csv(self.operator_roles))

    def effective_caller_auth_mode(self) -> CallerAuthMode:
        """Configured mode, or the environment's default.

        Production derives to ``API_KEY`` and refuses ``DISABLED``. This is the
        one refusal in the file with a direct financial consequence: the process
        holds ``upstream_api_key``, so an unauthenticated ``/v1`` lets anyone who
        can reach the port spend the operator's model budget (threat T-26).
        """
        if self.caller_auth_mode is None:
            return CallerAuthMode.API_KEY if self.is_production else CallerAuthMode.DISABLED
        if self.is_production and self.caller_auth_mode is CallerAuthMode.DISABLED:
            raise ValueError(
                "caller_auth_mode=disabled is refused when environment=production. "
                "The gateway holds the upstream credential, so an unauthenticated /v1 is "
                "an open proxy to a paid model (docs/adr/ADR-024-llm-caller-authentication.md)."
            )
        return self.caller_auth_mode

    @property
    def caller_key_digests(self) -> tuple[tuple[str, str], ...]:
        return parse_caller_keys(self.caller_api_keys)

    @property
    def caller_trusted_proxy_networks(self) -> tuple[IpNetwork, ...]:
        return parse_networks(self.caller_trusted_proxies, field="caller_trusted_proxies")

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
            "audit_write_mode": self.audit_write_mode.value,
            "audit_queue_size": self.audit_queue_size,
            "retention_enabled": self.retention_enabled,
            "retention_trace_days": self.retention_trace_days,
            "retention_event_days": self.retention_event_days,
            "metrics_enabled": self.metrics_enabled,
            "tracing_enabled": self.tracing_enabled,
            # The shared secret is reported as set/unset only. Everything else
            # here is a boundary description, not a credential.
            "console_auth_mode": self.console_auth_mode.value if self.console_auth_mode else None,
            "trusted_proxies": [str(net) for net in self.trusted_proxy_networks],
            "proxy_shared_secret_set": self.proxy_shared_secret is not None,
            "operator_roles": sorted(self.operator_role_values),
            "metrics_networks": [str(net) for net in self.metrics_scrape_networks],
            "https_enforced": self.https_enforced,
            # Caller IDs are operator-chosen labels and safe to log. The digests
            # are not logged: they are not presentable credentials, but there is
            # no reason for a startup line to carry them either.
            "caller_auth_mode": self.caller_auth_mode.value if self.caller_auth_mode else None,
            "caller_ids": [caller for caller, _ in self.caller_key_digests],
            "caller_trusted_proxies": [str(n) for n in self.caller_trusted_proxy_networks],
            "caller_proxy_shared_secret_set": self.caller_proxy_shared_secret is not None,
            "caller_rate_limit_per_minute": self.caller_rate_limit_per_minute,
            "caller_max_concurrent_requests": self.caller_max_concurrent_requests,
            "max_concurrent_requests": self.max_concurrent_requests,
            "auth_failures_per_minute": self.auth_failures_per_minute,
            "upstream_max_connections": self.upstream_max_connections,
            "upstream_max_keepalive_connections": self.upstream_max_keepalive_connections,
        }


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Process-wide settings. Cached: re-reading the environment per request is
    both wasteful and a source of configuration drift within a single request."""
    return Settings()
