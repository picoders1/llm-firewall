"""What `/ready` actually means (ADR-027).

`/ready` answers one question: **can this instance safely accept production
traffic through the boundary its deployment configured?** That is narrower than
"is everything healthy" and wider than "did the process start", and both
mistakes are expensive — the first takes a fleet out of rotation because a
non-blocking dependency blinked, the second routes traffic to an instance that
will refuse all of it.

## Two honest categories of check, and the difference matters

**Re-assertions.** Most security-boundary checks here restate an invariant the
process already refuses to start without: production cannot run with an
unauthenticated console, `api_key` mode cannot run with no keys, HTTPS
enforcement cannot run without a trusted proxy. Readiness cannot *discover* a
violation of those — the process would not be alive to answer. They earn their
place anyway, for two reasons: they make the security contract machine-readable
at the load balancer, and they are a regression net for the day someone relaxes
a startup check without noticing what depended on it. `test_readiness.py` pins
that correspondence so the two cannot drift.

**Genuinely new information.** Two checks report things nothing else does: the
applied database schema revision, and whether the audit store is reachable
*classified by whether this deployment actually needs it*. The second is a
correction — the previous implementation failed readiness whenever the database
was down, which contradicts ADR-012's decision that an audit outage must not
become a traffic outage.

Nothing here is inferred from live client behaviour. Readiness validates
configuration; "no authenticated request has arrived recently" is a monitoring
question, and answering it here would make a quiet Sunday look like an outage.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from app.auth.caller import CallerAuthConfig
from app.auth.identity import AuthConfig
from app.auth.transport import TransportPolicy
from app.config.settings import CallerAuthMode, ConsoleAuthMode, Settings

# A trusted range wider than this stops being an assertion about a proxy and
# becomes an assertion about a network. /16 is 65,536 addresses: large enough
# for any real ingress subnet, small enough that a /8 stands out.
BROAD_PREFIX_THRESHOLD = 16


class Category(StrEnum):
    """Which part of the service contract a check belongs to."""

    CONFIGURATION = "configuration"
    SECURITY_BOUNDARY = "security_boundary"
    DETECTORS = "detectors"
    DATABASE = "database"


class Requirement(StrEnum):
    """Whether failing this check should take the instance out of rotation.

    The distinction is the whole point of the file. Marking everything REQUIRED
    is how a readiness probe turns a degraded dependency into an outage; marking
    everything ADVISORY is how it stops being a probe.
    """

    REQUIRED = "required"
    ADVISORY = "advisory"


@dataclass(frozen=True, slots=True)
class Check:
    name: str
    category: Category
    requirement: Requirement
    passed: bool
    # Safe for an UNAUTHENTICATED reader: `/ready` is a public probe, so no
    # detail here names a mode, a CIDR, a caller id, a path or a credential.
    # The operator-authenticated `/api/v1/system/status` carries the specifics.
    detail: str | None = None


def _networks_detail(count: int) -> str:
    return f"{count} trusted range(s) configured"


def evaluate(state: Any) -> list[Check]:
    """Build the readiness breakdown from application state.

    Takes the state object rather than a `Request` so the whole contract is
    testable without an HTTP layer, and so every check is visible in one place
    instead of scattered across a handler.
    """
    config = getattr(state, "config", None)
    checks: list[Check] = [_policy(config)]

    if config is not None:
        settings: Settings = config.settings
        checks.extend(
            [
                _operator_boundary(getattr(state, "auth", None), settings),
                _caller_boundary(getattr(state, "caller_auth", None), settings),
                _transport(getattr(state, "transport", None), settings),
                _trusted_proxy_breadth(getattr(state, "auth", None)),
            ]
        )

    checks.append(_detectors(state))
    return checks


# --- configuration ------------------------------------------------------------


def _policy(config: Any) -> Check:
    loaded = config is not None and bool(getattr(config, "policy_version", None))
    return Check(
        name="policy_loaded",
        category=Category.CONFIGURATION,
        requirement=Requirement.REQUIRED,
        passed=loaded,
        # The version hash identifies which reviewed policy is in force and is
        # already published on the operator API; it is not a secret. The policy
        # *contents* and its path are never reported here.
        detail=config.policy_version if loaded else "policy not loaded",
    )


# --- security boundary ---------------------------------------------------------


def _operator_boundary(auth: AuthConfig | None, settings: Settings) -> Check:
    """The console boundary (ADR-023). A re-assertion of a startup invariant."""
    if auth is None:
        return Check(
            name="operator_boundary",
            category=Category.SECURITY_BOUNDARY,
            requirement=Requirement.REQUIRED,
            passed=False,
            detail="operator boundary not initialised",
        )

    if settings.is_production and auth.mode is not ConsoleAuthMode.PROXY:
        return Check(
            "operator_boundary",
            Category.SECURITY_BOUNDARY,
            Requirement.REQUIRED,
            False,
            "console is not authenticated",
        )
    if auth.enforcing and not auth.trusted_proxies:
        return Check(
            "operator_boundary",
            Category.SECURITY_BOUNDARY,
            Requirement.REQUIRED,
            False,
            "no trusted proxy configured",
        )
    return Check(
        "operator_boundary",
        Category.SECURITY_BOUNDARY,
        Requirement.REQUIRED,
        True,
        "enforcing" if auth.enforcing else "not enforced (non-production)",
    )


def _caller_boundary(caller: CallerAuthConfig | None, settings: Settings) -> Check:
    """The `/v1` boundary (ADR-024).

    Checks that credentials are *configured*, never that any have been
    presented. A gateway with no traffic is ready; §7 is explicit about the
    difference and it is the difference between a probe and a usage metric.
    """
    if caller is None:
        return Check(
            "caller_boundary",
            Category.SECURITY_BOUNDARY,
            Requirement.REQUIRED,
            False,
            "caller boundary not initialised",
        )

    if settings.is_production and not caller.enforcing:
        return Check(
            "caller_boundary",
            Category.SECURITY_BOUNDARY,
            Requirement.REQUIRED,
            False,
            "gateway callers are not authenticated",
        )
    if caller.mode is CallerAuthMode.API_KEY and not caller.key_digests:
        return Check(
            "caller_boundary",
            Category.SECURITY_BOUNDARY,
            Requirement.REQUIRED,
            False,
            "no caller credentials configured",
        )
    if caller.mode is CallerAuthMode.PROXY and not caller.trusted_proxies:
        return Check(
            "caller_boundary",
            Category.SECURITY_BOUNDARY,
            Requirement.REQUIRED,
            False,
            "no trusted proxy configured",
        )
    detail = (
        f"{len(caller.key_digests)} caller(s) configured"
        if caller.enforcing
        else "not enforced (non-production)"
    )
    return Check("caller_boundary", Category.SECURITY_BOUNDARY, Requirement.REQUIRED, True, detail)


def _transport(policy: TransportPolicy | None, settings: Settings) -> Check:
    """HTTPS enforcement (ADR-026).

    Verifies the assertion can *succeed*, not that it currently does. Whether a
    given request arrives over TLS is answered per request with 426; a readiness
    probe that depended on the last request's scheme would flap.
    """
    if policy is None:
        return Check(
            "transport",
            Category.SECURITY_BOUNDARY,
            Requirement.REQUIRED,
            False,
            "transport policy not initialised",
        )

    if settings.is_production and not policy.https_enforced:
        return Check(
            "transport",
            Category.SECURITY_BOUNDARY,
            Requirement.REQUIRED,
            False,
            "HTTPS is not required",
        )
    if policy.https_enforced and not policy.trusted_proxies:
        return Check(
            "transport",
            Category.SECURITY_BOUNDARY,
            Requirement.REQUIRED,
            False,
            "HTTPS required but no peer can assert it",
        )
    return Check(
        "transport",
        Category.SECURITY_BOUNDARY,
        Requirement.REQUIRED,
        True,
        "HTTPS required" if policy.https_enforced else "HTTPS not required (non-production)",
    )


def _trusted_proxy_breadth(auth: AuthConfig | None) -> Check:
    """ADVISORY, and one of the two checks that reports something new.

    `0.0.0.0/0` is refused at startup, but `10.0.0.0/8` is accepted — and a
    trusted range spanning a whole private network means every workload on it
    can assert an operator identity, a client address and a TLS claim. That is
    usually a mistake and occasionally deliberate, which is exactly what
    ADVISORY is for: visible, never fatal.
    """
    networks = tuple(getattr(auth, "trusted_proxies", ()) or ())
    broad = [n for n in networks if n.prefixlen < BROAD_PREFIX_THRESHOLD]
    if not networks:
        return Check(
            "trusted_proxy_breadth",
            Category.SECURITY_BOUNDARY,
            Requirement.ADVISORY,
            True,
            "no trusted proxy configured",
        )
    return Check(
        "trusted_proxy_breadth",
        Category.SECURITY_BOUNDARY,
        Requirement.ADVISORY,
        not broad,
        (
            f"{len(broad)} of {len(networks)} trusted range(s) are broader than a /"
            f"{BROAD_PREFIX_THRESHOLD}"
            if broad
            else _networks_detail(len(networks))
        ),
    )


# --- detectors ------------------------------------------------------------------


def _detectors(state: Any) -> Check:
    """Enabled detectors only (§10).

    A detector disabled by policy is not required, so it cannot block readiness —
    `injection.transformer` ships disabled and warn-only, and an instance without
    its weights is correctly ready. A detector that is *enabled* and failed to
    warm never reaches this code: `pipeline.warmup()` raises and the process does
    not start.
    """
    warmed = bool(getattr(state, "detectors_warmed", False))
    pipeline = getattr(state, "pipeline", None)
    count = len(pipeline.all_detectors) if pipeline is not None else 0
    return Check(
        name="detectors_warmed",
        category=Category.DETECTORS,
        requirement=Requirement.REQUIRED,
        passed=warmed,
        detail=(
            f"{count} enabled detector(s) warmed" if warmed else "detector warmup did not complete"
        ),
    )


# --- database --------------------------------------------------------------------


def database_checks(
    *, configured: bool, reachable: bool, revision: str | None, expected: str | None, required: bool
) -> list[Check]:
    """The audit store, classified by whether this deployment needs it.

    **This is where the previous implementation was wrong.** It failed readiness
    whenever the database was unreachable — which contradicts ADR-012: with
    `require_audit=false` an audit-write failure does not fail the request, the
    security decision is unaffected, and only the record is lost. Taking every
    instance out of rotation for that turns an audit outage into a traffic
    outage, which is the §5 mistake exactly.

    So the requirement level follows `require_audit`. When audit persistence is
    mandatory, an unusable store means every request fails and readiness must
    fail with it.

    Schema revision is classified the same way, and for a second reason:
    [docs/17](../../docs/17-deployment-architecture.md) prescribes expand/contract
    migrations run as a separate step *before* the rollout, so a new instance is
    expected to tolerate the previous revision briefly. Demanding exact equality
    would break the rollout pattern the project documents.
    """
    if not configured:
        return [
            Check(
                "database",
                Category.DATABASE,
                Requirement.ADVISORY,
                True,
                "persistence disabled",
            )
        ]

    level = Requirement.REQUIRED if required else Requirement.ADVISORY
    checks = [
        Check(
            "database",
            Category.DATABASE,
            level,
            reachable,
            "reachable" if reachable else "unreachable",
        )
    ]

    if not reachable:
        return checks

    if revision is None:
        detail = "no schema revision recorded; migrations have not been applied"
        matches = False
    elif expected is None:
        # The code could not determine its own expected head. Reporting the
        # applied revision is still useful; asserting a match would be a guess.
        detail = f"schema at {revision}; expected revision unknown"
        matches = True
    else:
        matches = revision == expected
        detail = (
            f"schema at {revision}" if matches else f"schema at {revision}, code expects {expected}"
        )

    checks.append(Check("database_schema", Category.DATABASE, level, matches, detail))
    return checks


def is_ready(checks: list[Check]) -> bool:
    """Only REQUIRED checks decide. Advisory failures are reported and ignored."""
    return all(check.passed for check in checks if check.requirement is Requirement.REQUIRED)


__all__ = [
    "BROAD_PREFIX_THRESHOLD",
    "Category",
    "Check",
    "Requirement",
    "database_checks",
    "evaluate",
    "is_ready",
]
