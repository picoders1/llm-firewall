"""The production topology, asserted rather than described (ADR-028).

Five phases produced deployment obligations — publish only the edge, keep the
database off any routable network, mount secrets instead of exporting them, probe
`/ready` rather than `/health` — and every one of them lived in a numbered list
in `docs/17-deployment-architecture.md` that a manifest could contradict without
anything noticing. `compose.yaml` contradicted several of them, which is how the
gap survived five phases.

This file reads the shipped manifests and asserts each obligation. It is a
static check by design: it runs in the fast suite with no containers, so a
manifest edit that quietly publishes the gateway fails in seconds rather than in
whatever review notices it. `tests/integration/test_prod_topology.py` then proves
the same properties against a running stack, because a manifest can be correct
and the runtime still wrong.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

pytestmark = pytest.mark.security

REPO = Path(__file__).resolve().parents[2]
PROD = REPO / "compose.prod.yaml"
SELFTEST = REPO / "compose.prod-selftest.yaml"

# Services that must never be reachable from the host or the internet. The edge
# is the only entry point, and that is the whole shape of the topology.
PRIVATE_SERVICES = ("firewall-api", "postgres", "migrate")

# Settings the application treats as SecretStr. Each must arrive as a mounted
# file, never as an environment variable.
SECRET_SETTINGS = (
    "FIREWALL_UPSTREAM_API_KEY",
    "FIREWALL_DATABASE_URL",
    "FIREWALL_CALLER_API_KEYS",
)


def _compose(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def prod() -> dict:
    return _compose(PROD)


# --- The obligation that five phases stated and no artefact enforced ----------


def test_only_the_edge_publishes_a_port(prod: dict):
    """docs/17 obligation 8. `compose.yaml` publishes the gateway on host :8005
    (container :8000, changed from :8000 when the host port was remapped) and
    PostgreSQL on :5434 — correct for development and the exact thing production
    must not do."""
    published = {
        name: service.get("ports")
        for name, service in prod["services"].items()
        if service.get("ports")
    }
    assert set(published) == {"edge"}, f"unexpected published ports: {published}"


@pytest.mark.parametrize("service", PRIVATE_SERVICES)
def test_no_private_service_publishes_anything(prod: dict, service: str):
    assert not prod["services"][service].get("ports")


def test_the_edge_publishes_only_https_and_the_redirect(prod: dict):
    ports = prod["services"]["edge"]["ports"]
    targets = {entry.rsplit(":", 1)[1] for entry in ports}
    assert targets == {"8443", "8080"}, targets


def test_the_database_is_on_an_internal_network_only(prod: dict):
    """`internal: true` means the Docker network has no route to the outside, so
    the isolation does not depend on a host firewall rule being right."""
    networks = prod["services"]["postgres"]["networks"]
    assert set(networks) == {"data"}, networks
    assert prod["networks"]["data"]["internal"] is True


def test_the_database_shares_no_network_with_the_edge(prod: dict):
    """A route from the public entry point to the audit store, however indirect,
    is the thing the three-network split exists to prevent."""
    edge_nets = set(prod["services"]["edge"]["networks"])
    db_nets = set(prod["services"]["postgres"]["networks"])
    assert not (edge_nets & db_nets), edge_nets & db_nets


def test_the_database_has_no_egress_path(prod: dict):
    """T-14 in the reverse direction: the audit store must not sit on the network
    that reaches the model provider."""
    assert "egress" not in prod["services"]["postgres"]["networks"]


def test_the_gateway_is_the_only_bridge_between_the_networks(prod: dict):
    gateway = set(prod["services"]["firewall-api"]["networks"])
    assert gateway == {"edge", "data", "egress"}


# --- Secrets are files, not environment ---------------------------------------


@pytest.mark.parametrize("secret", SECRET_SETTINGS)
def test_every_credential_is_mounted_rather_than_exported(prod: dict, secret: str):
    """An environment variable is readable by `docker inspect`, by anything that
    can read /proc/<pid>/environ, and by every crash reporter that dumps the
    environment on the way down."""
    service = prod["services"]["firewall-api"]
    assert secret in service["secrets"], f"{secret} is not mounted"
    assert secret not in (service.get("environment") or {}), f"{secret} is also exported"


def test_no_secret_value_is_written_inline(prod: dict):
    """Every declared secret is sourced from a file path, never a literal."""
    for name, definition in prod["secrets"].items():
        assert set(definition) == {"file"}, f"{name} is not file-sourced: {definition}"
        assert definition["file"].startswith("./deploy/secrets/"), name


def test_the_secrets_directory_is_ignored_by_git_and_docker():
    """The directory itself, not just its contents, so `git add deploy/secrets`
    cannot succeed by accident."""
    assert "deploy/secrets/" in (REPO / ".gitignore").read_text(encoding="utf-8")
    assert "deploy/secrets" in (REPO / ".dockerignore").read_text(encoding="utf-8")


def test_the_example_environment_file_carries_no_credential():
    """`prod.env.example` is committed, so anything secret-shaped in it would be
    a credential in git."""
    text = (REPO / "prod.env.example").read_text(encoding="utf-8")
    for line in text.splitlines():
        if line.startswith("#") or "=" not in line:
            continue
        key = line.partition("=")[0]
        if any(hint in key.lower() for hint in ("key", "secret", "password", "token")):
            pytest.fail(f"{key} carries a value in a committed file: {line}")


# --- Hardening ------------------------------------------------------------------


@pytest.mark.parametrize("service", ("edge", "firewall-api", "postgres", "migrate"))
def test_every_service_drops_all_capabilities(prod: dict, service: str):
    assert prod["services"][service]["cap_drop"] == ["ALL"]


@pytest.mark.parametrize("service", ("edge", "firewall-api", "postgres", "migrate"))
def test_every_service_refuses_privilege_escalation(prod: dict, service: str):
    assert "no-new-privileges:true" in prod["services"][service]["security_opt"]


@pytest.mark.parametrize("service", ("edge", "firewall-api", "migrate"))
def test_the_application_containers_have_read_only_roots(prod: dict, service: str):
    """PostgreSQL is excluded deliberately: it writes its data directory, and a
    read-only root with a volume mount is a configuration that fails at start-up
    for reasons unrelated to security."""
    assert prod["services"][service]["read_only"] is True


@pytest.mark.parametrize("service", ("edge", "firewall-api", "postgres"))
def test_every_long_running_service_is_resource_limited(prod: dict, service: str):
    """A model-loading OOM should kill one container, not the host."""
    limits = prod["services"][service]["deploy"]["resources"]["limits"]
    assert limits.get("memory")


@pytest.mark.parametrize("service", ("edge", "firewall-api", "postgres"))
def test_every_long_running_service_has_a_healthcheck(prod: dict, service: str):
    assert prod["services"][service]["healthcheck"]["test"]


def test_capability_additions_are_named_rather_than_broad(prod: dict):
    """`cap_drop: ALL` followed by an unexplained `cap_add` list is how a
    container quietly regains what it dropped. Each addition here is one an image
    genuinely needs, and NET_BIND_SERVICE is absent because the edge binds
    unprivileged ports."""
    for service in ("edge", "postgres"):
        added = set(prod["services"][service].get("cap_add", []))
        assert "NET_BIND_SERVICE" not in added
        assert "SYS_ADMIN" not in added
        assert added <= {"DAC_OVERRIDE", "SETUID", "SETGID", "CHOWN", "FOWNER"}


# --- The readiness contract is what gates traffic --------------------------------


def test_the_gateway_is_probed_on_ready_not_health(prod: dict):
    """`/health` is liveness only. Since ADR-027 `/ready` asserts the security
    boundary and the audit schema, so a container that lost its configuration
    never reports healthy and never has the edge started in front of it."""
    test = prod["services"]["firewall-api"]["healthcheck"]["test"]
    assert any("/ready" in part for part in test), test
    assert not any("/health" in part for part in test), test


def test_the_edge_waits_for_a_ready_gateway(prod: dict):
    assert prod["services"]["edge"]["depends_on"]["firewall-api"]["condition"] == (
        "service_healthy"
    )


def test_the_edge_probes_its_plain_listener(prod: dict):
    """A health check that followed the redirect would be validating a
    certificate, and `--no-check-certificate` in a health check is a habit that
    outlives development."""
    test = " ".join(prod["services"]["edge"]["healthcheck"]["test"])
    assert "http://" in test and "https://" not in test


# --- Production security posture --------------------------------------------------


def test_the_gateway_runs_in_production_mode(prod: dict):
    """Which is what makes the process refuse to start without its boundary."""
    env = prod["services"]["firewall-api"]["environment"]
    assert env["FIREWALL_ENVIRONMENT"] == "production"
    assert env["FIREWALL_HTTPS_ENFORCED"] == "true"
    assert env["FIREWALL_CONTENT_LOGGING"] == "none"


def test_the_trusted_range_defaults_to_the_edge_alone(prod: dict):
    """A `/32`. Everything that depends on the peer address is only as good as
    this being narrow."""
    default = prod["services"]["firewall-api"]["environment"]["FIREWALL_TRUSTED_PROXIES"]
    assert default.endswith("172.30.10.10/32}"), default


def test_the_upstream_has_no_default(prod: dict):
    """Compose refuses to render without one, so a production stack cannot
    silently start against a mock."""
    value = prod["services"]["firewall-api"]["environment"]["FIREWALL_UPSTREAM_BASE_URL"]
    assert ":?" in value, value


def test_the_production_file_ships_no_mock_upstream(prod: dict):
    """ADR-009's mock is a development fixture. A production topology that
    contains one is a production topology that can be pointed at it."""
    assert "mock-upstream" not in prod["services"]


def test_migrations_are_a_separate_profile_not_a_startup_step(prod: dict):
    """N replicas starting at once would race, and a failed migration would
    become a crash loop instead of a clear failure (docs/17)."""
    migrate = prod["services"]["migrate"]
    assert migrate["profiles"] == ["migrate"]
    assert migrate["restart"] == "no"
    assert "alembic" in migrate["command"]


# --- The verification overlay must not weaken what it verifies ------------------


def test_the_selftest_overlay_changes_only_ports_and_the_upstream():
    """If it relaxed isolation, capabilities or secrets, verifying against it
    would prove nothing about the thing being verified."""
    overlay = _compose(SELFTEST)
    assert set(overlay["services"]) == {"mock-upstream", "firewall-api"}
    # The only firewall-api change is an extra dependency.
    assert set(overlay["services"]["firewall-api"]) == {"depends_on"}
    for forbidden in ("cap_add", "privileged", "security_opt", "read_only", "ports", "networks"):
        assert forbidden not in overlay["services"]["firewall-api"], forbidden


def test_the_selftest_mock_cannot_reach_the_audit_store():
    overlay = _compose(SELFTEST)
    assert set(overlay["services"]["mock-upstream"]["networks"]) == {"egress"}
