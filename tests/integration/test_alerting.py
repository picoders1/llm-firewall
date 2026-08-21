"""The alert rules evaluated by Prometheus itself, not by a Python approximation.

`tests/unit/test_alert_rules.py` checks that the rules, the runbook and the metric
registry agree. It cannot check that an expression means what its author thought:
PromQL has its own semantics for staleness, absent series, aggregation and `for`
durations, and getting those wrong produces a rule that is syntactically perfect and
silent forever.

So the rules are run through the real engine here. `promtool test rules` drives the
shipped rule file with synthetic series and asserts what fires and what does not —
including the near-misses, which are the cases that matter.

The live section proves the other half: that a real Prometheus can actually scrape
this application. It could not, until Phase 17 ran this and found the endpoint
advertising OpenMetrics while serving the text format (R-87).
"""

from __future__ import annotations

import json
import shutil
import socket
import subprocess
import urllib.request
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration

REPO_ROOT = Path(__file__).resolve().parents[2]
ALERTS_DIR = REPO_ROOT / "deploy" / "alerts"
PROM_IMAGE = "prom/prometheus:v3.5.0"
PROM_URL = "http://localhost:9091"
GATEWAY_URL = "http://localhost:8000"


def docker_binary() -> str | None:
    return shutil.which("docker")


def docker_available() -> bool:
    docker = docker_binary()
    if docker is None:
        return False

    return subprocess.run((docker, "info"), capture_output=True).returncode == 0  # noqa: S603


def prometheus_is_up() -> bool:
    with socket.socket() as sock:
        sock.settimeout(1.0)
        return sock.connect_ex(("localhost", 9091)) == 0


def promtool(*args: str) -> subprocess.CompletedProcess[str]:
    docker = docker_binary()
    assert docker is not None
    return subprocess.run(  # noqa: S603 - fixed argv; only rule filenames vary
        (
            docker,
            "run",
            "--rm",
            "--entrypoint",
            "promtool",
            "-v",
            f"{ALERTS_DIR}:/rules:ro",
            PROM_IMAGE,
            *args,
        ),
        capture_output=True,
        text=True,
        timeout=180,
    )


def query(path: str) -> dict:
    with urllib.request.urlopen(f"{PROM_URL}{path}", timeout=10) as response:  # noqa: S310
        return json.load(response)


needs_docker = pytest.mark.skipif(not docker_available(), reason="docker is not available")
needs_prometheus = pytest.mark.skipif(
    not prometheus_is_up(),
    reason="Prometheus is not running (compose.observability.yaml)",
)


@needs_docker
def test_the_rule_file_is_valid_promql():
    result = promtool("check", "rules", "/rules/firewall.rules.yaml")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "SUCCESS" in result.stdout


@needs_docker
def test_every_alert_behaves_as_its_unit_tests_say():
    """The substance of this phase. Each case asserts a firing state *and* a
    near-miss: a single transient failure that must not page, a zero-valued gauge
    that must not read as 56 years of staleness, a sync-mode deployment with no
    queue to saturate."""
    result = promtool("test", "rules", "/rules/firewall.rules.test.yaml")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "SUCCESS" in result.stdout


@needs_prometheus
def test_prometheus_can_actually_scrape_this_application():
    """The regression guard for R-87.

    The endpoint declared `application/openmetrics-text` while `generate_latest`
    emitted the Prometheus text format. Prometheus trusts the declared type, parsed
    the body as OpenMetrics and rejected every scrape for lacking the mandatory
    `# EOF` terminator. Nothing in the previous test suite noticed, because nothing
    in it was a Prometheus.
    """
    targets = query("/api/v1/targets")["data"]["activeTargets"]
    firewall = [t for t in targets if t["labels"]["job"] == "llm-firewall"]
    assert firewall, "the gateway is not a configured scrape target"
    for target in firewall:
        assert target["health"] == "up", target.get("lastError")


@needs_prometheus
def test_the_shipped_rules_are_loaded_by_the_server():
    groups = query("/api/v1/rules")["data"]["groups"]
    loaded = {rule["name"] for group in groups for rule in group["rules"]}
    import yaml

    shipped = yaml.safe_load((ALERTS_DIR / "firewall.rules.yaml").read_text(encoding="utf-8"))
    document = [rule["alert"] for group in shipped["groups"] for rule in group["rules"]]
    assert set(document) == loaded


@needs_prometheus
def test_every_metric_the_rules_reference_exists_in_the_scraped_data():
    """A rule naming a metric this application never emits evaluates to an empty
    vector forever, which is indistinguishable from a healthy system. The unit test
    checks the names against the registry; this checks them against what a scrape
    actually produced.

    **The test drives the traffic it depends on.** Request-path metrics
    (`firewall_requests_total`, the overhead histogram, the detector histogram)
    do not exist until the gateway has served something, and Prometheus has to
    have scraped since. Before Phase 19B this test simply assumed both, so it
    passed whenever an earlier test in the session happened to generate traffic
    and failed in CI when it ran first — remote run 32441308224, naming exactly
    those three series. Establishing the precondition is the fix; exempting them
    would have deleted the assertion.

    Metrics that only appear once something goes wrong stay exempt by name — a
    healthy gateway legitimately has no detector errors and no rate-limit
    denials, and requiring them would mean requiring the system to be broken.
    """
    only_on_failure = {
        "firewall_detector_errors_total",
        "firewall_upstream_errors_total",
        "firewall_caller_auth_failures_total",
        "firewall_auth_denials_total",
        "firewall_concurrency_rejections_total",
        "firewall_retention_sweeps_total",
        "firewall_audit_oldest_row_age_seconds",
        "firewall_audit_queue_capacity",
        "firewall_audit_queue_depth",
    }
    import re
    import time

    import yaml

    rules = yaml.safe_load((ALERTS_DIR / "firewall.rules.yaml").read_text(encoding="utf-8"))
    referenced: set[str] = set()
    for group in rules["groups"]:
        for rule in group["rules"]:
            referenced |= set(re.findall(r"\bfirewall_[a-z_]+\b", rule["expr"]))
    expected = referenced - only_on_failure

    # One benign request, so the request-path families exist at all.
    request = urllib.request.Request(  # noqa: S310 - fixed http:// literal, no user input
        f"{GATEWAY_URL}/v1/chat/completions",
        data=json.dumps(
            {"model": "mock-model", "messages": [{"role": "user", "content": "2+2?"}]}
        ).encode(),
        headers={"content-type": "application/json"},
    )
    try:
        urllib.request.urlopen(request, timeout=15).read()  # noqa: S310
    except Exception as exc:
        print(f"traffic generation failed: {type(exc).__name__}")

    # Then wait for a scrape to pick it up. Bounded: the scrape interval is 15s,
    # so this polls rather than sleeping a fixed guess.
    deadline = time.monotonic() + 90
    missing: set[str] = set()
    while time.monotonic() < deadline:
        names = set(query("/api/v1/label/__name__/values")["data"])
        missing = {
            name
            for name in expected
            if name not in names
            and name.removesuffix("_bucket").removesuffix("_count") not in names
        }
        if not missing:
            break
        time.sleep(5)

    assert not missing, f"rules reference metrics no scrape produced: {sorted(missing)}"
