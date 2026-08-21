"""The benchmark's instruments must never become the deployment (Phase 15).

`config/policies/benchmark-passthrough.yaml` describes a gateway that inspects
nothing: every detector disabled, so condition B measures proxy cost alone. That
file is a measuring instrument and it is one `FIREWALL_POLICY_FILE` away from
being a catastrophic misconfiguration — a gateway that holds an upstream
credential, authenticates callers, and waves everything through.

Nothing stops someone pointing production at it except a test that notices.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from app.config.policy import load_policy
from app.core.types import Direction

pytestmark = pytest.mark.security

REPO = Path(__file__).resolve().parents[2]
BENCH_POLICY = REPO / "config" / "policies" / "benchmark-passthrough.yaml"
DEFAULT_POLICY = REPO / "config" / "policies" / "default.yaml"


def test_the_benchmark_policy_really_disables_every_detector():
    """Otherwise condition B would measure detection and the decomposition would
    attribute detection cost to proxying."""
    policy = load_policy(BENCH_POLICY)
    assert list(policy.enabled_detectors(Direction.INPUT)) == []
    assert list(policy.enabled_detectors(Direction.OUTPUT)) == []


def test_the_benchmark_policy_says_what_it_is_in_its_name_and_its_first_line():
    """A file that inspects nothing must be unmistakable in a diff and in
    `docker inspect`."""
    text = BENCH_POLICY.read_text(encoding="utf-8")
    assert text.startswith("# BENCHMARK-ONLY POLICY — NEVER DEPLOY THIS.")
    assert yaml.safe_load(text)["policy_name"] == "benchmark-passthrough"


def test_production_still_blocks_at_the_registered_threshold():
    """The control. Every assertion here would be satisfied by a repository whose
    real policy had also been gutted."""
    policy = load_policy(DEFAULT_POLICY)
    assert set(policy.enabled_detectors(Direction.INPUT)) == {
        "injection.heuristic",
        "jailbreak.heuristic",
        "pii.regex",
    }
    injection = next(d for d in policy.input.values() if d.detector == "injection.heuristic")
    assert injection.threshold == 0.85
    assert injection.action.value == "block"
    transformer = next(d for d in policy.input.values() if d.detector == "injection.transformer")
    assert transformer.enabled is False


def test_no_shipped_stack_configures_the_benchmark_policy():
    """`compose.bench.yaml` may — it is the benchmark. Nothing else may, and the
    production file least of all."""
    for name in ("compose.yaml", "compose.prod.yaml", "compose.edge.yaml", "compose.tls.yaml"):
        text = (REPO / name).read_text(encoding="utf-8")
        assert "benchmark-passthrough" not in text, name


def test_the_benchmark_stack_publishes_its_instruments_on_distinct_ports():
    """So a benchmark container can never be mistaken for the gateway under test,
    by a person or by a script."""
    bench = yaml.safe_load((REPO / "compose.bench.yaml").read_text(encoding="utf-8"))
    ports = {
        name: service.get("ports", [])
        for name, service in bench["services"].items()
        if service.get("ports")
    }
    assert ports["firewall-passthrough"] == ["8100:8000"]
    assert ports["firewall-noaudit"] == ["8101:8000"]
    # The gateway under test keeps its compose.yaml publishing (host :8005 ->
    # container :8000) and is not redefined here.
    assert "firewall-api" not in ports


def test_the_audit_off_instrument_differs_from_production_in_exactly_one_setting():
    """Condition F isolates the audit write. If it differed in anything else, C
    minus F would not be the audit write."""
    bench = yaml.safe_load((REPO / "compose.bench.yaml").read_text(encoding="utf-8"))
    noaudit = bench["services"]["firewall-noaudit"]["environment"]
    assert noaudit["FIREWALL_POLICY_FILE"] == "config/policies/default.yaml"
    assert noaudit["FIREWALL_PERSIST_EVENTS"] == "false"
