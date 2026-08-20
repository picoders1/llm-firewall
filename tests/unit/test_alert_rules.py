"""The alert rules, the runbook and the metric catalogue cannot drift apart.

Three artefacts have to agree for alerting to be worth anything: a rule must name a
metric the application actually exports, it must have a runbook entry telling an
operator what to do, and it must have been evaluated at least once against synthetic
data. Each of those is checked here.

None of this checks whether a *threshold* is right — no test can, without production
traffic. What it checks is that no alert can silently become undeliverable:
a typo'd metric name, a rule with no instructions, or an entry in the runbook for an
alert that no longer exists.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

from app.observability.metrics import Metrics

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
RULES_FILE = REPO_ROOT / "deploy" / "alerts" / "firewall.rules.yaml"
TESTS_FILE = REPO_ROOT / "deploy" / "alerts" / "firewall.rules.test.yaml"
RUNBOOK = REPO_ROOT / "docs" / "runbook.md"

SEVERITIES = {"critical", "warning"}
REQUIRED_ANNOTATIONS = {"summary", "description", "runbook"}
# Suffixes Prometheus appends to a family name in exposition.
SUFFIXES = ("_bucket", "_count", "_sum", "_total")


def rules() -> list[dict]:
    document = yaml.safe_load(RULES_FILE.read_text(encoding="utf-8"))
    return [rule for group in document["groups"] for rule in group["rules"]]


def alert_names() -> list[str]:
    return [rule["alert"] for rule in rules()]


def runbook_text() -> str:
    return RUNBOOK.read_text(encoding="utf-8")


def runbook_sections() -> dict[str, str]:
    """Each `## Firewall…` heading and the body until the next heading."""
    text = runbook_text()
    sections: dict[str, str] = {}
    matches = list(re.finditer(r"^## (Firewall\w+)$", text, re.MULTILINE))
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        sections[match.group(1)] = text[match.end() : end]
    return sections


def exported_metric_families() -> set[str]:
    """Family names as the client library reports them, plus their exposed forms."""
    names: set[str] = set()
    for metric in Metrics().registry.collect():
        names.add(metric.name)
        for sample_suffix in SUFFIXES:
            names.add(f"{metric.name}{sample_suffix}")
    return names


def test_the_rule_file_parses_and_is_not_empty():
    assert len(rules()) >= 10


def test_alert_names_are_unique():
    names = alert_names()
    assert len(names) == len(set(names))


@pytest.mark.parametrize("rule", rules(), ids=alert_names())
def test_every_alert_carries_a_severity_and_a_component(rule: dict):
    labels = rule.get("labels", {})
    assert labels.get("severity") in SEVERITIES, rule["alert"]
    assert labels.get("component"), rule["alert"]


@pytest.mark.parametrize("rule", rules(), ids=alert_names())
def test_every_alert_says_what_it_means_and_where_to_look(rule: dict):
    annotations = rule.get("annotations", {})
    missing = REQUIRED_ANNOTATIONS - set(annotations)
    assert not missing, f"{rule['alert']} is missing {sorted(missing)}"


@pytest.mark.parametrize("rule", rules(), ids=alert_names())
def test_every_alert_has_a_runbook_entry_at_the_anchor_it_advertises(rule: dict):
    """The `runbook` annotation is what an operator clicks at 3am. A rule whose
    anchor does not resolve is a page with no instructions."""
    expected = f"docs/runbook.md#{rule['alert'].lower()}"
    assert rule["annotations"]["runbook"] == expected
    assert rule["alert"] in runbook_sections(), rule["alert"]


def test_the_runbook_documents_no_alert_that_does_not_exist():
    """The other direction. A section for a deleted alert is a procedure nobody
    will ever be told to run, and it reads as current until someone checks."""
    assert set(runbook_sections()) == set(alert_names())


@pytest.mark.parametrize("rule", rules(), ids=alert_names())
def test_every_metric_an_alert_references_is_actually_exported(rule: dict):
    """The failure this prevents is the quiet one: a rule naming a metric that was
    renamed or never existed evaluates to an empty vector forever, which looks
    exactly like a healthy system."""
    exported = exported_metric_families()
    referenced = set(re.findall(r"\bfirewall_[a-z_]+\b", rule["expr"]))
    assert referenced, f"{rule['alert']} references no firewall metric"
    unknown = {name for name in referenced if name not in exported}
    assert not unknown, f"{rule['alert']} references unexported metrics: {sorted(unknown)}"


@pytest.mark.parametrize("rule", rules(), ids=alert_names())
def test_an_unvalidated_threshold_is_declared_in_both_places(rule: dict):
    """A development default labelled in the rule file and presented as measured in
    the runbook would be worse than not labelling it at all."""
    if rule.get("labels", {}).get("calibration") != "unvalidated":
        return
    body = runbook_sections()[rule["alert"]]
    assert "calibration: unvalidated" in body or "unvalidated" in body, rule["alert"]


def test_every_alert_has_at_least_one_evaluated_test_case():
    """An alert rule that has never been evaluated is a guess. `promtool test rules`
    runs these for real; this asserts none was skipped."""
    document = yaml.safe_load(TESTS_FILE.read_text(encoding="utf-8"))
    exercised = {
        case["alertname"] for test in document["tests"] for case in test.get("alert_rule_test", [])
    }
    missing = set(alert_names()) - exercised
    assert not missing, f"alerts with no promtool test: {sorted(missing)}"


def test_the_rule_tests_point_at_the_rule_file():
    document = yaml.safe_load(TESTS_FILE.read_text(encoding="utf-8"))
    assert document["rule_files"] == ["firewall.rules.yaml"]


def test_counter_expressions_aggregate_across_replicas():
    """Counters here are per process. An expression that thresholds a raw counter
    is wrong by a factor of N on an N-replica deployment, and it is wrong in the
    direction that hides incidents."""
    for rule in rules():
        expr = rule["expr"]
        if "_total" not in expr:
            continue
        assert re.search(r"\b(sum|min|max|avg|count)\s*(by|without)?\s*\(", expr), rule["alert"]


def test_the_runbook_records_what_is_deliberately_not_alerted():
    """Half of an alerting policy is the conditions it refuses to page on. Left
    undocumented, someone adds them back a year later."""
    text = runbook_text()
    assert "deliberately NOT alerts" in text
    not_alerted = text.split("deliberately NOT alerts", 1)[1]
    # Each entry names the condition and the circumstance that would change the call.
    assert not_alerted.count("###") >= 6
    for expected in (
        "firewall_audit_rows_deleted_total",
        "firewall_rate_limited_requests_total",
        "Certificate expiry",
    ):
        assert expected in not_alerted


def test_severity_is_defined_by_response_not_left_to_interpretation():
    text = runbook_text()
    assert "Wake someone now" in text
    assert "next working day" in text
