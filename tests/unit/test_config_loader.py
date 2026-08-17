"""AppConfig composition and the startup summary.

Includes a regression test for a real bug found during Phase 0 validation: the
startup log reported the *output* detectors under `input_detectors`, because
`section()` was written as `input if direction is Direction.INPUT else output`
and the call site passed the string `"input"`. The identity check failed, the
`else` branch returned the wrong section, and a `# type: ignore` was hiding the
type error that would have caught it.
"""

from __future__ import annotations

import pytest

from app.config.loader import load_config
from app.config.policy import PolicyConfig
from app.config.settings import Settings
from app.core.exceptions import ConfigurationError
from app.core.types import Direction

pytestmark = pytest.mark.unit


POLICY = {
    "input": {
        "a": {"detector": "injection.stub"},
        "b": {"detector": "jailbreak.stub"},
    },
    "output": {"c": {"detector": "output.stub"}},
}


# --- Regression: wrong-section bug -----------------------------------------


def test_section_rejects_a_non_direction_value():
    """A string must raise, not silently return the wrong section."""
    policy = PolicyConfig.model_validate(POLICY)

    with pytest.raises(ValueError, match="unknown direction"):
        policy.section("input")  # type: ignore[arg-type]


def test_each_direction_returns_its_own_section():
    policy = PolicyConfig.model_validate(POLICY)

    assert set(policy.section(Direction.INPUT)) == {"a", "b"}
    assert set(policy.section(Direction.OUTPUT)) == {"c"}


def test_startup_summary_reports_the_correct_detectors_per_direction():
    """The bug surfaced here: input_detectors listed the output detectors."""
    config = load_config(Settings())
    summary = config.safe_summary()

    assert summary["input_detectors"] == list(config.policy.enabled_detectors(Direction.INPUT))
    assert summary["output_detectors"] == list(config.policy.enabled_detectors(Direction.OUTPUT))
    # With the shipped skeleton policy these genuinely differ, so a regression
    # cannot pass by both sections happening to match.
    assert summary["input_detectors"] != summary["output_detectors"]


# --- Composition -----------------------------------------------------------


def test_load_config_resolves_policy_and_version():
    config = load_config(Settings())

    assert config.policy_version.startswith("sha256:")
    assert config.policy_version == config.policy.version_hash()
    assert config.policy_path == config.settings.policy_file


def test_load_config_fails_loudly_on_a_missing_policy(tmp_path):
    settings = Settings(policy_file=tmp_path / "nope.yaml")

    with pytest.raises(ConfigurationError, match="not found"):
        load_config(settings)


def test_summary_masks_secrets_and_names_fail_open_detectors():
    config = load_config(
        Settings(upstream_api_key="sk-should-not-appear", database_url="postgres://u:p@h/d")
    )
    summary = config.safe_summary()

    assert "sk-should-not-appear" not in str(summary)
    assert "fail_open_detectors" in summary
    # The shipped skeleton runs the jailbreak stub fail-open; it must be visible.
    assert summary["fail_open_detectors"] == list(config.fail_open_detectors)
