"""Policy loading and validation.

Every case here must be a *startup* failure. Invalid security configuration is
never silently repaired and never deferred to request time (NFR-009).
"""

from __future__ import annotations

import pytest

from app.config.policy import (
    DetectorCapabilities,
    PolicyConfig,
    load_policy,
)
from app.core.exceptions import ConfigurationError
from app.core.types import Action, Direction, ErrorPolicy, Role

pytestmark = pytest.mark.unit

MINIMAL = """
version: 1
input:
  prompt_injection:
    detector: injection.stub
    threshold: 0.85
    action: block
"""


def caps(**overrides: DetectorCapabilities) -> dict[str, DetectorCapabilities]:
    base = {
        "injection.stub": DetectorCapabilities(name="injection.stub", emits_spans=False),
        "pii.stub": DetectorCapabilities(name="pii.stub", emits_spans=True),
        "input.only": DetectorCapabilities(
            name="input.only", directions=frozenset({Direction.INPUT})
        ),
    }
    return base | overrides


# --- Happy path ------------------------------------------------------------


def test_loads_the_shipped_default_policy(policy_path):
    policy = load_policy(policy_path)
    assert policy.version == 1
    assert Role.USER in policy.inspect_roles
    assert Role.TOOL in policy.inspect_roles, "tool is the indirect-injection surface"


def test_shipped_policy_validates_against_the_real_registry(policy_path):
    from app.detectors import registry

    load_policy(policy_path).validate_against_registry(registry.capabilities())


def test_defaults_are_the_safe_defaults(write_policy):
    policy = load_policy(write_policy(MINIMAL))
    entry = policy.input["prompt_injection"]
    assert entry.on_error is ErrorPolicy.FAIL_CLOSED, "fail-closed must be the default"
    assert entry.enabled is True


# --- Secret rejection (ADR-011, threat T-19) -------------------------------


@pytest.mark.parametrize(
    "key",
    [
        "api_key",
        "openai_api_key",
        "secret",
        "client_secret",
        "password",
        "auth_token",
        "credential",
    ],
)
def test_secret_shaped_keys_are_rejected_anywhere(write_policy, key: str):
    document = f"""
version: 1
input:
  prompt_injection:
    detector: injection.stub
    options:
      {key}: sk-not-a-real-value
"""
    with pytest.raises(ConfigurationError, match="secret-shaped key"):
        load_policy(write_policy(document))


def test_secret_rejected_at_top_level(write_policy):
    with pytest.raises(ConfigurationError, match="secret-shaped key"):
        load_policy(write_policy("version: 1\napi_key: abc\n"))


def test_secret_rejected_inside_a_list(write_policy):
    document = """
version: 1
input:
  pii:
    detector: pii.stub
    action: redact
    options:
      custom_patterns:
        - name: X
          token: sk-secret
"""
    with pytest.raises(ConfigurationError, match="secret-shaped key"):
        load_policy(write_policy(document))


# --- Schema validation -----------------------------------------------------


@pytest.mark.parametrize("threshold", [-0.1, 1.1, 2.0])
def test_threshold_out_of_range_is_rejected(write_policy, threshold: float):
    document = f"""
version: 1
input:
  x:
    detector: injection.stub
    threshold: {threshold}
"""
    with pytest.raises(ConfigurationError):
        load_policy(write_policy(document))


def test_unknown_action_is_rejected(write_policy):
    document = """
version: 1
input:
  x:
    detector: injection.stub
    action: quarantine
"""
    with pytest.raises(ConfigurationError):
        load_policy(write_policy(document))


def test_action_allow_is_rejected(write_policy):
    """`allow` would be a no-op that still costs latency; disable instead."""
    document = """
version: 1
input:
  x:
    detector: injection.stub
    action: allow
"""
    with pytest.raises(ConfigurationError, match="enabled: false"):
        load_policy(write_policy(document))


def test_unknown_field_is_rejected(write_policy):
    """A typo must not be silently ignored — it would disable a control."""
    document = """
version: 1
input:
  x:
    detector: injection.stub
    thresold: 0.9
"""
    with pytest.raises(ConfigurationError):
        load_policy(write_policy(document))


def test_duplicate_detector_in_one_direction_is_rejected(write_policy):
    document = """
version: 1
input:
  a:
    detector: injection.stub
  b:
    detector: injection.stub
"""
    with pytest.raises(ConfigurationError, match="configured twice"):
        load_policy(write_policy(document))


def test_unknown_role_is_rejected(write_policy):
    with pytest.raises(ConfigurationError):
        load_policy(write_policy("version: 1\ninspect_roles: [user, moderator]\n"))


def test_redaction_template_must_have_placeholder(write_policy):
    document = """
version: 1
redaction:
  template: "REDACTED"
"""
    with pytest.raises(ConfigurationError, match=r"\{entity\}"):
        load_policy(write_policy(document))


@pytest.mark.parametrize(
    ("content", "match"),
    [
        ("", "empty"),
        ("- just\n- a list\n", "mapping"),
        ("key: [unclosed\n", "not valid YAML"),
    ],
)
def test_malformed_documents_are_rejected(write_policy, content: str, match: str):
    with pytest.raises(ConfigurationError, match=match):
        load_policy(write_policy(content))


def test_missing_file_is_rejected(tmp_path):
    with pytest.raises(ConfigurationError, match="not found"):
        load_policy(tmp_path / "absent.yaml")


# --- Registry validation ---------------------------------------------------


def test_unknown_detector_is_rejected():
    policy = PolicyConfig.model_validate({"input": {"x": {"detector": "does.not.exist"}}})
    with pytest.raises(ConfigurationError, match="unknown detector"):
        policy.validate_against_registry(caps())


def test_redact_on_a_span_less_detector_is_rejected():
    """It would silently degrade to a no-op at runtime."""
    policy = PolicyConfig.model_validate(
        {"input": {"x": {"detector": "injection.stub", "action": "redact"}}}
    )
    with pytest.raises(ConfigurationError, match="requires character spans"):
        policy.validate_against_registry(caps())


def test_redact_on_a_span_emitting_detector_is_accepted():
    policy = PolicyConfig.model_validate(
        {"input": {"x": {"detector": "pii.stub", "action": "redact"}}}
    )
    policy.validate_against_registry(caps())


def test_detector_used_in_an_unsupported_direction_is_rejected():
    policy = PolicyConfig.model_validate({"output": {"x": {"detector": "input.only"}}})
    with pytest.raises(ConfigurationError, match="does not support the output direction"):
        policy.validate_against_registry(caps())


def test_all_problems_are_reported_at_once():
    """An operator fixing a policy should not rediscover the next error per restart."""
    policy = PolicyConfig.model_validate(
        {
            "input": {
                "a": {"detector": "nope.one"},
                "b": {"detector": "injection.stub", "action": "redact"},
            }
        }
    )
    with pytest.raises(ConfigurationError) as exc:
        policy.validate_against_registry(caps())
    assert "nope.one" in str(exc.value)
    assert "requires character spans" in str(exc.value)


def test_disabled_entries_are_still_validated():
    """A disabled entry with a typo must be caught before it is ever enabled."""
    policy = PolicyConfig.model_validate(
        {"input": {"x": {"detector": "does.not.exist", "enabled": False}}}
    )
    with pytest.raises(ConfigurationError, match="unknown detector"):
        policy.validate_against_registry(caps())


# --- Lookups ---------------------------------------------------------------


def test_fail_open_detectors_are_enumerable_for_the_startup_warning():
    policy = PolicyConfig.model_validate(
        {
            "input": {
                "a": {"detector": "injection.stub", "on_error": "fail_open"},
                "b": {"detector": "pii.stub", "action": "redact"},
                "c": {"detector": "input.only", "on_error": "fail_open", "enabled": False},
            }
        }
    )
    assert policy.fail_open_detectors() == ("input:injection.stub",)


def test_for_detector_is_direction_scoped():
    policy = PolicyConfig.model_validate(
        {"input": {"a": {"detector": "pii.stub", "action": "redact"}}}
    )
    assert policy.for_detector(Direction.INPUT, "pii.stub") is not None
    assert policy.for_detector(Direction.OUTPUT, "pii.stub") is None


def test_enabled_detectors_excludes_disabled():
    policy = PolicyConfig.model_validate(
        {
            "input": {
                "a": {"detector": "injection.stub"},
                "b": {"detector": "pii.stub", "action": "redact", "enabled": False},
            }
        }
    )
    assert policy.enabled_detectors(Direction.INPUT) == ("injection.stub",)
    assert Action.BLOCK is policy.input["a"].action
