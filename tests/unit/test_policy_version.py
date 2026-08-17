"""Policy version determinism.

`policy_version` is recorded on every persisted decision. Without it, "why was
this blocked in March" is unanswerable after any config change
(docs/11-data-model.md). It is computed over the canonical serialisation of the
*effective* policy, not the raw file bytes, so it is stable across comments and
formatting and changes if and only if behaviour changes.
"""

from __future__ import annotations

import pytest

from app.config.policy import PolicyConfig, load_policy

pytestmark = pytest.mark.unit

BASE = """
version: 1
policy_name: test
input:
  prompt_injection:
    detector: injection.stub
    threshold: 0.85
    action: block
"""


def test_hash_is_stable_across_repeated_computation(write_policy):
    policy = load_policy(write_policy(BASE))
    assert policy.version_hash() == policy.version_hash()


def test_hash_is_stable_across_separate_loads(write_policy):
    first = load_policy(write_policy(BASE)).version_hash()
    second = load_policy(write_policy(BASE)).version_hash()
    assert first == second


def test_hash_ignores_comments_and_formatting(write_policy):
    """Two semantically identical policies must produce the same version."""
    commented = """
# a comment that changes nothing about behaviour
version: 1
policy_name: test

input:

  prompt_injection:
    detector: injection.stub     # trailing comment
    threshold: 0.85
    action: block
"""
    assert load_policy(write_policy(BASE)).version_hash() == (
        load_policy(write_policy(commented)).version_hash()
    )


def test_hash_ignores_key_order(write_policy):
    reordered = """
version: 1
policy_name: test
input:
  prompt_injection:
    action: block
    threshold: 0.85
    detector: injection.stub
"""
    assert load_policy(write_policy(BASE)).version_hash() == (
        load_policy(write_policy(reordered)).version_hash()
    )


@pytest.mark.parametrize(
    "mutation",
    [
        ("threshold: 0.85", "threshold: 0.86"),
        ("action: block", "action: warn"),
        ("detector: injection.stub", "detector: pii.stub"),
        ("policy_name: test", "policy_name: other"),
    ],
)
def test_hash_changes_when_effective_policy_changes(write_policy, mutation):
    old, new = mutation
    original = load_policy(write_policy(BASE)).version_hash()
    changed = load_policy(write_policy(BASE.replace(old, new))).version_hash()
    assert original != changed


def test_hash_changes_when_a_detector_is_disabled(write_policy):
    disabled = BASE + "    enabled: false\n"
    assert load_policy(write_policy(BASE)).version_hash() != (
        load_policy(write_policy(disabled)).version_hash()
    )


def test_hash_is_independent_of_construction_route():
    """A policy built in code and one parsed from YAML must agree."""
    from_dict = PolicyConfig.model_validate(
        {
            "version": 1,
            "policy_name": "test",
            "input": {
                "prompt_injection": {
                    "detector": "injection.stub",
                    "threshold": 0.85,
                    "action": "block",
                }
            },
        }
    )
    assert from_dict.version_hash().startswith("sha256:")


def test_hash_format():
    policy = PolicyConfig()
    digest = policy.version_hash()
    assert digest.startswith("sha256:")
    assert len(digest.split(":", 1)[1]) == 32
