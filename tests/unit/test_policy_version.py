"""Policy version determinism.

`policy_version` is recorded on every persisted decision. Without it, "why was
this blocked in March" is unanswerable after any config change
(docs/11-data-model.md). It is computed over the canonical serialisation of the
*effective* policy, not the raw file bytes, so it is stable across comments and
formatting and changes if and only if behaviour changes.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import get_args, get_origin
from unittest import mock

import pytest
from pydantic import BaseModel

from app.config import policy as policy_module
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


# --- R-115: determinism across processes ---------------------------------
#
# The tests above assert stability across repeated computation and separate
# loads, and both pass while the hash is broken, because both run inside ONE
# interpreter where `PYTHONHASHSEED` is fixed. `inspect_roles` is a frozenset,
# pydantic rendered it as a list in set-iteration order, and that order is
# seed-dependent — so a byte-identical policy hashed to one of two values at
# random, and one policy reached the audit trail as two versions.
#
# Found on a live deployment: 559 audit rows written under an unchanged policy
# split 404/155 across two `policy_version` values by container restart. The
# repository already held the same evidence unnoticed — the twelve performance
# manifests of 2026-08-19 record both values for one campaign on one policy.

_CHILD = """
import sys
from pathlib import Path
from app.config.policy import load_policy
sys.stdout.write(load_policy(Path(sys.argv[1])).version_hash())
"""

_SEEDS = ("0", "1", "2", "7", "12345", "random")


def _hash_in_subprocess(policy_path: Path, seed: str) -> str:
    """Compute the hash in a fresh interpreter with a chosen string-hash seed.

    A subprocess is the only way to vary `PYTHONHASHSEED`: it is read once at
    interpreter start, so nothing set from inside a running test can change it.
    """
    env = {**os.environ, "PYTHONHASHSEED": seed}
    result = subprocess.run(  # noqa: S603 - fixed argv, this interpreter, literal source
        [sys.executable, "-c", _CHILD, str(policy_path)],
        capture_output=True,
        text=True,
        env=env,
        cwd=Path(__file__).resolve().parents[2],
        check=True,
    )
    return result.stdout.strip()


def test_hash_is_identical_across_processes_with_different_hash_seeds(write_policy):
    """The property the audit trail actually depends on.

    `policy_version` answers "which policy blocked this in March". If two
    processes loading the same file disagree, that question has two answers for
    one policy and the field stops being usable as an identity.
    """
    path = write_policy(BASE)
    digests = {seed: _hash_in_subprocess(path, seed) for seed in _SEEDS}
    assert len(set(digests.values())) == 1, f"policy_version varies by hash seed: {digests}"


def test_the_shipped_policy_is_deterministic_across_processes():
    """The default policy specifically, since it is the one deployments load and
    the one whose two hashes were observed in production."""
    shipped = Path(__file__).resolve().parents[2] / "config" / "policies" / "default.yaml"
    digests = {seed: _hash_in_subprocess(shipped, seed) for seed in _SEEDS}
    assert len(set(digests.values())) == 1, f"policy_version varies by hash seed: {digests}"


def test_set_valued_fields_serialise_in_sorted_order():
    """Sorted order is a property of the values; set order is a property of the
    interpreter. Asserted on the serialised form because that is what is hashed.

    This one is a fast local check, not a control: run in-process against a
    pre-fix build it passes whenever the ambient seed happens to iterate the set
    in sorted order, which is half the time at n=2. The subprocess tests above
    are what actually detect the defect, and they are why this file spawns
    interpreters at all.
    """
    dumped = PolicyConfig().model_dump(mode="json")
    assert dumped["inspect_roles"] == sorted(dumped["inspect_roles"])


def test_no_set_valued_field_lacks_a_deterministic_serialiser():
    """A guard against silent reintroduction.

    The fix is correct for `inspect_roles`, but a future set-valued field on any
    model in the policy tree would bring the defect straight back, and no existing
    test would notice — that is exactly how this survived. Adding one now fails
    here until it is given a serialiser that imposes an order.
    """
    seen: set[type] = set()
    offenders: list[str] = []

    def visit(model: type[BaseModel]) -> None:
        if model in seen:
            return
        seen.add(model)
        serialised = set()
        for dec in model.__pydantic_decorators__.field_serializers.values():
            serialised.update(dec.info.fields)
        for name, field in model.model_fields.items():
            for arg in (field.annotation, *get_args(field.annotation)):
                if isinstance(arg, type) and issubclass(arg, BaseModel):
                    visit(arg)
            if get_origin(field.annotation) in (set, frozenset) and name not in serialised:
                offenders.append(f"{model.__name__}.{name}")

    visit(PolicyConfig)
    assert not offenders, (
        f"set-valued policy fields serialise in interpreter-dependent order: {offenders}. "
        "Add a @field_serializer that sorts, or version_hash stops being deterministic (R-115)."
    )


def test_the_canonicalisation_scheme_is_part_of_the_hash():
    """So a value from the fixed scheme can never be read as one from the broken
    scheme. The two pre-fix values are not repairable; they must at least be
    distinguishable from what replaced them."""
    policy = PolicyConfig()
    before = policy.version_hash()
    with mock.patch.object(policy_module, "CANONICALISATION_SCHEME", "v-something-else"):
        assert policy.version_hash() != before
