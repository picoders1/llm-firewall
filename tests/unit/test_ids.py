"""Request identity and content fingerprinting."""

from __future__ import annotations

import pytest

from app.core.ids import content_hash, is_valid_request_id, new_request_id

pytestmark = pytest.mark.unit


def test_generated_ids_are_unique_and_valid():
    ids = {new_request_id() for _ in range(1000)}

    assert len(ids) == 1000
    assert all(is_valid_request_id(value) for value in ids)


@pytest.mark.parametrize(
    "value",
    ["abc123", "trace-1", "a_b.c:d", "A" * 128, "0", "req.2026-08-17.42"],
)
def test_valid_ids_are_accepted(value: str):
    assert is_valid_request_id(value)


@pytest.mark.parametrize(
    ("value", "why"),
    [
        ("", "empty"),
        ("A" * 129, "too long"),
        ("has space", "space"),
        ("line\nbreak", "log injection via newline"),
        ("carriage\rreturn", "log injection via CR"),
        ("tab\there", "control character"),
        ("null\x00byte", "null byte"),
        ('quote"brace}', "JSON forgery characters"),
        ("unicode-ʼ-char", "non-ASCII: str.isalnum() would wrongly accept this"),
        ("digits-٤٥٦", "Arabic-Indic digits are alnum but not ASCII"),
        ("emoji-🙂", "non-ASCII"),
        ("semi;colon", "delimiter"),
        ("path/traversal", "slash"),
    ],
)
def test_invalid_ids_are_rejected(value: str, why: str):
    assert not is_valid_request_id(value), f"should reject: {why}"


# --- Content hashing -------------------------------------------------------


def test_hash_is_deterministic():
    assert content_hash("hello") == content_hash("hello")


def test_hash_differs_for_different_content():
    assert content_hash("hello") != content_hash("hello ")


def test_hash_does_not_contain_the_content():
    secret = "my-very-secret-prompt"
    assert secret not in content_hash(secret)


def test_hash_format_is_labelled_and_truncated():
    digest = content_hash("x")

    assert digest.startswith("sha256:")
    assert len(digest.split(":", 1)[1]) == 16


def test_hash_handles_unicode():
    assert content_hash("🙂 café 混合").startswith("sha256:")
