"""The canary test.

A firewall that inspects prompts is a system that has all the prompts. This
suite proves the property the whole product depends on: **inspected content does
not reach the logs at the default configuration**, and it does so by driving a
canary string through the real logging stack rather than by reading the code.

Redaction is enforced by a structlog processor at the sink, so a future
contributor writing `logger.info("blocked", prompt=text)` produces a harmless
line. These tests exist to keep that true.

See docs/10-security-model.md and ADR-008.
"""

from __future__ import annotations

import io
import json
from collections.abc import Iterator

import pytest
import structlog

from app.config.settings import ContentLogging, Environment, LogFormat, Settings
from app.observability.logging import configure_logging

pytestmark = [pytest.mark.security, pytest.mark.unit]

CANARY = "CANARY-b4f1c9d2-my-password-is-hunter2-and-my-card-is-4111111111111111"


@pytest.fixture
def capture_logs(tmp_path) -> Iterator[io.StringIO]:
    """Configure real logging against an in-memory stream."""
    stream = io.StringIO()

    def _configure(mode: ContentLogging, environment: Environment = Environment.TESTING) -> None:
        settings = Settings(
            environments_dir=tmp_path / "missing",
            environment=environment,
            content_logging=mode,
            log_format=LogFormat.JSON,
            log_level="DEBUG",
        )
        configure_logging(settings)
        structlog.configure(
            processors=structlog.get_config()["processors"],
            wrapper_class=structlog.get_config()["wrapper_class"],
            logger_factory=structlog.PrintLoggerFactory(file=stream),
            cache_logger_on_first_use=False,
        )

    stream.configure = _configure  # type: ignore[attr-defined]
    yield stream
    structlog.reset_defaults()


def emitted(stream: io.StringIO) -> str:
    return stream.getvalue()


# --- The core property -----------------------------------------------------


@pytest.mark.parametrize(
    "key",
    ["content", "prompt", "messages", "text", "raw_text", "normalized_text", "completion", "body"],
)
def test_content_never_appears_in_logs_at_default_configuration(capture_logs, key: str):
    capture_logs.configure(ContentLogging.NONE)
    structlog.get_logger("test").info("decision", **{key: CANARY})

    assert CANARY not in emitted(capture_logs), f"canary leaked through key {key!r}"


def test_canary_absent_even_at_debug_level(capture_logs):
    capture_logs.configure(ContentLogging.NONE)
    log = structlog.get_logger("test")
    log.debug("inspecting", prompt=CANARY)
    log.warning("suspicious", raw_text=CANARY)
    log.error("blocked", content=CANARY)

    assert CANARY not in emitted(capture_logs)


def test_nested_content_key_is_dropped(capture_logs):
    capture_logs.configure(ContentLogging.NONE)
    structlog.get_logger("test").info("decision", messages=[{"role": "user", "content": CANARY}])

    assert CANARY not in emitted(capture_logs)


def test_non_content_fields_survive_redaction(capture_logs):
    """Redaction must not be so aggressive that the log becomes useless."""
    capture_logs.configure(ContentLogging.NONE)
    structlog.get_logger("test").info(
        "decision",
        detector="injection.stub",
        score=0.91,
        action="block",
        category="prompt_injection",
        content=CANARY,
    )

    line = emitted(capture_logs)
    record = json.loads(line)
    assert record["detector"] == "injection.stub"
    assert record["score"] == 0.91
    assert record["action"] == "block"
    assert "content" not in record
    assert CANARY not in line


# --- Hash mode -------------------------------------------------------------


def test_hash_mode_emits_a_fingerprint_not_the_content(capture_logs):
    capture_logs.configure(ContentLogging.HASH)
    structlog.get_logger("test").info("decision", prompt=CANARY)

    record = json.loads(emitted(capture_logs))
    assert CANARY not in emitted(capture_logs)
    assert record["prompt_hash"].startswith("sha256:")
    assert record["prompt_length"] == len(CANARY)
    assert "prompt" not in record


def test_hash_mode_is_stable_for_repeat_payload_correlation(capture_logs):
    """The operational point of hashing: `GROUP BY` instead of forensics."""
    capture_logs.configure(ContentLogging.HASH)
    log = structlog.get_logger("test")
    log.info("first", prompt=CANARY)
    log.info("second", prompt=CANARY)

    records = [json.loads(line) for line in emitted(capture_logs).strip().splitlines()]
    assert records[0]["prompt_hash"] == records[1]["prompt_hash"]


# --- Full mode and the production refusal ----------------------------------


def test_full_mode_emits_content_outside_production(capture_logs):
    """`full` exists for local debugging and must actually work."""
    capture_logs.configure(ContentLogging.FULL, Environment.DEVELOPMENT)
    structlog.get_logger("test").info("decision", prompt=CANARY)

    assert CANARY in emitted(capture_logs)


def test_full_mode_is_refused_in_production(capture_logs):
    """The 3 a.m. incident guard: config cannot turn this into a prompt sink."""
    capture_logs.configure(ContentLogging.FULL, Environment.PRODUCTION)
    structlog.get_logger("test").info("decision", prompt=CANARY)

    output = emitted(capture_logs)
    assert CANARY not in output
    assert json.loads(output)["prompt_hash"].startswith("sha256:")


# --- Secrets ---------------------------------------------------------------


@pytest.mark.parametrize(
    "key",
    ["api_key", "authorization", "password", "database_url", "upstream_api_key", "token"],
)
@pytest.mark.parametrize("mode", [ContentLogging.NONE, ContentLogging.HASH, ContentLogging.FULL])
def test_secrets_are_redacted_in_every_mode(capture_logs, key: str, mode: ContentLogging):
    """Unlike content, secrets have no mode in which they may be emitted."""
    capture_logs.configure(mode, Environment.DEVELOPMENT)
    structlog.get_logger("test").info("startup", **{key: "sk-super-secret-value"})

    assert "sk-super-secret-value" not in emitted(capture_logs)
