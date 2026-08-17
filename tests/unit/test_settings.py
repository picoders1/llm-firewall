"""Settings: precedence, validation and the production content-logging downgrade."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.config.settings import ContentLogging, Environment, LogFormat, Settings

pytestmark = pytest.mark.unit


def write_overlay(tmp_path: Path, name: str, body: str) -> Path:
    directory = tmp_path / "environments"
    directory.mkdir(exist_ok=True)
    (directory / f"{name}.yaml").write_text(body, encoding="utf-8")
    return directory


# --- Precedence ------------------------------------------------------------
# built-in defaults < environment overlay < env vars < runtime overrides


def test_defaults_apply_when_nothing_is_set(tmp_path, monkeypatch):
    # The suite pins FIREWALL_ENVIRONMENT=testing; drop it to see true defaults.
    monkeypatch.delenv("FIREWALL_ENVIRONMENT", raising=False)
    settings = Settings(environments_dir=tmp_path / "missing")
    assert settings.environment is Environment.DEVELOPMENT
    assert settings.content_logging is ContentLogging.NONE
    assert settings.tracing_enabled is False


def test_overlay_overrides_defaults(tmp_path, monkeypatch):
    directory = write_overlay(tmp_path, "development", "log_level: ERROR\n")
    monkeypatch.setenv("FIREWALL_ENVIRONMENT", "development")
    assert Settings(environments_dir=directory).log_level == "ERROR"


def test_env_var_overrides_overlay(tmp_path, monkeypatch):
    directory = write_overlay(tmp_path, "development", "log_level: ERROR\n")
    monkeypatch.setenv("FIREWALL_ENVIRONMENT", "development")
    monkeypatch.setenv("FIREWALL_LOG_LEVEL", "DEBUG")
    assert Settings(environments_dir=directory).log_level == "DEBUG"


def test_runtime_override_wins_over_env_var(tmp_path, monkeypatch):
    monkeypatch.setenv("FIREWALL_LOG_LEVEL", "DEBUG")
    settings = Settings(environments_dir=tmp_path / "missing", log_level="WARNING")
    assert settings.log_level == "WARNING"


def test_missing_overlay_is_not_an_error(tmp_path, monkeypatch):
    monkeypatch.setenv("FIREWALL_ENVIRONMENT", "production")
    assert Settings(environments_dir=tmp_path / "missing").is_production


def test_overlay_rejects_secret_shaped_keys(tmp_path, monkeypatch):
    directory = write_overlay(tmp_path, "development", "upstream_api_key: sk-nope\n")
    monkeypatch.setenv("FIREWALL_ENVIRONMENT", "development")
    with pytest.raises(Exception, match="looks like a secret"):
        Settings(environments_dir=directory)


def test_shipped_overlays_load(monkeypatch):
    for environment in ("development", "testing", "production"):
        monkeypatch.setenv("FIREWALL_ENVIRONMENT", environment)
        settings = Settings()
        assert settings.environment.value == environment


# --- Validation ------------------------------------------------------------


def test_invalid_log_level_is_rejected(tmp_path):
    with pytest.raises(Exception, match="log_level"):
        Settings(environments_dir=tmp_path / "missing", log_level="CHATTY")


def test_log_level_is_normalised(tmp_path):
    assert Settings(environments_dir=tmp_path / "missing", log_level="debug").log_level == "DEBUG"


@pytest.mark.parametrize("url", ["localhost:8081/v1", "ftp://host/v1", ""])
def test_invalid_upstream_url_is_rejected(tmp_path, url: str):
    with pytest.raises(Exception, match="upstream_base_url"):
        Settings(environments_dir=tmp_path / "missing", upstream_base_url=url)


def test_upstream_url_trailing_slash_is_normalised(tmp_path):
    settings = Settings(
        environments_dir=tmp_path / "missing", upstream_base_url="http://host:8081/v1/"
    )
    assert settings.upstream_base_url == "http://host:8081/v1"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("max_request_bytes", 0),
        ("detector_default_timeout_ms", 0),
        ("detector_max_threads", 0),
        ("database_pool_size", 0),
        ("port", 70000),
        ("upstream_read_timeout_s", 0),
    ],
)
def test_out_of_range_values_are_rejected(tmp_path, field: str, value: int):
    with pytest.raises(Exception, match=field):
        Settings(**{"environments_dir": tmp_path / "missing", field: value})


# --- Content-logging downgrade (docs/10-security-model.md) -----------------


def test_full_content_logging_is_refused_in_production(tmp_path):
    settings = Settings(
        environments_dir=tmp_path / "missing",
        environment=Environment.PRODUCTION,
        content_logging=ContentLogging.FULL,
    )
    # The requested value is preserved for transparency; the effective value is not.
    assert settings.content_logging is ContentLogging.FULL
    assert settings.effective_content_logging() is ContentLogging.HASH


@pytest.mark.parametrize("environment", [Environment.DEVELOPMENT, Environment.TESTING])
def test_full_content_logging_is_allowed_outside_production(tmp_path, environment: Environment):
    settings = Settings(
        environments_dir=tmp_path / "missing",
        environment=environment,
        content_logging=ContentLogging.FULL,
    )
    assert settings.effective_content_logging() is ContentLogging.FULL


@pytest.mark.parametrize("mode", [ContentLogging.NONE, ContentLogging.HASH])
def test_safe_modes_are_unchanged_in_production(tmp_path, mode: ContentLogging):
    settings = Settings(
        environments_dir=tmp_path / "missing",
        environment=Environment.PRODUCTION,
        content_logging=mode,
    )
    assert settings.effective_content_logging() is mode


# --- Secret handling -------------------------------------------------------


def test_secrets_are_masked_in_repr(tmp_path):
    settings = Settings(
        environments_dir=tmp_path / "missing",
        upstream_api_key="sk-super-secret-value",
        database_url="postgresql+asyncpg://user:hunter2@host/db",
    )
    rendered = repr(settings) + str(settings.model_dump())
    assert "sk-super-secret-value" not in rendered
    assert "hunter2" not in rendered


def test_safe_summary_contains_no_secret_values(tmp_path):
    settings = Settings(
        environments_dir=tmp_path / "missing",
        upstream_api_key="sk-super-secret-value",
        database_url="postgresql+asyncpg://user:hunter2@host/db",
    )
    summary = str(settings.safe_summary())
    assert "sk-super-secret-value" not in summary
    assert "hunter2" not in summary
    # But it still tells the operator whether they are configured.
    assert settings.safe_summary()["upstream_api_key_set"] is True
    assert settings.safe_summary()["database_configured"] is True


def test_safe_summary_reports_effective_not_requested_content_logging(tmp_path):
    settings = Settings(
        environments_dir=tmp_path / "missing",
        environment=Environment.PRODUCTION,
        content_logging=ContentLogging.FULL,
    )
    summary = settings.safe_summary()
    assert summary["content_logging"] == "hash"
    assert summary["content_logging_requested"] == "full"


def test_log_format_enum(tmp_path):
    assert Settings(environments_dir=tmp_path / "missing", log_format="console").log_format is (
        LogFormat.CONSOLE
    )
