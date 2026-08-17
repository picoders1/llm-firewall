"""Architecture enforcement.

The layering rules in docs/02-system-architecture.md are enforced here rather
than by review, because a documented dependency direction that nothing checks
becomes fiction within a month (PM-12 in docs/20-risk-register.md).

These tests parse the AST rather than importing, so a violation is caught even if
the offending module is never imported at runtime.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

APP = Path(__file__).resolve().parents[2] / "app"


def modules_under(package: str) -> list[Path]:
    return sorted((APP / package).rglob("*.py"))


def imported_modules(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            found.add(node.module)
    return found


def imported_names(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            found.update(alias.name for alias in node.names)
    return found


# --- The two load-bearing constraints (ADR-002, ADR-003) -------------------


@pytest.mark.parametrize("path", modules_under("detectors"), ids=lambda p: p.name)
def test_detectors_cannot_import_the_policy_engine(path: Path):
    """A detector must be structurally unable to decide."""
    offenders = {m for m in imported_modules(path) if m.startswith("app.policy")}
    assert not offenders, f"{path.name} imports {offenders}"


@pytest.mark.parametrize("path", modules_under("detectors"), ids=lambda p: p.name)
def test_action_is_not_importable_inside_detectors(path: Path):
    """`Action` lives in app.core.types; detectors must never reference it."""
    assert "Action" not in imported_names(path), f"{path.name} imports Action"
    source = path.read_text(encoding="utf-8")
    assert "Action." not in source, f"{path.name} references Action directly"


@pytest.mark.parametrize("path", modules_under("policy"), ids=lambda p: p.name)
def test_policy_cannot_import_detectors(path: Path):
    """The engine consumes results and has no idea what produced them."""
    offenders = {m for m in imported_modules(path) if m.startswith("app.detectors")}
    assert not offenders, f"{path.name} imports {offenders}"


def test_policy_engine_is_pure():
    """No I/O, no clock, no logging, no randomness — that is what makes the
    truth table possible (ADR-003)."""
    forbidden = {
        "logging",
        "structlog",
        "time",
        "datetime",
        "random",
        "asyncio",
        "httpx",
        "sqlalchemy",
    }
    imports = imported_modules(APP / "policy" / "engine.py")
    offenders = {m for m in imports if m.split(".")[0] in forbidden}
    assert not offenders, f"policy/engine.py is not pure: imports {offenders}"


# --- Dependency direction --------------------------------------------------


@pytest.mark.parametrize("path", modules_under("core"), ids=lambda p: p.name)
def test_core_depends_on_nothing_else_in_app(path: Path):
    offenders = {
        m for m in imported_modules(path) if m.startswith("app.") and not m.startswith("app.core")
    }
    assert not offenders, f"core/{path.name} imports {offenders}"


@pytest.mark.parametrize("path", modules_under("config"), ids=lambda p: p.name)
def test_config_does_not_import_upper_layers(path: Path):
    """Notably app.detectors: policy validation takes a capability map instead."""
    allowed = ("app.core", "app.config")
    offenders = {
        m for m in imported_modules(path) if m.startswith("app.") and not m.startswith(allowed)
    }
    assert not offenders, f"config/{path.name} imports {offenders}"


@pytest.mark.parametrize("path", modules_under("database"), ids=lambda p: p.name)
def test_database_does_not_import_upper_layers(path: Path):
    allowed = ("app.core", "app.config", "app.models", "app.database")
    offenders = {
        m for m in imported_modules(path) if m.startswith("app.") and not m.startswith(allowed)
    }
    assert not offenders, f"database/{path.name} imports {offenders}"


# --- Vendor coupling (ADR-008) ---------------------------------------------


def test_no_langfuse_sdk_anywhere_in_app():
    """Instrumentation is against the OTel API; Langfuse is an exporter."""
    for path in APP.rglob("*.py"):
        assert "langfuse" not in path.read_text(encoding="utf-8").lower(), path


def test_no_provider_sdk_on_the_request_path():
    """The gateway speaks HTTP, not a vendor SDK (ADR-004)."""
    banned = {"openai", "anthropic", "cohere", "litellm"}
    for path in APP.rglob("*.py"):
        offenders = {m for m in imported_modules(path) if m.split(".")[0] in banned}
        assert not offenders, f"{path} imports {offenders}"
