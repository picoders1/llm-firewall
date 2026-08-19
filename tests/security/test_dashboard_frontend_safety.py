"""Static safety analysis of the frontend source.

This is a security product, so the console is held to the same standard as the
gateway: the dangerous primitives are not merely avoided by convention, their
absence is asserted.

Scanning the source is the right tool here. A browser test proves one path was
safe on one render; a static assertion proves the primitive is absent from every
path, including the ones no test exercises.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.security

REPO_ROOT = Path(__file__).resolve().parents[2]
DASHBOARD = REPO_ROOT / "dashboard"
JS_FILES = sorted(DASHBOARD.rglob("*.js"))
ALL_FILES = sorted(p for p in DASHBOARD.rglob("*") if p.is_file())


def test_the_frontend_exists_so_these_tests_are_not_vacuous():
    assert len(JS_FILES) >= 10, "expected the console's modules to be present"


@pytest.mark.parametrize("path", JS_FILES, ids=lambda p: p.name)
def test_no_innerhtml_anywhere(path: Path):
    """Not for server data, not for icons, not "just this once". The rule is
    absolute because the exceptions are where the bugs live."""
    source = path.read_text(encoding="utf-8")
    for banned in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write"):
        # Mentions inside a comment explaining the rule are permitted; uses are not.
        code = "\n".join(
            line for line in source.splitlines() if not line.strip().startswith(("*", "//", "/*"))
        )
        assert banned not in code, f"{path.name} uses {banned}"


@pytest.mark.parametrize("path", JS_FILES, ids=lambda p: p.name)
def test_no_dynamic_code_execution(path: Path):
    source = path.read_text(encoding="utf-8")
    code = "\n".join(
        line for line in source.splitlines() if not line.strip().startswith(("*", "//", "/*"))
    )
    assert not re.search(r"\beval\s*\(", code), f"{path.name} calls eval()"
    assert not re.search(r"\bnew\s+Function\s*\(", code), f"{path.name} constructs a Function"
    assert 'setTimeout("' not in code and 'setInterval("' not in code


@pytest.mark.parametrize("path", JS_FILES, ids=lambda p: p.name)
def test_no_script_injection_primitives(path: Path):
    source = path.read_text(encoding="utf-8")
    code = "\n".join(
        line for line in source.splitlines() if not line.strip().startswith(("*", "//", "/*"))
    )
    assert 'createElement("script")' not in code
    assert "createElement('script')" not in code
    assert ".src =" not in code or "script" not in code.lower().split(".src =")[0][-80:]


def test_no_secrets_or_credentials_in_the_frontend():
    pattern = re.compile(
        r"(api[_-]?key|secret|password|bearer\s+[A-Za-z0-9._-]{8,}|sk-[A-Za-z0-9]{16,}|AKIA[0-9A-Z]{16})",
        re.IGNORECASE,
    )
    for path in ALL_FILES:
        if path.suffix in {".svg", ".json"}:
            continue
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            stripped = line.strip()
            # Prose explaining that secrets are not stored is not a secret.
            if stripped.startswith(("*", "//", "/*")):
                continue
            assert not pattern.search(line), f"{path.name}:{number} looks like a credential"


def test_nothing_sensitive_is_written_to_browser_storage():
    """The console persists one thing: the colour theme."""
    writes = []
    for path in JS_FILES:
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if "setItem" in line and not line.strip().startswith(("*", "//")):
                writes.append((path.name, number, line.strip()))
    assert len(writes) <= 1, f"unexpected browser-storage writes: {writes}"
    if writes:
        assert "THEME_KEY" in writes[0][2], writes[0]
    # Comments documenting "nothing is written to sessionStorage" are not uses,
    # so the check looks at code lines only.
    for path in JS_FILES:
        code = [
            line
            for line in path.read_text(encoding="utf-8").splitlines()
            if not line.strip().startswith(("*", "//", "/*"))
        ]
        assert not any("sessionStorage" in line for line in code), path.name


def test_no_third_party_origin_is_referenced():
    """CSP would block it, but a reference means someone intended it to work."""
    pattern = re.compile(r"https?://(?!localhost)[a-z0-9.-]+", re.IGNORECASE)
    allowed = {"http://www.w3.org"}  # SVG namespace, not a network fetch
    for path in ALL_FILES:
        if path.suffix == ".json":
            continue
        for match in pattern.findall(path.read_text(encoding="utf-8")):
            assert any(match.startswith(prefix) for prefix in allowed), f"{path.name}: {match}"


def test_the_html_contains_no_inline_script_or_style():
    """The strict CSP is only possible because the markup carries neither."""
    html = (DASHBOARD / "index.html").read_text(encoding="utf-8")
    assert "<script>" not in html
    assert "onclick=" not in html.lower()
    assert "onerror=" not in html.lower()
    assert re.search(r"<style[\s>]", html) is None
    # The one script tag must be an external module.
    scripts = re.findall(r"<script[^>]*>", html)
    assert len(scripts) == 1
    assert 'src="/dashboard/js/app.js"' in scripts[0]
    assert 'type="module"' in scripts[0]


def test_no_analytics_or_tracking():
    for path in ALL_FILES:
        source = path.read_text(encoding="utf-8").lower()
        for banned in (
            "google-analytics",
            "gtag(",
            "googletagmanager",
            "segment.io",
            "mixpanel",
            "sentry.io",
        ):
            assert banned not in source, f"{path.name} references {banned}"


def test_no_hardcoded_metric_values_masquerading_as_data():
    """§36: static labels are fine; fabricated numbers are not. Catches the
    classic placeholders a dashboard template ships with."""
    suspicious = re.compile(r"\b(98\.7|99\.9|1,234|12\s*ms|0\.9[0-9]{2}\s*recall)\b")
    for path in JS_FILES:
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if line.strip().startswith(("*", "//", "/*")):
                continue
            assert not suspicious.search(line), f"{path.name}:{number} looks like fabricated data"


def test_the_api_client_is_the_only_place_that_fetches():
    """One network surface, so error handling and timeouts cannot be bypassed."""
    offenders = [
        path.name
        for path in JS_FILES
        if path.name != "api.js" and re.search(r"\bfetch\s*\(", path.read_text(encoding="utf-8"))
    ]
    assert not offenders, f"fetch() outside the API client: {offenders}"


def test_package_manifest_declares_no_dependencies():
    """Vanilla means vanilla: the manifest exists only to mark ES modules."""
    manifest = json.loads((DASHBOARD / "package.json").read_text(encoding="utf-8"))
    assert "dependencies" not in manifest
    assert "devDependencies" not in manifest
    assert manifest["type"] == "module"


# --- Operator identity in the console (ADR-023) -----------------------------


def test_the_console_tells_the_three_identity_failures_apart():
    """Session expired, access denied and gateway unreachable have different
    remedies. A console that shows one shrug for all three sends an operator to
    debug the wrong thing during an incident (§16)."""
    source = (DASHBOARD / "js" / "api.js").read_text(encoding="utf-8")
    assert "UNAUTHENTICATED" in source and "FORBIDDEN" in source
    assert "response.status === 401" in source
    assert "response.status === 403" in source


def test_the_console_stores_no_session_and_no_identity():
    """Authentication introduced the obvious temptation: keep the token, keep the
    subject, skip a round trip. The console asks the gateway every time instead,
    so a stolen browser profile yields nothing."""
    for path in JS_FILES:
        code = "\n".join(
            line
            for line in path.read_text(encoding="utf-8").splitlines()
            if not line.strip().startswith(("*", "//", "/*"))
        )
        for forbidden in ("document.cookie", "sessionStorage"):
            assert forbidden not in code, f"{path.name} touches {forbidden}"
        # The theme is the only setItem in the console; asserted above. Here the
        # point is narrower: nothing identity-shaped is written next to it.
        for key in ("subject", "session", "token", "logout_path"):
            assert f'setItem("{key}' not in code and f"setItem('{key}" not in code


def test_the_sign_out_link_cannot_leave_the_origin():
    """The path comes from server configuration, so a typo must not be able to
    walk an operator to an attacker-chosen host. `safeHref` refuses anything that
    is not a same-origin absolute path — including `//evil.example`, which starts
    with a slash and is exactly the case a naive check passes."""
    shell = (DASHBOARD / "js" / "components" / "shell.js").read_text(encoding="utf-8")
    assert "safeHref(session.logout_path)" in shell
    body = shell.split("function identity(")[1].split("\nexport function renderHeader")[0]
    code = "\n".join(
        line for line in body.splitlines() if not line.strip().startswith(("*", "//", "/*"))
    )
    # No raw use of the server-supplied path as an href.
    assert "href: session.logout_path" not in code
