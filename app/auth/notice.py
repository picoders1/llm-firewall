"""The page a browser gets when it is not signed in.

§15 of the Phase 9 brief: an externally terminated identity boundary means the
console must **not** invent its own login form. There is no password to collect
here and no session to create — the proxy already owns both. What is left is to
say, once and safely, that the request was not authenticated, and to give the
browser a way to retry so the proxy's own flow runs.

## Why this page is generated rather than served from `dashboard/`

The console's assets live behind the same boundary as its data (`classify_path`
treats unknown paths as operator-only). A stylesheet for the denied page would
therefore need its own public exception, and public exceptions in an access-class
table are how boundaries erode. Instead the page carries one inline `<style>`
block whose SHA-256 is added to that response's CSP as an exact hash source —
which keeps `unsafe-inline` out of the policy entirely.

Every string here is a constant. Nothing from the request reaches the markup, so
there is no escaping to get wrong and no way for a header to become HTML.
"""

from __future__ import annotations

import base64
import hashlib
from typing import Final

_STYLE: Final[str] = """
:root { color-scheme: dark light; }
body {
  margin: 0; min-height: 100vh; display: grid; place-items: center;
  background: #0b0f14; color: #e6edf3; padding: 2rem;
  font: 400 15px/1.6 ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
}
main { max-width: 30rem; text-align: center; }
h1 { font-size: 1.25rem; font-weight: 600; margin: 0 0 .5rem; letter-spacing: -0.01em; }
p { margin: 0 0 1.5rem; color: #9aa7b4; }
a {
  display: inline-block; padding: .55rem 1.1rem; border-radius: .5rem;
  border: 1px solid #2a3441; color: #e6edf3; text-decoration: none;
}
a:hover { border-color: #3d4a5c; }
a:focus-visible { outline: 2px solid #4c8eda; outline-offset: 2px; }
@media (prefers-color-scheme: light) {
  body { background: #f6f8fa; color: #1c2128; }
  p { color: #57606a; }
  a { border-color: #d0d7de; color: #1c2128; }
}
"""

STYLE_HASH: Final[str] = (
    "'sha256-" + base64.b64encode(hashlib.sha256(_STYLE.encode("utf-8")).digest()).decode() + "'"
)

_MESSAGES: Final[dict[int, tuple[str, str]]] = {
    401: (
        "Not signed in",
        "This console requires an authenticated operator session. "
        "Sign in through your organisation's access boundary, then reload.",
    ),
    403: (
        "Access denied",
        "You are signed in, but this account is not authorised for the "
        "security console. Ask an administrator to grant operator access.",
    ),
}


def notice_html(status_code: int) -> str:
    """A complete document for 401 or 403. No request data is interpolated.

    Only the 401 offers a reload. Reloading re-runs the proxy's sign-in flow, so
    it is a real remedy for an expired session — and it can never fix an account
    that is authenticated but unauthorised, where the same button would be a loop
    dressed as a remedy. The console's own notice makes the same distinction.
    """
    title, body = _MESSAGES[status_code]
    # An empty href re-requests the current URL, which is what makes the proxy's
    # authentication flow run again. It cannot be redirected somewhere else by
    # anything in the request.
    action = '<a href="">Reload</a>' if status_code == 401 else ""
    return (
        "<!doctype html>\n"
        '<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>{title} — LLM Firewall</title>"
        f"<style>{_STYLE}</style>"
        "</head><body><main>"
        f"<h1>{title}</h1><p>{body}</p>"
        f"{action}"
        "</main></body></html>"
    )


__all__ = ["STYLE_HASH", "notice_html"]
