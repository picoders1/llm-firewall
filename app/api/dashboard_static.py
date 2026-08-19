"""Static delivery for the Security Operations Dashboard.

Served from the gateway's own origin, deliberately. A separate host would need
CORS, and CORS on a security console is a policy surface nobody asked for —
same-origin means the browser enforces the boundary for free and the API client
needs no base URL, no credentials and no preflight.

## The header assumption this changes

`app/middleware/request_id.py` omits CSP with a stated reason: "this is an API,
not a browser origin". Serving HTML makes that premise false, so a Content
Security Policy is applied **to dashboard responses only**. API responses keep
exactly the headers they had, which is why the existing header tests still hold.

The policy is strict because the dashboard is built to allow it: no inline script,
no inline style, no external origin, no eval. `default-src 'self'` with everything
else locked down is only possible because the frontend was written to those
constraints from the start rather than retrofitted (ADR-022).

## Routing

History-API routes (`/dashboard/events/42`) are resolved by falling back to
`index.html` for any path that is not a real file, so a browser refresh on a deep
link works without the frontend resorting to hash URLs. Path traversal is refused
by resolving against the root and rejecting anything that escapes it.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, HTTPException, Response
from fastapi.responses import FileResponse

DASHBOARD_ROOT = Path(__file__).resolve().parents[2] / "dashboard"
INDEX = DASHBOARD_ROOT / "index.html"

# No 'unsafe-inline', no 'unsafe-eval', no external origins. `connect-src 'self'`
# means the console can only ever talk to the gateway that served it.
CONTENT_SECURITY_POLICY = "; ".join(
    (
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self'",
        "img-src 'self' data:",
        "font-src 'self'",
        "connect-src 'self'",
        "frame-ancestors 'none'",
        "base-uri 'none'",
        "object-src 'none'",
        "form-action 'none'",
    )
)

_CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".svg": "image/svg+xml",
    ".json": "application/json",
    ".ico": "image/x-icon",
}

router = APIRouter(tags=["dashboard"], include_in_schema=False)


def _headers() -> dict[str, str]:
    return {
        "content-security-policy": CONTENT_SECURITY_POLICY,
        "x-frame-options": "DENY",
    }


def _serve(path: Path) -> FileResponse:
    return FileResponse(
        path,
        media_type=_CONTENT_TYPES.get(path.suffix, "application/octet-stream"),
        headers=_headers(),
    )


@router.get("/dashboard")
@router.get("/dashboard/")
async def dashboard_index() -> Response:
    if not INDEX.is_file():
        raise HTTPException(status_code=404, detail="dashboard is not installed")
    return _serve(INDEX)


@router.get("/dashboard/{asset_path:path}")
async def dashboard_asset(asset_path: str) -> Response:
    """A real file, or `index.html` so client-side routes survive a refresh."""
    if not INDEX.is_file():
        raise HTTPException(status_code=404, detail="dashboard is not installed")

    candidate = (DASHBOARD_ROOT / asset_path).resolve()
    try:
        # Refuses `../` traversal by construction rather than by pattern-matching
        # the string, which is the check people get wrong.
        candidate.relative_to(DASHBOARD_ROOT.resolve())
    except ValueError:
        raise HTTPException(status_code=404, detail="not found") from None

    if candidate.is_file():
        return _serve(candidate)

    # Only extensionless paths are client-side routes. A missing `.js` or `.css`
    # must 404 rather than fall back to `index.html`: returning HTML for a script
    # request makes the browser try to execute a document, which fails in a way
    # that looks like an application bug rather than a missing file.
    if Path(asset_path).suffix:
        raise HTTPException(status_code=404, detail="not found")
    return _serve(INDEX)


__all__ = ["CONTENT_SECURITY_POLICY", "DASHBOARD_ROOT", "router"]
