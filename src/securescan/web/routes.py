from __future__ import annotations

from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, HTTPException
from fastapi import Path as ApiPath
from fastapi.responses import FileResponse

_WEB_ROOT = Path(__file__).resolve().parent
_CACHE_CONTROL = "no-cache"
_CANONICAL_UUID_PATTERN = (
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_CanonicalUuidPath = Annotated[str, ApiPath(pattern=_CANONICAL_UUID_PATTERN)]
_SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; base-uri 'none'; connect-src 'self'; "
        "font-src 'self'; form-action 'self'; frame-ancestors 'none'; "
        "img-src 'self'; object-src 'none'; script-src 'self'; "
        "style-src 'self'"
    ),
    "Permissions-Policy": "camera=(), geolocation=(), microphone=()",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
}
_ASSETS = {
    "app.js": "text/javascript; charset=utf-8",
    "api.js": "text/javascript; charset=utf-8",
    "components.js": "text/javascript; charset=utf-8",
    "coverage.js": "text/javascript; charset=utf-8",
    "dependencies.js": "text/javascript; charset=utf-8",
    "format.js": "text/javascript; charset=utf-8",
    "findings.js": "text/javascript; charset=utf-8",
    "gaps.js": "text/javascript; charset=utf-8",
    "overview.js": "text/javascript; charset=utf-8",
    "project.js": "text/javascript; charset=utf-8",
    "projects.js": "text/javascript; charset=utf-8",
    "report.js": "text/javascript; charset=utf-8",
    "router.js": "text/javascript; charset=utf-8",
    "scan.js": "text/javascript; charset=utf-8",
    "scans.js": "text/javascript; charset=utf-8",
    "state.js": "text/javascript; charset=utf-8",
    "base.css": "text/css; charset=utf-8",
    "shell.css": "text/css; charset=utf-8",
    "tokens.css": "text/css; charset=utf-8",
    "views.css": "text/css; charset=utf-8",
}

router = APIRouter(include_in_schema=False)


def _file(filename: str, media_type: str) -> FileResponse:
    return FileResponse(
        _WEB_ROOT / filename,
        media_type=media_type,
        headers={**_SECURITY_HEADERS, "Cache-Control": _CACHE_CONTROL},
    )


def _shell() -> FileResponse:
    return _file("index.html", "text/html; charset=utf-8")


@router.get("/")
def frontend_index() -> FileResponse:
    return _shell()


@router.get("/projects")
def frontend_projects() -> FileResponse:
    return _shell()


@router.get("/projects/{project_id}")
def frontend_project(project_id: _CanonicalUuidPath) -> FileResponse:
    del project_id
    return _shell()


@router.get("/scans")
def frontend_scans() -> FileResponse:
    return _shell()


@router.get("/scans/{run_id}")
def frontend_scan(run_id: _CanonicalUuidPath) -> FileResponse:
    del run_id
    return _shell()


@router.get("/scans/{run_id}/findings")
@router.get("/scans/{run_id}/dependencies")
@router.get("/scans/{run_id}/coverage")
@router.get("/scans/{run_id}/gaps")
@router.get("/scans/{run_id}/report")
def frontend_scan_view(run_id: _CanonicalUuidPath) -> FileResponse:
    del run_id
    return _shell()


@router.get("/assets/{filename}")
def frontend_asset(filename: str) -> FileResponse:
    media_type = _ASSETS.get(filename)
    if media_type is None:
        raise HTTPException(status_code=404, detail="Frontend asset was not found")
    return _file(filename, media_type)
