from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import FileResponse

_WEB_ROOT = Path(__file__).resolve().parent
_SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; base-uri 'none'; connect-src 'self'; "
        "font-src 'self'; form-action 'self'; frame-ancestors 'none'; "
        "img-src 'self' data:; object-src 'none'; script-src 'self'; "
        "style-src 'self'"
    ),
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
}

router = APIRouter(include_in_schema=False)


def _asset(filename: str, media_type: str, *, cache_control: str) -> FileResponse:
    return FileResponse(
        _WEB_ROOT / filename,
        media_type=media_type,
        headers={**_SECURITY_HEADERS, "Cache-Control": cache_control},
    )


@router.get("/")
def frontend_index() -> FileResponse:
    return _asset("index.html", "text/html; charset=utf-8", cache_control="no-store")


@router.get("/assets/app.js")
def frontend_javascript() -> FileResponse:
    return _asset(
        "app.js",
        "text/javascript; charset=utf-8",
        cache_control="public, max-age=3600",
    )


@router.get("/assets/styles.css")
def frontend_stylesheet() -> FileResponse:
    return _asset(
        "styles.css",
        "text/css; charset=utf-8",
        cache_control="public, max-age=3600",
    )
