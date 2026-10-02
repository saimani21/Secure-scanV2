from __future__ import annotations

import time
from collections.abc import Callable
from urllib.parse import urljoin, urlsplit

import httpx

from .ingestion import EPSS_MAX_COMPRESSED_BYTES, KEV_MAX_BYTES

CISA_KEV_URL = (
    "https://raw.githubusercontent.com/cisagov/kev-data/"
    "develop/known_exploited_vulnerabilities.json"
)
FIRST_EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
_SOURCES = {
    "kev": (CISA_KEV_URL, KEV_MAX_BYTES, frozenset({"raw.githubusercontent.com"})),
    "epss": (
        FIRST_EPSS_URL,
        EPSS_MAX_COMPRESSED_BYTES,
        frozenset({"epss.empiricalsecurity.com", "epss.cyentia.com"}),
    ),
}


class FeedClientError(RuntimeError):
    pass


class SnapshotFeedClient:
    """Fetch only fixed public feeds with explicit redirect and byte policies."""

    def __init__(
        self,
        *,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._client = httpx.Client(
            timeout=httpx.Timeout(connect=5.0, read=30.0, write=30.0, pool=5.0),
            follow_redirects=False,
            headers={"Accept": "application/json, text/csv", "User-Agent": "SecureScan-Intel-V1.5"},
            transport=transport,
        )
        self._sleep = sleep

    def close(self) -> None:
        self._client.close()

    def fetch(self, source: str) -> bytes:
        if source not in _SOURCES:
            raise ValueError("unknown intelligence feed")
        initial, limit, allowed_hosts = _SOURCES[source]
        url = initial
        redirects = 0
        attempts = 0
        while attempts < 3:
            try:
                with self._client.stream("GET", url) as response:
                    if response.status_code in {301, 302, 303, 307, 308}:
                        location = response.headers.get("Location")
                        if location is None or redirects >= 3:
                            raise FeedClientError("intelligence feed redirect was rejected")
                        redirected = urljoin(url, location)
                        parsed = urlsplit(redirected)
                        if parsed.scheme != "https" or parsed.hostname not in allowed_hosts:
                            raise FeedClientError("intelligence feed redirect was rejected")
                        redirects += 1
                        url = redirected
                        continue
                    if response.status_code in {429, 500, 502, 503, 504}:
                        attempts += 1
                        if attempts >= 3:
                            raise FeedClientError("intelligence feed is temporarily unavailable")
                        self._sleep(float(2 ** (attempts - 1)))
                        continue
                    if response.status_code != 200:
                        raise FeedClientError("intelligence feed request failed")
                    chunks = []
                    size = 0
                    for chunk in response.iter_bytes():
                        size += len(chunk)
                        if size > limit:
                            raise FeedClientError("intelligence feed exceeded its byte limit")
                        chunks.append(chunk)
                    payload = b"".join(chunks)
                    if not payload:
                        raise FeedClientError("intelligence feed was empty")
                    return payload
            except FeedClientError:
                raise
            except (httpx.TimeoutException, httpx.NetworkError):
                attempts += 1
                if attempts >= 3:
                    raise FeedClientError("intelligence feed request failed") from None
                self._sleep(float(2 ** (attempts - 1)))
            except httpx.HTTPError:
                raise FeedClientError("intelligence feed request failed") from None
        raise FeedClientError("intelligence feed request failed")

    def __enter__(self) -> SnapshotFeedClient:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
