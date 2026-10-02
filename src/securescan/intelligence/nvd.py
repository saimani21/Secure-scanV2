from __future__ import annotations

import time
from collections.abc import Callable

import httpx

from .cve import validate_cve_id
from .ingestion import NVD_MAX_BYTES, IntelligenceIngestionError

NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CONNECT_TIMEOUT_SECONDS = 5.0
NVD_READ_TIMEOUT_SECONDS = 20.0
NVD_MAX_ATTEMPTS = 3


class NvdClientError(RuntimeError):
    pass


class NvdExactCveClient:
    """Bounded NVD 2.0 client that can request only an already-proven CVE."""

    def __init__(
        self,
        *,
        api_key: str | None = None,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if api_key is not None and (not isinstance(api_key, str) or not api_key):
            raise ValueError("NVD API key is invalid")
        headers = {"Accept": "application/json", "User-Agent": "SecureScan-NVD-V1.5"}
        if api_key is not None:
            headers["apiKey"] = api_key
        self._client = httpx.Client(
            timeout=httpx.Timeout(
                connect=NVD_CONNECT_TIMEOUT_SECONDS,
                read=NVD_READ_TIMEOUT_SECONDS,
                write=NVD_READ_TIMEOUT_SECONDS,
                pool=NVD_CONNECT_TIMEOUT_SECONDS,
            ),
            follow_redirects=False,
            headers=headers,
            transport=transport,
        )
        self._sleep = sleep

    def close(self) -> None:
        self._client.close()

    def fetch(self, cve_id: str) -> bytes:
        cve_id = validate_cve_id(cve_id)
        for attempt in range(NVD_MAX_ATTEMPTS):
            try:
                with self._client.stream("GET", NVD_CVE_API, params={"cveId": cve_id}) as response:
                    if response.status_code in {429, 500, 502, 503, 504}:
                        if attempt + 1 < NVD_MAX_ATTEMPTS:
                            self._sleep(float(2**attempt))
                            continue
                        raise NvdClientError("NVD is temporarily unavailable")
                    if 300 <= response.status_code < 400:
                        raise NvdClientError("NVD redirect was rejected")
                    if response.status_code != 200:
                        raise NvdClientError("NVD request failed")
                    chunks = []
                    size = 0
                    for chunk in response.iter_bytes():
                        size += len(chunk)
                        if size > NVD_MAX_BYTES:
                            raise NvdClientError("NVD response exceeded the byte limit")
                        chunks.append(chunk)
                    return b"".join(chunks)
            except NvdClientError:
                raise
            except (httpx.TimeoutException, httpx.NetworkError):
                if attempt + 1 == NVD_MAX_ATTEMPTS:
                    raise NvdClientError("NVD request failed") from None
                self._sleep(float(2**attempt))
            except (httpx.HTTPError, IntelligenceIngestionError):
                raise NvdClientError("NVD request failed") from None
        raise NvdClientError("NVD request failed")

    def __enter__(self) -> NvdExactCveClient:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
