"""Pure-Python HTTP/HTTPS client compatible with requests API over urllib.request."""

from __future__ import annotations

import json as _json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Iterator


class RequestException(Exception):
    """Base exception for requests operations."""


class ConnectionError(RequestException):
    """Raised when a network connection error occurs."""


class Timeout(RequestException):
    """Raised when an HTTP request times out."""


class HTTPError(RequestException):
    """Raised when an HTTP error status code (4xx/5xx) is returned."""


class Response:
    def __init__(
        self,
        status_code: int = 200,
        content: bytes = b"",
        headers: dict[str, str] | None = None,
        url: str = "",
    ) -> None:
        self.status_code = int(status_code)
        self.content = bytes(content)
        self.headers: dict[str, str] = dict(headers or {})
        self.url = url

    @property
    def text(self) -> str:
        return self.content.decode("utf-8", errors="replace")

    def json(self) -> Any:
        return _json.loads(self.content.decode("utf-8"))

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise HTTPError(f"HTTP Error {self.status_code} for url: {self.url}")

    def iter_content(self, chunk_size: int = 65536) -> Iterator[bytes]:
        step = max(1, int(chunk_size))
        for offset in range(0, len(self.content), step):
            yield self.content[offset : offset + step]

    def close(self) -> None:
        return None


def _request(
    method: str,
    url: str,
    *,
    params: dict[str, Any] | None = None,
    data: bytes | str | dict[str, Any] | None = None,
    json: Any = None,
    headers: dict[str, str] | None = None,
    timeout: float | tuple[float, float] | None = None,
    allow_redirects: bool = True,
    stream: bool = False,
) -> Response:
    del allow_redirects, stream
    target_url = url
    if params:
        query = urllib.parse.urlencode(params)
        sep = "&" if "?" in target_url else "?"
        target_url = f"{target_url}{sep}{query}"

    req_headers = dict(headers or {})
    body: bytes | None = None
    if json is not None:
        body = _json.dumps(json).encode("utf-8")
        req_headers.setdefault("Content-Type", "application/json")
    elif isinstance(data, bytes):
        body = data
    elif isinstance(data, str):
        body = data.encode("utf-8")
    elif isinstance(data, dict):
        body = urllib.parse.urlencode(data).encode("utf-8")

    timeout_sec: float = 30.0
    if isinstance(timeout, (tuple, list)) and timeout:
        timeout_sec = float(max(timeout))
    elif isinstance(timeout, (int, float)):
        timeout_sec = float(timeout)

    req = urllib.request.Request(target_url, data=body, headers=req_headers, method=method.upper())
    try:
        with urllib.request.urlopen(req, timeout=timeout_sec) as resp:  # nosec B310
            raw = resp.read()
            resp_headers = {k: v for k, v in resp.headers.items()}
            return Response(
                status_code=getattr(resp, "status", 200),
                content=raw,
                headers=resp_headers,
                url=target_url,
            )
    except urllib.error.HTTPError as exc:
        raw_err = exc.read() if hasattr(exc, "read") else b""
        resp_headers = {k: v for k, v in exc.headers.items()} if exc.headers else {}
        return Response(
            status_code=exc.code,
            content=raw_err,
            headers=resp_headers,
            url=target_url,
        )
    except Exception as exc:
        raise RequestException(str(exc)) from exc


def get(url: str, **kwargs: Any) -> Response:
    return _request("GET", url, **kwargs)


def post(url: str, **kwargs: Any) -> Response:
    return _request("POST", url, **kwargs)


def head(url: str, **kwargs: Any) -> Response:
    return _request("HEAD", url, **kwargs)
