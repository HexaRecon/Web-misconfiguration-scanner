"""HTTP helpers that restrict every request and redirect to loopback targets."""

import ipaddress
import socket
import time
from urllib.parse import urljoin, urlsplit, urlunsplit

import requests

from config import HTTP_TIMEOUT_SECONDS, MAX_RESPONSE_BYTES, REQUEST_INTERVAL_SECONDS

REDIRECT_CODES = {301, 302, 303, 307, 308}
MAX_REDIRECTS = 3


class UnsafeTargetError(ValueError):
    """Raised when a URL is not an explicitly local scan target."""


def validate_local_url(url, *, preserve_path=False):
    """Normalize a URL and reject public, private-network, and metadata targets."""
    if not isinstance(url, str) or not url.strip() or len(url) > 2048:
        raise UnsafeTargetError("Enter a valid local website URL.")

    try:
        parsed = urlsplit(url.strip())
        port = parsed.port
    except ValueError as exc:
        raise UnsafeTargetError("The URL is malformed or has an invalid port.") from exc
    if parsed.scheme.lower() not in {"http", "https"}:
        raise UnsafeTargetError("Only HTTP and HTTPS URLs are supported.")
    if parsed.username or parsed.password:
        raise UnsafeTargetError("URLs containing credentials are not allowed.")
    if not parsed.hostname:
        raise UnsafeTargetError("The URL must include a hostname.")

    host = parsed.hostname.rstrip(".").lower()
    if "%" in host:
        raise UnsafeTargetError("Scoped IP addresses are not allowed.")
    try:
        address = ipaddress.ip_address(host)
        if not address.is_loopback:
            raise UnsafeTargetError("For safety, this scanner only accepts loopback targets.")
    except ValueError:
        if host != "localhost":
            raise UnsafeTargetError("For safety, only localhost or a loopback IP is allowed.")
        try:
            resolved = socket.getaddrinfo(host, port or 80, type=socket.SOCK_STREAM)
        except OSError as exc:
            raise UnsafeTargetError("Could not resolve localhost.") from exc
        if not resolved or any(not ipaddress.ip_address(item[4][0].split("%")[0]).is_loopback for item in resolved):
            raise UnsafeTargetError("Localhost did not resolve exclusively to loopback addresses.")

    netloc = f"[{host}]" if ":" in host else host
    if port is not None:
        netloc = f"{netloc}:{port}"
    path = (parsed.path or "/") if preserve_path else "/"
    return urlunsplit((parsed.scheme.lower(), netloc, path, "", ""))


class SafeHttpClient:
    """Small, rate-limited HTTP client for predefined, read-only checks."""

    def __init__(self):
        self._last_request = 0.0

    def request(self, method, url, *, max_response_bytes=MAX_RESPONSE_BYTES, headers=None):
        current_url = validate_local_url(url, preserve_path=True)
        for redirect_count in range(MAX_REDIRECTS + 1):
            delay = REQUEST_INTERVAL_SECONDS - (time.monotonic() - self._last_request)
            if delay > 0:
                time.sleep(delay)
            response = requests.request(
                method,
                current_url,
                allow_redirects=False,
                stream=True,
                timeout=HTTP_TIMEOUT_SECONDS,
                headers={"User-Agent": "Local-Misconfiguration-Scanner/1.0", **(headers or {})},
            )
            self._last_request = time.monotonic()
            if response.status_code not in REDIRECT_CODES:
                self._limit_response(response, max_response_bytes)
                return response

            location = response.headers.get("Location")
            if not location or redirect_count >= MAX_REDIRECTS:
                response.close()
                raise requests.TooManyRedirects("Redirect limit reached or Location header missing.")
            next_url = validate_local_url(urljoin(current_url, location), preserve_path=True)
            current_parts = urlsplit(current_url)
            next_parts = urlsplit(next_url)
            if (
                (current_parts.scheme, current_parts.hostname, current_parts.port, current_parts.path)
                != (next_parts.scheme, next_parts.hostname, next_parts.port, next_parts.path)
            ):
                response.close()
                raise UnsafeTargetError("Redirect changed the origin or path outside the fixed check.")
            response.close()
            current_url = next_url
        raise requests.TooManyRedirects("Redirect limit reached.")

    @staticmethod
    def _limit_response(response, max_response_bytes):
        chunks = []
        size = 0
        for chunk in response.iter_content(chunk_size=8192):
            if not chunk:
                continue
            remaining = max_response_bytes - size
            chunks.append(chunk[:remaining])
            size += min(len(chunk), remaining)
            if size >= max_response_bytes:
                break
        response._content = b"".join(chunks)
        response._content_consumed = True
