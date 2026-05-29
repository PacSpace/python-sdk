from __future__ import annotations

import json
import random
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Dict, Mapping, Optional

from .errors import (
    CadenceLimitError,
    PacSpaceError,
    RateLimitError,
    ServiceUnavailableError,
    map_api_error,
)

DEFAULT_SANDBOX_URL = "https://api-sandbox-wnizuypena-uw.a.run.app"
DEFAULT_PRODUCTION_URL = "https://app.pacspace.io"
DEFAULT_TIMEOUT_MS = 30_000
DEFAULT_MAX_RETRIES = 2

RETRYABLE_STATUS_CODES = {408, 429, 500, 502, 503, 504}


@dataclass
class TransportResponse:
    status_code: int
    headers: Dict[str, str]
    body: bytes


TransportCallable = Callable[
    [str, str, Dict[str, str], Optional[str], int],
    TransportResponse,
]


@dataclass
class ClientConfig:
    api_key: str
    base_url: Optional[str] = None
    sandbox_url: Optional[str] = None
    production_url: Optional[str] = None
    chain_id: Optional[int] = None
    credit_pool_id: Optional[int] = None
    max_retries: int = DEFAULT_MAX_RETRIES
    timeout: int = DEFAULT_TIMEOUT_MS
    transport: Optional[TransportCallable] = None


def default_transport(
    method: str,
    url: str,
    headers: Dict[str, str],
    body: Optional[str],
    timeout_ms: int,
) -> TransportResponse:
    validate_http_url(url)
    encoded_body = body.encode("utf-8") if body is not None else None
    request = urllib.request.Request(
        url=url,
        data=encoded_body,
        headers=headers,
        method=method,
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout_ms / 1000) as response:  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
            return TransportResponse(
                status_code=response.status,
                headers={k.lower(): v for k, v in response.headers.items()},
                body=response.read(),
            )
    except urllib.error.HTTPError as exc:
        return TransportResponse(
            status_code=exc.code,
            headers={k.lower(): v for k, v in exc.headers.items()},
            body=exc.read(),
        )


def validate_http_url(url: str) -> None:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise PacSpaceError("Request URL must be an absolute HTTP(S) URL.", 0, "INVALID_URL")
    if parsed.username or parsed.password:
        raise PacSpaceError("Request URL must not include credentials.", 0, "INVALID_URL")


class HttpClient:
    def __init__(self, config: ClientConfig):
        if not config.api_key:
            raise PacSpaceError(
                "API key is required. Pass api_key='pk_...'.",
                0,
                "MISSING_API_KEY",
            )

        self._api_key = config.api_key
        self._max_retries = max(0, int(config.max_retries))
        self._timeout = max(1, int(config.timeout))
        self._transport = config.transport or default_transport

        if config.base_url:
            base_url = config.base_url
        else:
            base_url = self._detect_base_url(
                config.api_key,
                config.sandbox_url,
                config.production_url,
            )
        self._base_url = base_url.rstrip("/")
        validate_http_url(self._base_url)

        self.default_chain_id = (
            config.chain_id if config.chain_id is not None else self._detect_chain_id(config.api_key)
        )
        self.default_credit_pool_id = config.credit_pool_id
        self._closed = False

    def close(self, reason: str = "Client closed") -> None:
        self._closed = True
        self._close_reason = reason

    def get(self, path: str, options: Optional[Dict[str, Any]] = None) -> Any:
        return self._request("GET", path, None, options, authenticated=True)

    def post(
        self,
        path: str,
        body: Optional[Dict[str, Any]] = None,
        options: Optional[Dict[str, Any]] = None,
    ) -> Any:
        return self._request("POST", path, body, options, authenticated=True)

    def get_public(self, path: str) -> Any:
        return self._request("GET", path, None, None, authenticated=False)

    def _request(
        self,
        method: str,
        path: str,
        body: Optional[Dict[str, Any]],
        options: Optional[Dict[str, Any]],
        authenticated: bool,
    ) -> Any:
        if self._closed:
            raise PacSpaceError(getattr(self, "_close_reason", "Client closed"), 0, "CLIENT_CLOSED", path)

        url = f"{self._base_url}{path}"
        headers = self._build_headers(options, authenticated)
        payload = json.dumps(body) if body is not None else None

        last_error: Optional[Exception] = None
        for attempt in range(self._max_retries + 1):
            if attempt > 0:
                delay = self._retry_delay(attempt, last_error)
                time.sleep(delay)

            try:
                response = self._transport(method, url, headers, payload, self._timeout)
            except Exception as exc:  # pragma: no cover - exercised via tests through this branch
                last_error = exc
                if attempt < self._max_retries:
                    continue
                raise PacSpaceError(f"Network error: {exc}", 0, "NETWORK_ERROR", path) from exc

            parsed = self._parse_json(response.body)
            if 200 <= response.status_code < 300:
                if isinstance(parsed, dict):
                    if parsed.get("success") is True and "data" in parsed:
                        return parsed["data"]
                    # Public verify endpoint may return direct payload.
                    if authenticated:
                        raise PacSpaceError(
                            "Unexpected response format",
                            response.status_code,
                            "API_ERROR",
                            path,
                        )
                    return parsed
                return parsed

            error_message, error_payload = self._extract_api_error(parsed, "Request failed")
            mapped = map_api_error(
                response.status_code,
                error_message,
                request_path=path,
                headers=response.headers,
                api_error=error_payload,
            )

            if (
                mapped.status_code not in RETRYABLE_STATUS_CODES
                or isinstance(mapped, CadenceLimitError)
                or attempt == self._max_retries
            ):
                raise mapped

            last_error = mapped

        # Unreachable in normal flow.
        raise PacSpaceError("Request failed", 0, "UNKNOWN", path)

    def _build_headers(
        self,
        options: Optional[Dict[str, Any]],
        authenticated: bool,
    ) -> Dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "pacspace-sdk-python/0.2.0",
        }
        if authenticated:
            headers["X-Api-Key"] = self._api_key

        chain_id = (options or {}).get("chainId")
        if chain_id is None:
            chain_id = self.default_chain_id
        if chain_id is not None:
            headers["X-Chain-Id"] = str(chain_id)

        credit_pool_id = (options or {}).get("creditPoolId")
        if credit_pool_id is None:
            credit_pool_id = self.default_credit_pool_id
        if credit_pool_id is not None:
            headers["X-Credit-Pool-Id"] = str(credit_pool_id)

        idempotency_key = (options or {}).get("idempotencyKey")
        if idempotency_key:
            headers["Idempotency-Key"] = str(idempotency_key)
        dashboard_token = (options or {}).get("dashboardToken")
        if dashboard_token:
            headers["Authorization"] = f"Bearer {dashboard_token}"
        return headers

    def _extract_api_error(
        self,
        body: Any,
        fallback: str,
    ) -> tuple[str, Dict[str, Any]]:
        if not isinstance(body, dict):
            return fallback, {}

        nested = body.get("error")
        if isinstance(nested, dict):
            message = self._as_message(nested.get("message")) or self._as_message(body.get("message")) or fallback
            payload = {
                "code": nested.get("code") if isinstance(nested.get("code"), str) else body.get("code"),
                "retryAfterSeconds": self._as_number(nested.get("retryAfterSeconds")),
                "customerId": nested.get("customerId") if isinstance(nested.get("customerId"), str) else None,
            }
            return message, payload

        message = self._as_message(body.get("message")) or self._as_message(body.get("error")) or fallback
        payload = {
            "code": body.get("code") if isinstance(body.get("code"), str) else None,
            "retryAfterSeconds": self._as_number(body.get("retryAfterSeconds")),
            "customerId": body.get("customerId") if isinstance(body.get("customerId"), str) else None,
        }
        return message, payload

    def _retry_delay(self, attempt: int, last_error: Optional[Exception]) -> float:
        if isinstance(last_error, RateLimitError) and getattr(last_error, "retry_after", None):
            return float(last_error.retry_after)
        if isinstance(last_error, ServiceUnavailableError) and getattr(last_error, "retry_after", None):
            return float(last_error.retry_after)
        base = 0.5 * (2 ** max(0, attempt - 1))
        jitter = base * 0.25 * random.random()
        return base + jitter

    @staticmethod
    def _parse_json(body: bytes) -> Any:
        if not body:
            return None
        try:
            return json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None

    @staticmethod
    def _as_number(value: Any) -> Optional[float]:
        if isinstance(value, (int, float)):
            return float(value)
        if isinstance(value, str):
            try:
                return float(value)
            except ValueError:
                return None
        return None

    @staticmethod
    def _as_message(value: Any) -> Optional[str]:
        if isinstance(value, str):
            return value
        if isinstance(value, list):
            messages = [item.strip() for item in value if isinstance(item, str) and item.strip()]
            if messages:
                return "; ".join(messages)
        return None

    @staticmethod
    def _detect_base_url(
        api_key: str,
        sandbox_url: Optional[str],
        production_url: Optional[str],
    ) -> str:
        if api_key.startswith("pk_test_"):
            return sandbox_url or DEFAULT_SANDBOX_URL
        if api_key.startswith("pk_live_"):
            return production_url or DEFAULT_PRODUCTION_URL
        return production_url or DEFAULT_PRODUCTION_URL

    @staticmethod
    def _detect_chain_id(api_key: str) -> Optional[int]:
        if api_key.startswith("pk_test_"):
            return 296
        if api_key.startswith("pk_live_"):
            return 295
        return None
