from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Optional


@dataclass
class PacSpaceError(Exception):
    message: str
    status_code: int
    code: str
    request_path: Optional[str] = None

    def __post_init__(self) -> None:
        super().__init__(self.message)


class InvalidApiKeyError(PacSpaceError):
    def __init__(
        self,
        message: str = "Invalid or missing API key",
        request_path: Optional[str] = None,
    ) -> None:
        super().__init__(message, 401, "INVALID_API_KEY", request_path)


class InsufficientCreditsError(PacSpaceError):
    def __init__(
        self,
        message: str = "Insufficient credits for this operation",
        request_path: Optional[str] = None,
    ) -> None:
        super().__init__(message, 402, "INSUFFICIENT_CREDITS", request_path)


class NotFoundError(PacSpaceError):
    def __init__(
        self,
        message: str = "Resource not found",
        request_path: Optional[str] = None,
    ) -> None:
        super().__init__(message, 404, "NOT_FOUND", request_path)


class ContractNotDeployedError(PacSpaceError):
    def __init__(
        self,
        message: str = "No contract deployed. Provision an environment first.",
        request_path: Optional[str] = None,
    ) -> None:
        super().__init__(message, 412, "CONTRACT_NOT_DEPLOYED", request_path)


class RateLimitError(PacSpaceError):
    def __init__(
        self,
        message: str = "Rate limit exceeded",
        retry_after: Optional[int] = None,
        request_path: Optional[str] = None,
    ) -> None:
        super().__init__(message, 429, "RATE_LIMITED", request_path)
        self.retry_after = retry_after


class CadenceLimitError(PacSpaceError):
    def __init__(
        self,
        message: str = "Submission cadence limit reached",
        retry_after_seconds: Optional[float] = None,
        customer_id: Optional[str] = None,
        request_path: Optional[str] = None,
    ) -> None:
        super().__init__(message, 429, "CADENCE_LIMIT", request_path)
        self.retry_after_ms = (
            int(max(0.0, retry_after_seconds) * 1000)
            if isinstance(retry_after_seconds, (int, float))
            else None
        )
        self.customer_id = customer_id


class ServiceUnavailableError(PacSpaceError):
    def __init__(
        self,
        message: str = "Service temporarily unavailable",
        retry_after: Optional[int] = None,
        request_path: Optional[str] = None,
    ) -> None:
        super().__init__(message, 503, "SERVICE_UNAVAILABLE", request_path)
        self.retry_after = retry_after


class ValidationError(PacSpaceError):
    def __init__(
        self,
        message: str = "Invalid request data",
        request_path: Optional[str] = None,
    ) -> None:
        super().__init__(message, 400, "VALIDATION_ERROR", request_path)


class InvalidScopeCombinationError(PacSpaceError):
    def __init__(
        self,
        message: str = "Choose either a checkpoint or a time scope for this request.",
        request_path: Optional[str] = None,
    ) -> None:
        super().__init__(message, 400, "INVALID_SCOPE_COMBINATION", request_path)


class ScopeTooWideError(PacSpaceError):
    def __init__(
        self,
        message: str = "Scope window is too wide for a single request.",
        request_path: Optional[str] = None,
    ) -> None:
        super().__init__(message, 400, "SCOPE_TOO_WIDE", request_path)


class TimeoutError(PacSpaceError):
    def __init__(
        self,
        message: str = "Operation timed out waiting for verification",
        request_path: Optional[str] = None,
    ) -> None:
        super().__init__(message, 0, "TIMEOUT", request_path)


class WebhookVerificationError(PacSpaceError):
    def __init__(self, message: str = "Webhook signature verification failed") -> None:
        super().__init__(message, 0, "WEBHOOK_VERIFICATION_FAILED")


def _parse_retry_after(headers: Optional[Mapping[str, str]]) -> Optional[int]:
    if not headers:
        return None
    for key, value in headers.items():
        if key.lower() == "retry-after":
            try:
                parsed = int(value)
            except (TypeError, ValueError):
                return None
            return parsed if parsed >= 0 else None
    return None


def map_api_error(
    status_code: int,
    message: str,
    request_path: Optional[str] = None,
    headers: Optional[Mapping[str, str]] = None,
    api_error: Optional[Mapping[str, object]] = None,
) -> PacSpaceError:
    api_error = api_error or {}
    retry_after_header = _parse_retry_after(headers)
    retry_after_seconds = api_error.get("retryAfterSeconds")
    if isinstance(retry_after_seconds, str):
        try:
            retry_after_seconds = float(retry_after_seconds)
        except ValueError:
            retry_after_seconds = None
    if retry_after_seconds is None and retry_after_header is not None:
        retry_after_seconds = retry_after_header

    if status_code == 400:
        if api_error.get("code") == "INVALID_SCOPE_COMBINATION":
            return InvalidScopeCombinationError(message, request_path)
        if api_error.get("code") == "SCOPE_TOO_WIDE":
            return ScopeTooWideError(message, request_path)
        return ValidationError(message, request_path)
    if status_code == 401:
        return InvalidApiKeyError(message, request_path)
    if status_code == 402:
        return InsufficientCreditsError(message, request_path)
    if status_code == 404:
        return NotFoundError(message, request_path)
    if status_code == 412:
        return ContractNotDeployedError(message, request_path)
    if status_code == 429:
        if api_error.get("code") == "CADENCE_LIMIT":
            return CadenceLimitError(
                message,
                retry_after_seconds if isinstance(retry_after_seconds, (int, float)) else None,
                api_error.get("customerId") if isinstance(api_error.get("customerId"), str) else None,
                request_path,
            )
        return RateLimitError(
            message,
            int(retry_after_seconds) if isinstance(retry_after_seconds, (int, float)) else None,
            request_path,
        )
    if status_code == 503:
        return ServiceUnavailableError(
            message,
            int(retry_after_seconds) if isinstance(retry_after_seconds, (int, float)) else None,
            request_path,
        )
    return PacSpaceError(message, status_code, "API_ERROR", request_path)
