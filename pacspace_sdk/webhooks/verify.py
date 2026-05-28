from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import Any, Dict, Mapping, Optional

from ..errors import WebhookVerificationError


class Webhooks:
    def __init__(self, secret: str):
        if not secret:
            raise WebhookVerificationError(
                "Webhook secret is required. Get it from your PacSpace dashboard.",
            )
        self._secret = secret

    def verify(
        self,
        signature: str,
        timestamp: str,
        raw_body: str,
        tolerance: int = 300,
    ) -> Dict[str, Any]:
        if not signature or not timestamp or not raw_body:
            raise WebhookVerificationError(
                "Missing required parameters: signature, timestamp, and raw_body are all required.",
            )

        self._validate_timestamp(timestamp, tolerance_seconds=tolerance)

        signed_content = f"{timestamp}.{raw_body}".encode("utf-8")
        expected = "v1=" + hmac.new(
            self._secret.encode("utf-8"),
            signed_content,
            hashlib.sha256,
        ).hexdigest()

        if not hmac.compare_digest(expected, signature):
            raise WebhookVerificationError(
                "Signature mismatch. Ensure you are using the correct webhook secret and raw request body.",
            )

        try:
            parsed = json.loads(raw_body)
        except json.JSONDecodeError as exc:
            raise WebhookVerificationError(
                "Failed to parse webhook payload as JSON.",
            ) from exc

        if not isinstance(parsed, dict):
            raise WebhookVerificationError(
                "Webhook payload must decode to a JSON object.",
            )
        return parsed

    def verify_from_headers(
        self,
        headers: Mapping[str, Any],
        raw_body: str,
        tolerance: int = 300,
    ) -> Dict[str, Any]:
        signature = self._get_header(headers, "x-pacspace-signature")
        timestamp = self._get_header(headers, "x-pacspace-timestamp")

        if not signature:
            raise WebhookVerificationError("Missing X-PacSpace-Signature header.")
        if not timestamp:
            raise WebhookVerificationError("Missing X-PacSpace-Timestamp header.")

        return self.verify(signature, timestamp, raw_body, tolerance=tolerance)

    def _validate_timestamp(self, timestamp: str, tolerance_seconds: int) -> None:
        webhook_time_seconds = self._parse_timestamp_to_seconds(timestamp)
        if webhook_time_seconds is None:
            raise WebhookVerificationError(
                f'Invalid timestamp: "{timestamp}". Expected Unix epoch in seconds or milliseconds.',
            )
        now_seconds = int(time.time())
        age = abs(now_seconds - webhook_time_seconds)
        if age > tolerance_seconds:
            raise WebhookVerificationError(
                f"Timestamp too old ({age}s > {tolerance_seconds}s tolerance). "
                "This may indicate replay or clock skew.",
            )

    @staticmethod
    def _parse_timestamp_to_seconds(timestamp: str) -> Optional[int]:
        try:
            raw = int(timestamp)
        except (TypeError, ValueError):
            return None
        if abs(raw) >= 1_000_000_000_000:
            return raw // 1000
        return raw

    @staticmethod
    def _get_header(headers: Mapping[str, Any], key: str) -> Optional[str]:
        for header_key, value in headers.items():
            if str(header_key).lower() != key.lower():
                continue
            if isinstance(value, list):
                if not value:
                    return None
                return str(value[0])
            if value is None:
                return None
            return str(value)
        return None
