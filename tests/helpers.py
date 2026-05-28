from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from pacspace_sdk.client import TransportResponse


@dataclass
class QueuedResponse:
    status_code: int
    body: Any
    headers: Optional[Dict[str, str]] = None


class FakeTransport:
    def __init__(self) -> None:
        self.calls: List[Dict[str, Any]] = []
        self.responses: List[QueuedResponse] = []

    def queue(
        self,
        *,
        status_code: int,
        body: Any,
        headers: Optional[Dict[str, str]] = None,
    ) -> None:
        self.responses.append(
            QueuedResponse(status_code=status_code, body=body, headers=headers or {}),
        )

    def __call__(
        self,
        method: str,
        url: str,
        headers: Dict[str, str],
        body: Optional[str],
        timeout_ms: int,
    ) -> TransportResponse:
        self.calls.append(
            {
                "method": method,
                "url": url,
                "headers": dict(headers),
                "body": body,
                "timeout_ms": timeout_ms,
            }
        )
        if not self.responses:
            raise AssertionError("No queued response configured for FakeTransport call")
        response = self.responses.pop(0)
        encoded = json.dumps(response.body).encode("utf-8")
        return TransportResponse(
            status_code=response.status_code,
            headers={k.lower(): v for k, v in (response.headers or {}).items()},
            body=encoded,
        )
