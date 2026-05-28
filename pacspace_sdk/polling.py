from __future__ import annotations

import time
from typing import Any, Callable, Dict

from .errors import TimeoutError

TERMINAL_STATUSES = {"VERIFIED", "FAILED"}


def poll_until_terminal(
    status_fn: Callable[[], Dict[str, Any]],
    timeout_ms: int = 60_000,
    poll_interval_ms: int = 2_000,
) -> Dict[str, Any]:
    deadline = time.monotonic() + (timeout_ms / 1000.0)

    while time.monotonic() < deadline:
        result = status_fn()
        status = str(result.get("status", "")).upper()
        if status in TERMINAL_STATUSES:
            return result

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        sleep_for = min(remaining, poll_interval_ms / 1000.0)
        time.sleep(max(0.0, sleep_for))

    raise TimeoutError(
        f"Operation did not reach a terminal status within {timeout_ms}ms",
    )
