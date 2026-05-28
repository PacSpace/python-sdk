"""Internal batch transport used by SubmissionCoordinator only.

Not part of the public SDK surface. Do not reference from public code paths.
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional

from ..client import HttpClient


def submit_internal_batch(
    client: HttpClient,
    deltas: Iterable[Dict[str, Any]],
    options: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Submit deltas via the internal transport used by the summary submission coordinator.

    This helper is internal; do not invoke it from public SDK code paths.
    """
    payload_deltas: List[Dict[str, Any]] = list(deltas)
    response = client.post(
        "/api/v1/balance/delta/batch",
        {"deltas": payload_deltas},
        options,
    )
    return _normalize_internal_batch_response(response)


def _normalize_internal_batch_response(data: Any) -> Dict[str, Any]:
    if not isinstance(data, dict):
        return {"totalQueued": 0, "totalFailed": 0, "results": []}

    results = data.get("results")
    if not isinstance(results, list):
        results = []

    return {
        "totalQueued": int(data.get("totalQueued", len(results))),
        "totalFailed": int(data.get("totalFailed", 0)),
        "results": results,
        "_efficiency": data.get("_efficiency"),
    }
