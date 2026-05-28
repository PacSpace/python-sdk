from __future__ import annotations

from typing import Any, Dict, Optional

from .client import HttpClient


class CustomersResource:
    def __init__(self, client: HttpClient):
        self._client = client

    def create(
        self,
        *,
        display_name: str,
        customer_id: Optional[str] = None,
        sharing_state_hint: Optional[str] = None,
        event_cadence: Optional[str] = None,
        unit_label: Optional[str] = None,
        options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Create a dashboard customer before integration events arrive.

        This calls the JWT-authenticated dashboard API. Pass a dashboard JWT in
        ``options={"dashboardToken": "..."}``; Balance API keys alone cannot
        create customers.
        """
        body: Dict[str, Any] = {"displayName": display_name}
        if customer_id is not None:
            body["customerId"] = customer_id
        if sharing_state_hint is not None:
            body["sharingStateHint"] = sharing_state_hint
        if event_cadence is not None:
            body["eventCadence"] = event_cadence
        if unit_label is not None:
            body["unitLabel"] = unit_label
        return self._client.post("/dashboard/customers", body, options)
