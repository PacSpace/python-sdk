from __future__ import annotations

from typing import Any, Dict, Optional
from urllib.parse import quote

from .balance import BalanceResource
from .client import ClientConfig, HttpClient
from .customers import CustomersResource
from .webhooks.verify import Webhooks

_VERIFY_SOURCES = {"db", "chain", "both"}


class PacSpace:
    @classmethod
    def init(
        cls,
        api_key: str,
        **options: Any,
    ) -> "PacSpace":
        return cls(api_key=api_key, **options)

    def __init__(
        self,
        api_key: str,
        *,
        base_url: Optional[str] = None,
        sandbox_url: Optional[str] = None,
        production_url: Optional[str] = None,
        chain_id: Optional[int] = None,
        credit_pool_id: Optional[int] = None,
        max_retries: int = 2,
        timeout: int = 30_000,
        webhook_secret: Optional[str] = None,
        submission: Optional[Dict[str, Any]] = None,
        transport: Optional[Any] = None,
    ) -> None:
        self._client = HttpClient(
            ClientConfig(
                api_key=api_key,
                base_url=base_url,
                sandbox_url=sandbox_url,
                production_url=production_url,
                chain_id=chain_id,
                credit_pool_id=credit_pool_id,
                max_retries=max_retries,
                timeout=timeout,
                transport=transport,
            )
        )
        self.balance = BalanceResource(self._client, submission_options=submission)
        self.customers = CustomersResource(self._client)
        self.webhooks = Webhooks(webhook_secret) if webhook_secret else None

    def close(self, reason: str = "SDK closed") -> None:
        self.balance.stop_summary_scheduler()
        self._client.close(reason)

    def shutdown(self, reason: str = "SDK shutdown") -> None:
        self.balance.shutdown_summary_scheduler()
        self._client.close(reason)

    def verify(self, proof_root: str, source: Optional[str] = None) -> Dict[str, Any]:
        if source is not None and source not in _VERIFY_SOURCES:
            raise ValueError(
                f"Invalid verify source '{source}'. Expected one of: db, chain, both."
            )
        path = f"/api/v1/verify/{quote(proof_root, safe='')}"
        if source and source != "db":
            path += f"?source={quote(source, safe='')}"
        response = self._client.get_public(path)
        if isinstance(response, dict) and response.get("success") is True and "data" in response:
            return response["data"]
        if isinstance(response, dict):
            return response
        raise ValueError("Verification failed: unexpected response format")
