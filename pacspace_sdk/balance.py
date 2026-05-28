from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Optional
from urllib.parse import quote, urlencode

from .client import HttpClient
from .polling import poll_until_terminal
from .submission import SubmissionCoordinator
from ._internal.batch_transport import submit_internal_batch


def _build_query(params: Dict[str, Any]) -> str:
    compact = {key: value for key, value in params.items() if value is not None}
    if not compact:
        return ""
    return "?" + urlencode(compact, doseq=True)


class BalanceResource:
    def __init__(
        self,
        client: HttpClient,
        submission_options: Optional[Dict[str, Any]] = None,
    ) -> None:
        self._client = client
        self.submission = SubmissionCoordinator(
            submit_batch=lambda deltas: submit_internal_batch(self._client, deltas),
            options=submission_options,
        )

    @staticmethod
    def _normalize_status(status: Any) -> str:
        normalized = str(status or "").upper()
        if normalized in {"QUEUED", "PROCESSING", "VERIFIED", "FAILED"}:
            return normalized
        return "QUEUED"

    @staticmethod
    def _to_api_checkpoint_type(checkpoint_type: Any) -> Any:
        return checkpoint_type

    @staticmethod
    def _validate_scope_mode(options: Dict[str, Any]) -> None:
        period = options.get("period")
        time_preset = options.get("timePreset")
        start_date = options.get("startDate")
        end_date = options.get("endDate")
        starting_checkpoint = options.get("startingCheckpoint")

        has_scope = any(
            value is not None for value in (period, time_preset, start_date, end_date)
        )
        if starting_checkpoint is not None and has_scope:
            raise ValueError(
                "startingCheckpoint cannot be combined with period, timePreset, startDate, or endDate."
            )

        if period is not None and any(
            value is not None for value in (time_preset, start_date, end_date)
        ):
            raise ValueError(
                "period cannot be combined with timePreset, startDate, or endDate."
            )

        if time_preset is not None and time_preset != "custom" and any(
            value is not None for value in (start_date, end_date)
        ):
            raise ValueError(
                "startDate/endDate can only be used when timePreset is 'custom' or omitted."
            )

        if time_preset == "custom" and (start_date is None or end_date is None):
            raise ValueError("timePreset='custom' requires both startDate and endDate.")

        if time_preset is None and ((start_date is None) != (end_date is None)):
            raise ValueError("startDate and endDate must be provided together.")

    @staticmethod
    def _to_utc_iso(dt: datetime) -> str:
        return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

    def _normalize_payload(self, value: Any) -> Any:
        if isinstance(value, list):
            return [self._normalize_payload(item) for item in value]
        if not isinstance(value, dict):
            return value

        normalized: Dict[str, Any] = {
            key: self._normalize_payload(payload) for key, payload in value.items()
        }

        if "status" in normalized:
            normalized["status"] = self._normalize_status(normalized["status"])

        return normalized

    def _normalize_invoice_proof_payload(self, value: Any) -> Dict[str, Any]:
        normalized = self._normalize_payload(value)
        if not isinstance(normalized, dict):
            return {}

        for key in (
            "verificationApiUrl",
            "accessHint",
            "customerLinkUrl",
            "customerLinkHost",
        ):
            field_value = normalized.get(key)
            normalized[key] = None if field_value is None else str(field_value)

        return normalized

    def emit(
        self,
        customer_id: str,
        delta: float,
        reason: str,
        options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        options = options or {}
        body: Dict[str, Any] = {
            "customerId": customer_id,
            "delta": delta,
            "reason": reason,
        }
        if "referenceId" in options:
            body["referenceId"] = options["referenceId"]
        if "metadata" in options:
            body["metadata"] = options["metadata"]

        request_options = {
            key: value
            for key, value in options.items()
            if key not in {"referenceId", "metadata"}
        }
        response = self._client.post("/api/v1/balance/delta", body, request_options)
        return self._normalize_payload(response)

    def emit_and_wait(
        self,
        customer_id: str,
        delta: float,
        reason: str,
        options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        options = options or {}
        timeout_ms = int(options.get("timeout", 60_000))
        poll_interval_ms = int(options.get("pollInterval", 2_000))
        emit_options = {
            key: value
            for key, value in options.items()
            if key not in {"timeout", "pollInterval"}
        }

        initial = self.emit(customer_id, delta, reason, emit_options)
        if str(initial.get("status", "")).upper() in {"VERIFIED", "FAILED"}:
            return initial

        record_id = str(initial["recordId"])
        return poll_until_terminal(
            lambda: self.delta_status(record_id),
            timeout_ms=timeout_ms,
            poll_interval_ms=poll_interval_ms,
        )

    def delta_status(
        self,
        record_id: str,
        options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        response = self._client.get(f"/api/v1/balance/delta/{quote(record_id, safe='')}", options)
        return self._normalize_payload(response)

    def get_record_status(
        self,
        record_id: str,
        options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return self.delta_status(record_id, options)

    def wait_for_verified(
        self,
        record_id: str,
        options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        options = options or {}
        timeout_ms = int(options.get("timeout", 60_000))
        poll_interval_ms = int(options.get("pollInterval", 2_000))
        request_options = {
            key: value
            for key, value in options.items()
            if key not in {"timeout", "pollInterval"}
        }
        return poll_until_terminal(
            lambda: self.get_record_status(record_id, request_options),
            timeout_ms=timeout_ms,
            poll_interval_ms=poll_interval_ms,
        )

    def usage(self, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        response = self._client.get("/api/v1/balance/usage", options)
        return self._normalize_payload(response)

    def gaps(
        self,
        customer_id: str,
        options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        options = options or {}
        query = _build_query(
            {
                "fromSequence": options.get("fromSequence"),
                "toSequence": options.get("toSequence"),
                "limit": options.get("limit"),
            }
        )
        request_options = {
            key: value
            for key, value in options.items()
            if key not in {"fromSequence", "toSequence", "limit"}
        }
        path = f"/api/v1/balance/gaps/{quote(customer_id, safe='')}{query}"
        response = self._client.get(path, request_options)
        return self._normalize_payload(response)

    def queue_summary(self, summary: Dict[str, Any]) -> Dict[str, Any]:
        return self.submission.queue_summary(summary)

    def queue_summaries(self, summaries: Iterable[Dict[str, Any]]) -> list[Dict[str, Any]]:
        return self.submission.queue_summaries(summaries)

    def flush_summaries(self, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return self.submission.flush_summaries(options)

    def start_summary_scheduler(self) -> None:
        self.submission.start()

    def stop_summary_scheduler(self) -> None:
        self.submission.stop()

    def get_summary_queue_state(self) -> Dict[str, Any]:
        return self.submission.get_queue_state()

    def shutdown_summary_scheduler(self) -> None:
        self.submission.shutdown()

    def derive(
        self,
        customer_id: str,
        options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        options = options or {}
        self._validate_scope_mode(options)
        checkpoint_type = self._to_api_checkpoint_type(options.get("startingCheckpointType"))
        query = _build_query(
            {
                "startingBalance": options.get("startingBalance"),
                "startingCheckpoint": options.get("startingCheckpoint"),
                "startingCheckpointType": checkpoint_type,
                "limit": options.get("limit"),
                "offset": options.get("offset"),
                "period": options.get("period"),
                "timePreset": options.get("timePreset"),
                "startDate": options.get("startDate"),
                "endDate": options.get("endDate"),
            }
        )
        request_options = {
            key: value
            for key, value in options.items()
            if key
            not in {
                "startingBalance",
                "startingCheckpoint",
                "startingCheckpointType",
                "limit",
                "offset",
                "period",
                "timePreset",
                "startDate",
                "endDate",
            }
        }
        path = f"/api/v1/balance/derive/{quote(customer_id, safe='')}{query}"
        response = self._client.get(path, request_options)
        return self._normalize_payload(response)

    def derive_current_month(
        self,
        customer_id: str,
        options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        merged = {**(options or {}), "timePreset": "current_month"}
        return self.derive(customer_id, merged)

    def derive_for_period(
        self,
        customer_id: str,
        period: str,
        options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        merged = {**(options or {}), "period": period}
        return self.derive(customer_id, merged)

    def derive_months_back(
        self,
        customer_id: str,
        months: int,
        options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        if not isinstance(months, int) or months < 1:
            raise ValueError("months must be a positive integer.")

        now = datetime.now(timezone.utc)
        end_year = now.year + (1 if now.month == 12 else 0)
        end_month = 1 if now.month == 12 else now.month + 1
        end_exclusive = datetime(end_year, end_month, 1, tzinfo=timezone.utc)

        start_month = now.month - (months - 1)
        start_year = now.year
        while start_month <= 0:
            start_month += 12
            start_year -= 1
        start_inclusive = datetime(start_year, start_month, 1, tzinfo=timezone.utc)

        merged = {
            **(options or {}),
            "timePreset": "custom",
            "startDate": self._to_utc_iso(start_inclusive),
            "endDate": self._to_utc_iso(end_exclusive),
        }
        return self.derive(customer_id, merged)

    def compare(
        self,
        customer_id: str,
        balances: Dict[str, Any],
        options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        options = options or {}
        self._validate_scope_mode(options)
        body: Dict[str, Any] = {
            "customerId": customer_id,
            "yourBalance": balances["yours"],
            "theirBalance": balances["theirs"],
            "startingBalance": options.get("startingBalance", 0),
        }
        if options.get("startingCheckpoint") is not None:
            body["startingCheckpoint"] = options["startingCheckpoint"]
        if options.get("startingCheckpointType") is not None:
            body["startingCheckpointType"] = self._to_api_checkpoint_type(
                options["startingCheckpointType"]
            )
        for key in ("period", "timePreset", "startDate", "endDate"):
            if options.get(key) is not None:
                body[key] = options[key]

        request_options = {
            key: value
            for key, value in options.items()
            if key
            not in {
                "startingBalance",
                "startingCheckpoint",
                "startingCheckpointType",
                "period",
                "timePreset",
                "startDate",
                "endDate",
            }
        }
        response = self._client.post("/api/v1/balance/compare", body, request_options)
        return self._normalize_payload(response)

    def receipt(
        self,
        customer_id: str,
        options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        options = options or {}
        has_scoped_receipt = any(
            options.get(key) is not None for key in ("period", "timePreset", "startDate", "endDate")
        )
        if has_scoped_receipt:
            return self._receipt_for_period(customer_id, options)

        request_options = {
            key: value
            for key, value in options.items()
            if key not in {"period", "timePreset", "startDate", "endDate"}
        }
        response = self._client.get(
            f"/api/v1/balance/receipt/{quote(customer_id, safe='')}",
            request_options or None,
        )
        return self._normalize_payload(response)

    def _receipt_for_period(
        self,
        customer_id: str,
        options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        options = options or {}
        query = _build_query(
            {
                "period": options.get("period"),
                "timePreset": options.get("timePreset"),
                "startDate": options.get("startDate"),
                "endDate": options.get("endDate"),
            }
        )
        request_options = {
            key: value
            for key, value in options.items()
            if key not in {"period", "timePreset", "startDate", "endDate"}
        }
        path = f"/api/v1/balance/invoice-proof/{quote(customer_id, safe='')}{query}"
        response = self._client.get(path, request_options)
        return self._normalize_invoice_proof_payload(response)

    def checkpoint(
        self,
        customer_id: Optional[str] = None,
        options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        options = options or {}
        body: Dict[str, Any] = {}
        if customer_id is not None:
            body["customerId"] = customer_id

        for key in ("period", "timePreset", "startDate", "endDate", "mode", "fingerprints"):
            if options.get(key) is not None:
                body[key] = options[key]

        request_options = {
            key: value
            for key, value in options.items()
            if key not in {"period", "timePreset", "startDate", "endDate", "mode", "fingerprints"}
        }
        response = self._client.post("/api/v1/balance/checkpoint", body, request_options)
        return self._normalize_payload(response)

    def list_checkpoints(self, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        options = options or {}
        query = _build_query(
            {
                "customerId": options.get("customerId"),
                "period": options.get("period"),
                "timePreset": options.get("timePreset"),
                "startDate": options.get("startDate"),
                "endDate": options.get("endDate"),
                "limit": options.get("limit"),
                "offset": options.get("offset"),
            }
        )
        request_options = {
            key: value
            for key, value in options.items()
            if key not in {"customerId", "period", "timePreset", "startDate", "endDate", "limit", "offset"}
        }
        response = self._client.get(f"/api/v1/balance/checkpoints{query}", request_options)
        return self._normalize_payload(response)

    def list_webhook_deliveries(self, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        options = options or {}
        query = _build_query(
            {
                "status": options.get("status"),
                "limit": options.get("limit"),
                "offset": options.get("offset"),
            }
        )
        request_options = {
            key: value
            for key, value in options.items()
            if key not in {"status", "limit", "offset"}
        }
        response = self._client.get(f"/api/v1/balance/webhooks{query}", request_options)
        return self._normalize_payload(response)

    def retry_webhook(
        self,
        event_id: str,
        options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        path = f"/api/v1/balance/webhooks/{quote(event_id, safe='')}/retry"
        response = self._client.post(path, {}, options)
        return self._normalize_payload(response)

    def customers(self, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        options = options or {}
        query = _build_query(
            {
                "search": options.get("search"),
                "limit": options.get("limit"),
                "page": options.get("page"),
            }
        )
        request_options = {
            key: value
            for key, value in options.items()
            if key not in {"search", "limit", "page"}
        }
        response = self._client.get(f"/api/v1/balance/customers{query}", request_options)
        return self._normalize_payload(response)

    def customer(
        self,
        customer_id: str,
        options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        options = options or {}
        query = _build_query(
            {
                "deltaPage": options.get("deltaPage"),
                "deltaLimit": options.get("deltaLimit"),
                "period": options.get("period"),
            }
        )
        request_options = {
            key: value
            for key, value in options.items()
            if key not in {"deltaPage", "deltaLimit", "period"}
        }
        path = f"/api/v1/balance/customers/{quote(customer_id, safe='')}{query}"
        response = self._client.get(path, request_options)
        return self._normalize_payload(response)

    def invoice_proof(
        self,
        customer_id: str,
        options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return self._receipt_for_period(customer_id, options)
