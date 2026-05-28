from __future__ import annotations

import atexit
import hashlib
import json
import math
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional

from .errors import PacSpaceError

SubmissionProfile = str
SubmitBatchCallable = Callable[[List[Dict[str, Any]]], Dict[str, Any]]

PROFILE_DEFAULT_CADENCE_MS = {
    "daily": 86_400_000,
    "sub_daily": 21_600_000,  # DEFAULT UNVALIDATED (6h)
    "immediate": 0,
}


class SubmissionCoordinator:
    def __init__(
        self,
        submit_batch: SubmitBatchCallable,
        options: Optional[Dict[str, Any]] = None,
    ) -> None:
        self._submit_batch = submit_batch
        options = options or {}

        self._profile: SubmissionProfile = str(options.get("profile", "daily"))
        self._enterprise = bool(options.get("enterprise", False))
        self._auto_start = bool(options.get("autoStart", True))
        self._auto_flush_on_shutdown = bool(options.get("autoFlushOnShutdown", True))
        self._default_reason = str(options.get("defaultReason", "usage_summary"))

        configured_cadence = options.get("cadenceMs", PROFILE_DEFAULT_CADENCE_MS.get(self._profile, 86_400_000))
        self._cadence_ms = max(0, int(configured_cadence))

        configured_per_request = int(options.get("maxDeltasPerRequest", 100))
        self._max_deltas_per_request = min(100, max(1, configured_per_request))

        configured_rpm = int(options.get("maxRequestsPerMinute", 10))
        self._max_requests_per_minute = max(1, configured_rpm)

        self._queue: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.RLock()
        self._flush_lock = threading.Lock()
        self._timer: Optional[threading.Timer] = None
        self._running = False
        self._next_flush_at: Optional[float] = None
        self._last_request_at = 0.0
        self._shutdown_hook_registered = False

        self._assert_profile_compatibility()

    def queue_summary(self, summary: Dict[str, Any]) -> Dict[str, Any]:
        normalized = self._normalize_summary(summary)
        with self._lock:
            self._queue[normalized["key"]] = normalized
            self._ensure_shutdown_hook()

        if self._profile == "immediate":
            self.flush_summaries()
        elif self._auto_start and not self._running:
            self.start()
        return normalized

    def queue_summaries(self, summaries: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return [self.queue_summary(summary) for summary in summaries]

    def get_queue_state(self) -> Dict[str, Any]:
        with self._lock:
            next_flush = (
                datetime.fromtimestamp(self._next_flush_at, tz=timezone.utc).isoformat().replace("+00:00", "Z")
                if self._next_flush_at is not None
                else None
            )
            return {
                "profile": self._profile,
                "cadenceMs": self._cadence_ms,
                "enterprise": self._enterprise,
                "queuedCount": len(self._queue),
                "isRunning": self._running,
                "nextFlushAt": next_flush,
            }

    def start(self) -> None:
        self._ensure_shutdown_hook()
        with self._lock:
            if self._profile == "immediate":
                self._running = True
                self._next_flush_at = None
                return
            if self._running:
                return
            self._running = True
            self._schedule_next_flush(self._cadence_ms)

    def stop(self) -> None:
        with self._lock:
            self._running = False
            self._next_flush_at = None
            if self._timer is not None:
                self._timer.cancel()
                self._timer = None

    def flush_summaries(self, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        with self._flush_lock:
            return self._perform_flush(options or {})

    def shutdown(self) -> None:
        self.stop()
        with self._lock:
            has_items = len(self._queue) > 0
        if has_items:
            self.flush_summaries()

    def _perform_flush(self, options: Dict[str, Any]) -> Dict[str, Any]:
        started_at = self._now_iso()
        max_items = options.get("maxItems")
        if max_items is None:
            max_items_value = math.inf
        else:
            max_items_value = max(0, int(max_items))

        with self._lock:
            selected = list(self._queue.values())[: int(max_items_value) if max_items_value != math.inf else None]

        if not selected:
            return {
                "profile": self._profile,
                "startedAt": started_at,
                "finishedAt": self._now_iso(),
                "attempted": 0,
                "submitted": 0,
                "failed": 0,
                "replayed": 0,
                "requestCount": 0,
                "queuedAfterFlush": len(self._queue),
                "failures": [],
            }

        chunks = self._chunk(selected, self._max_deltas_per_request)
        failures: List[Dict[str, Any]] = []
        submitted = 0
        replayed = 0
        request_count = 0
        keys_to_delete: set[str] = set()

        for chunk in chunks:
            payload: List[Dict[str, Any]] = []
            for item in chunk:
                payload.append(
                    {
                        "customerId": item["customerId"],
                        "delta": item["delta"],
                        "reason": item.get("reason") or self._default_reason,
                        "referenceId": item.get("referenceId"),
                        "metadata": {
                            "summaryWindowStart": item["windowStart"],
                            "summaryWindowEnd": item["windowEnd"],
                            "summaryProfile": self._profile,
                            "submissionType": "tenant_summary",
                            **(item.get("metadata") or {}),
                        },
                    }
                )

            try:
                self._pace_requests()
                request_count += 1
                response = self._submit_batch(payload)
                indexed_results: Dict[int, Dict[str, Any]] = {}
                for result in response.get("results", []):
                    idx = result.get("index")
                    if isinstance(idx, int):
                        indexed_results[idx] = result

                for index, item in enumerate(chunk):
                    result = indexed_results.get(index, {})
                    status = str(result.get("status", "")).upper()
                    if status == "FAILED":
                        failures.append(
                            {
                                "customerId": item["customerId"],
                                "referenceId": item.get("referenceId"),
                                "error": str(result.get("error", "Summary submission failed")),
                            }
                        )
                        continue
                    submitted += 1
                    if result.get("idempotent") is True:
                        replayed += 1
                    keys_to_delete.add(item["key"])
            except Exception as exc:
                for item in chunk:
                    failures.append(
                        {
                            "customerId": item["customerId"],
                            "referenceId": item.get("referenceId"),
                            "error": str(exc),
                        }
                    )

        with self._lock:
            for key in keys_to_delete:
                self._queue.pop(key, None)
            queued_after = len(self._queue)

        return {
            "profile": self._profile,
            "startedAt": started_at,
            "finishedAt": self._now_iso(),
            "attempted": len(selected),
            "submitted": submitted,
            "failed": len(failures),
            "replayed": replayed,
            "requestCount": request_count,
            "queuedAfterFlush": queued_after,
            "failures": failures,
        }

    def _assert_profile_compatibility(self) -> None:
        if not self._enterprise and self._profile in {"sub_daily", "immediate"}:
            raise PacSpaceError(
                f'Submission profile "{self._profile}" is enterprise-only. Set enterprise=True to enable it.',
                0,
                "INVALID_SUBMISSION_PROFILE",
            )
        if self._profile != "immediate" and self._cadence_ms <= 0:
            raise PacSpaceError(
                f'Submission profile "{self._profile}" requires cadenceMs > 0.',
                0,
                "INVALID_SUBMISSION_PROFILE",
            )

    def _normalize_summary(self, summary: Dict[str, Any]) -> Dict[str, Any]:
        customer_id = str(summary.get("customerId", "")).strip()
        if not customer_id:
            raise PacSpaceError(
                "customerId is required for summary submission.",
                0,
                "INVALID_SUMMARY",
            )

        delta = summary.get("delta")
        if not isinstance(delta, (int, float)) or not math.isfinite(delta) or float(delta) == 0.0:
            raise PacSpaceError(
                "delta must be a finite non-zero number for summary submission.",
                0,
                "INVALID_SUMMARY",
            )

        window_start = self._normalize_iso(str(summary.get("windowStart")), "windowStart")
        window_end = self._normalize_iso(str(summary.get("windowEnd")), "windowEnd")

        if window_end <= window_start:
            raise PacSpaceError(
                "windowEnd must be later than windowStart.",
                0,
                "INVALID_SUMMARY",
            )

        key = f"{customer_id}|{window_start}|{window_end}"
        raw_ref = summary.get("referenceId")
        reference_id = str(raw_ref).strip() if isinstance(raw_ref, str) and raw_ref.strip() else self._build_reference_id(
            customer_id=customer_id,
            delta=float(delta),
            window_start=window_start,
            window_end=window_end,
        )

        return {
            "customerId": customer_id,
            "delta": float(delta),
            "windowStart": window_start,
            "windowEnd": window_end,
            "reason": str(summary.get("reason") or self._default_reason),
            "referenceId": reference_id,
            "metadata": summary.get("metadata") if isinstance(summary.get("metadata"), dict) else {},
            "queuedAt": self._now_iso(),
            "key": key,
        }

    def _normalize_iso(self, value: str, field: str) -> str:
        text = value.strip()
        if not text:
            raise PacSpaceError(
                f"{field} must be a valid ISO-8601 timestamp.",
                0,
                "INVALID_SUMMARY",
            )

        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError as exc:
            raise PacSpaceError(
                f"{field} must be a valid ISO-8601 timestamp.",
                0,
                "INVALID_SUMMARY",
            ) from exc

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

    def _build_reference_id(
        self,
        customer_id: str,
        delta: float,
        window_start: str,
        window_end: str,
    ) -> str:
        digest = hashlib.sha256(
            json.dumps(
                {
                    "customerId": customer_id,
                    "delta": delta,
                    "windowStart": window_start,
                    "windowEnd": window_end,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()[:48]
        return f"sum_{digest}"

    def _pace_requests(self) -> None:
        min_interval = 60.0 / float(self._max_requests_per_minute)
        now = time.monotonic()
        wait_for = (self._last_request_at + min_interval) - now
        if wait_for > 0:
            time.sleep(wait_for)
        self._last_request_at = time.monotonic()

    @staticmethod
    def _chunk(items: List[Dict[str, Any]], size: int) -> List[List[Dict[str, Any]]]:
        return [items[index : index + size] for index in range(0, len(items), size)]

    def _schedule_next_flush(self, delay_ms: int) -> None:
        if not self._running or self._profile == "immediate":
            return
        if self._timer is not None:
            self._timer.cancel()

        safe_delay_ms = max(1, int(delay_ms))
        self._next_flush_at = time.time() + (safe_delay_ms / 1000.0)
        self._timer = threading.Timer(safe_delay_ms / 1000.0, self._on_scheduled_flush)
        self._timer.daemon = True
        self._timer.start()

    def _on_scheduled_flush(self) -> None:
        with self._lock:
            self._timer = None
            if not self._running or self._profile == "immediate":
                return
            self._next_flush_at = None

        try:
            self.flush_summaries()
        finally:
            with self._lock:
                if self._running:
                    self._schedule_next_flush(self._cadence_ms)

    def _ensure_shutdown_hook(self) -> None:
        if not self._auto_flush_on_shutdown or self._shutdown_hook_registered:
            return
        atexit.register(self._shutdown_flush)
        self._shutdown_hook_registered = True

    def _shutdown_flush(self) -> None:
        try:
            if self.get_queue_state()["queuedCount"] > 0:
                self.flush_summaries()
        except Exception:
            # Best-effort only.
            return

    @staticmethod
    def _now_iso() -> str:
        return datetime.now(tz=timezone.utc).isoformat().replace("+00:00", "Z")
