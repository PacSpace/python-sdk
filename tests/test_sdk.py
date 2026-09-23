from __future__ import annotations

import hashlib
import hmac
import json
import time
import unittest
from unittest.mock import patch

from pacspace_sdk import (
    CadenceLimitError,
    InvalidScopeCombinationError,
    PacSpace,
    PacSpaceError,
    RateLimitError,
    ServiceUnavailableError,
    ScopeTooWideError,
    WebhookVerificationError,
    fingerprint,
)
from pacspace_sdk.submission import SubmissionCoordinator
from pacspace_sdk.webhooks.verify import Webhooks

from helpers import FakeTransport


class BalanceFlowsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.transport = FakeTransport()
        self.sdk = PacSpace.init("pk_test_demo", transport=self.transport)

    def test_emit_flow(self) -> None:
        self.transport.queue(
            status_code=201,
            body={
                "success": True,
                "data": {
                    "recordId": "rec_123",
                    "status": "QUEUED",
                    "receiptId": "0xabc",
                    "customerId": "cust_1",
                    "delta": -5,
                },
            },
        )

        result = self.sdk.balance.emit("cust_1", -5, "usage")
        self.assertEqual(result["recordId"], "rec_123")
        self.assertEqual(self.transport.calls[0]["method"], "POST")
        self.assertIn("/api/v1/balance/delta", self.transport.calls[0]["url"])
        payload = json.loads(self.transport.calls[0]["body"])
        self.assertEqual(payload["customerId"], "cust_1")
        self.assertEqual(payload["delta"], -5)

    def test_emit_carries_adjusts_reference(self) -> None:
        self.transport.queue(
            status_code=201,
            body={
                "success": True,
                "data": {"recordId": "rec_adj", "status": "QUEUED", "receiptId": "0xdef"},
            },
        )
        self.sdk.balance.emit(
            "cust_1",
            -10,
            "adjustment",
            {"adjusts": {"referenceId": "inv_001"}},
        )
        payload = json.loads(self.transport.calls[0]["body"])
        self.assertEqual(payload["adjusts"], {"referenceId": "inv_001"})

    def test_emit_carries_adjusts_record_id(self) -> None:
        self.transport.queue(
            status_code=201,
            body={
                "success": True,
                "data": {"recordId": "rec_adj", "status": "QUEUED", "receiptId": "0xdef"},
            },
        )
        self.sdk.balance.emit(
            "cust_1",
            25,
            "adjustment",
            {"adjusts": {"recordId": "rec_orig"}},
        )
        payload = json.loads(self.transport.calls[0]["body"])
        self.assertEqual(payload["adjusts"], {"recordId": "rec_orig"})

    def test_derive_compare_checkpoint_usage_flows(self) -> None:
        self.transport.queue(
            status_code=200,
            body={"success": True, "data": {"computedBalance": -575, "deltasCount": 5}},
        )
        self.transport.queue(
            status_code=201,
            body={"success": True, "data": {"matchesYours": True, "matchesTheirs": True}},
        )
        self.transport.queue(
            status_code=201,
            body={"success": True, "data": {"checkpointId": "chk_1", "status": "QUEUED"}},
        )
        self.transport.queue(
            status_code=200,
            body={"success": True, "data": {"remaining": 99, "allowed": True}},
        )

        derive = self.sdk.balance.derive("cust_1", {"limit": 10})
        compare = self.sdk.balance.compare("cust_1", {"yours": -575, "theirs": -575})
        checkpoint = self.sdk.balance.checkpoint("cust_1", {"period": "2026-03"})
        usage = self.sdk.balance.usage()

        self.assertEqual(derive["computedBalance"], -575)
        self.assertTrue(compare["matchesYours"])
        self.assertEqual(checkpoint["checkpointId"], "chk_1")
        self.assertEqual(usage["remaining"], 99)

    def test_scoped_derive_and_compare_options(self) -> None:
        self.transport.queue(
            status_code=200,
            body={"success": True, "data": {"computedBalance": 100, "deltasCount": 2}},
        )
        self.transport.queue(
            status_code=201,
            body={"success": True, "data": {"matchesYours": True, "matchesTheirs": False}},
        )

        self.sdk.balance.derive("cust_1", {"period": "2026-04", "limit": 10})
        self.sdk.balance.compare(
            "cust_1",
            {"yours": 100, "theirs": 90},
            {"period": "2026-04", "startingBalance": 5},
        )

        derive_call = self.transport.calls[0]
        compare_call = self.transport.calls[1]
        self.assertIn("period=2026-04", derive_call["url"])
        self.assertIn("limit=10", derive_call["url"])

        compare_payload = json.loads(compare_call["body"])
        self.assertEqual(compare_payload["period"], "2026-04")
        self.assertEqual(compare_payload["startingBalance"], 5)

    def test_runtime_scope_validation_rejects_checkpoint_scope_combo(self) -> None:
        with self.assertRaises(ValueError):
            self.sdk.balance.derive(
                "cust_1",
                {"startingCheckpoint": "chk_1", "period": "2026-04"},
            )

        with self.assertRaises(ValueError):
            self.sdk.balance.compare(
                "cust_1",
                {"yours": 10, "theirs": 10},
                {"startingCheckpoint": "chk_1", "timePreset": "current_month"},
            )

    def test_derive_helpers(self) -> None:
        self.transport.queue(
            status_code=200,
            body={"success": True, "data": {"computedBalance": 1}},
        )
        self.transport.queue(
            status_code=200,
            body={"success": True, "data": {"computedBalance": 2}},
        )
        self.transport.queue(
            status_code=200,
            body={"success": True, "data": {"computedBalance": 3}},
        )

        self.sdk.balance.derive_current_month("cust_1")
        self.sdk.balance.derive_for_period("cust_1", "2026-02")
        self.sdk.balance.derive_months_back("cust_1", 3)

        self.assertIn("timePreset=current_month", self.transport.calls[0]["url"])
        self.assertIn("period=2026-02", self.transport.calls[1]["url"])
        self.assertIn("timePreset=custom", self.transport.calls[2]["url"])
        self.assertIn("startDate=", self.transport.calls[2]["url"])
        self.assertIn("endDate=", self.transport.calls[2]["url"])

    def test_customer_period_query(self) -> None:
        self.transport.queue(
            status_code=200,
            body={
                "success": True,
                "data": {
                    "customerId": "cust_1",
                    "computedBalance": 0,
                    "totalDeltas": 0,
                    "recentActivity": {"items": [], "pagination": {"total": 0}},
                },
            },
        )

        self.sdk.balance.customer("cust_1", {"period": "2026-04", "deltaPage": 2})
        self.assertIn("period=2026-04", self.transport.calls[0]["url"])
        self.assertIn("deltaPage=2", self.transport.calls[0]["url"])

    def test_invoice_proof_shared_record_fields(self) -> None:
        self.transport.queue(
            status_code=200,
            body={
                "success": True,
                "data": {
                    "customerId": "cust_1",
                    "period": "2026-04",
                    "proofRoot": "0xproof",
                    "verificationApiUrl": "https://app.pacspace.io/api/v1/verify/0xproof",
                    "verifyUrl": "https://customer-links.pacspace.io/c/cus_abc123",
                    "accessHint": "A1B2C3",
                    "customerLinkUrl": "https://customer-links.pacspace.io/c/cus_abc123",
                    "customerLinkHost": "customer-links.pacspace.io",
                },
            },
        )
        self.transport.queue(
            status_code=200,
            body={
                "success": True,
                "data": {
                    "customerId": "cust_1",
                    "period": "2026-05",
                    "proofRoot": "0xproof2",
                },
            },
        )

        shared_record = self.sdk.balance.receipt("cust_1", {"period": "2026-04"})
        fallback = self.sdk.balance.invoice_proof("cust_1", {"period": "2026-05"})

        self.assertEqual(
            shared_record["verificationApiUrl"],
            "https://app.pacspace.io/api/v1/verify/0xproof",
        )
        self.assertEqual(shared_record["accessHint"], "A1B2C3")
        self.assertEqual(
            shared_record["customerLinkUrl"],
            "https://customer-links.pacspace.io/c/cus_abc123",
        )
        self.assertEqual(shared_record["customerLinkHost"], "customer-links.pacspace.io")
        self.assertIsNone(fallback["verificationApiUrl"])
        self.assertIsNone(fallback["accessHint"])
        self.assertIsNone(fallback["customerLinkUrl"])
        self.assertIsNone(fallback["customerLinkHost"])

    def test_wait_for_verified(self) -> None:
        self.transport.queue(
            status_code=200,
            body={"success": True, "data": {"recordId": "rec_1", "status": "QUEUED"}},
        )
        self.transport.queue(
            status_code=200,
            body={"success": True, "data": {"recordId": "rec_1", "status": "VERIFIED"}},
        )

        result = self.sdk.balance.wait_for_verified("rec_1", {"pollInterval": 1, "timeout": 1000})
        self.assertEqual(result["status"], "VERIFIED")
        self.assertEqual(len(self.transport.calls), 2)

    def test_one_host_the_key_decides_the_environment(self) -> None:
        for api_key in ("pk_test_demo", "pk_live_demo"):
            transport = FakeTransport()
            transport.queue(status_code=200, body={"verified": True, "proofRoot": "0xroot", "message": "ok"})
            PacSpace.init(api_key, transport=transport).verify("0xroot")
            self.assertTrue(transport.calls[0]["url"].startswith("https://app.pacspace.io/"), api_key)

    def test_sandbox_url_stays_a_bring_your_own_override_for_test_keys_only(self) -> None:
        test_transport = FakeTransport()
        test_transport.queue(status_code=200, body={"verified": True, "proofRoot": "0xroot", "message": "ok"})
        PacSpace.init("pk_test_demo", transport=test_transport, sandbox_url="https://sandbox.example.com/").verify(
            "0xroot"
        )
        self.assertTrue(test_transport.calls[0]["url"].startswith("https://sandbox.example.com/"))

        live_transport = FakeTransport()
        live_transport.queue(status_code=200, body={"verified": True, "proofRoot": "0xroot", "message": "ok"})
        PacSpace.init("pk_live_demo", transport=live_transport, sandbox_url="https://sandbox.example.com/").verify(
            "0xroot"
        )
        self.assertTrue(live_transport.calls[0]["url"].startswith("https://app.pacspace.io/"))

    def test_verify_public_endpoint(self) -> None:
        self.transport.queue(
            status_code=200,
            body={
                "verified": True,
                "proofRoot": "0xroot",
                "message": "ok",
            },
        )

        result = self.sdk.verify("0xroot")
        self.assertTrue(result["verified"])
        self.assertIn("/api/v1/verify/0xroot", self.transport.calls[0]["url"])

    def test_verify_public_endpoint_with_source(self) -> None:
        self.transport.queue(
            status_code=200,
            body={
                "verified": False,
                "proofRoot": "0xroot",
                "message": "chain unavailable",
            },
        )

        result = self.sdk.verify("0xroot", source="chain")
        self.assertFalse(result["verified"])
        self.assertIn("/api/v1/verify/0xroot?source=chain", self.transport.calls[0]["url"])

    def test_verify_public_endpoint_rejects_invalid_source(self) -> None:
        with self.assertRaises(ValueError):
            self.sdk.verify("0xroot", source="invalid")
        self.assertEqual(len(self.transport.calls), 0)


class ErrorClassificationTest(unittest.TestCase):
    def test_cadence_limit_error_mapping(self) -> None:
        transport = FakeTransport()
        sdk = PacSpace.init("pk_test_demo", transport=transport)
        transport.queue(
            status_code=429,
            body={
                "error": {
                    "message": "Submission cadence limit reached",
                    "code": "CADENCE_LIMIT",
                    "retryAfterSeconds": 120,
                    "customerId": "cust_1",
                }
            },
        )

        with self.assertRaises(CadenceLimitError) as ctx:
            sdk.balance.emit("cust_1", -1, "usage")
        self.assertEqual(ctx.exception.retry_after_ms, 120000)
        self.assertEqual(ctx.exception.customer_id, "cust_1")

    def test_rate_limit_and_retry_after(self) -> None:
        transport = FakeTransport()
        sdk = PacSpace.init("pk_test_demo", transport=transport, max_retries=0)
        transport.queue(
            status_code=429,
            body={"message": "Too many requests"},
            headers={"retry-after": "5"},
        )

        with self.assertRaises(RateLimitError) as ctx:
            sdk.balance.emit("cust_1", -1, "usage")
        self.assertEqual(ctx.exception.retry_after, 5)

    def test_scope_error_mapping(self) -> None:
        transport = FakeTransport()
        sdk = PacSpace.init("pk_test_demo", transport=transport, max_retries=0)

        transport.queue(
            status_code=400,
            body={
                "error": {
                    "message": "Choose either a checkpoint or scope.",
                    "code": "INVALID_SCOPE_COMBINATION",
                }
            },
        )
        with self.assertRaises(InvalidScopeCombinationError):
            sdk.balance.derive("cust_1", {"period": "2026-04"})

        transport.queue(
            status_code=400,
            body={
                "error": {
                    "message": "Requested scope is too wide.",
                    "code": "SCOPE_TOO_WIDE",
                }
            },
        )
        with self.assertRaises(ScopeTooWideError):
            sdk.balance.derive("cust_1", {"startDate": "2020-01-01", "endDate": "2026-01-01"})

    def test_retries_transient_errors_then_succeeds(self) -> None:
        transport = FakeTransport()
        sdk = PacSpace.init("pk_test_demo", transport=transport, max_retries=1)
        transport.queue(
            status_code=503,
            body={"message": "temporarily unavailable"},
            headers={"retry-after": "0"},
        )
        transport.queue(
            status_code=201,
            body={"success": True, "data": {"recordId": "rec_ok", "status": "QUEUED"}},
        )

        with patch("pacspace_sdk.client.time.sleep", return_value=None):
            result = sdk.balance.emit("cust_1", -1, "usage")

        self.assertEqual(result["recordId"], "rec_ok")
        self.assertEqual(len(transport.calls), 2)

    def test_exhausted_service_unavailable_retries(self) -> None:
        transport = FakeTransport()
        sdk = PacSpace.init("pk_test_demo", transport=transport, max_retries=0)
        transport.queue(
            status_code=503,
            body={"message": "temporarily unavailable"},
            headers={"retry-after": "1"},
        )

        with self.assertRaises(ServiceUnavailableError):
            sdk.balance.emit("cust_1", -1, "usage")


class WebhookAndSubmissionTest(unittest.TestCase):
    def test_webhook_verification_accepts_either_signature_in_a_rotation_window(self) -> None:
        raw_body = json.dumps({"event": "delta.verified", "data": {"receiptId": "0xabc"}})
        timestamp = str(int(time.time() * 1000))

        def sign(secret: str) -> str:
            return "v1=" + hmac.new(
                secret.encode("utf-8"), f"{timestamp}.{raw_body}".encode("utf-8"), hashlib.sha256
            ).hexdigest()

        header = f"{sign('whsec_new')},{sign('whsec_old')}"
        self.assertEqual(Webhooks("whsec_new").verify(header, timestamp, raw_body)["event"], "delta.verified")
        self.assertEqual(Webhooks("whsec_old").verify(header, timestamp, raw_body)["event"], "delta.verified")
        with self.assertRaises(WebhookVerificationError):
            Webhooks("whsec_other").verify(header, timestamp, raw_body)
        with self.assertRaises(WebhookVerificationError):
            Webhooks("whsec_new").verify("t=1,v0=zz", timestamp, raw_body)

    def test_webhook_verification_accepts_millisecond_timestamp(self) -> None:
        secret = "whsec_test"
        raw_body = json.dumps({"event": "delta.verified", "data": {"recordId": "rec_1"}})
        timestamp = str(int(time.time() * 1000))
        signature = "v1=" + hmac.new(
            secret.encode("utf-8"),
            f"{timestamp}.{raw_body}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        webhooks = Webhooks(secret)
        event = webhooks.verify(signature, timestamp, raw_body)
        self.assertEqual(event["event"], "delta.verified")

    def test_submission_coordinator_flush_and_failures(self) -> None:
        def submit_batch(payload: list[dict[str, object]]) -> dict[str, object]:
            return {
                "totalQueued": 1,
                "totalFailed": 1,
                "results": [
                    {
                        "index": 0,
                        "customerId": payload[0]["customerId"],
                        "delta": payload[0]["delta"],
                        "status": "FAILED",
                        "error": "CADENCE_LIMIT",
                    },
                    {
                        "index": 1,
                        "customerId": payload[1]["customerId"],
                        "delta": payload[1]["delta"],
                        "status": "QUEUED",
                        "idempotent": True,
                    },
                ],
            }

        coordinator = SubmissionCoordinator(
            submit_batch=submit_batch,
            options={"maxRequestsPerMinute": 1000},
        )
        coordinator.queue_summaries(
            [
                {
                    "customerId": "cust_1",
                    "delta": -1,
                    "windowStart": "2026-03-17T00:00:00Z",
                    "windowEnd": "2026-03-18T00:00:00Z",
                },
                {
                    "customerId": "cust_2",
                    "delta": -2,
                    "windowStart": "2026-03-17T00:00:00Z",
                    "windowEnd": "2026-03-18T00:00:00Z",
                },
            ]
        )

        result = coordinator.flush_summaries()
        self.assertEqual(result["attempted"], 2)
        self.assertEqual(result["submitted"], 1)
        self.assertEqual(result["failed"], 1)
        self.assertEqual(coordinator.get_queue_state()["queuedCount"], 1)

    def test_submission_profile_requires_enterprise(self) -> None:
        with self.assertRaises(PacSpaceError):
            SubmissionCoordinator(
                submit_batch=lambda _: {"results": [], "totalQueued": 0, "totalFailed": 0},
                options={"profile": "sub_daily", "enterprise": False},
            )


class RecordsFlowsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.transport = FakeTransport()
        self.sdk = PacSpace.init("pk_test_demo", transport=self.transport)

    def test_fingerprint_bytes(self) -> None:
        ref = fingerprint(b"hello")
        self.assertEqual(ref["alg"], "sha-256")
        self.assertEqual(ref["byteLength"], "5")
        self.assertEqual(
            ref["digest"],
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
        )

    def test_emit_and_history(self) -> None:
        self.transport.queue(
            status_code=200,
            body={
                "success": True,
                "data": {
                    "receiptId": "anc_1",
                    "recordType": "machine-action-record",
                    "entityId": "build-1",
                    "recordKey": "0xab",
                    "status": "QUEUED",
                },
            },
        )
        self.transport.queue(
            status_code=200,
            body={
                "schema": "record-history-bundle/v1",
                "recordKey": "0xab",
                "receipts": [],
                "entries": [{"seq": 0, "status": "queued"}],
            },
            headers={"x-next-from-seq": "1"},
        )
        emitted = self.sdk.records.emit(
            record="build-1",
            title="Build passed",
            occurred_at="2026-09-15T16:04:17Z",
            actor_id="ci",
            payloads=[{"alg": "sha-256", "digest": "aa" * 32, "byteLength": "1"}],
            idempotency_key="build-1:t",
        )
        self.assertEqual(emitted["status"], "QUEUED")
        self.assertIn("/api/v1/records/machine-action-record/build-1/transitions", self.transport.calls[0]["url"])
        payload = json.loads(self.transport.calls[0]["body"])
        self.assertEqual(payload["lifecycle"], "recorded")
        self.assertEqual(payload["referenceId"], "build-1:t")

        history = self.sdk.records.history("build-1")
        self.assertEqual(history["entries"][0]["status"], "queued")
        self.assertEqual(history["nextFromSeq"], 1)

    def _queue_emit(self) -> None:
        self.transport.queue(
            status_code=200,
            body={
                "success": True,
                "data": {
                    "receiptId": "anc_2",
                    "recordType": "machine-action-record",
                    "entityId": "build-1",
                    "status": "QUEUED",
                },
            },
        )

    def test_emit_counts_entries_from_one_as_the_pages_do(self) -> None:
        self._queue_emit()
        self.sdk.records.emit(
            record="build-1",
            title="Handoff restated",
            occurred_at="2026-09-14T10:02:00Z",
            actor_id="ci",
            payloads=[{"alg": "sha-256", "digest": "bb" * 32, "byteLength": "1"}],
            amends={"recordKey": "0x" + ("ab" * 32), "entry": 1},
            references=[{"recordKey": "0x" + ("cd" * 32), "entry": 3}, {"recordKey": "0x" + ("ef" * 32), "seq": 4}],
            note="handoff restated",
            lifecycle="amended",
        )
        payload = json.loads(self.transport.calls[0]["body"])
        self.assertEqual(payload["lifecycle"], "amended")
        # entry 1 is the first entry: seq 0 on the wire. A seq given as seq goes as it is.
        self.assertEqual(payload["content"]["amends"], {"recordKey": "0x" + ("ab" * 32), "seq": 0})
        self.assertEqual(
            payload["content"]["references"],
            [{"recordKey": "0x" + ("cd" * 32), "seq": 2}, {"recordKey": "0x" + ("ef" * 32), "seq": 4}],
        )
        self.assertEqual(payload["content"]["note"], "handoff restated")

    def test_entry_below_one_is_refused_before_anything_is_sent(self) -> None:
        from pacspace_sdk.errors import ValidationError

        base = dict(record="build-1", title="t", occurred_at="2026-09-14T10:02:00Z", actor_id="ci", payloads=[])
        with self.assertRaises(ValidationError) as caught:
            self.sdk.records.emit(**base, amends={"recordKey": "0xab", "entry": 0})
        self.assertEqual(
            str(caught.exception),
            "amends.entry is 0. Entries count from 1: the first entry is entry 1. "
            "(The HTTP API's seq counts the same positions from 0.)",
        )
        with self.assertRaises(ValidationError):
            self.sdk.records.emit(**base, references=[{"recordKey": "0xab", "entry": True}])
        with self.assertRaises(ValidationError):
            self.sdk.records.emit(**base, amends={"recordKey": "0xab"})
        with self.assertRaises(ValidationError):
            self.sdk.records.receipt("build-1", 0)
        with self.assertRaises(ValidationError):
            self.sdk.records.history("build-1", from_entry=0)
        with self.assertRaises(ValidationError):
            self.sdk.records.check({"receipts": []}, expect=[{"entry": 0, "payloads": []}])
        self.assertEqual(self.transport.calls, [])

    def test_receipt_and_history_window_are_addressed_by_seq_on_the_wire(self) -> None:
        self.transport.queue(status_code=200, body={"success": True, "data": {"receipt": {}}})
        self.transport.queue(status_code=200, body={"schema": "record-history-bundle/v1", "receipts": []}, headers={})
        self.sdk.records.receipt("build-1", 1)
        self.assertIn("/receipts/0", self.transport.calls[0]["url"])
        self.sdk.records.history("build-1", from_entry=2, to_entry=5)
        self.assertIn("/history?fromSeq=1&toSeq=4", self.transport.calls[1]["url"])

    def test_check_speaks_entry_numbers(self) -> None:
        digest = "aa" * 32
        result = self.sdk.records.check(
            {
                "schema": "record-history-bundle/v1",
                "receipts": [
                    {"seq": 0, "status": "committed", "recordContent": {"payloads": [{"alg": "sha-256", "digest": digest, "byteLength": "1"}]}}
                ],
                "entries": [{"seq": 0, "status": "committed"}],
            },
            expect=[{"entry": 1, "payloads": [{"alg": "sha-256", "digest": digest, "byteLength": "1"}]}],
        )
        self.assertEqual(result["entries"][0]["entry"], 1)
        self.assertTrue(result["entries"][0]["expected"])

    def test_check_failed_entry(self) -> None:
        result = self.sdk.records.check(
            {
                "schema": "record-history-bundle/v1",
                "receipts": [],
                "entries": [
                    {
                        "seq": 0,
                        "status": "failed",
                        "code": "RECORD_GENESIS_MISMATCH",
                        "sentence": "A record opens with recorded; amended and closed come after it.",
                    }
                ],
            }
        )
        self.assertFalse(result["ok"])
        self.assertEqual(result["failedCheck"], "schema")
        self.assertEqual(result["entries"][0]["status"], "failed")


if __name__ == "__main__":
    unittest.main()

