from __future__ import annotations

import hashlib
import hmac
import json
import time
import unittest
from pathlib import Path
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
        ref = fingerprint(b"hello", blind=False).ref
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


VECTORS_DIR = Path(__file__).resolve().parent / "vectors"

BLINDED_DIGEST_CASES = [
    "bd-empty",
    "bd-text",
    "bd-text-other-value",
    "bd-large-chunked",
    "bd-binary",
]


def _source_bytes(source: dict) -> bytes:
    if "hex" in source:
        return bytes.fromhex(source["hex"])
    if source.get("generator") == "byte[i] = (i*31+7) & 0xff":
        return bytes((i * 31 + 7) & 0xFF for i in range(source["byteLength"]))
    raise AssertionError(f"unknown source {source!r}")


class BlindedFingerprintReferenceTest(unittest.TestCase):
    """Standard-library reference checks of the shared blinded-digest vectors."""

    def test_known_answers(self) -> None:
        self.assertEqual(
            hashlib.sha256(b"abc").hexdigest(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )
        self.assertEqual(
            hmac.new(b"\x0b" * 20, b"Hi There", hashlib.sha256).hexdigest(),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
        )
        self.assertEqual(
            hmac.new(
                bytes(range(32)),
                b"pacspace blinded fingerprint known answer",
                hashlib.sha256,
            ).hexdigest(),
            "43aef7475f6d6a9b29b6e6f2a0170c92a1178722a75684a2750c511121ac6c9c",
        )

    def test_blinded_digest_vectors(self) -> None:
        vectors = json.loads((VECTORS_DIR / "blinding-v1.json").read_text(encoding="utf-8"))
        cases = [c for c in vectors["cases"] if c["kind"] == "blinded-digest"]
        self.assertEqual([c["id"] for c in cases], BLINDED_DIGEST_CASES)
        for case in cases:
            with self.subTest(case["id"]):
                value = bytes.fromhex(case["input"]["valueHex"])
                self.assertEqual(len(value), 32)
                data = _source_bytes(case["input"]["source"])
                self.assertEqual(
                    {
                        "alg": "hmac-sha-256",
                        "digest": hmac.new(value, data, hashlib.sha256).hexdigest(),
                        "byteLength": str(len(data)),
                    },
                    case["expected"]["ref"],
                )


BLINDING_FILE_CASES = ["bf-canary", "bf-empty-file", "bf-largest"]
BLINDING_FILE_REJECT_CASES = [
    "bf-reject-bom", "bf-reject-invalid-utf8", "bf-reject-empty", "bf-reject-crlf", "bf-reject-no-final-lf",
    "bf-reject-key-order", "bf-reject-indent", "bf-reject-duplicate-key", "bf-reject-extra-field",
    "bf-reject-missing-schema", "bf-reject-missing-alg", "bf-reject-missing-value", "bf-reject-missing-digest",
    "bf-reject-missing-bytelength", "bf-reject-schema", "bf-reject-alg", "bf-reject-value-uppercase",
    "bf-reject-value-0x", "bf-reject-value-nonhex", "bf-reject-value-62-hex", "bf-reject-value-66-hex",
    "bf-reject-digest-uppercase", "bf-reject-digest-62-hex", "bf-reject-digest-null", "bf-reject-bytelength-number",
    "bf-reject-bytelength-leading-zero", "bf-reject-bytelength-too-large", "bf-reject-top-level-array",
    "bf-reject-not-json", "bf-reject-over-cap",
]
BLINDING_VALUE_REJECT_CASES = [
    "bv-reject-0", "bv-reject-31", "bv-reject-33", "bv-reject-64", "bv-reject-65", "bv-reject-32-plus-00",
]
HELD_FILE_MATCH_CASES = [
    "hm-plain-match", "hm-plain-no-alg", "hm-plain-length-differs", "hm-plain-other-file", "hm-blinded-no-file",
    "hm-blinded-match", "hm-blinded-other", "hm-reject-digest-mismatch", "hm-reject-length-mismatch",
    "hm-binary-invalid-utf8", "hm-binary-blinded-match",
]
BLINDING_MATERIAL_CASES = [
    "bm-b1-whole-file", "bm-b1-missing-bytelength", "bm-b1-missing-alg", "bm-b3-missing-schema", "bm-b1-alg-sha256",
    "bm-b1-nested-in-sha256-ref", "bm-b2-pair-file", "bm-b2-pair-hex", "bm-b2-pair-object", "bm-b1-whole-file-deep",
    "bm-b1-missing-bytelength-deep", "bm-b1-missing-alg-deep", "bm-b3-missing-schema-deep", "bm-b1-alg-sha256-deep",
    "bm-b1-nested-in-sha256-ref-deep", "bm-b2-pair-file-deep", "bm-b2-pair-hex-deep", "bm-b2-pair-object-deep",
    "bm-guard-hmac-ref", "bm-guard-sha256-extra-field", "bm-guard-sha256-leading-zero",
    "bm-guard-sha256-extra-holds-invalid-ref", "bm-b1-in-digest-of-nested-ref", "bm-b2-before-b3",
    "bm-outside-ref-alg-with-keyid", "bm-outside-ref-alg-alone", "bm-outside-ref-in-sha256-extra",
    "bm-outside-ref-pair-blinding-null",
]

W6 = (
    "This payload includes a blinding file or its value. Pass the fingerprint's ref as the payload, "
    "and keep its blinding file with the file. Nothing was sent."
)
W6C = "A blinded fingerprint carries only alg, digest and byteLength. Move any other field out of it. Nothing was sent."
W8 = "This is not a valid blinding file."
W9 = "This blinding file does not match these bytes."
W10 = "A blinding value is exactly 32 bytes."
W11 = "alg and blind disagree. Pass one of them."
W12 = "A fingerprint is made with sha-256 or hmac-sha-256."
W13 = "A blinded entry was not matched. Pass each file with its blinding file to check it."
W14 = "Each expected row is a dict with an entry number."
W15 = "Each expected item is a payload reference dict. Pass the fingerprint's ref."
W17 = "<Blinding: value hidden>"
WS7 = "A different blinding file already exists at this path. Nothing was written."
WS8 = "The path for the blinding file is a link or not a regular file. Nothing was written."

TEXT_HEX = "706163737061636520626c696e6465642066696e6765727072696e7420766563746f720a"
TEXT_PLAIN_REF = {
    "alg": "sha-256",
    "digest": "5c83bad1e442fec89a331dc9347991d703d1c1915f83059938773c964db90817",
    "byteLength": "36",
}


def _vectors(name: str) -> dict:
    return json.loads((VECTORS_DIR / name).read_text(encoding="utf-8"))


def _ids(vectors: dict, kind: str) -> list:
    return [c["id"] for c in vectors["cases"] if c["kind"] == kind]


def _case(vectors: dict, case_id: str) -> dict:
    return next(c for c in vectors["cases"] if c["id"] == case_id)


def _value_forms(value: bytes) -> list:
    import base64

    return [
        value.hex(),
        value.hex().upper(),
        base64.b64encode(value).decode("ascii"),
        base64.urlsafe_b64encode(value).decode("ascii").rstrip("="),
    ]


def _value_of(blinding) -> bytes:
    from pacspace_sdk import blinding_file_text

    return bytes.fromhex(json.loads(blinding_file_text(blinding))["value"])


def _leaks(obj, value: bytes, forms: list, depth: int = 0) -> bool:
    if depth > 6:
        return False
    if isinstance(obj, (bytes, bytearray, memoryview)):
        data = bytes(obj)
        return value in data or any(form.encode("ascii") in data for form in forms)
    if isinstance(obj, str):
        return any(form in obj for form in forms)
    if isinstance(obj, dict):
        return any(_leaks(k, value, forms, depth + 1) or _leaks(v, value, forms, depth + 1) for k, v in obj.items())
    if isinstance(obj, (list, tuple, set, frozenset)):
        return any(_leaks(item, value, forms, depth + 1) for item in obj)
    return any(form in repr(obj) for form in forms)


class BlindedFingerprintTest(unittest.TestCase):
    def setUp(self) -> None:
        self.crypto = _vectors("blinding-v1.json")
        self.text = bytes.fromhex(TEXT_HEX)
        self.dir = Path(__import__("tempfile").mkdtemp(prefix="pacspace-sdk-blinding-"))

    def tearDown(self) -> None:
        __import__("shutil").rmtree(self.dir, ignore_errors=True)

    def test_blinds_by_default(self) -> None:
        from pacspace_sdk import Blinding, Fingerprint

        a = fingerprint(b"hello")
        b = fingerprint(b"hello")
        self.assertIsInstance(a, Fingerprint)
        self.assertEqual(a.ref["alg"], "hmac-sha-256")
        self.assertEqual(a.ref["byteLength"], "5")
        self.assertIsInstance(a.blinding, Blinding)
        self.assertEqual(a.blinding.digest, a.ref["digest"])
        self.assertNotEqual(a.ref["digest"], b.ref["digest"])

    def test_the_way_back(self) -> None:
        off = fingerprint(self.text, blind=False)
        self.assertEqual(off.ref, TEXT_PLAIN_REF)
        self.assertIsNone(off.blinding)
        self.assertEqual(fingerprint(self.text, "sha-256").ref, TEXT_PLAIN_REF)
        self.assertEqual(fingerprint(self.text, alg="sha-256").ref, TEXT_PLAIN_REF)
        self.assertEqual(repr(off), f"Fingerprint(ref={TEXT_PLAIN_REF!r}, blinding=None)")

    def test_the_alias(self) -> None:
        from pacspace_sdk.errors import ValidationError

        with self.assertRaises(PacSpaceError) as caught:
            fingerprint(b"x", "md5")
        self.assertEqual((caught.exception.code, str(caught.exception)), ("RECORD_PAYLOAD_ALG_UNSUPPORTED", W12))
        with self.assertRaises(ValidationError) as caught:
            fingerprint(b"x", "sha-256", blind=True)
        self.assertEqual((caught.exception.code, str(caught.exception)), ("VALIDATION_ERROR", W11))
        with self.assertRaises(ValidationError):
            fingerprint(b"x", "hmac-sha-256", blind=False)
        self.assertEqual(fingerprint(b"x", "hmac-sha-256", blind=True).ref["alg"], "hmac-sha-256")

    def test_blinding_on_another_file_is_refused(self) -> None:
        from pacspace_sdk.errors import ValidationError

        first = fingerprint(self.text)
        again = fingerprint(self.text, blinding=first.blinding)
        self.assertEqual(again.ref, first.ref)
        self.assertIs(again.blinding, first.blinding)
        with self.assertRaises(ValidationError) as caught:
            fingerprint(b"another file", blinding=first.blinding)
        self.assertEqual(str(caught.exception), W9)
        with self.assertRaises(ValidationError) as caught:
            fingerprint(self.text, blinding={"digest": "aa", "byteLength": "1"})
        self.assertEqual(str(caught.exception), W8)

    def test_blinded_digest_vectors_through_fingerprint(self) -> None:
        from pacspace_sdk import Blinding

        self.assertEqual(_ids(self.crypto, "blinded-digest"), BLINDED_DIGEST_CASES)
        for case_id in BLINDED_DIGEST_CASES:
            with self.subTest(case_id):
                case = _case(self.crypto, case_id)
                ref = case["expected"]["ref"]
                blinding = Blinding(bytes.fromhex(case["input"]["valueHex"]), ref["digest"], ref["byteLength"])
                data = _source_bytes(case["input"]["source"])
                chunks = [data[:7], data[7:65543], data[65543:]]
                result = fingerprint(iter(chunks), blinding=blinding)
                self.assertEqual(result.ref, ref)
                self.assertIs(result.blinding, blinding)

    def test_blinding_file_vectors(self) -> None:
        from pacspace_sdk import Blinding, blinding_file_text, read_blinding_file

        self.assertEqual(_ids(self.crypto, "blinding-file"), BLINDING_FILE_CASES)
        for case_id in BLINDING_FILE_CASES:
            with self.subTest(case_id):
                case = _case(self.crypto, case_id)
                path = self.dir / f"{case_id}.pacspace.json"
                path.write_bytes(case["expected"]["text"].encode("utf-8"))
                read = read_blinding_file(path)
                self.assertEqual(read.digest, case["input"]["fields"]["digest"])
                self.assertEqual(read.byteLength, case["input"]["fields"]["byteLength"])
                self.assertEqual(blinding_file_text(read), case["expected"]["text"])
                fields = case["input"]["fields"]
                made = Blinding(bytes.fromhex(fields["value"]), fields["digest"], fields["byteLength"])
                self.assertEqual(blinding_file_text(made), case["expected"]["text"])

    def test_blinding_file_reject_vectors(self) -> None:
        from pacspace_sdk import read_blinding_file
        from pacspace_sdk.errors import ValidationError

        self.assertEqual(_ids(self.crypto, "blinding-file-reject"), BLINDING_FILE_REJECT_CASES)
        for case_id in BLINDING_FILE_REJECT_CASES:
            with self.subTest(case_id):
                path = self.dir / f"{case_id}.json"
                path.write_bytes(bytes.fromhex(_case(self.crypto, case_id)["input"]["bytesHex"]))
                with self.assertRaises(ValidationError) as caught:
                    read_blinding_file(path)
                self.assertEqual(str(caught.exception), W8)

    def test_blinding_value_reject_vectors(self) -> None:
        from pacspace_sdk import Blinding
        from pacspace_sdk.errors import ValidationError

        self.assertEqual(_ids(self.crypto, "blinding-value-reject"), BLINDING_VALUE_REJECT_CASES)
        text_ref = _case(self.crypto, "bd-text")["expected"]["ref"]
        for case_id in BLINDING_VALUE_REJECT_CASES:
            with self.subTest(case_id):
                value = bytes.fromhex(_case(self.crypto, case_id)["input"]["valueHex"])
                with self.assertRaises(ValidationError) as caught:
                    Blinding(value, text_ref["digest"], text_ref["byteLength"])
                self.assertEqual(str(caught.exception), W10)
                with self.assertRaises(ValidationError) as caught:
                    fingerprint(self.text, blinding=Blinding(value, text_ref["digest"], text_ref["byteLength"]))
                self.assertEqual(str(caught.exception), W10)

    def test_hygiene(self) -> None:
        result = fingerprint(self.text)
        blinding = result.blinding
        value = _value_of(blinding)
        forms = _value_forms(value)
        self.assertEqual(repr(blinding), W17)
        self.assertEqual(str(blinding), W17)
        self.assertEqual(f"{blinding}", W17)
        self.assertEqual(repr(result), f"Fingerprint(ref={result.ref!r}, blinding={W17})")
        with self.assertRaises(TypeError):
            vars(blinding)
        outputs = [repr(blinding), str(blinding), f"{blinding}", f"{blinding!r}", repr(result), str(result), " ".join(dir(blinding))]
        for output in outputs:
            self.assertFalse(any(form in output for form in forms), output)
        for target in (blinding, result, {"ref": result.ref, "blinding": blinding}):
            with self.assertRaises(TypeError) as caught:
                json.dumps(target)
            self.assertFalse(any(form in str(caught.exception) for form in forms))
            self.assertIn("is not JSON serializable", str(caught.exception))

    def test_no_refusal_leaves_the_value_in_an_sdk_frame(self) -> None:
        import traceback

        from pacspace_sdk import Blinding, read_blinding_file, write_blinding_file

        result = fingerprint(self.text)
        value = _value_of(result.blinding)
        forms = _value_forms(value)
        written = write_blinding_file(self.dir / "weights.bin", result.blinding)
        file_text = Path(written).read_text(encoding="ascii")
        transport = FakeTransport()
        sdk = PacSpace.init("pk_test_demo", transport=transport)
        base = dict(record="r", title="t", occurred_at="2026-09-30T00:00:00Z", actor_id="a")
        bad_file = self.dir / "bad.pacspace.json"
        bad_file.write_text(file_text.replace("\n}", ",\n}"), encoding="ascii")
        refusals = [
            lambda: fingerprint(b"another file", blinding=result.blinding),
            lambda: fingerprint(self.text, "sha-256", blinding=result.blinding),
            lambda: Blinding(value + b"\x00", result.blinding.digest, result.blinding.byteLength),
            lambda: Blinding(value, "AA", result.blinding.byteLength),
            lambda: read_blinding_file(bad_file),
            lambda: write_blinding_file(self.dir / "weights.bin", fingerprint(b"other").blinding),
            lambda: sdk.records.emit(**base, payloads=[result]),
            lambda: sdk.records.emit(**base, payloads=[json.loads(file_text)]),
            lambda: sdk.records.emit(**base, payloads=[{"ref": result.ref, "blinding": value.hex()}]),
            lambda: sdk.records.emit(**base, payloads=[{**TEXT_PLAIN_REF, "note": json.loads(file_text)}]),
            lambda: sdk.records.check({"receipts": []}, expect=[{"entry": 1, "payloads": [json.loads(file_text)]}]),
            lambda: sdk.records.check({"receipts": []}, expect=[{"entry": 1, "payloads": [{"ref": result.ref, "blinding": value.hex()}]}]),
        ]
        for index, refuse in enumerate(refusals):
            with self.subTest(index):
                with self.assertRaises(PacSpaceError) as caught:
                    refuse()
                error = caught.exception
                text = f"{error}\n{''.join(traceback.format_exception(error))}\n{error.__cause__!r}\n{error.__context__!r}"
                self.assertFalse(any(form in text for form in forms), text)
                tb = error.__traceback__
                while tb is not None:
                    frame = tb.tb_frame
                    if "pacspace_sdk" in Path(frame.f_code.co_filename).parts:
                        for name, local in frame.f_locals.items():
                            self.assertFalse(_leaks(local, value, forms), f"{frame.f_code.co_name}: {name}")
                    tb = tb.tb_next
        self.assertEqual(transport.calls, [])


class BlindingFileTest(unittest.TestCase):
    def setUp(self) -> None:
        crypto = _vectors("blinding-v1.json")
        self.canary = _case(crypto, "bf-canary")
        self.dir = Path(__import__("tempfile").mkdtemp(prefix="pacspace-sdk-blinding-file-"))

    def tearDown(self) -> None:
        __import__("shutil").rmtree(self.dir, ignore_errors=True)

    def _canary_blinding(self):
        from pacspace_sdk import Blinding

        fields = self.canary["input"]["fields"]
        return Blinding(bytes.fromhex(fields["value"]), fields["digest"], fields["byteLength"])

    def test_writes_the_vector_bytes(self) -> None:
        from pacspace_sdk import read_blinding_file, write_blinding_file

        target = self.dir / "weights.bin"
        written = write_blinding_file(target, self._canary_blinding())
        self.assertEqual(written, f"{target}.pacspace.json")
        self.assertEqual(Path(written).read_bytes(), self.canary["expected"]["text"].encode("utf-8"))
        self.assertEqual(read_blinding_file(written).digest, self.canary["input"]["fields"]["digest"])

    @unittest.skipIf(__import__("os").name == "nt", "the mode is not enforced on Windows")
    def test_mode_0600(self) -> None:
        import os
        import stat

        from pacspace_sdk import write_blinding_file

        written = write_blinding_file(self.dir / "mode.bin", self._canary_blinding())
        self.assertEqual(stat.S_IMODE(os.lstat(written).st_mode), 0o600)

    def test_same_bytes_do_nothing_and_other_bytes_are_refused(self) -> None:
        import os

        from pacspace_sdk import write_blinding_file
        from pacspace_sdk.errors import ValidationError

        target = self.dir / "same.bin"
        written = write_blinding_file(target, self._canary_blinding())
        before = os.stat(written).st_mtime_ns
        self.assertEqual(write_blinding_file(target, self._canary_blinding()), written)
        self.assertEqual(os.stat(written).st_mtime_ns, before)
        with self.assertRaises(ValidationError) as caught:
            write_blinding_file(target, fingerprint(b"another file").blinding)
        self.assertEqual(str(caught.exception), WS7)
        self.assertEqual(Path(written).read_bytes(), self.canary["expected"]["text"].encode("utf-8"))

    @unittest.skipIf(__import__("os").name == "nt", "symlinks need privileges on Windows")
    def test_symlink_is_refused(self) -> None:
        import os

        from pacspace_sdk import write_blinding_file
        from pacspace_sdk.errors import ValidationError

        target = self.dir / "linked.bin"
        elsewhere = self.dir / "elsewhere.json"
        elsewhere.write_bytes(b"")
        os.symlink(elsewhere, f"{target}.pacspace.json")
        with self.assertRaises(ValidationError) as caught:
            write_blinding_file(target, self._canary_blinding())
        self.assertEqual(str(caught.exception), WS8)
        self.assertEqual(elsewhere.read_bytes(), b"")

    def test_directory_is_refused(self) -> None:
        from pacspace_sdk import write_blinding_file
        from pacspace_sdk.errors import ValidationError

        target = self.dir / "folder.bin"
        Path(f"{target}.pacspace.json").mkdir()
        with self.assertRaises(ValidationError) as caught:
            write_blinding_file(target, self._canary_blinding())
        self.assertEqual(str(caught.exception), WS8)


class BlindedRecordsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.transport = FakeTransport()
        self.sdk = PacSpace.init("pk_test_demo", transport=self.transport)
        self.base = dict(record="build-1", title="Build passed", occurred_at="2026-09-30T16:04:17Z", actor_id="ci")
        self.dir = Path(__import__("tempfile").mkdtemp(prefix="pacspace-sdk-records-blinding-"))

    def tearDown(self) -> None:
        __import__("shutil").rmtree(self.dir, ignore_errors=True)

    def _queue_emit(self) -> None:
        self.transport.queue(status_code=200, body={"success": True, "data": {"receiptId": "anc_1", "status": "QUEUED"}})

    @staticmethod
    def _history(payloads: list) -> dict:
        return {
            "schema": "record-history-bundle/v1",
            "recordKey": "0xab",
            "receipts": [{"seq": 0, "status": "committed", "recordContent": {"payloads": payloads}}],
            "entries": [{"seq": 0, "status": "committed"}],
        }

    def test_correct_use_sends_the_ref_and_no_value(self) -> None:
        from pacspace_sdk import blinding_file_text, write_blinding_file

        result = fingerprint(b"weights, build 14")
        write_blinding_file(self.dir / "weights.bin", result.blinding)
        self._queue_emit()
        self.sdk.records.emit(**self.base, payloads=[result.ref])
        self.assertEqual(len(self.transport.calls), 1)
        body = self.transport.calls[0]["body"]
        self.assertEqual(json.loads(body)["content"]["payloads"], [result.ref])
        value = _value_of(result.blinding)
        for secret in [*_value_forms(value), blinding_file_text(result.blinding)]:
            self.assertNotIn(secret, body)
            self.assertNotIn(secret, json.dumps(self.transport.calls[0]["headers"]))

    def test_each_misuse_is_refused_before_any_request(self) -> None:
        from pacspace_sdk import read_blinding_file, write_blinding_file

        result = fingerprint(b"weights, build 14")
        plain = fingerprint(b"weights, build 14", blind=False)
        written = write_blinding_file(self.dir / "misuse.bin", result.blinding)
        loaded = read_blinding_file(written)
        file_json = json.loads(Path(written).read_text(encoding="ascii"))
        misuses = {
            "the whole result": [result],
            "the whole plain result": [plain],
            "the Blinding alone": [result.blinding],
            "a loaded blinding file": [loaded],
            "the blinding file as JSON": [file_json],
            "a pair built by hand": [{"ref": result.ref, "blinding": file_json["value"]}],
            "a blinding file nested in a sha-256 reference": [{**plain.ref, "note": file_json}],
        }
        for name, payloads in misuses.items():
            with self.subTest(name):
                with self.assertRaises(PacSpaceError) as caught:
                    self.sdk.records.emit(**self.base, payloads=payloads)
                self.assertEqual((caught.exception.status_code, caught.exception.code, str(caught.exception)), (400, "RECORD_BLINDING_INCLUDED", W6))
                with self.assertRaises(PacSpaceError):
                    self.sdk.records.check(self._history([result.ref]), expect=[{"entry": 1, "payloads": payloads}])
        self.assertEqual(self.transport.calls, [])

    def test_a_blinded_ref_with_another_field_is_refused_with_w6c(self) -> None:
        ref = fingerprint(b"x").ref
        with self.assertRaises(PacSpaceError) as caught:
            self.sdk.records.emit(**self.base, payloads=[{**ref, "note": "weights"}])
        self.assertEqual(str(caught.exception), W6C)
        self.assertEqual(self.transport.calls, [])

    def test_guard_sha256_with_an_extra_field_is_sent_untouched(self) -> None:
        payload = {"alg": "sha-256", "digest": "aa" * 32, "byteLength": "007", "note": "weights, build 14"}
        self._queue_emit()
        self.sdk.records.emit(**self.base, payloads=[payload])
        self.assertEqual(json.loads(self.transport.calls[0]["body"])["content"]["payloads"], [payload])

    def test_blinding_material_vectors_through_emit(self) -> None:
        material = _vectors("blinding-material-v1.json")
        self.assertEqual([c["id"] for c in material["cases"]], BLINDING_MATERIAL_CASES)
        for case_id in BLINDING_MATERIAL_CASES:
            with self.subTest(case_id):
                case = _case(material, case_id)
                content = dict(case["input"]["content"])
                payloads = content.pop("payloads")
                transport = FakeTransport()
                sdk = PacSpace.init("pk_test_demo", transport=transport)
                # Rule B runs at every object and depth, so content emit does
                # not build (a top-level "detail") is carried as further items.
                items = [*payloads, *content.values()]
                if case["expected"].get("accepted"):
                    transport.queue(status_code=200, body={"success": True, "data": {"status": "QUEUED"}})
                    sdk.records.emit(**self.base, payloads=items)
                    self.assertEqual(json.loads(transport.calls[0]["body"])["content"]["payloads"], payloads)
                    continue
                with self.assertRaises(PacSpaceError) as caught:
                    sdk.records.emit(**self.base, payloads=items)
                self.assertEqual((caught.exception.status_code, caught.exception.code), (400, case["expected"]["errorCode"]))
                rule = case["expected"].get("rule")
                if rule:
                    self.assertEqual(str(caught.exception), W6C if rule == "B3" else W6)
                self.assertEqual(transport.calls, [])

    def test_held_file_match_vectors_through_check(self) -> None:
        from pacspace_sdk import Blinding

        crypto = _vectors("blinding-v1.json")
        self.assertEqual(_ids(crypto, "held-file-match"), HELD_FILE_MATCH_CASES)
        for case_id in HELD_FILE_MATCH_CASES:
            with self.subTest(case_id):
                case = _case(crypto, case_id)
                given = case["input"]["blinding"]
                blinding = Blinding(bytes.fromhex(given["valueHex"]), given["digest"], given["byteLength"]) if given else None
                result = self.sdk.records.check(
                    self._history(case["input"]["items"]),
                    expect=[{"entry": 1, "files": [{"source": _source_bytes(case["input"]["held"]), "blinding": blinding}]}],
                )
                self.assertEqual(result["entries"][0]["expected"], case["expected"]["matched"])
                self.assertEqual(result.get("blindingFileNeeded", []), [1] if case["expected"]["blindingNeeded"] else [])
                if case["expected"]["blindingNeeded"]:
                    self.assertEqual(result["note"], W13)
        self.assertEqual(self.transport.calls, [])

    def test_check_with_files(self) -> None:
        data = b"weights, build 14"
        mine = fingerprint(data)
        other = fingerprint(b"another file")
        history = self._history([mine.ref])
        right = self.sdk.records.check(history, expect=[{"entry": 1, "files": [{"source": data, "blinding": mine.blinding}]}])
        self.assertTrue(right["entries"][0]["expected"])
        wrong = self.sdk.records.check(history, expect=[{"entry": 1, "files": [{"source": data, "blinding": other.blinding}]}])
        self.assertFalse(wrong["entries"][0]["expected"])
        needed = self.sdk.records.check(history, expect=[{"entry": 1, "files": [{"source": data}]}])
        self.assertFalse(needed["entries"][0]["expected"])
        self.assertFalse(needed["ok"])
        self.assertEqual(needed["blindingFileNeeded"], [1])
        self.assertEqual(needed["note"], W13)
        plain = fingerprint(b"in the record", blind=False)
        missing = self.sdk.records.check(self._history([plain.ref]), expect=[{"entry": 1, "files": [{"source": b"not in the record"}]}])
        self.assertFalse(missing["entries"][0]["expected"])
        self.assertNotIn("blindingFileNeeded", missing)
        binary = bytes.fromhex("255044462d312e370a25fffe0080c328e2820a2525454f460a")
        text = b"plain text"
        both = self.sdk.records.check(
            self._history([{"digest": fingerprint(text, blind=False).ref["digest"]}, fingerprint(binary, blind=False).ref]),
            expect=[{"entry": 1, "files": [{"source": text}, {"source": binary}]}],
        )
        self.assertTrue(both["entries"][0]["expected"])

    def test_check_refuses_rows_and_items_it_cannot_read(self) -> None:
        from pacspace_sdk.errors import ValidationError

        result = fingerprint(b"x")
        history = self._history([result.ref])
        with self.assertRaises(ValidationError) as caught:
            self.sdk.records.check(history, expect=[{"entry": 1, "payloads": [result]}])
        self.assertEqual(str(caught.exception), W15)
        with self.assertRaises(ValidationError) as caught:
            self.sdk.records.check(history, expect=[{"payloads": [result.ref]}])
        self.assertEqual(str(caught.exception), W14)
        with self.assertRaises(ValidationError) as caught:
            self.sdk.records.check(history, expect=["entry 1"])
        self.assertEqual(str(caught.exception), W14)


SELECTIVE_DISCLOSURE = json.loads((VECTORS_DIR / "selective-disclosure-v1.json").read_text(encoding="utf-8"))
LINK_COPY_VECTORS = json.loads((VECTORS_DIR / "record-link-copy-v1.json").read_text(encoding="utf-8"))
KIND_VALUES = ("amended", "machine-action-record/v1#transitions.closed", "cas_exhausted")


def _sd_case(case_id: str) -> dict:
    return next(c for c in SELECTIVE_DISCLOSURE["cases"] if c["id"] == case_id)


def _v3_receipt(seq: int, revealed: list) -> dict:
    return {"schema": "semantic-receipt/v3", "seq": seq, "status": "committed", "leaves": [], "revealed": revealed}


def _leaf(pointer: str, value) -> dict:
    return {"pointer": pointer, "value": value, "salt": "0x" + "11" * 32}


class RecordsCheckReadsV2AndKindsTest(unittest.TestCase):
    """records.check reads record hash v2 histories and lists each row's kind (L1d)."""

    def setUp(self) -> None:
        self.sdk = PacSpace.init("pk_test_demo", transport=FakeTransport())

    def test_a_seal_history_a_kept_copy_and_a_disclosure_are_refused_by_name(self) -> None:
        kept = LINK_COPY_VECTORS["cases"][1]["input"]
        for document in (kept["sealHistory"], {"schema": "record-link-copy/v1", **kept}, kept["disclosure"]):
            result = self.sdk.records.check(document, expect=["entry 1"])
            self.assertEqual(
                (result["ok"], result["failedCheck"], result["reason"], result["entries"]),
                (False, "schema", "Not a record-history-bundle/v1.", []),
            )

    def test_a_v2_history_from_the_rh_vectors_matches_a_payload_read_from_revealed_leaves(self) -> None:
        rh = _sd_case("RH-01")["expected"]
        payload = next(leaf["value"] for leaf in rh["revealed"] if leaf["pointer"] == "/payloads/0")
        receipt = {"schema": "semantic-receipt/v3", "seq": 0, "status": "committed", "leaves": rh["leaves"], "revealed": rh["revealed"]}
        history = {"schema": "record-history-bundle/v2", "receipts": [receipt]}
        result = self.sdk.records.check(history, expect=[{"entry": 1, "payloads": [payload]}])
        self.assertTrue(result["ok"])
        self.assertEqual([(row["entry"], row["status"], row["expected"]) for row in result["entries"]], [(1, "committed", True)])
        other = {**payload, "digest": "00" * 32}
        self.assertFalse(self.sdk.records.check(history, expect=[{"entry": 1, "payloads": [other]}])["ok"])

    def test_three_kinds_from_a_v1_history(self) -> None:
        history = {
            "schema": "record-history-bundle/v1",
            "receipts": [
                {"seq": 0, "status": "committed", "recordContent": {"title": "Arm 4 paused the line", "actorId": "cell-controller-4"}},
                {
                    "seq": 1,
                    "status": "committed",
                    "recordContent": {"title": "Arm 4 asked to reopen the run", "attemptedTarget": KIND_VALUES[0], "ruleId": KIND_VALUES[1]},
                },
                {"seq": 2, "status": "committed", "recordContent": {"failureClass": KIND_VALUES[2], "attempts": 5}},
            ],
        }
        result = self.sdk.records.check(history)
        self.assertEqual([row["kind"] for row in result["entries"]], ["transition", "attempt", "failure"])
        text = json.dumps(result)
        for value in KIND_VALUES:
            self.assertNotIn(value, text)

    def test_three_kinds_from_a_v2_history_read_from_which_leaves_are_revealed(self) -> None:
        history = {
            "schema": "record-history-bundle/v2",
            "receipts": [
                _v3_receipt(0, [_leaf("/title", "Arm 4 paused the line")]),
                _v3_receipt(1, [_leaf("/attemptedTarget", KIND_VALUES[0]), _leaf("/ruleId", KIND_VALUES[1])]),
                _v3_receipt(2, [_leaf("/attempts", 5), _leaf("/failureClass", KIND_VALUES[2])]),
            ],
            "pendingEntries": [{"seq": None, "status": "queued"}],
        }
        result = self.sdk.records.check(history)
        kinds = {row["status"]: [] for row in result["entries"]}
        for row in result["entries"]:
            kinds[row["status"]].append(row["kind"])
        self.assertEqual(kinds, {"committed": ["transition", "attempt", "failure"], "queued": [None]})
        text = json.dumps(result)
        for value in KIND_VALUES:
            self.assertNotIn(value, text)


class DependencyFreeTest(unittest.TestCase):
    """The SDK's one runtime dependency is cryptography (L2a2), imported by
    records_asymmetric.py and encrypted_records.py (L2d3), which records.py
    loads on an encrypted path only; everything else is the standard library."""

    PACKAGE = Path(__file__).resolve().parent.parent / "pacspace_sdk"
    CRYPTOGRAPHY_ONLY_IN = {"records_asymmetric.py", "encrypted_records.py"}

    def test_pyproject_declares_cryptography_only(self) -> None:
        text = (self.PACKAGE.parent / "pyproject.toml").read_text(encoding="utf-8")
        self.assertRegex(text, r'(?m)^dependencies = \["cryptography>=48"\]$')

    def test_the_package_imports_the_standard_library_and_cryptography_where_named(self) -> None:
        import ast
        import sys

        stdlib = set(sys.stdlib_module_names) | {"__future__"}
        outside = []
        for path in sorted(self.PACKAGE.rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            allowed = stdlib | ({"cryptography"} if path.name in self.CRYPTOGRAPHY_ONLY_IN else set())
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                    names = [node.module]
                else:
                    continue
                outside.extend(f"{path.name}: {name}" for name in names if name.split(".")[0] not in allowed)
        self.assertEqual(outside, [])

    def test_no_module_imports_records_asymmetric(self) -> None:
        import ast

        importers = []
        for path in sorted(self.PACKAGE.rglob("*.py")):
            if path.name in self.CRYPTOGRAPHY_ONLY_IN:
                continue
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if isinstance(node, ast.ImportFrom) and (node.module or "").endswith("records_asymmetric"):
                    importers.append(path.name)
                elif isinstance(node, ast.ImportFrom) and any(alias.name == "records_asymmetric" for alias in node.names):
                    importers.append(path.name)
        self.assertEqual(importers, [])

    def test_a_client_with_no_workspace_secret_never_loads_cryptography(self) -> None:
        import subprocess
        import sys

        script = (
            "import sys, pacspace_sdk\n"
            "p = pacspace_sdk.PacSpace('pk_test_x', base_url='https://example.test')\n"
            "pacspace_sdk.generate_workspace_secret()\n"
            "print(any(m.split('.')[0] == 'cryptography' for m in sys.modules))\n"
        )
        out = subprocess.run([sys.executable, "-c", script], cwd=self.PACKAGE.parent, capture_output=True, text=True, check=True)
        self.assertEqual(out.stdout.strip(), "False")


from test_selective_disclosure_vectors import (  # noqa: E402 - run by the command CI and publish.yml use
    DisclosureResultTest,
    LinkCopyTest,
    SelectiveDisclosureVectorsTest,
)
from test_records_encryption_vectors import (  # noqa: E402 - run by the command CI and publish.yml use
    RecordsEncryptionRoundTripTest,
    RecordsEncryptionVectorsTest,
)
from test_records_asymmetric_vectors import (  # noqa: E402 - run by the command CI and publish.yml use
    RecordsAsymmetricRoundTripTest,
    RecordsAsymmetricVectorsTest,
)
from test_records_encrypted import (  # noqa: E402 - run by the command CI and publish.yml use
    AdmissionTest,
    EncryptedEmitTest,
    EncryptedReadTest,
    InterceptionTest,
    OpenLinkTest,
    PinsHoldersGrantsTest,
    RefusedAfterRekeyTest,
    RotateAndRekeyTest,
    WordsTest,
    WorkspaceSecretTest,
)


if __name__ == "__main__":
    unittest.main()

