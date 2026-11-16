"""R3 (D-7, D-23), the mirror of the TypeScript spec: labels on a write,
blinded under the workspace's id key in an encrypted workspace, and
records.close, which names the record's last entry by its number counted
from 1 and writes no entry."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import unittest
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import unquote, urlparse

from helpers import FakeTransport
from records_encrypted_support import FakeEncryptedApi

from pacspace_sdk import PacSpace, PacSpaceError, memory_pin_store
from pacspace_sdk import records_encryption as R
from pacspace_sdk.client import TransportResponse
from pacspace_sdk.webhooks.types import KnownWebhookEventType, RecordClosedPayload

# A byte-for-byte copy of packages/shared/src/records/__vectors__/blinded-labels-v1.json.
LABEL_VECTORS = json.loads((Path(__file__).resolve().parent / "vectors" / "blinded-labels-v1.json").read_text(encoding="utf-8"))
# Version 1 of the published vector keyring (a copy of records-encryption-v1.json) as a one-version secret file.
_KEYRING = json.loads(json.loads((Path(__file__).resolve().parent / "vectors" / "records-encryption-v1.json").read_text(encoding="utf-8"))["fixtures"]["keyring"])
VECTOR_SECRET = json.dumps({"schema": "pacspace-workspace-secret/v1", "secrets": [s for s in _KEYRING["secrets"] if s["version"] == 1]})
RECORD_TYPE = "machine-action-record"
LABELS_INVALID = "Labels are up to 10 key=value pairs. Keys are lowercase."


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def entry(record: str = "session-1") -> Dict[str, Any]:
    return {
        "record": record,
        "title": "Session 12",
        "occurred_at": "2026-10-19T09:00:00Z",
        "actor_id": "agent-7",
        "payloads": [{"alg": "sha-256", "digest": "aa" * 32, "byteLength": "1"}],
    }


def written(seq: int, entity_id: str = "session-1") -> Dict[str, Any]:
    return {"success": True, "data": {"receiptId": "", "recordType": RECORD_TYPE, "entityId": entity_id, "status": "QUEUED", "seq": seq}}


def closed(last_seq: int, entity_id: str = "session-1") -> Dict[str, Any]:
    return {
        "success": True,
        "data": {
            "recordType": RECORD_TYPE,
            "entityId": entity_id,
            "recordKey": "0xab",
            "closed": True,
            "closedBy": "code",
            "closedAt": "2026-10-19T10:00:00.000Z",
            "lastSeq": last_seq,
            "lastSeal": "0xseal",
            "idempotent": False,
        },
    }


class BlindedLabelVectorsTest(unittest.TestCase):
    def test_reproduces_every_b1_value_from_the_vector_keyring(self) -> None:
        ring = R.RecordsKeyring.from_provider(R.local_records_key_provider(VECTOR_SECRET))
        id_key = R.export_key_bytes(ring.id_key)
        self.assertEqual(len(id_key), 32)
        for case in LABEL_VECTORS["cases"]:
            self.assertEqual(R.blinded_label(ring.id_key, case["name"], case["value"]), case["blinded"])
            # The definition, by hand: b1: and the base64url HMAC-SHA-256 of name=value, the name lowercased.
            by_hand = hmac.new(id_key, f"{case['name'].lower()}={case['value']}".encode("utf-8"), hashlib.sha256).digest()
            self.assertEqual("b1:" + b64url(by_hand), case["blinded"])


class LabelsOnAWriteTest(unittest.TestCase):
    def setUp(self) -> None:
        self.transport = FakeTransport()
        self.sdk = PacSpace.init("pk_test_demo", transport=self.transport, max_retries=0)

    def test_sends_a_plaintext_record_its_labels_beside_the_content_never_in_it(self) -> None:
        self.transport.queue(status_code=200, body=written(0))
        self.sdk.records.emit(**entry(), labels={"model": "m-0926", "site": "press-line-4"})
        body = json.loads(self.transport.calls[0]["body"])
        self.assertEqual(body["labels"], {"model": "m-0926", "site": "press-line-4"})
        self.assertNotIn("m-0926", json.dumps(body["content"]))

    def test_reads_a_string_with_the_prototype_grammar(self) -> None:
        self.transport.queue(status_code=200, body=written(0))
        self.sdk.records.emit(**entry(), labels="Model=m-0926; site: press-line-4\nticket=OPS:1234/a, ")
        body = json.loads(self.transport.calls[0]["body"])
        self.assertEqual(body["labels"], {"model": "m-0926", "site": "press-line-4", "ticket": "OPS:1234/a"})

    def test_refuses_labels_the_api_would_refuse_before_anything_is_sent(self) -> None:
        eleven = {f"k{i}": "v" for i in range(11)}
        for labels in (eleven, {"Model": "m-0926"}, {"model": "two words"}, {"model": "x" * 65}, {"k" * 33: "v"}, {}, "model", "model=m-0926, nonsense", "", ["b1:" + "A" * 43], {"model": 1}):
            with self.assertRaises(PacSpaceError) as caught:
                self.sdk.records.emit(**entry(), labels=labels)
            self.assertEqual(caught.exception.code, "RECORD_LABELS_INVALID")
            self.assertEqual(caught.exception.message, LABELS_INVALID)
        self.assertEqual(self.transport.calls, [])

    def test_blinds_an_encrypted_record_labels_sorted_once_each_with_no_name_or_value_on_the_wire(self) -> None:
        api = FakeEncryptedApi()
        api.add_workspace("pk_test_A.SECRET", "cfixtureworkspacea0000001")
        a = PacSpace("pk_test_A.SECRET", base_url="https://api.test", max_retries=0, transport=api, records={"secret": VECTOR_SECRET, "pin_store": memory_pin_store()})
        a.records.identity.register()
        api.requests.clear()
        model, site, region, ticket = LABEL_VECTORS["cases"][:4]
        a.records.emit(
            **entry(),
            labels=f"model={model['value']}, site={site['value']}; Region={region['value']}\nticket={ticket['value']}, model={model['value']}",
        )
        body = api.requests[0]["body"]
        self.assertEqual(json.loads(body)["labels"], sorted([model["blinded"], site["blinded"], region["blinded"], ticket["blinded"]]))
        for case in (model, site, region, ticket):
            self.assertNotIn(case["value"], body)

        api.requests.clear()
        a.records.emit(**entry("plain-1"), encrypt=False, labels={"model": model["value"]})
        self.assertEqual(json.loads(api.requests[0]["body"])["labels"], {"model": model["value"]})


class RecordsCloseTest(unittest.TestCase):
    def setUp(self) -> None:
        self.transport = FakeTransport()
        self.sdk = PacSpace.init("pk_test_demo", transport=self.transport, max_retries=0)

    def sent(self, index: int = -1) -> Dict[str, Any]:
        call = self.transport.calls[index]
        return {"method": call["method"], "path": urlparse(call["url"]).path, "body": json.loads(call["body"]) if call["body"] else None}

    def test_returns_each_write_entry_number_counted_from_1(self) -> None:
        self.transport.queue(status_code=200, body=written(4))
        self.assertEqual(self.sdk.records.emit(**entry())["entry"], 5)

    def test_closes_after_the_entry_named_and_the_answer_counts_from_1(self) -> None:
        self.transport.queue(status_code=200, body=closed(2))
        result = self.sdk.records.close("session-1", last_entry=3)
        self.assertEqual(self.sent(), {"method": "POST", "path": f"/api/v1/records/{RECORD_TYPE}/session-1/close", "body": {"lastSeq": 2}})
        self.assertEqual(result["lastEntry"], 3)
        self.assertEqual((result["closed"], result["closedBy"], result["idempotent"]), (True, "code", False))

    def test_closes_after_the_last_entry_this_process_wrote_by_record_type(self) -> None:
        for seq, record, record_type in ((0, "session-1", None), (1, "session-1", None), (2, "session-2", None), (3, "session-1", "other-type")):
            self.transport.queue(status_code=200, body=written(seq, record))
            self.sdk.records.emit(**entry(record), record_type=record_type)
        self.transport.queue(status_code=200, body=closed(1))
        self.assertEqual(self.sdk.records.close("session-1")["lastEntry"], 2)
        self.assertEqual(self.sent()["body"], {"lastSeq": 1})
        self.transport.queue(status_code=200, body=closed(3))
        self.sdk.records.close("session-1", record_type="other-type")
        self.assertEqual(self.sent(), {"method": "POST", "path": "/api/v1/records/other-type/session-1/close", "body": {"lastSeq": 3}})

    def test_reads_the_record_last_entry_when_this_process_wrote_none(self) -> None:
        self.transport.queue(status_code=200, body={"success": True, "data": {"recordType": RECORD_TYPE, "entityId": "session-9", "lastSeq": 11}})
        self.transport.queue(status_code=200, body=closed(11, "session-9"))
        result = self.sdk.records.close("session-9")
        self.assertEqual(self.sent(0), {"method": "GET", "path": f"/api/v1/records/{RECORD_TYPE}/session-9", "body": None})
        self.assertEqual(self.sent(1)["body"], {"lastSeq": 11})
        self.assertEqual(result["lastEntry"], 12)

    def test_refuses_before_closing_when_no_last_entry_is_known(self) -> None:
        self.transport.queue(status_code=200, body={"success": True, "data": {"recordType": RECORD_TYPE, "entityId": "session-0", "lastSeq": None}})
        with self.assertRaises(PacSpaceError) as caught:
            self.sdk.records.close("session-0")
        self.assertEqual(
            caught.exception.message,
            "records.close found no entry on this record. Pass last_entry, the number of its last entry, counted from 1.",
        )
        self.assertEqual([c["method"] for c in self.transport.calls], ["GET"])
        with self.assertRaises(PacSpaceError) as caught:
            self.sdk.records.close("session-0", last_entry=0)
        self.assertTrue(caught.exception.message.startswith("last_entry is 0. Entries count from 1"))
        self.assertEqual(len(self.transport.calls), 1)

    def test_passes_the_api_refusal_through_with_its_code(self) -> None:
        sentence = "Entries are still arriving for this record. Close it after the last one."
        self.transport.queue(status_code=409, body={"success": False, "error": {"code": "RECORD_CLOSE_SEQ_MISMATCH", "message": sentence}})
        with self.assertRaises(PacSpaceError) as caught:
            self.sdk.records.close("session-1", last_entry=2)
        self.assertEqual((caught.exception.code, caught.exception.message), ("RECORD_CLOSE_SEQ_MISMATCH", sentence))

    def test_closes_an_encrypted_record_by_its_wire_id_after_the_last_entry_written_to_it(self) -> None:
        api = FakeEncryptedApi()
        api.add_workspace("pk_test_A.SECRET", "cfixtureworkspacea0000001")
        seqs = iter(range(100))
        closes: List[Dict[str, Any]] = []

        def transport(method: str, url: str, headers: Dict[str, str], body: Optional[str], timeout_ms: int) -> TransportResponse:
            path = urlparse(url).path
            if path.endswith("/close"):
                closes.append({"url": url, "body": body})
                answer = closed(json.loads(body or "{}")["lastSeq"], unquote(path.split("/")[5]))
                return TransportResponse(status_code=200, headers={}, body=json.dumps(answer).encode("utf-8"))
            response = api(method, url, headers, body, timeout_ms)
            if not path.endswith("/transitions"):
                return response
            parsed = json.loads(response.body)
            parsed["data"]["seq"] = next(seqs)
            return TransportResponse(status_code=response.status_code, headers=response.headers, body=json.dumps(parsed).encode("utf-8"))

        a = PacSpace("pk_test_A.SECRET", base_url="https://api.test", max_retries=0, transport=transport, records={"secret": VECTOR_SECRET, "pin_store": memory_pin_store()})
        a.records.identity.register()
        first = a.records.emit(**entry())
        a.records.emit(**entry())
        wire = a.records.wire_id("session-1")
        self.assertEqual(first["wireRecordId"], wire)
        result = a.records.close("session-1")
        self.assertEqual(closes[-1]["url"], f"https://api.test/api/v1/records/{RECORD_TYPE}/{wire}/close")
        self.assertEqual(json.loads(closes[-1]["body"]), {"lastSeq": 1})
        self.assertNotIn("session-1", closes[-1]["body"])
        self.assertEqual(
            {k: result[k] for k in ("recordId", "wireRecordId", "entityId", "lastEntry", "encrypted")},
            {"recordId": "session-1", "wireRecordId": wire, "entityId": wire, "lastEntry": 2, "encrypted": True},
        )


class RecordClosedWebhookTest(unittest.TestCase):
    def test_is_a_known_event_with_its_payload_typed(self) -> None:
        self.assertIn("record.closed", KnownWebhookEventType.__args__)
        self.assertEqual(
            set(RecordClosedPayload.__annotations__),
            {"recordType", "entityId", "closedBy", "lastSeq", "lastSeal", "closedOn"},
        )


if __name__ == "__main__":
    unittest.main()
