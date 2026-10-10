"""L2d3: the Python SDK's encrypted records (ADR 0015; design-v1, "L2d2 and
L2d3, the SDKs"), the mirror of the TypeScript spec, end to end against an
in-memory fake of the routes. The read path runs on the door proof's sandbox
history, sealed under the published vector secret (DK-01 version 1, DK-02
version 2; L2-13). Python reads up to each entry's record hash; the seals are
the TypeScript SDK's and the checker's."""

from __future__ import annotations

import base64
import copy
import json
import os
import stat
import tempfile
import unittest
from typing import Any, Dict, List, Optional

from records_encrypted_support import (
    VECTOR_KEYRING,
    VECTOR_KEYRING_V1,
    FakeEncryptedApi,
    admission_cases,
    disclosure_link,
    door_proof_bundle,
)

from pacspace_sdk import (
    RECORDS_ENCRYPTION_WORDS,
    PacSpace,
    PacSpaceError,
    file_pin_store,
    generate_workspace_secret,
    memory_pin_store,
    next_workspace_secret,
)
from pacspace_sdk import records_asymmetric as A
from pacspace_sdk import records_encryption as R
from pacspace_sdk.encrypted_records import AEAD
from pacspace_sdk.record_disclosure import commit_record_content_v2
from pacspace_sdk.records_admission import admit_record_entry

RECORD_TYPE = "machine-action-record"
KEY_A, KEY_B, KEY_C = "pk_test_A.SECRET", "pk_test_B.SECRET", "pk_test_C.SECRET"


def setup() -> FakeEncryptedApi:
    api = FakeEncryptedApi()
    api.add_workspace(KEY_A, "ws_a")
    api.add_workspace(KEY_B, "ws_b")
    api.add_workspace(KEY_C, "ws_c")
    return api


def client(api: FakeEncryptedApi, api_key: str, secret: Optional[str] = None, pin_store: Any = None) -> PacSpace:
    records = {"secret": secret, "pin_store": pin_store or memory_pin_store()} if secret is not None else None
    return PacSpace(api_key, base_url="https://api.test", max_retries=0, transport=api, records=records)


def ring_of(text: str) -> R.RecordsKeyring:
    return R.RecordsKeyring.from_provider(R.local_records_key_provider(text))


def content(title: str) -> Dict[str, Any]:
    return {
        "title": title,
        "occurred_at": "2026-10-05T12:00:00Z",
        "actor_id": "agent-7",
        "payloads": [{"alg": "sha-256", "digest": "a" * 64, "byteLength": "10"}],
    }


def with_fixture(secret: str = VECTOR_KEYRING_V1):
    api = setup()
    bundle = door_proof_bundle()
    api.serve_history("ws_a", bundle)
    a = client(api, KEY_A, secret)
    a.records.identity.register()
    return api, bundle, a


def posts(api: FakeEncryptedApi) -> List[Dict[str, Any]]:
    return [r for r in api.requests if r["url"].endswith("/transitions")]


class WorkspaceSecretTest(unittest.TestCase):
    def test_generate_draws_version_1_and_next_adds_exactly_the_next(self) -> None:
        first = generate_workspace_secret()
        parsed = R.parse_records_keyring_file(first)
        self.assertEqual([v for v, _ in parsed["secrets"]], [1])
        following = R.parse_records_keyring_file(next_workspace_secret(first))
        self.assertEqual([v for v, _ in following["secrets"]], [1, 2])
        self.assertEqual(following["secrets"][0][1], parsed["secrets"][0][1])
        with self.assertRaises(PacSpaceError) as caught:
            next_workspace_secret("not a keyring")
        self.assertEqual(str(caught.exception), RECORDS_ENCRYPTION_WORDS["RECORDS_SECRET_INVALID"])

    def test_a_malformed_secret_is_refused_with_w24_before_any_request(self) -> None:
        api = setup()
        a = client(api, KEY_A, '{"schema":"pacspace-workspace-secret/v1","secrets":[]}')
        with self.assertRaises(PacSpaceError) as caught:
            a.records.emit(record="r-1", **content("x"))
        self.assertEqual(caught.exception.code, "RECORDS_SECRET_INVALID")
        self.assertEqual(caught.exception.message, RECORDS_ENCRYPTION_WORDS["RECORDS_SECRET_INVALID"])
        self.assertEqual(api.requests, [])

    def test_wire_ids_need_a_secret_and_without_one_emit_writes_plaintext(self) -> None:
        api = setup()
        a = client(api, KEY_A)
        with self.assertRaises(PacSpaceError) as caught:
            a.records.wire_id("r-1")
        self.assertEqual(caught.exception.code, "RECORDS_SECRET_REQUIRED")
        a.records.emit(record="r-1", **content("Plain"))
        sent = json.loads(api.requests[0]["body"])
        self.assertEqual(api.requests[0]["url"], f"https://api.test/api/v1/records/{RECORD_TYPE}/r-1/transitions")
        self.assertEqual(sent["content"]["title"], "Plain")
        self.assertNotIn("envelope", sent)


class EncryptedEmitTest(unittest.TestCase):
    def test_encrypts_by_default_with_wire_ids_the_v2_hash_the_tag_and_an_envelope(self) -> None:
        api = setup()
        a = client(api, KEY_A, VECTOR_KEYRING)
        a.records.identity.register()
        api.requests.clear()
        out = a.records.emit(record="invoice-77", idempotency_key="ref-1", **content("Encrypted entry"))

        ring = ring_of(VECTOR_KEYRING)
        wire = R.wire_record_id(ring.id_key, RECORD_TYPE, "invoice-77")
        wire_ref = R.wire_reference_id(ring.id_key, "ref-1")
        self.assertEqual(
            {k: out[k] for k in ("recordId", "wireRecordId", "wireReferenceId", "referenceId", "encrypted", "entityId")},
            {"recordId": "invoice-77", "wireRecordId": wire, "wireReferenceId": wire_ref, "referenceId": "ref-1", "encrypted": True, "entityId": wire},
        )
        self.assertEqual(len(api.requests), 1)
        self.assertEqual(api.requests[0]["url"], f"https://api.test/api/v1/records/{RECORD_TYPE}/{wire}/transitions")
        body = json.loads(api.requests[0]["body"])
        self.assertEqual(sorted(body), ["contentTag", "envelope", "lifecycle", "recordHash", "referenceId"])
        self.assertEqual(body["referenceId"], wire_ref)
        self.assertEqual(body["envelope"]["kid"], ring.by_version(2).id)
        opened = R.open_record_entry_envelope(AEAD, body["envelope"], RECORD_TYPE, wire, record_key=R.record_key_of(ring.by_version(2), wire))
        self.assertTrue(opened["ok"])
        self.assertEqual(opened["content"]["title"], "Encrypted entry")
        self.assertEqual(commit_record_content_v2(opened["content"], opened["saltKey"])["recordHash"], body["recordHash"])

    def test_with_no_reference_id_the_content_tag_makes_it_so_a_repeat_is_a_replay(self) -> None:
        api = setup()
        a = client(api, KEY_A, VECTOR_KEYRING)
        a.records.identity.register()
        api.requests.clear()
        a.records.emit(record="r-2", **content("Same"))
        a.records.emit(record="r-2", **content("Same"))
        first, second = (json.loads(r["body"]) for r in api.requests)
        self.assertRegex(first["referenceId"], r"^[A-Za-z0-9_-]{22}$")
        self.assertEqual(second["referenceId"], first["referenceId"])
        self.assertNotEqual(second["recordHash"], first["recordHash"])

    def test_writes_under_the_version_the_api_names_and_retries_once(self) -> None:
        api = setup()
        v1 = client(api, KEY_A, VECTOR_KEYRING_V1)
        v1.records.identity.register()
        v1.records.emit(record="r-3", **content("Under version 1"))
        both = client(api, KEY_A, VECTOR_KEYRING)
        both.records.identity.register()
        api.requests.clear()
        both.records.emit(record="r-3", **content("Still version 1"))
        ring = ring_of(VECTOR_KEYRING)
        self.assertEqual([json.loads(r["body"])["envelope"]["kid"] for r in posts(api)], [ring.by_version(2).id, ring.by_version(1).id])
        api.requests.clear()
        both.records.emit(record="r-3", **content("Cached version"))
        self.assertEqual(len(posts(api)), 1)

    def test_a_version_this_secret_does_not_hold_is_named(self) -> None:
        api = setup()
        owner = client(api, KEY_A, VECTOR_KEYRING)
        owner.records.identity.register()
        owner.records.emit(record="r-4", **content("Under version 2"))
        only_v1 = client(api, KEY_A, VECTOR_KEYRING_V1)
        api.requests.clear()
        with self.assertRaises(PacSpaceError) as caught:
            only_v1.records.emit(record="r-4", **content("x"))
        self.assertEqual(caught.exception.code, "RECORDS_VERSION_NOT_HELD")
        self.assertEqual(caught.exception.message, "This record is under version 2, which this workspace secret doesn't hold.")
        self.assertEqual(len(posts(api)), 1)

    def test_runs_intake_admission_here_before_anything_is_sent(self) -> None:
        api = setup()
        a = client(api, KEY_A, VECTOR_KEYRING)
        with self.assertRaises(PacSpaceError) as caught:
            a.records.emit(record="r-5", **{**content("Unknown state")}, lifecycle="no-such-state")
        self.assertEqual((caught.exception.status_code, caught.exception.code), (400, "RECORD_STATE_UNKNOWN"))
        with self.assertRaises(PacSpaceError) as caught:
            a.records.emit(record="r-5", **{**content("No payloads"), "payloads": []})
        self.assertEqual(caught.exception.code, "RECORD_PAYLOADS_REQUIRED")
        self.assertEqual(api.requests, [])

    def test_encrypt_false_writes_plaintext_for_a_record_started_in_plaintext(self) -> None:
        api = setup()
        a = client(api, KEY_A, VECTOR_KEYRING)
        a.records.emit(record="old-1", encrypt=False, **content("Plain again"))
        self.assertIn("/old-1/transitions", api.requests[0]["url"])
        self.assertEqual(json.loads(api.requests[0]["body"])["content"]["title"], "Plain again")

    def test_an_entry_too_large_is_refused_with_intakes_sentence(self) -> None:
        api = setup()
        a = client(api, KEY_A, VECTOR_KEYRING)
        with self.assertRaises(PacSpaceError) as caught:
            a.records.emit(record="r-6", note="x" * 48000, **content("Large"))
        self.assertEqual((caught.exception.status_code, caught.exception.code), (413, "RECORD_ENTRY_TOO_LARGE"))
        self.assertEqual(api.requests, [])


class AdmissionTest(unittest.TestCase):
    """The checks intake makes, with its codes and messages (shared
    admitRecordEntryV1), for what the SDK sends: a lifecycle and content."""

    BASE = {"title": "T", "occurredAt": "2026-10-05T12:00:00Z", "actorId": "a", "payloads": [{"alg": "sha-256", "digest": "a" * 64, "byteLength": "1"}]}

    def test_a_good_entry_is_admitted_and_a_type_with_no_layout_is_left_to_intake(self) -> None:
        self.assertIsNone(admit_record_entry(RECORD_TYPE, "recorded", dict(self.BASE)))
        self.assertIsNone(admit_record_entry("no-such-type", "anything", {}))

    def test_each_refusal_carries_intakes_code_and_message(self) -> None:
        cases = [
            ("recorded", {k: v for k, v in self.BASE.items() if k != "actorId"}, ("RECORD_CONTENT_INVALID", "content.actorId is required by record-content/machine-action-record/v1")),
            ("recorded", {**self.BASE, "payloads": []}, ("RECORD_PAYLOADS_REQUIRED", "content.payloads must carry at least 1 payload-ref/v1")),
            ("recorded", {**self.BASE, "seq": 1}, ("RECORD_CONTENT_INVALID", "content.seq is PacSpace bookkeeping and is never part of a sealed record")),
            ("recorded", {**self.BASE, "title": "x" * 1000}, ("RECORD_TITLE_TOO_LONG", None)),
            ("recorded", {**self.BASE, "payloads": [{"alg": "md5", "digest": "a" * 64, "byteLength": "1"}]}, ("RECORD_PAYLOAD_ALG_UNSUPPORTED", "payload alg is not supported; use one of sha-256, hmac-sha-256")),
            ("no-such-state", dict(self.BASE), ("RECORD_STATE_UNKNOWN", "lifecycle=no-such-state is not in the layout")),
        ]
        for lifecycle, entry, (code, message) in cases:
            with self.subTest(code=code):
                refused = admit_record_entry(RECORD_TYPE, lifecycle, entry)
                self.assertIsNotNone(refused)
                self.assertEqual(refused[0], code)
                if message is not None:
                    self.assertEqual(refused[1], message)

    def test_answers_every_shared_admission_case_as_the_typescript_sdk_does(self) -> None:
        cases = admission_cases()
        self.assertGreater(len(cases), 500)
        for case, content in cases:
            with self.subTest(case=case["name"]):
                refused = admit_record_entry(case["recordType"], case["lifecycle"], content)
                expected = case["refused"]
                self.assertEqual(None if refused is None else {"code": refused[0], "message": refused[1]}, expected)


class EncryptedReadTest(unittest.TestCase):
    def test_opens_the_sandbox_history_with_the_vector_secret(self) -> None:
        api, bundle, a = with_fixture()
        api.requests.clear()
        history = a.records.history(None, wire_record_id=bundle["entityId"])
        self.assertEqual([e["entry"] for e in history["opened"]], [1, 2, 3])
        self.assertEqual(history["opened"][0]["content"]["title"], "Encrypted door proof")
        self.assertEqual({k for e in history["opened"] for k in e}, {"entry", "recordHash", "content"})
        self.assertEqual(set(a.records.receipt(None, 1, wire_record_id=bundle["entityId"])["opened"]), {"entry", "recordHash", "content"})
        self.assertEqual(api.requests[0]["headers"]["x-pacspace-records-encryption"], "1")
        both = client(api, KEY_A, VECTOR_KEYRING)
        self.assertEqual(len(both.records.bundle(None, wire_record_id=bundle["entityId"])["opened"]), 3)

    def test_opens_one_receipt(self) -> None:
        _, bundle, a = with_fixture()
        receipt = a.records.receipt(None, 2, wire_record_id=bundle["entityId"])
        self.assertEqual(receipt["opened"]["entry"], 2)
        self.assertEqual(receipt["opened"]["content"]["title"], "Encrypted door proof corrected")

    def test_a_history_served_for_another_record_is_refused(self) -> None:
        api = setup()
        a = client(api, KEY_A, VECTOR_KEYRING_V1)
        a.records.identity.register()
        asked = R.wire_record_id(ring_of(VECTOR_KEYRING_V1).id_key, RECORD_TYPE, "asked-for")
        api.serve_history("ws_a", door_proof_bundle(), asked)
        with self.assertRaises(PacSpaceError) as caught:
            a.records.history("asked-for")
        self.assertEqual(caught.exception.code, "RECORDS_HISTORY_OTHER_RECORD")
        self.assertEqual(caught.exception.message, RECORDS_ENCRYPTION_WORDS["RECORDS_HISTORY_OTHER_RECORD"])

    def test_a_changed_envelope_is_refused_by_entry(self) -> None:
        api = setup()
        bundle = door_proof_bundle()
        receipt = next(r for r in bundle["receipts"] if r["seq"] == 1)
        ct = receipt["envelopes"][0]["ct"]
        receipt["envelopes"][0]["ct"] = ("B" if ct[0] == "A" else "A") + ct[1:]
        api.serve_history("ws_a", bundle)
        a = client(api, KEY_A, VECTOR_KEYRING_V1)
        with self.assertRaises(PacSpaceError) as caught:
            a.records.history(None, wire_record_id=bundle["entityId"])
        self.assertEqual(caught.exception.code, "RECORDS_ENTRY_UNOPENED")
        self.assertEqual(caught.exception.message, "Entry 2 didn't open. The record or the workspace secret is not the one expected.")

    def test_names_the_version_a_secret_does_not_hold(self) -> None:
        api, bundle, _ = with_fixture()
        other = client(api, KEY_A, generate_workspace_secret())
        with self.assertRaises(PacSpaceError) as caught:
            other.records.history(None, wire_record_id=bundle["entityId"])
        self.assertEqual(caught.exception.code, "RECORDS_VERSION_NOT_HELD")
        self.assertEqual(caught.exception.message, "This record is under version 1, which this workspace secret doesn't hold.")

    def test_keeps_a_copy_that_opens_with_its_own_key_and_refuses_a_plaintext_record(self) -> None:
        _, bundle, a = with_fixture()
        kept = a.records.keep_copy(wire_record_id=bundle["entityId"])
        self.assertEqual(kept["schema"], "pacspace-record-copy/v1")
        opened = R.open_record_copy_v1(AEAD, json.loads(kept["bytes"].decode("utf-8")))
        self.assertTrue(opened["ok"])
        self.assertEqual(len([e for e in opened["opened"] if "content" in e]), 3)
        with self.assertRaises(PacSpaceError) as caught:
            a.records.keep_copy("plain-1", encrypted=False)
        self.assertEqual(caught.exception.code, "RECORDS_NOT_ENCRYPTED")

    def test_reads_with_a_grant_and_the_exported_record_key_with_no_secret(self) -> None:
        api, bundle, a = with_fixture()
        rk = a.records.record_key(wire_record_id=bundle["entityId"])
        grant = a.records.grants.create(wire_record_id=bundle["entityId"], kind="BEARER")
        reader = client(api, KEY_C)
        api.requests.clear()
        history = reader.records.history(None, wire_record_id=bundle["entityId"], grant=grant["grant"], record_key=rk)
        self.assertEqual(len(history["opened"]), 3)
        self.assertEqual(api.requests[0]["headers"]["x-pacspace-grant"], grant["grant"])
        self.assertNotIn("grant=", api.requests[0]["url"])


class RefusedAfterRekeyTest(unittest.TestCase):
    """A re-key swaps committed entries only (ADR 0015, N15), so an attempt's
    refused envelope keeps its original version: it is opened with the held
    key its kid names, and one no held key opens is reported as not opened
    while the history is still read (David, 2026-10-05; #630's mirror)."""

    def keys(self, wire: str):
        ring = ring_of(VECTOR_KEYRING)
        return R.record_key_of(ring.by_version(1), wire), R.record_key_of(ring.by_version(2), wire)

    def rekeyed(self):
        bundle = door_proof_bundle()
        v1, v2 = self.keys(bundle["entityId"])
        for receipt in bundle["receipts"]:
            if receipt["schema"] != "semantic-receipt/v4":
                continue
            opened = R.open_record_entry_envelope(AEAD, receipt["envelopes"][0], bundle["recordType"], bundle["entityId"], record_key=v1)
            receipt["envelopes"].append(R.seal_record_entry(AEAD, v2, bundle["recordType"], bundle["entityId"], opened["content"], opened["saltKey"]))
        return bundle, v1, v2

    def refused_of(self, result: Dict[str, Any]) -> List[Dict[str, Any]]:
        self.assertTrue(result["ok"], result)
        return [{"seq": r["seq"], "opened": r["opened"]} for r in result["refused"]]

    def test_before_a_rekey_the_record_key_opens_the_refused_envelope(self) -> None:
        bundle = door_proof_bundle()
        v1, _ = self.keys(bundle["entityId"])
        self.assertEqual(self.refused_of(R.open_record_history_v3(AEAD, bundle, v1)), [{"seq": 3, "opened": True}])

    def test_with_only_the_new_version_the_attempt_is_not_opened(self) -> None:
        bundle, _, v2 = self.rekeyed()
        result = R.open_record_history_v3(AEAD, bundle, v2, {"recordType": bundle["recordType"], "wireRecordId": bundle["entityId"]})
        self.assertEqual(self.refused_of(result), [{"seq": 3, "opened": False}])
        self.assertEqual(len([e for e in result["opened"] if "content" in e]), 3)

    def test_with_the_old_version_held_too_the_attempt_opens_with_the_key_its_kid_names(self) -> None:
        bundle, v1, v2 = self.rekeyed()
        self.assertEqual(self.refused_of(R.open_record_history_v3(AEAD, bundle, v2, record_keys=[v1])), [{"seq": 3, "opened": True}])

    def test_keys_that_arrived_as_bytes_are_tried_and_none_opening_is_not_opened(self) -> None:
        bundle, v1, v2 = self.rekeyed()
        bare2 = R.record_key_from_bytes(R.export_key_bytes(v2))
        bare1 = R.record_key_from_bytes(R.export_key_bytes(v1))
        self.assertEqual(self.refused_of(R.open_record_history_v3(AEAD, bundle, bare2)), [{"seq": 3, "opened": False}])
        self.assertEqual(self.refused_of(R.open_record_history_v3(AEAD, bundle, bare2, record_keys=[bare1])), [{"seq": 3, "opened": True}])

    def test_a_changed_envelope_under_a_held_version_is_still_refused(self) -> None:
        bundle = door_proof_bundle()
        v1, _ = self.keys(bundle["entityId"])
        envelope = bundle["refused"][0]["envelope"]
        envelope["ct"] = ("B" if envelope["ct"][0] == "A" else "A") + envelope["ct"][1:]
        result = R.open_record_history_v3(AEAD, bundle, v1)
        self.assertEqual((result["ok"], result["code"], result.get("seq")), (False, "RECORD_ENVELOPE_AUTH_FAILED", 3))

    def test_a_refused_record_hash_that_does_not_match_is_still_refused(self) -> None:
        bundle = door_proof_bundle()
        v1, _ = self.keys(bundle["entityId"])
        bundle["refused"][0]["recordHash"] = "0x" + "00" * 32
        result = R.open_record_history_v3(AEAD, bundle, v1)
        self.assertEqual((result["ok"], result["code"]), (False, "RECORD_ENTRY_HASH_MISMATCH"))

    def test_a_key_id_from_bytes_must_be_64_hex(self) -> None:
        with self.assertRaises(R.RecordsEncryptionError):
            R.record_key_from_bytes(b"\x01" * 32, "not-hex")
        self.assertEqual(R.record_key_from_bytes(b"\x01" * 32, "a" * 64).records_key_id, "a" * 64)


class PinsHoldersGrantsTest(unittest.TestCase):
    def test_a_grant_to_a_confirmed_workspace_carries_a_wrap_it_reads_with_its_own_secret(self) -> None:
        api, bundle, a = with_fixture()
        c = client(api, KEY_C, generate_workspace_secret())
        code = c.records.identity.register()["code"]
        grant = a.records.grants.create(wire_record_id=bundle["entityId"], kind="TENANT_BOUND", counterparty_workspace_id="ws_c", confirmed_code=code)
        self.assertRegex(grant["readerWrap"]["rkid"], r"^[0-9a-f]{64}$")
        history = c.records.history(None, wire_record_id=bundle["entityId"], grant=grant["grant"])
        self.assertEqual(len(history["opened"]), 3)

    def test_a_substituted_key_is_refused_before_any_wrap_and_a_changed_one_after_the_pin(self) -> None:
        api, bundle, a = with_fixture()
        c = client(api, KEY_C, generate_workspace_secret())
        code = c.records.identity.register()["code"]
        impostor = client(api, KEY_B, generate_workspace_secret())
        impostor.records.identity.register()
        served = api.workspaces[KEY_B]["identity"]
        api.substituted["ws_c"] = {"xwingPublic": served["xwingPublic"], "xwingPublicId": served["xwingPublicId"]}
        api.requests.clear()
        with self.assertRaises(PacSpaceError) as caught:
            a.records.grants.create(wire_record_id=bundle["entityId"], kind="TENANT_BOUND", counterparty_workspace_id="ws_c", confirmed_code=code)
        self.assertEqual(caught.exception.code, "RECORDS_CODE_MISMATCH")
        self.assertEqual(caught.exception.message, RECORDS_ENCRYPTION_WORDS["RECORDS_CODE_MISMATCH"])
        self.assertFalse(any(r["method"] != "GET" for r in api.requests))

        api.substituted.clear()
        a.records.holders.add(workspace_id="ws_c", confirmed_code=code)
        api.substituted["ws_c"] = {"xwingPublic": served["xwingPublic"], "xwingPublicId": served["xwingPublicId"]}
        api.requests.clear()
        with self.assertRaises(PacSpaceError) as caught:
            a.records.grants.create(wire_record_id=bundle["entityId"], kind="TENANT_BOUND", counterparty_workspace_id="ws_c")
        self.assertEqual(caught.exception.code, "RECORDS_PIN_CHANGED")
        self.assertFalse(any(r["method"] != "GET" for r in api.requests))

    def test_asks_for_the_code_when_no_pin_is_held(self) -> None:
        api, bundle, a = with_fixture()
        client(api, KEY_C, generate_workspace_secret()).records.identity.register()
        with self.assertRaises(PacSpaceError) as caught:
            a.records.grants.create(wire_record_id=bundle["entityId"], kind="TENANT_BOUND", counterparty_workspace_id="ws_c")
        self.assertEqual(caught.exception.code, "RECORDS_CODE_REQUIRED")

    def test_a_workspace_holder_confirms_and_reads_and_a_record_holder_confirms_by_opening_an_entry(self) -> None:
        api, bundle, a = with_fixture()
        b = client(api, KEY_B, generate_workspace_secret())
        code = b.records.identity.register()["code"]
        added = a.records.holders.add(workspace_id="ws_b", confirmed_code=code, required=True)
        self.assertEqual(added["wraps"], [{"version": 1, "state": "stored"}])
        a.records.holders.add(workspace_id="ws_b", scope="record", wire_record_id=bundle["entityId"])
        self.assertEqual([r["state"] for r in b.records.holdings.confirm()], ["confirmed", "confirmed"])
        history = b.records.history(None, wire_record_id=bundle["entityId"], holder_for="ws_a")
        self.assertEqual(len(history["opened"]), 3)

    def test_a_wrap_that_does_not_open_is_refused_so_the_writer_is_told(self) -> None:
        api, _, a = with_fixture()
        b = client(api, KEY_B, generate_workspace_secret())
        code = b.records.identity.register()["code"]
        a.records.holders.add(workspace_id="ws_b", confirmed_code=code)
        wrap = api.holders[0]["wraps"][0]["wrap"]
        wrap["ct"] = ("B" if wrap["ct"][0] == "A" else "A") + wrap["ct"][1:]
        self.assertEqual(b.records.holdings.confirm(), [{"holderId": api.holders[0]["holderId"], "version": 1, "state": "refused", "reason": "unopened"}])

    def test_another_identity_than_the_secret_opens_is_refused(self) -> None:
        api, _, _ = with_fixture()
        stranger = client(api, KEY_A, generate_workspace_secret())
        with self.assertRaises(PacSpaceError) as caught:
            stranger.records.identity.register()
        self.assertEqual(caught.exception.code, "RECORDS_IDENTITY_OTHER")

    def test_the_file_pin_store_keeps_pins_readable_by_its_owner_only(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "pins", "pins.json")
            store = file_pin_store(path)
            self.assertIsNone(store.get("ws_b"))
            store.set("ws_b", {"publicKeyId": "c" * 64, "confirmedAt": "2026-10-05T12:00:00.000Z"})
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
            self.assertEqual(file_pin_store(path).get("ws_b")["publicKeyId"], "c" * 64)
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("not pins")
            self.assertIsNone(file_pin_store(path).get("ws_b"))


class RotateAndRekeyTest(unittest.TestCase):
    def test_rotates_to_version_2_registers_it_wraps_it_to_pinned_holders_and_the_seed_under_it(self) -> None:
        api, _, a = with_fixture()
        b = client(api, KEY_B, generate_workspace_secret())
        code = b.records.identity.register()["code"]
        a.records.holders.add(workspace_id="ws_b", confirmed_code=code)
        with self.assertRaises(PacSpaceError) as caught:
            a.records.rotate(next_workspace_secret(VECTOR_KEYRING))
        self.assertEqual(caught.exception.code, "RECORDS_ROTATE_NOT_NEXT")
        rotated = a.records.rotate(VECTOR_KEYRING)
        ring = ring_of(VECTOR_KEYRING)
        self.assertEqual((rotated["version"], rotated["kid"]), (2, ring.by_version(2).id))
        self.assertEqual([(h["workspaceId"], h["wrapped"]) for h in rotated["holders"]], [("ws_b", True)])
        self.assertEqual(api.workspaces[KEY_A]["versions"][2], ring.by_version(2).id)
        self.assertEqual(sorted(w["version"] for w in api.workspaces[KEY_A]["identity"]["seedWraps"]), [1, 2])
        self.assertEqual(sorted(w["version"] for w in api.holders[0]["wraps"]), [1, 2])

    def test_rekeys_latest_first_with_hashes_unchanged_and_grants_rewrapped_and_a_repeat_is_done(self) -> None:
        api, bundle, a = with_fixture()
        b = client(api, KEY_B, generate_workspace_secret())
        a.records.holders.add(workspace_id="ws_b", confirmed_code=b.records.identity.register()["code"])
        c = client(api, KEY_C, generate_workspace_secret())
        code = c.records.identity.register()["code"]
        a.records.grants.create(wire_record_id=bundle["entityId"], kind="TENANT_BOUND", counterparty_workspace_id="ws_c", confirmed_code=code)
        a.records.rotate(VECTOR_KEYRING)
        out = a.records.rekey(wire_record_id=bundle["entityId"], to_version=2)
        self.assertEqual(out["entries"], [{"entry": 3, "state": "swapped"}, {"entry": 2, "state": "swapped"}, {"entry": 1, "state": "swapped"}])
        self.assertEqual(out["grants"], [{"grantId": api.grants[0]["grantId"], "wrapped": True}])

        v2 = R.record_key_of(ring_of(VECTOR_KEYRING).by_version(2), bundle["entityId"])
        swapped = api.rekeyed[f"{RECORD_TYPE}\0{bundle['entityId']}"]
        for receipt in bundle["receipts"]:
            if receipt["schema"] != "semantic-receipt/v4":
                continue
            opened = R.open_record_entry_envelope(AEAD, swapped[receipt["seq"]], RECORD_TYPE, bundle["entityId"], record_key=v2)
            self.assertTrue(opened["ok"])
            self.assertEqual(commit_record_content_v2(opened["content"], opened["saltKey"])["recordHash"], receipt["recordHash"])
        self.assertEqual(len(client(api, KEY_A, VECTOR_KEYRING).records.history(None, wire_record_id=bundle["entityId"])["opened"]), 3)
        b.records.holdings.confirm()
        self.assertEqual(len(b.records.history(None, wire_record_id=bundle["entityId"], holder_for="ws_a")["opened"]), 3)
        self.assertEqual(len(c.records.history(None, wire_record_id=bundle["entityId"], grant=api.grants[0]["token"])["opened"]), 3)
        again = a.records.rekey(wire_record_id=bundle["entityId"], to_version=2)
        self.assertTrue(all(e["state"] == "already" for e in again["entries"]))

    def test_reports_where_a_rekey_stopped(self) -> None:
        api = setup()
        bundle = door_proof_bundle()
        bundle["refused"] = []
        api.serve_history("ws_a", bundle)
        owner = client(api, KEY_A, VECTOR_KEYRING)
        owner.records.identity.register()
        swaps = {"count": 0}

        def fail(method: str, url: str) -> None:
            if url.endswith("/envelope"):
                swaps["count"] += 1
                if swaps["count"] == 2:
                    raise OSError("network")

        api.fail = fail
        with self.assertRaises(PacSpaceError) as caught:
            owner.records.rekey(wire_record_id=bundle["entityId"], to_version=2)
        self.assertEqual(caught.exception.code, "RECORDS_REKEY_STOPPED")
        self.assertEqual(caught.exception.message, "Re-encryption stopped at entry 2. Entries after it are done; run it again to finish.")


class OpenLinkTest(unittest.TestCase):
    def link_setup(self, access_code: Optional[str]):
        api = setup()
        fixture = disclosure_link()
        api.links[fixture["handle"]] = {"form": fixture["form"], "envelope": fixture["envelope"], "accessCode": access_code}
        return api, fixture

    def test_opens_a_link_with_the_key_after_hash_and_the_access_code(self) -> None:
        api, fixture = self.link_setup("K7Q2MX")
        out = client(api, KEY_C).records.open(f"https://app.pacspace.io/c/{fixture['handle']}#{fixture['fragment']}", access_code="K7Q2MX")
        self.assertEqual([e["entry"] for e in out["entries"]], [1, 3])
        self.assertIn({"pointer": "/title", "value": fixture["revealedTitle"]}, out["entries"][0]["fields"])
        self.assertGreater(out["entries"][0]["withheld"], 0)
        self.assertNotIn(fixture["withheldTitle"], json.dumps([e["fields"] for e in out["entries"]]))
        self.assertEqual(out["chainCheck"], "not-checked")
        self.assertTrue(all("#" not in r["url"] and "dk=" not in r["url"] for r in api.requests))

    def test_opens_it_with_this_workspaces_wrap_when_the_link_has_no_key(self) -> None:
        api, fixture = self.link_setup(None)
        with self.assertRaises(PacSpaceError) as caught:
            client(api, KEY_C).records.open(f"https://app.pacspace.io/c/{fixture['handle']}")
        self.assertEqual(caught.exception.code, "RECORDS_LINK_NO_KEY")
        owner = client(api, KEY_A, VECTOR_KEYRING_V1)
        owner.records.identity.register()
        c = client(api, KEY_C, generate_workspace_secret())
        code = c.records.identity.register()["code"]
        owner.records.share_key_wrap(
            wire_record_id="qno1FsvCZIpEt1eZo2BFiA", handle=fixture["handle"], disclosure_key=fixture["fragment"], workspace_id="ws_c", confirmed_code=code
        )
        self.assertEqual(len(c.records.open(f"https://app.pacspace.io/c/{fixture['handle']}")["entries"]), 2)

    def test_a_link_for_another_handle_does_not_open(self) -> None:
        api, fixture = self.link_setup(None)
        api.links["csh1_other"] = {"form": fixture["form"], "envelope": fixture["envelope"], "accessCode": None}
        with self.assertRaises(PacSpaceError) as caught:
            client(api, KEY_C).records.open(f"https://app.pacspace.io/c/csh1_other#{fixture['fragment']}")
        self.assertEqual(caught.exception.code, "DISCLOSURE_ENVELOPE_AUTH_FAILED")


class WordsTest(unittest.TestCase):
    def test_ships_exactly_the_approved_sentences_ascii_only(self) -> None:
        self.assertEqual(len(RECORDS_ENCRYPTION_WORDS), 15)
        for sentence in RECORDS_ENCRYPTION_WORDS.values():
            self.assertRegex(sentence, r"^[\x20-\x7e]+$")
        self.assertEqual(
            RECORDS_ENCRYPTION_WORDS["RECORDS_SECRET_REQUIRED"],
            "Encrypted records need the workspace secret. Pass it as records.secret or records.secretProvider.",
        )


class InterceptionTest(unittest.TestCase):
    """Every encrypted path driven, then every request (URL, headers, body)
    searched for the workspace secrets, the id key, each K_v and W_v, each
    record key, every salt key, the seed, the disclosure key and the
    plaintext, as raw text, hex, base64 and base64url."""

    def test_no_request_carries_a_secret_a_key_a_salt_key_a_seed_or_the_plaintext(self) -> None:
        mark = "Interception plaintext marker 4f1c"
        api, bundle, a = with_fixture()
        c = client(api, KEY_C, generate_workspace_secret())
        code = c.records.identity.register()["code"]
        b = client(api, KEY_B, generate_workspace_secret())
        b_code = b.records.identity.register()["code"]

        a.records.emit(record="interception-1", note=f"{mark} note", **content(mark))
        a.records.history(None, wire_record_id=bundle["entityId"])
        a.records.receipt(None, 1, wire_record_id=bundle["entityId"])
        a.records.holders.add(workspace_id="ws_b", confirmed_code=b_code)
        a.records.holders.add(workspace_id="ws_b", scope="record", wire_record_id=bundle["entityId"])
        b.records.holdings.confirm()
        b.records.history(None, wire_record_id=bundle["entityId"], holder_for="ws_a")
        grant = a.records.grants.create(wire_record_id=bundle["entityId"], kind="TENANT_BOUND", counterparty_workspace_id="ws_c", confirmed_code=code)
        c.records.history(None, wire_record_id=bundle["entityId"], grant=grant["grant"])
        fixture = disclosure_link()
        api.links[fixture["handle"]] = {"form": fixture["form"], "envelope": fixture["envelope"], "accessCode": None}
        a.records.share_key_wrap(wire_record_id=bundle["entityId"], handle=fixture["handle"], disclosure_key=fixture["fragment"], workspace_id="ws_c")
        c.records.open(f"https://app.pacspace.io/c/{fixture['handle']}")
        a.records.rotate(VECTOR_KEYRING)
        a.records.rekey(wire_record_id=bundle["entityId"], to_version=2)

        ring = ring_of(VECTOR_KEYRING)
        secrets: List[bytes] = [s for _, s in R.parse_records_keyring_file(VECTOR_KEYRING)["secrets"]]
        secrets.append(R.export_key_bytes(ring.id_key))
        for v in ring.versions:
            secrets += [R.export_key_bytes(ring.by_version(v)), R.export_key_bytes(ring.wrap_key(v))]
        emitted_wire = R.wire_record_id(ring.id_key, RECORD_TYPE, "interception-1")
        for wire in (bundle["entityId"], emitted_wire):
            for v in ring.versions:
                secrets.append(R.export_key_bytes(R.record_key_of(ring.by_version(v), wire)))
        salt_keys: List[str] = []
        v1_key = R.record_key_of(ring.by_version(1), bundle["entityId"])
        for receipt in bundle["receipts"]:
            if receipt.get("envelopes"):
                opened = R.open_record_entry_envelope(AEAD, receipt["envelopes"][0], RECORD_TYPE, bundle["entityId"], record_key=v1_key)
                if opened["ok"]:
                    salt_keys.append(opened["saltKey"])
        emitted = api.writes[f"{RECORD_TYPE}\0{emitted_wire}"][0]["body"]
        opened_emit = R.open_record_entry_envelope(AEAD, emitted["envelope"], RECORD_TYPE, emitted_wire, record_key=R.record_key_of(ring.by_version(1), emitted_wire))
        self.assertTrue(opened_emit["ok"])
        salt_keys.append(opened_emit["saltKey"])
        identity = api.workspaces[KEY_A]["identity"]
        seeds = 0
        for w in identity["seedWraps"]:
            seed = A.open_seed_wrap(w["wrap"], identity["xwingPublicId"], keyring=ring)
            if seed["ok"]:
                secrets.append(A.export_workspace_seed_bytes(seed["seed"]))
                seeds += 1
        self.assertEqual(seeds, 2)
        secrets.append(base64.urlsafe_b64decode(fixture["fragment"][3:] + "="))

        needles = set()
        for data in secrets:
            needles.add(data.hex())
            needles.add(base64.b64encode(data).decode("ascii"))
            needles.add(base64.urlsafe_b64encode(data).decode("ascii").rstrip("="))
        for salt in salt_keys:
            needles.add(salt[2:] if salt.startswith("0x") else salt)
        needles.add(mark)
        needles.add("Encrypted door proof")
        self.assertGreaterEqual(len(salt_keys), 4)
        self.assertGreaterEqual(len(secrets), 13)

        seen = [f"{r['method']} {r['url']}\n{json.dumps(r['headers'])}\n{r['body']}".lower() for r in api.requests]
        for needle in needles:
            found = next((text for text in seen if needle.lower() in text), None)
            self.assertIsNone(found, f"a request carries {needle[:6]}...")
        self.assertGreater(len(api.requests), 30)


if __name__ == "__main__":
    unittest.main()
