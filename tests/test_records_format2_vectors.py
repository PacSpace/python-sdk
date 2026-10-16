"""Format 2 (card 10, F1) against records-format2-v1.json: record hash v3,
the seal input, record-disclosure/v2 and a record hash v3 history.

The vectors are a byte-for-byte copy of the shared file, which the
generator's ``--check`` compares. Every case is asserted. A v3 history's
``verified`` is TypeScript's whole check; Python's ``sealsVerified`` covers
the seals only, and is asserted against it. keccak256 is pinned by known
answers and by every slot-encoding record item (its v1 record hash, seal,
seal tag and item hash), read from the shared vector file in this repository.
"""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path
from typing import Any, Dict

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from pacspace_sdk import records_encryption as R
from pacspace_sdk.encrypted_records import disclosure_digest_fragment, read_link_fragment
from pacspace_sdk.keccak import keccak256
from pacspace_sdk.record_disclosure import (
    RECORD_SLOT_WHOLE_V3,
    commit_record_content_v3,
    compute_record_disclosure_digest,
    compute_record_hash_v3,
    member_tag_v3,
    open_record_entry_v3,
    validate_record_items_v3,
    verify_record_disclosure_v1,
)
from pacspace_sdk.record_seal import (
    compute_record_hash_v1,
    compute_seal_v1,
    compute_slot_item_hash_v1,
    seal_input_hash,
    seal_tag_of_v1,
    split_word_v1,
)

VECTORS = Path(__file__).parent / "vectors"
FILE = json.loads((VECTORS / "records-format2-v1.json").read_text(encoding="utf-8"))
CASES = {c["id"]: c for c in FILE["cases"]}
SLOT_ENCODING = VECTORS / "slot-encoding-v1.json"

# The coverage gate reads these literal ids (scripts/records/check-vector-coverage.mjs).
CASE_IDS = [
    "MT-01", "MT-02", "MT-03",
    "H3-01", "H3-02", "H3-03", "H3-04",
    "HR-01", "HR-02", "HR-03", "HR-04", "HR-05", "HR-06", "HR-07",
    "SI-01", "SI-02", "SI-03",
    "O3-01", "O3-02", "O3-03", "O3-04", "O3-05", "O3-06",
    "HB3-01", "HB3-02", "HB3-03", "HB3-04", "HB3-05", "HB3-06", "HB3-07", "HB3-08",
    "CF3-01",
    "RD2-01", "RD2-02", "RD2-03", "RD2-04", "RD2-05", "RD2-06", "RD2-07",
    "CT2-01", "CT2-02", "CT2-03",
    "LF-01", "LF-02", "LF-03", "LF-04", "LF-05", "LF-06", "LF-07", "LF-08", "LF-09", "LF-10", "LF-11", "LF-12",
]


class _AesGcm:
    def encrypt(self, key: bytes, iv: bytes, plaintext: bytes, aad: bytes) -> bytes:
        return AESGCM(key).encrypt(iv, plaintext, aad)

    def decrypt(self, key: bytes, iv: bytes, sealed: bytes, aad: bytes) -> bytes:
        return AESGCM(key).decrypt(iv, sealed, aad)


AEAD = _AesGcm()


def _rk(hex_text: str) -> R.RecordKey:
    return R.record_key_from_bytes(bytes.fromhex(hex_text))


class Keccak256Test(unittest.TestCase):
    def test_known_answers(self) -> None:
        self.assertEqual(keccak256(b"").hex(), "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
        self.assertEqual(keccak256(b"abc").hex(), "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45")
        self.assertEqual(
            keccak256(b"The quick brown fox jumps over the lazy dog").hex(),
            "4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15",
        )

    def test_every_slot_encoding_record_item(self) -> None:
        # A seal's input is exactly one 136-byte block and an item hash's is longer than one.
        cases = json.loads(SLOT_ENCODING.read_text(encoding="utf-8"))["cases"]
        checked = 0
        for c in cases:
            expected = c.get("expected")
            for item in expected.get("items", []) if isinstance(expected, dict) else []:
                if "seal" not in item:
                    continue
                with self.subTest(case=c["id"], seq=item.get("seq")):
                    self.assertEqual(compute_record_hash_v1(item["recordContent"]), item["recordHash"])
                    state96, seal_tag = split_word_v1(item["newWord"])
                    self.assertEqual(state96, int(item["state96"], 16))
                    seal = compute_seal_v1(
                        item["layoutId"], item["layoutVersion"], item["layoutDigest"], state96, item["recordHash"], item["recordOpening"]
                    )
                    self.assertEqual(seal, item["seal"])
                    self.assertEqual(seal_tag_of_v1(seal), item["sealTag"])
                    self.assertEqual(seal_tag, item["sealTag"])
                    self.assertEqual(
                        compute_slot_item_hash_v1(item["recordKey"], item["seq"], item["previousWord"], item["newWord"], seal),
                        item["itemHash"],
                    )
                checked += 1
        self.assertGreaterEqual(checked, 19)


class RecordsFormat2VectorsTest(unittest.TestCase):
    maxDiff = None

    def test_the_case_list_is_the_file(self) -> None:
        self.assertEqual(FILE["caseCount"], len(FILE["cases"]))
        self.assertEqual(sorted(CASE_IDS), sorted(CASES))

    def test_the_constants_equal_the_file(self) -> None:
        self.assertEqual(FILE["constants"]["slotWhole"], RECORD_SLOT_WHOLE_V3)
        self.assertEqual(
            FILE["constants"]["labels"],
            {
                "member": "pacspace:record-member:v3",
                "salt": "pacspace:record-leaf-salt:v3",
                "leaf": "pacspace:record-leaf:v3",
                "record": "pacspace:record:v3",
                "sealInput": "pacspace:record-hash-version:v1",
                "disclosureDigest": "pacspace:record-disclosure-digest:v2",
            },
        )

    def test_every_case(self) -> None:
        for case_id in CASE_IDS:
            with self.subTest(case_id):
                self._check(copy.deepcopy(CASES[case_id]))

    def _check(self, c: Dict[str, Any]) -> None:
        kind, i, e = c["kind"], c["input"], c["expected"]
        if kind == "member-tag":
            self.assertEqual(member_tag_v3(i["key"]), e["memberTag"])
        elif kind == "record-hash-v3":
            self.assertEqual(commit_record_content_v3(i["content"], i["saltKey"]), e)
        elif kind == "record-items-reject":
            self.assertEqual(validate_record_items_v3(i["items"]), e["valid"])
            if e["valid"]:
                self.assertEqual(compute_record_hash_v3(i["items"]), e["recordHash"])
            else:
                with self.assertRaises(ValueError):
                    compute_record_hash_v3(i["items"])
        elif kind == "seal-input":
            self.assertEqual(seal_input_hash(i["version"], i["recordHash"]), e["sealInput"])
        elif kind == "open-v3":
            result = open_record_entry_v3(i["entry"], every=i["every"])
            self.assertEqual(result, e)
        elif kind in ("bundle-v3-format2", "copy-file-format2"):
            if kind == "bundle-v3-format2":
                result = R.open_record_history_v3(AEAD, i["bundle"], _rk(i["recordKey"]), i.get("expect"))
            else:
                result = R.open_record_copy_v1(AEAD, i["file"], i.get("expect"))
            if not e["ok"]:
                got = {"ok": result["ok"], "code": result.get("code")}
                if "seq" in e:
                    got["seq"] = result.get("seq")
                self.assertEqual(got, e)
                return
            self.assertEqual(result["opened"], e["opened"])
            if "refused" in e:
                self.assertEqual(result["refused"], e["refused"])
            self.assertIs(result["sealsVerified"], e["verified"])
        elif kind == "disclosure-v2":
            result = verify_record_disclosure_v1(i["form"], i["disclosure"])
            self.assertEqual(result["chainCheck"], "not-checked")
            if not e["ok"]:
                self.assertEqual({k: result[k] for k in ("ok", "code", "seq", "reason")}, e)
                return
            self.assertEqual(compute_record_disclosure_digest(i["disclosure"]), e["digest"])
            batch = {fe["seq"]: fe["batchId"] for fe in i["form"]["entries"]}
            got = {
                "ok": result["ok"],
                "recordHashVersion": i["disclosure"]["recordHashVersion"],
                "entries": [
                    {"seq": x["seq"], "batchId": batch[x["seq"]], "fields": x["fields"], "withheld": x["withheld"], "content": x["content"]}
                    for x in result["entries"]
                ],
                "digest": i["disclosure"]["digest"],
            }
            self.assertEqual(got, e)
        elif kind == "content-tag-v2":
            tag_key = R.derive_content_tag_key(R.b64url_decode(i["ikm"]), i["version"])
            tag = R.content_tag_v2(tag_key, i["recordType"], i["wireRecordId"], i["content"], i["lifecycle"])
            id_key = R.derive_records_id_key(R.b64url_decode(i["ikmV1"]))
            got = {
                "contentTagKey": R.export_key_bytes(tag_key).hex(),
                "contentTag": tag,
                "defaultWireReferenceId": R.wire_reference_id(id_key, tag),
            }
            self.assertEqual(got, e)
        elif kind == "link-fragment-v2":
            got = read_link_fragment(i["fragment"])
            if got is None or e is None:
                self.assertEqual(got, e)
            elif got["kind"] == "key":
                self.assertEqual({"kind": "key", "keyHex": got["key"].hex()}, e)
            else:
                self.assertEqual(got, e)
                self.assertEqual("#" + disclosure_digest_fragment(got["digest"]), i["fragment"])
        else:
            self.fail(f"unknown kind {kind}")


class Format2HistoryTest(unittest.TestCase):
    def test_a_v2_history_has_no_seal_answer_and_refuses_a_stated_version(self) -> None:
        enc = json.loads((VECTORS / "records-encryption-v1.json").read_text(encoding="utf-8"))
        c = next(x for x in enc["cases"] if x["id"] == "HB-01")
        result = R.open_record_history_v3(AEAD, c["input"]["bundle"], _rk(c["input"]["recordKey"]), c["input"].get("expect"))
        self.assertIs(result["ok"], True)
        self.assertIsNone(result["sealsVerified"])
        stated = copy.deepcopy(c["input"]["bundle"])
        stated["receipts"][0]["recordHashVersion"] = 2
        result = R.open_record_history_v3(AEAD, stated, _rk(c["input"]["recordKey"]), c["input"].get("expect"))
        self.assertEqual((result["ok"], result["code"]), (False, "RECORD_HISTORY_RECEIPT_FORM"))

    def test_a_v6_row_whose_items_do_not_open_fails_the_seals(self) -> None:
        c = CASES["HB3-01"]
        bundle = copy.deepcopy(c["input"]["bundle"])
        row = next(r for r in bundle["receipts"] if r["schema"] == "semantic-receipt/v6")
        row["revealed"] = row["revealed"][:-1]
        result = R.open_record_history_v3(AEAD, bundle, _rk(c["input"]["recordKey"]), c["input"].get("expect"))
        self.assertIs(result["ok"], True)
        self.assertIs(result["sealsVerified"], False)

    def test_a_v2_disclosure_against_a_v2_form_and_a_v1_against_a_v3_form_are_refused(self) -> None:
        c = CASES["RD2-01"]
        form = {k: v for k, v in c["input"]["form"].items() if k != "recordHashVersion"}
        result = verify_record_disclosure_v1(form, c["input"]["disclosure"])
        self.assertEqual(result["code"], "RECORD_HASH_VERSION_MISMATCH")
        self.assertEqual(result["reason"], "This shared record's format doesn't match the record on the ledger.")


if __name__ == "__main__":
    unittest.main()
