"""Level 2's symmetric layer against records-encryption-v1.json (L2a1).

The symmetric layer takes AES-256-GCM as an ``aead`` (it imports only the
standard library); these tests pass one built on ``cryptography``
(tests/requirements-test.txt). The vectors are a byte-for-byte copy of the
shared file, which the generator's ``--check`` compares. Python opens a
history up to each entry's record hash; the cases that need the bundle
digest (keccak256) or the receipt-form rule (the layout's words) are the
TypeScript verifier's and the checker's, and are listed below by id.
"""

from __future__ import annotations

import copy
import json
import os
import unittest
from pathlib import Path
from typing import Any, Dict

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from pacspace_sdk import records_encryption as R
from pacspace_sdk.record_disclosure import canonicalize_jcs, commit_record_content_v2

VECTORS = Path(__file__).parent / "vectors"
FILE = json.loads((VECTORS / "records-encryption-v1.json").read_text(encoding="utf-8"))
CASES = {c["id"]: c for c in FILE["cases"]}

CASE_IDS = [
    "DK-01", "DK-02", "DK-03",
    "WI-01", "WI-02", "WI-03", "WI-04", "WR-01", "WR-02", "CT-01", "CT-02", "CT-03",
    "EN-01", "EN-02", "PD-01", "PD-02", "PD-03", "PD-04", "PD-05",
    "EX-01", "EX-02", "EX-03", "EX-04", "EX-05", "EX-06", "EX-07", "EX-08", "EX-09", "EX-10",
    "EX-11", "EX-12", "EX-13", "EX-14", "EX-15", "EX-16", "EX-17", "EX-18", "EX-19", "EX-20",
    "BC-01", "BC-02", "BC-03",
    "RM-01", "RM-02", "RM-03", "RM-04", "RM-05", "RM-06",
    "KR-01", "KR-02", "KR-03", "KR-04", "KR-05", "KR-06", "KR-07", "KR-08", "KR-09", "KR-10",
    "RC-01", "RC-02", "RC-03", "RC-04", "RC-05",
    "HB-01", "HB-03", "HB-05", "HB-06", "HB-07",
    "CF-01", "CF-02", "CF-03", "CF-04",
]
# The bundle digest (keccak256) and the receipt-form rule (the layout's words) are not Python's.
OUT_OF_SCOPE = {"HB-02": "RECORD_HISTORY_RECEIPT_FORM", "HB-04": "RECORD_HISTORY_DIGEST", "CF-05": "RECORD_HISTORY_DIGEST"}


class _AesGcm:
    def encrypt(self, key: bytes, iv: bytes, plaintext: bytes, aad: bytes) -> bytes:
        return AESGCM(key).encrypt(iv, plaintext, aad)

    def decrypt(self, key: bytes, iv: bytes, sealed: bytes, aad: bytes) -> bytes:
        return AESGCM(key).decrypt(iv, sealed, aad)


AEAD = _AesGcm()


def _keyring(versions=None) -> R.RecordsKeyring:
    parsed = R.parse_records_keyring_file(FILE["fixtures"]["keyring"])
    assert parsed["ok"]
    secrets = [s for s in parsed["secrets"] if versions is None or s[0] in versions]
    return R.RecordsKeyring.from_provider(R.local_records_key_provider(secrets))


def _rk(hex_text: str) -> R.RecordKey:
    return R.record_key_from_bytes(bytes.fromhex(hex_text))


def _refusal(result: Dict[str, Any], expected: Dict[str, Any]) -> Dict[str, Any]:
    out = {"ok": result["ok"], "code": result.get("code")}
    if "seq" in expected:
        out["seq"] = result.get("seq")
    return out


class RecordsEncryptionVectorsTest(unittest.TestCase):
    maxDiff = None

    def test_the_case_list_is_the_file_less_the_named_cases(self) -> None:
        self.assertEqual(FILE["caseCount"], len(FILE["cases"]))
        self.assertEqual(sorted(CASE_IDS + list(OUT_OF_SCOPE)), sorted(CASES))
        for case_id, code in OUT_OF_SCOPE.items():
            self.assertEqual(CASES[case_id]["expected"].get("code"), code)
        named = {c["id"] for c in FILE["cases"] if c["expected"].get("code") in ("RECORD_HISTORY_DIGEST", "RECORD_HISTORY_RECEIPT_FORM")}
        self.assertEqual(named, set(OUT_OF_SCOPE))

    def test_the_constants_equal_the_file(self) -> None:
        self.assertEqual(
            FILE["constants"],
            {
                "padBlock": R.PAD_BLOCK,
                "plaintextMaxBytes": R.PLAINTEXT_MAX_BYTES,
                "ciphertextMaxBytes": R.CIPHERTEXT_MAX_BYTES,
                "ciphertextMaxChars": R.CIPHERTEXT_MAX_CHARS,
                "bodyMaxBytes": R.BODY_MAX_BYTES,
                "keyringMaxBytes": R.KEYRING_MAX_BYTES,
                "labels": R.LABELS,
            },
        )

    def test_every_case(self) -> None:
        for case_id in CASE_IDS:
            with self.subTest(case_id):
                self._check(CASES[case_id])

    def _check(self, c: Dict[str, Any]) -> None:
        kind, i, e = c["kind"], c["input"], c["expected"]
        if kind == "derive":
            secret = R.b64url_decode(i["secret"])
            if e["idKey"] is not None:
                self.assertEqual(R.export_key_bytes(R.derive_records_id_key(secret)).hex(), e["idKey"])
            records_key, wrap_key = R.derive_records_keys(secret, i["version"])
            self.assertEqual(
                [R.export_key_bytes(records_key).hex(), records_key.id, R.export_key_bytes(wrap_key).hex(), wrap_key.id],
                [e["recordsKey"], e["recordsKeyId"], e["wrapKey"], e["wrapKeyId"]],
            )
        elif kind == "record-key":
            ring = _keyring()
            keys = [ring.by_version(1), ring.by_version(2)]
            self.assertEqual([R.export_key_bytes(k).hex() for k in keys], i["recordsKeys"])
            rks = [R.record_key_of(k, i["wireRecordId"]) for k in keys]
            self.assertEqual([R.export_key_bytes(rk).hex() for rk in rks], e["recordKeys"])
            self.assertEqual([rk.id for rk in rks], e["recordKeyIds"])
        elif kind in ("wire-record-id", "wire-reference-id", "content-tag"):
            ring = _keyring()
            self.assertEqual(R.export_key_bytes(ring.id_key).hex(), i["idKey"])
            if kind == "wire-record-id":
                self.assertEqual(R.wire_record_id(ring.id_key, i["recordType"], i["entityId"]), e["wireRecordId"])
            elif kind == "wire-reference-id":
                self.assertEqual(R.wire_reference_id(ring.id_key, i["referenceId"]), e["wireReferenceId"])
            else:
                tag = R.content_tag(ring.id_key, i["recordType"], i["wireRecordId"], i["content"], i["lifecycle"])
                self.assertEqual(tag, e["contentTag"])
                self.assertEqual(R.wire_reference_id(ring.id_key, tag), e["fallbackWireReferenceId"])
        elif kind == "envelope":
            rk = _rk(i["recordKey"])
            plaintext = R.record_entry_plaintext(i["content"], i["saltKey"])
            padded = R.pad_record_entry(plaintext)
            self.assertEqual([len(plaintext), len(padded)], [e["plaintextBytes"], e["paddedBytes"]])
            envelope = R._seal_padded_entry(AEAD, rk, i["recordsKeyId"], i["recordType"], i["wireRecordId"], padded, R.b64url_decode(i["iv"]))
            self.assertEqual(envelope, e["envelope"])
            for opener in ({"record_key": rk}, {"keyring": _keyring()}):
                opened = R.open_record_entry_envelope(AEAD, envelope, i["recordType"], i["wireRecordId"], **opener)
                self.assertEqual([opened["ok"], opened["content"], opened["saltKey"]], [True, i["content"], i["saltKey"]])
            self.assertEqual(commit_record_content_v2(i["content"], i["saltKey"])["recordHash"], e["recordHash"])
        elif kind == "seal-reject":
            self.assertEqual(len(canonicalize_jcs({"content": i["content"], "saltKey": i["saltKey"]}).encode("utf-8")), e["plaintextBytes"])
            with self.assertRaises(R.RecordsEncryptionError) as raised:
                R.record_entry_plaintext(i["content"], i["saltKey"])
            self.assertEqual(raised.exception.code, e["code"])
        elif kind == "envelope-reject":
            if i.get("recordsKeys"):
                opened = R.open_record_entry_envelope(AEAD, i["envelope"], i["recordType"], i["wireRecordId"], keyring=_keyring([1]))
            else:
                opened = R.open_record_entry_envelope(AEAD, i["envelope"], i["recordType"], i["wireRecordId"], record_key=_rk(i["recordKey"]))
            if e.get("ok"):
                self.assertTrue(opened["ok"])
            else:
                self.assertEqual(opened, {"ok": False, "code": e["code"]})
        elif kind == "body-cap":
            result = R.check_encrypted_write_size(i["body"], i["recordsKeyId"], i["plaintextBytes"])
            self.assertEqual(result["bodyBytes"], e["bodyBytes"])
            self.assertEqual({k: v for k, v in result.items() if k != "bodyBytes"}, {k: v for k, v in e.items() if k != "bodyBytes"})
        elif kind == "refs-match":
            self.assertEqual(R.entry_refs_match(i["content"], i["outside"]), e)
        elif kind == "keyring":
            parsed = R.parse_records_keyring_file(i["text"])
            if not e["ok"]:
                self.assertEqual(parsed, {"ok": False, "code": e["code"]})
                return
            self.assertEqual([v for v, _ in parsed["secrets"]], e["versions"])
            ring = R.RecordsKeyring.from_provider(R.local_records_key_provider(i["text"]))
            self.assertEqual([ring.by_version(v).id for v in ring.versions], e["recordsKeyIds"])
            if c["id"] == "KR-01":
                self.assertEqual(R.serialize_records_keyring_file(parsed["secrets"]), i["text"])
        elif kind == "receipt-v4":
            result = R.open_receipt_v4(AEAD, i["receipt"], _rk(i["recordKey"]), i["recordType"], i["wireRecordId"])
            if not e["ok"]:
                self.assertEqual(_refusal(result, e), e)
                return
            opened = {"seq": i["receipt"]["seq"], "recordHash": result["recordHash"], "content": result["content"], "saltKey": result["saltKey"]}
            self.assertEqual(opened, e["opened"])
        elif kind in ("bundle-v3", "copy-file"):
            if kind == "bundle-v3":
                result = R.open_record_history_v3(AEAD, i["bundle"], _rk(i["recordKey"]), i.get("expect"))
            else:
                result = R.open_record_copy_v1(AEAD, i["file"], i.get("expect"))
            if not e["ok"]:
                self.assertEqual(_refusal(result, e), e)
                return
            self.assertEqual(result["opened"], e["opened"])
            if "refused" in e:
                self.assertEqual(result["refused"], e["refused"])
        else:
            self.fail(f"unknown kind {kind}")


class RecordsEncryptionRoundTripTest(unittest.TestCase):
    SALT = "0x" + "ab" * 32

    def _fresh(self, versions: int = 2):
        secrets = [(v, R.generate_workspace_secret()) for v in range(1, versions + 1)]
        return secrets, R.RecordsKeyring.from_provider(R.local_records_key_provider(secrets))

    def test_seal_and_open_many_sizes(self) -> None:
        _, ring = self._fresh()
        wire = R.wire_record_id(ring.id_key, "machine-action", "press-line-4")
        rk = R.record_key_of(ring.current, wire)
        for size in (0, 1, 255, 256, 4096, 40000):
            content = {"note": "x" * size, "n": size}
            envelope = R.seal_record_entry(AEAD, rk, "machine-action", wire, content, self.SALT)
            self.assertEqual(envelope["kid"], ring.current.id)
            for opener in ({"record_key": rk}, {"keyring": ring}):
                opened = R.open_record_entry_envelope(AEAD, envelope, "machine-action", wire, **opener)
                self.assertEqual([opened["ok"], opened["content"]], [True, content])

    def test_the_records_key_that_opened_the_envelope_is_named_never_only_its_claim(self) -> None:
        _, ring = self._fresh()
        wire = R.wire_record_id(ring.id_key, "t", "e")
        rk = R.record_key_of(ring.current, wire)
        envelope = R.seal_record_entry(AEAD, rk, "t", wire, {"a": 1}, self.SALT)
        alone = R.record_key_from_bytes(R.export_key_bytes(rk))
        named = [R.open_record_entry_envelope(AEAD, envelope, "t", wire, **opener)["recordsKeyId"] for opener in ({"keyring": ring}, {"record_key": rk}, {"record_key": alone})]
        self.assertEqual(named, [ring.current.id, ring.current.id, None])

    def test_every_single_byte_change_is_refused(self) -> None:
        _, ring = self._fresh(1)
        wire = R.wire_record_id(ring.id_key, "t", "e")
        rk = R.record_key_of(ring.current, wire)
        envelope = R.seal_record_entry(AEAD, rk, "t", wire, {"a": 1}, self.SALT)
        for member in ("iv", "ct"):
            data = R.b64url_decode(envelope[member])
            for index in range(len(data)):
                changed = bytearray(data)
                changed[index] ^= 1
                tampered = {**envelope, member: R.b64url_encode(bytes(changed))}
                result = R.open_record_entry_envelope(AEAD, tampered, "t", wire, record_key=rk)
                self.assertEqual(result, {"ok": False, "code": "RECORD_ENVELOPE_AUTH_FAILED"})

    def test_a_keyring_file_round_trips(self) -> None:
        secrets, _ = self._fresh(3)
        parsed = R.parse_records_keyring_file(R.serialize_records_keyring_file(secrets))
        self.assertEqual(parsed["secrets"], secrets)

    def test_no_key_shows_its_bytes(self) -> None:
        secrets, ring = self._fresh(2)
        wire = R.wire_record_id(ring.id_key, "t", "e")
        rk = R.record_key_of(ring.current, wire)
        provider = R.local_records_key_provider(secrets)
        keys = [ring.id_key, ring.current, ring.by_version(1), ring.wrap_key(1), ring.wrap_key(2), rk]
        forbidden = [s.hex() for _, s in secrets] + [R.b64url_encode(s) for _, s in secrets]
        forbidden += [R.export_key_bytes(k).hex() for k in keys] + [R.b64url_encode(R.export_key_bytes(k)) for k in keys]
        for item in [*keys, ring, provider]:
            shown = [repr(item), str(item), f"{item}", repr([item]), repr({"k": item})]
            for text in shown:
                for value in forbidden:
                    self.assertNotIn(value, text)
            self.assertFalse(hasattr(item, "__dict__"))
            with self.assertRaises(TypeError):
                json.dumps(item)

    def test_a_refusal_carries_a_code_only(self) -> None:
        result = R.open_record_entry_envelope(AEAD, {"v": 1}, "t", "A" * 22, record_key=R.record_key_from_bytes(os.urandom(32)))
        self.assertEqual(sorted(result), ["code", "ok"])

    def test_the_vector_bundle_is_not_changed_by_opening(self) -> None:
        c = CASES["HB-01"]
        before = copy.deepcopy(c["input"])
        R.open_record_history_v3(AEAD, c["input"]["bundle"], _rk(c["input"]["recordKey"]), c["input"].get("expect"))
        self.assertEqual(c["input"], before)


if __name__ == "__main__":
    unittest.main()
