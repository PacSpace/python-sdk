"""Level 2's asymmetric layer against records-asymmetric-v1.json (L2a2).

The vectors are a byte-for-byte copy of the shared file, and
hpke-pq-05-test-vectors.json a byte-for-byte copy of the pinned draft's,
both compared by the generator's ``--check``. The draft cases run this SDK's
own seed expansion and the X-Wing combiner against the draft (the key
schedule too, for HKDF-SHA256); every other case runs through
``pacspace_sdk.records_asymmetric`` on ``cryptography``. Python cannot fix an
encapsulation's randomness, so the sealing cases are opened here and sealed
afresh in the round trips; ML-DSA signing is hedged, so the deterministic
signature is verified, not remade.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import subprocess
import sys
import unittest
from pathlib import Path
from typing import Any, Dict

from cryptography.hazmat.primitives.asymmetric import mlkem, x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from pacspace_sdk import records_asymmetric as A
from pacspace_sdk import records_encryption as R

VECTORS = Path(__file__).parent / "vectors"
FILE = json.loads((VECTORS / "records-asymmetric-v1.json").read_text(encoding="utf-8"))
DRAFT_BYTES = (VECTORS / "hpke-pq-05-test-vectors.json").read_bytes()
DRAFT = json.loads(DRAFT_BYTES)
CASES = {c["id"]: c for c in FILE["cases"]}

CASE_IDS = [
    "HP-01", "HP-02",
    "KP-01", "KP-02", "KP-03", "KP-04",
    "SW-01", "SW-02", "SW-03", "SW-04", "SW-05", "SW-06", "SW-07", "SW-08",
    "WP-01", "WP-02", "WP-03", "WP-04", "WP-05", "WP-06", "WP-07", "WP-08", "WP-09",
    "WP-10", "WP-11", "WP-12", "WP-13", "WP-14", "WP-15", "WP-16", "WP-17", "WP-18",
    "AK-01", "AK-02", "AK-03",
    "MD-01", "MD-02", "MD-03", "MD-04", "MD-05",
]


def b64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _keyring() -> R.RecordsKeyring:
    parsed = R.parse_records_keyring_file(FILE["fixtures"]["keyring"])
    assert parsed["ok"]
    return R.RecordsKeyring.from_provider(R.local_records_key_provider(parsed["secrets"]))


# --------------------------------------------- the draft, independently of the SDK


def _i2osp(n: int, width: int) -> bytes:
    return n.to_bytes(width, "big")


def _derive_key_pair_seed(ikm: bytes, kem_id: int) -> bytes:
    suite_id = b"KEM" + _i2osp(kem_id, 2)
    label = b"DeriveKeyPair"
    labeled = ikm + b"HPKE-v1" + suite_id + _i2osp(len(label), 2) + label + _i2osp(32, 2)
    return hashlib.shake_256(labeled).digest(32)


def _xwing_decap(enc: bytes, seed: bytes) -> bytes:
    expanded = hashlib.shake_256(seed).digest(96)
    mk = mlkem.MLKEM768PrivateKey.from_seed_bytes(expanded[:64])
    xk = x25519.X25519PrivateKey.from_private_bytes(expanded[64:])
    ct_x = enc[1088:]
    ss_m = mk.decapsulate(enc[:1088])
    ss_x = xk.exchange(x25519.X25519PublicKey.from_public_bytes(ct_x))
    return hashlib.sha3_256(ss_m + ss_x + ct_x + xk.public_key().public_bytes_raw() + b"\\.//^\\").digest()


class _KeySchedule:
    """RFC 9180 section 5.1 with HKDF-SHA256, base mode."""

    def __init__(self, vector: Dict[str, Any], shared_secret: bytes) -> None:
        self.suite = b"HPKE" + _i2osp(vector["kem_id"], 2) + _i2osp(vector["kdf_id"], 2) + _i2osp(vector["aead_id"], 2)
        context = b"\x00" + self._lx(b"", b"psk_id_hash", b"") + self._lx(b"", b"info_hash", bytes.fromhex(vector["info"]))
        secret = self._lx(shared_secret, b"secret", b"")
        self.key = self._le(secret, b"key", context, 32)
        self.base_nonce = self._le(secret, b"base_nonce", context, 12)
        self.exporter = self._le(secret, b"exp", context, 32)

    def _lx(self, salt: bytes, label: bytes, ikm: bytes) -> bytes:
        return hmac.new(salt or bytes(32), b"HPKE-v1" + self.suite + label + ikm, hashlib.sha256).digest()

    def _le(self, prk: bytes, label: bytes, info: bytes, length: int) -> bytes:
        full, out, block, i = _i2osp(length, 2) + b"HPKE-v1" + self.suite + label + info, b"", b"", 1
        while len(out) < length:
            block = hmac.new(prk, block + full + bytes([i]), hashlib.sha256).digest()
            out += block
            i += 1
        return out[:length]

    def nonce(self, seq: int) -> bytes:
        return bytes(a ^ b for a, b in zip(self.base_nonce, _i2osp(seq, 12)))

    def export(self, context: bytes, length: int) -> bytes:
        return self._le(self.exporter, b"sec", context, length)


def _ack_key_id(es256: Dict[str, str], mldsa_public_key: str) -> Any:
    x, y, pk = b64(es256["x"]), b64(es256["y"]), b64(mldsa_public_key)
    if len(x) != 32 or len(y) != 32 or len(pk) != A.MLDSA65_PUBLIC_KEY_BYTES:
        return None
    label = FILE["constants"]["ackKeyIdLabel"].encode("ascii")
    return hashlib.sha256(label + b"\x00" + b"\x04" + x + y + b"\x00" + pk).hexdigest()


class RecordsAsymmetricVectorsTest(unittest.TestCase):
    maxDiff = None

    def test_the_case_list_is_the_file(self) -> None:
        self.assertEqual(FILE["caseCount"], len(FILE["cases"]))
        self.assertEqual(sorted(CASE_IDS), sorted(CASES))

    def test_the_draft_copy_is_the_pinned_file(self) -> None:
        self.assertEqual(hashlib.sha256(DRAFT_BYTES).hexdigest(), FILE["draft"]["sha256"])
        self.assertEqual(FILE["draft"]["tag"], "draft-ietf-hpke-pq-05")

    def test_the_constants_equal_the_module(self) -> None:
        constants = FILE["constants"]
        self.assertEqual(constants["labels"], A.LABELS)
        self.assertEqual(constants["suites"], A.KEY_WRAP_SUITES)
        self.assertEqual(
            constants["sizes"],
            {
                "seed": A.WORKSPACE_SEED_BYTES,
                "publicKey": A.WORKSPACE_PUBLIC_KEY_BYTES,
                "enc": A.KEY_WRAP_ENC_BYTES,
                "wrapCt": A.KEY_WRAP_CT_BYTES,
                "seedWrapCt": A.SEED_WRAP_CT_BYTES,
                "mldsaSeed": A.MLDSA65_SEED_BYTES,
                "mldsaPublicKey": A.MLDSA65_PUBLIC_KEY_BYTES,
                "mldsaSignature": A.MLDSA65_SIGNATURE_BYTES,
                "holderKeyCodeDigits": A.HOLDER_KEY_CODE_DIGITS,
            },
        )

    def test_every_case(self) -> None:
        for case_id in CASE_IDS:
            case = CASES[case_id]
            with self.subTest(case_id):
                getattr(self, "_" + case["kind"].replace("-", "_"))(case)

    def _draft(self, case: Dict[str, Any]) -> None:
        v = DRAFT[case["input"]["index"]]
        expected = case["expected"]
        self.assertEqual([v["kem_id"], v["kdf_id"], v["aead_id"]], [case["input"]["kemId"], case["input"]["kdfId"], case["input"]["aeadId"]])
        seed = _derive_key_pair_seed(bytes.fromhex(v["ikmR"]), v["kem_id"])
        self.assertEqual(seed.hex(), expected["skRm"])
        self.assertEqual(A.workspace_seed_from_bytes(seed).public_key.hex(), expected["pkRm"])
        self.assertEqual(v["enc"], expected["enc"])
        shared_secret = _xwing_decap(bytes.fromhex(v["enc"]), seed)
        self.assertEqual(shared_secret.hex(), expected["sharedSecret"])
        self.assertEqual([len(v["encryptions"]), len(v["exports"])], [expected["encryptions"], expected["exports"]])
        if v["kdf_id"] != 0x0001:
            return
        schedule = _KeySchedule(v, shared_secret)
        self.assertEqual([schedule.key.hex(), schedule.base_nonce.hex(), schedule.exporter.hex()], [v["key"], v["base_nonce"], v["exporter_secret"]])
        for seq, e in enumerate(v["encryptions"]):
            self.assertEqual(e["nonce"], schedule.nonce(seq).hex())
            self.assertEqual(ChaCha20Poly1305(schedule.key).decrypt(schedule.nonce(seq), bytes.fromhex(e["ct"]), bytes.fromhex(e["aad"])).hex(), e["pt"])
        for x in v["exports"]:
            self.assertEqual(schedule.export(bytes.fromhex(x["exporter_context"]), x["L"]).hex(), x["exported_value"])

    def _keypair(self, case: Dict[str, Any]) -> None:
        seed = b64(case["input"]["seed"])
        expected = case["expected"]
        if expected.get("ok") is False:
            with self.assertRaises(A.RecordsAsymmetricError) as raised:
                A.workspace_seed_from_bytes(seed)
            self.assertEqual(raised.exception.code, expected["code"])
            return
        made = A.workspace_seed_from_bytes(seed)
        self.assertEqual(R.b64url_encode(made.public_key), expected["publicKey"])
        self.assertEqual(made.public_key_id, expected["publicKeyId"])
        self.assertEqual(A.public_key_id(made.public_key), expected["publicKeyId"])
        self.assertEqual(A.holder_key_code(made.public_key), expected["holderKeyCode"])

    def _seed_wrap(self, case: Dict[str, Any]) -> None:
        ring = _keyring()
        i, expected = case["input"], case["expected"]
        if "seal" in i:
            seed = A.workspace_seed_from_bytes(b64(i["seal"]["seed"]))
            sealed = A._seal_seed_wrap_with_iv(ring.wrap_key(i["seal"]["wrapKeyVersion"]), seed, b64(i["seal"]["iv"]))
            self.assertEqual(sealed, i["wrap"])
        if i["open"].get("keyring"):
            opened = A.open_seed_wrap(i["wrap"], i["publicKeyId"], keyring=ring)
        else:
            opened = A.open_seed_wrap(i["wrap"], i["publicKeyId"], wrap_key=ring.wrap_key(i["open"]["wrapKeyVersion"]))
        if expected["ok"]:
            self.assertTrue(opened["ok"])
            self.assertEqual(R.b64url_encode(A.export_workspace_seed_bytes(opened["seed"])), expected["seed"])
            self.assertEqual(R.b64url_encode(opened["seed"].public_key), expected["publicKey"])
        else:
            self.assertEqual(opened, {"ok": False, "code": expected["code"]})

    def _key_wrap(self, case: Dict[str, Any]) -> None:
        i, expected = case["input"], case["expected"]
        seed = A.workspace_seed_from_bytes(b64(i["holderSeed"]))
        binding = i["binding"]
        purpose = binding["purpose"]
        if purpose == "records-key":
            opened = A.unwrap_records_key(seed, i["wrap"], binding["version"], binding["recordsKeyId"])
            key_bytes = R.export_key_bytes(opened["recordsKey"]) if opened["ok"] else None
        elif purpose == "record-key":
            opened = A.unwrap_record_key(seed, i["wrap"], binding["recordType"], binding["wireRecordId"])
            key_bytes = R.export_key_bytes(opened["recordKey"]) if opened["ok"] else None
        else:
            opened = A.unwrap_disclosure_key(seed, i["wrap"], binding["handle"])
            key_bytes = opened.get("disclosureKey")
        if not expected["ok"]:
            self.assertEqual(opened, {"ok": False, "code": expected["code"]})
            return
        self.assertEqual(R.b64url_encode(key_bytes), expected["keyBytes"])
        info_binding = {k: v for k, v in binding.items() if k != "version"}
        self.assertEqual(A.key_wrap_info(info_binding).hex(), expected["info"])
        self.assertEqual(R.b64url_encode(seed.public_key), i["seal"]["publicKey"])
        self.assertEqual(i["seal"]["keyBytes"], expected["keyBytes"])

    def _ack_v2(self, case: Dict[str, Any]) -> None:
        i, expected = case["input"], case["expected"]
        self.assertEqual(_ack_key_id(i["es256"], i["mldsaPublicKey"]), expected["keyId"])
        if i["body"] is not None:
            b = i["body"]
            # The body's members in their fixed order (as v1's), not sorted.
            body = {
                "v": 2,
                "kind": "acknowledgment",
                "handle": b["handle"],
                "seq": b["seq"],
                "matched": b["matched"],
                "missing": b["missing"],
                "historyDigest": b["historyDigest"].lower(),
                "signedAt": b["signedAt"],
                "keyId": b["keyId"].lower(),
            }
            self.assertEqual(json.dumps(body, separators=(",", ":"), ensure_ascii=False), expected["body"])
            self.assertEqual(b["keyId"], expected["keyId"])

    def _mldsa(self, case: Dict[str, Any]) -> None:
        i, expected = case["input"], case["expected"]
        message = b64(i["message"])
        if "seed" in i:
            key = A.mldsa_signing_key_from_seed(b64(i["seed"]))
            self.assertEqual(R.b64url_encode(key.public_key), expected["publicKey"])
            public_key, signature = key.public_key, b64(expected["signature"])
            self.assertTrue(A.verify_mldsa65(public_key, message, A.sign_mldsa65(key, message)))
        else:
            public_key, signature = b64(i["publicKey"]), b64(i["signature"])
        self.assertEqual(A.verify_mldsa65(public_key, message, signature), expected["verifies"])


class RecordsAsymmetricRoundTripTest(unittest.TestCase):
    def setUp(self) -> None:
        self.seed = A.generate_workspace_seed()

    def test_every_purpose_round_trips(self) -> None:
        records_key, _ = R.derive_records_keys(R.generate_workspace_secret(), 4)
        wrap = A.wrap_records_key(self.seed.public_key, records_key)
        opened = A.unwrap_records_key(self.seed, wrap, 4, records_key.id)
        self.assertEqual(R.export_key_bytes(opened["recordsKey"]), R.export_key_bytes(records_key))

        record_key = R.record_key_from_bytes(bytes(range(32)))
        wire_id = FILE["fixtures"]["wireRecordId"]
        wrap = A.wrap_record_key(self.seed.public_key, record_key, "machine-action", wire_id)
        opened = A.unwrap_record_key(self.seed, wrap, "machine-action", wire_id)
        self.assertEqual(R.export_key_bytes(opened["recordKey"]), bytes(range(32)))

        wrap = A.wrap_disclosure_key(self.seed.public_key, b"\x07" * 32, "vectors-handle-01")
        self.assertEqual(A.unwrap_disclosure_key(self.seed, wrap, "vectors-handle-01"), {"ok": True, "disclosureKey": b"\x07" * 32})
        self.assertEqual(sorted(wrap), ["ct", "enc", "suite", "to", "v"])
        self.assertEqual([wrap["v"], wrap["suite"], wrap["to"]], [1, "hpke-1", self.seed.public_key_id])
        self.assertEqual([len(b64(wrap["enc"])), len(b64(wrap["ct"]))], [A.KEY_WRAP_ENC_BYTES, A.KEY_WRAP_CT_BYTES])

    def test_a_vector_holder_opens_a_wrap_python_makes(self) -> None:
        case = CASES["WP-01"]["input"]
        holder = A.workspace_seed_from_bytes(b64(case["holderSeed"]))
        records_key = R.records_key_from_bytes(b64(case["seal"]["keyBytes"]), 1)
        wrap = A.wrap_records_key(b64(case["seal"]["publicKey"]), records_key)
        opened = A.unwrap_records_key(holder, wrap, 1, case["binding"]["recordsKeyId"])
        self.assertEqual(R.b64url_encode(R.export_key_bytes(opened["recordsKey"])), case["seal"]["keyBytes"])

    def test_every_single_byte_change_is_refused(self) -> None:
        wrap = A.wrap_disclosure_key(self.seed.public_key, b"\x01" * 32, "h")
        codes = set()
        for field in ("enc", "ct"):
            data = b64(wrap[field])
            for index in range(len(data)):
                changed = bytearray(data)
                changed[index] ^= 0x01
                result = A.unwrap_disclosure_key(self.seed, {**wrap, field: R.b64url_encode(bytes(changed))}, "h")
                self.assertFalse(result["ok"])
                codes.add(result["code"])
        self.assertEqual(codes, {"KEY_WRAP_AUTH_FAILED"})

    def test_a_seed_wrap_round_trips_and_refuses_every_byte_change(self) -> None:
        ring = _keyring()
        wrap = A.seal_seed_wrap(ring.wrap_key(2), self.seed)
        opened = A.open_seed_wrap(wrap, self.seed.public_key_id, keyring=ring)
        self.assertEqual(opened["seed"].public_key, self.seed.public_key)
        for field in ("iv", "ct"):
            data = b64(wrap[field])
            for index in range(len(data)):
                changed = bytearray(data)
                changed[index] ^= 0x01
                result = A.open_seed_wrap({**wrap, field: R.b64url_encode(bytes(changed))}, self.seed.public_key_id, keyring=ring)
                self.assertEqual(result, {"ok": False, "code": "SEED_WRAP_AUTH_FAILED"})

    def test_malformed_input_is_refused_and_nothing_raises(self) -> None:
        for wrap in (None, 1, "x", [], {}, {"v": 1}, {"v": 1, "suite": "hpke-1", "to": "x", "enc": "!", "ct": "!"}):
            self.assertFalse(A.unwrap_disclosure_key(self.seed, wrap, "h")["ok"])
            self.assertFalse(A.read_key_wrap_shape(wrap)["ok"])
            self.assertFalse(A.open_seed_wrap(wrap, self.seed.public_key_id)["ok"])
        self.assertFalse(A.verify_mldsa65(bytes(1952), b"m", bytes(10)))
        self.assertFalse(A.verify_mldsa65(bytes(5), b"m", bytes(3309)))

    def test_no_key_shows_its_bytes(self) -> None:
        signing = A.generate_mldsa_signing_key()
        for key, data in ((self.seed, A.export_workspace_seed_bytes(self.seed)), (signing, A.export_mldsa_seed_bytes(signing))):
            shown = "\n".join([repr(key), str(key), repr([key]), repr(getattr(key, "__dict__", None)), repr(dir(key))])
            for form in (data.hex(), R.b64url_encode(data), base64.b64encode(data).decode("ascii"), repr(data)):
                self.assertNotIn(form, shown)
        self.assertEqual(repr(self.seed), f"[workspace seed {self.seed.public_key_id[:8]}]")
        self.assertEqual(repr(signing), "[ML-DSA-65 signing key]")

    def test_importing_the_sdk_does_not_load_cryptography(self) -> None:
        root = Path(__file__).resolve().parent.parent
        out = subprocess.run(
            [sys.executable, "-c", "import sys, pacspace_sdk; print('cryptography' in sys.modules)"],
            cwd=root,
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertEqual(out.stdout.strip(), "False")


if __name__ == "__main__":
    unittest.main()
