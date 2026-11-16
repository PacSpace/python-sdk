"""Level 2's asymmetric layer (ADR 0015 sections 4, 5 and 11; formats note
N3, N9 and N12), as the TypeScript in
packages/shared/src/records-crypto/asymmetric/records-asymmetric-v1.ts does
it, against the same vectors: the workspace keypair from a 32-byte seed, the
seed's wrap under ``W_v``, the public key id and the holder key code, wraps
to a holder under the suite ``hpke-1``, and ML-DSA-65.

This module runs on ``cryptography`` (48 or later), the SDK's one runtime
dependency, and only ``encrypted_records.py`` imports it, which
``records.py`` loads on an encrypted path, so ``import pacspace_sdk`` does
not load it. ``cryptography`` takes an X-Wing key as its
two halves, so the seed is expanded here, as draft-ietf-hpke-pq-05 fixes it:
SHAKE256 of the seed to 96 bytes, the first 64 the ML-KEM-768 seed and the
last 32 the X25519 private key.

No seed or private key is printed: those types keep their bytes in a module
table, so ``repr`` and ``str`` show a short description only. Refusals carry
a code and no sentence; nothing here logs.
"""

from __future__ import annotations

import hashlib
import os
import re
import weakref
from typing import Any, Dict, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hpke
from cryptography.hazmat.primitives.asymmetric import mldsa, mlkem, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .records_encryption import (
    RecordKey,
    RecordsEncryptionError,
    RecordsKey,
    RecordsKeyring,
    RecordsWrapKey,
    b64url_decode,
    b64url_encode,
    export_key_bytes,
    record_key_from_bytes,
    records_key_from_bytes,
)

LABELS = {
    "publicKeyId": "pacspace:public-key-id:v1",
    "holderKeyCode": "pacspace:holder-key-code:v1",
    "seedWrap": "pacspace:seed-wrap:v1",
    "wrap": "pacspace:wrap:v1",
    "wrapV2": "pacspace:wrap:v2",
    "identityRotation": "pacspace:identity-rotation:v1",
}

KEY_WRAP_SUITE = "hpke-1"
KEY_WRAP_SUITES = {"hpke-1": {"kem": 0x647A, "kdf": 0x0001, "aead": 0x0002, "draft": "draft-ietf-hpke-pq-05"}}
WORKSPACE_SEED_BYTES = 32
WORKSPACE_PUBLIC_KEY_BYTES = 1216
KEY_WRAP_ENC_BYTES = 1120
KEY_WRAP_CT_BYTES = 48
SEED_WRAP_CT_BYTES = 48
MLDSA65_SEED_BYTES = 32
MLDSA65_PUBLIC_KEY_BYTES = 1952
MLDSA65_SIGNATURE_BYTES = 3309
HOLDER_KEY_CODE_DIGITS = 40

_MLKEM_PUBLIC_KEY_BYTES = 1184
_IV_BYTES = 12
_SEP = b"\x00"
_HEX64 = re.compile(r"[0-9a-f]{64}")
_WIRE_ID = re.compile(r"[A-Za-z0-9_-]{22}")
_PRINTABLE_ASCII = re.compile(r"[\x21-\x7e]+")
_SAFE_MAX = 9007199254740991
_SUITE = hpke.Suite(hpke.KEM.MLKEM768_X25519, hpke.KDF.HKDF_SHA256, hpke.AEAD.AES_256_GCM)


class RecordsAsymmetricError(ValueError):
    """Raised by the writing side only; its message is the code."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _refuse(code: str) -> Dict[str, Any]:
    return {"ok": False, "code": code}


def _is_bytes(value: Any) -> bool:
    return isinstance(value, (bytes, bytearray))


# -------------------------------------------------------------- hidden keys

_HELD: "weakref.WeakKeyDictionary[Any, bytes]" = weakref.WeakKeyDictionary()


class WorkspaceSeed:
    """The workspace's private seed, with the X-Wing public key it makes."""

    __slots__ = ("__weakref__", "_public_key", "public_key_id")

    def __init__(self, seed: bytes, public_key: bytes, public_key_id: str) -> None:
        _HELD[self] = bytes(seed)
        self._public_key = bytes(public_key)
        self.public_key_id = public_key_id

    @property
    def public_key(self) -> bytes:
        """The encoded public key (1,216 bytes): the ML-KEM-768 key, then the X25519 key."""
        return self._public_key

    def __repr__(self) -> str:
        return f"[workspace seed {self.public_key_id[:8]}]"

    __str__ = __repr__


class MldsaSigningKey:
    """An ML-DSA-65 signing key, made from a 32-byte seed."""

    __slots__ = ("__weakref__", "_public_key")

    def __init__(self, seed: bytes, public_key: bytes) -> None:
        _HELD[self] = bytes(seed)
        self._public_key = bytes(public_key)

    @property
    def public_key(self) -> bytes:
        return self._public_key

    def __repr__(self) -> str:
        return "[ML-DSA-65 signing key]"

    __str__ = __repr__


def _held(key: Any, code: str) -> bytes:
    try:
        return _HELD[key]
    except (KeyError, TypeError):
        raise RecordsAsymmetricError(code) from None


def export_workspace_seed_bytes(seed: WorkspaceSeed) -> bytes:
    """The seed's 32 bytes, for the two places they may leave the key layer: the seed wrap and the published vectors."""
    return bytes(_held(seed, "WORKSPACE_SEED_INVALID"))


# ------------------------------------------- the workspace keypair, its id and code


def _xwing_halves(seed: bytes) -> "tuple[mlkem.MLKEM768PrivateKey, x25519.X25519PrivateKey]":
    expanded = hashlib.shake_256(seed).digest(96)
    return mlkem.MLKEM768PrivateKey.from_seed_bytes(expanded[:64]), x25519.X25519PrivateKey.from_private_bytes(expanded[64:])


def _assert_public_key(public_key: Any) -> None:
    if not _is_bytes(public_key) or len(public_key) != WORKSPACE_PUBLIC_KEY_BYTES:
        raise RecordsAsymmetricError("WORKSPACE_PUBLIC_KEY_INVALID")


def public_key_id(public_key: bytes) -> str:
    """``SHA-256("pacspace:public-key-id:v1" || 0x00 || encoded public key)``, 64 lowercase hex."""
    _assert_public_key(public_key)
    return hashlib.sha256(LABELS["publicKeyId"].encode("ascii") + _SEP + bytes(public_key)).hexdigest()


def holder_key_code(public_key: bytes) -> str:
    """The first 17 bytes of the code digest as a big-endian integer, modulo 10^40, in eight groups of five."""
    _assert_public_key(public_key)
    digest = hashlib.sha256(LABELS["holderKeyCode"].encode("ascii") + _SEP + bytes(public_key)).digest()
    digits = str(int.from_bytes(digest[:17], "big") % 10**HOLDER_KEY_CODE_DIGITS).zfill(HOLDER_KEY_CODE_DIGITS)
    return " ".join(digits[i : i + 5] for i in range(0, HOLDER_KEY_CODE_DIGITS, 5))


def workspace_seed_from_bytes(seed: bytes) -> WorkspaceSeed:
    """The keypair the 32-byte seed makes, as draft-ietf-hpke-pq-05's MLKEM768-X25519 derives it."""
    if not _is_bytes(seed) or len(seed) != WORKSPACE_SEED_BYTES:
        raise RecordsAsymmetricError("WORKSPACE_SEED_INVALID")
    m, x = _xwing_halves(bytes(seed))
    public_key = m.public_key().public_bytes_raw() + x.public_key().public_bytes_raw()
    return WorkspaceSeed(bytes(seed), public_key, public_key_id(public_key))


def generate_workspace_seed() -> WorkspaceSeed:
    """A new workspace keypair from 32 random bytes this code draws."""
    return workspace_seed_from_bytes(os.urandom(WORKSPACE_SEED_BYTES))


# ------------------------------------------------------- the seed wrap under W_v


def _seed_wrap_aad(public_key_id_hex: str) -> bytes:
    return LABELS["seedWrap"].encode("ascii") + _SEP + bytes.fromhex(public_key_id_hex)


def _seal_seed_wrap_with_iv(wrap_key: RecordsWrapKey, seed: WorkspaceSeed, iv: bytes) -> Dict[str, Any]:
    """Seals the seed under a given IV; vectors and seal_seed_wrap only."""
    if not isinstance(wrap_key, RecordsWrapKey) or not isinstance(seed, WorkspaceSeed) or not _is_bytes(iv) or len(iv) != _IV_BYTES:
        raise RecordsAsymmetricError("WORKSPACE_SEED_INVALID")
    ct = AESGCM(export_key_bytes(wrap_key)).encrypt(bytes(iv), _held(seed, "WORKSPACE_SEED_INVALID"), _seed_wrap_aad(seed.public_key_id))
    return {"v": 1, "alg": "A256GCM", "kid": wrap_key.id, "iv": b64url_encode(bytes(iv)), "ct": b64url_encode(ct)}


def seal_seed_wrap(wrap_key: RecordsWrapKey, seed: WorkspaceSeed) -> Dict[str, Any]:
    """The seed, sealed for storage at PacSpace under ``W_v`` with a fresh IV."""
    return _seal_seed_wrap_with_iv(wrap_key, seed, os.urandom(_IV_BYTES))


def read_seed_wrap_shape(wrap: Any) -> Dict[str, Any]:
    """The keyless checks. Never raises."""
    if not isinstance(wrap, dict) or sorted(wrap.keys()) != ["alg", "ct", "iv", "kid", "v"]:
        return _refuse("SEED_WRAP_MALFORMED")
    v = wrap["v"]
    if not (type(v) in (int, float) and v == 1) or wrap["alg"] != "A256GCM":
        return _refuse("SEED_WRAP_MALFORMED")
    if not isinstance(wrap["kid"], str) or _HEX64.fullmatch(wrap["kid"]) is None:
        return _refuse("SEED_WRAP_MALFORMED")
    iv, ct = b64url_decode(wrap["iv"]), b64url_decode(wrap["ct"])
    if iv is None or len(iv) != _IV_BYTES or ct is None or len(ct) != SEED_WRAP_CT_BYTES:
        return _refuse("SEED_WRAP_MALFORMED")
    return {"ok": True, "kid": wrap["kid"], "iv": iv, "ct": ct}


def open_seed_wrap(
    wrap: Any,
    public_key_id: str,
    wrap_key: Optional[RecordsWrapKey] = None,
    keyring: Optional[RecordsKeyring] = None,
) -> Dict[str, Any]:
    """Opens a seed wrap with ``W_v``, or with a keyring whose ``W_v`` named by ``kid`` opens it. Never raises."""
    try:
        shape = read_seed_wrap_shape(wrap)
        if not shape["ok"]:
            return shape
        if not isinstance(public_key_id, str) or _HEX64.fullmatch(public_key_id) is None:
            return _refuse("SEED_WRAP_MALFORMED")
        key = wrap_key
        if keyring is not None:
            key = next((k for k in (keyring.wrap_key(v) for v in keyring.versions) if k is not None and k.id == shape["kid"]), None)
        if not isinstance(key, RecordsWrapKey) or key.id != shape["kid"]:
            return _refuse("SEED_WRAP_WRONG_KEY")
        try:
            seed = AESGCM(export_key_bytes(key)).decrypt(shape["iv"], shape["ct"], _seed_wrap_aad(public_key_id))
        except Exception:
            return _refuse("SEED_WRAP_AUTH_FAILED")
        made = workspace_seed_from_bytes(seed)
        if made.public_key_id != public_key_id:
            return _refuse("SEED_WRAP_AUTH_FAILED")
        return {"ok": True, "seed": made}
    except Exception:
        return _refuse("SEED_WRAP_AUTH_FAILED")


# ------------------------------------------------------------ wraps to a holder


def _binding_bytes(binding: Any) -> bytes:
    purpose = binding.get("purpose") if isinstance(binding, dict) else None
    if purpose == "records-key":
        key_id = binding.get("recordsKeyId")
        if isinstance(key_id, str) and _HEX64.fullmatch(key_id):
            return bytes.fromhex(key_id)
    elif purpose == "record-key":
        record_type, wire_id = binding.get("recordType"), binding.get("wireRecordId")
        if isinstance(record_type, str) and _PRINTABLE_ASCII.fullmatch(record_type) and isinstance(wire_id, str) and _WIRE_ID.fullmatch(wire_id):
            return record_type.encode("ascii") + _SEP + wire_id.encode("ascii")
    elif purpose == "disclosure-key":
        handle = binding.get("handle")
        if isinstance(handle, str) and _PRINTABLE_ASCII.fullmatch(handle):
            return handle.encode("ascii")
    raise RecordsAsymmetricError("KEY_WRAP_BINDING_INVALID")


def key_wrap_info(binding: Dict[str, Any]) -> bytes:
    """``"pacspace:wrap:v1" || 0x00 || purpose || 0x00 || SHA-256(binding)``, at most 64 bytes."""
    data = _binding_bytes(binding)
    return LABELS["wrap"].encode("ascii") + _SEP + binding["purpose"].encode("ascii") + _SEP + hashlib.sha256(data).digest()


def _hybrid_public_key(public_key: bytes) -> hpke.MLKEM768X25519PublicKey:
    return hpke.MLKEM768X25519PublicKey(
        mlkem.MLKEM768PublicKey.from_public_bytes(bytes(public_key[:_MLKEM_PUBLIC_KEY_BYTES])),
        x25519.X25519PublicKey.from_public_bytes(bytes(public_key[_MLKEM_PUBLIC_KEY_BYTES:])),
    )


def _seal_key_wrap(public_key: bytes, binding: Dict[str, Any], key_bytes: bytes, v: int = 1) -> Dict[str, Any]:
    _assert_public_key(public_key)
    if not _is_bytes(key_bytes) or len(key_bytes) != 32:
        raise RecordsAsymmetricError("KEY_WRAP_BINDING_INVALID")
    info = key_wrap_info_v2(binding) if v == 2 else key_wrap_info(binding)
    try:
        hybrid = _hybrid_public_key(public_key)
    except Exception:
        raise RecordsAsymmetricError("WORKSPACE_PUBLIC_KEY_INVALID") from None
    sealed = _SUITE.encrypt(bytes(key_bytes), hybrid, info=info)
    return {
        "v": v,
        "suite": KEY_WRAP_SUITE,
        "to": public_key_id(public_key),
        "enc": b64url_encode(sealed[:KEY_WRAP_ENC_BYTES]),
        "ct": b64url_encode(sealed[KEY_WRAP_ENC_BYTES:]),
    }


def wrap_records_key(public_key: bytes, records_key: RecordsKey) -> Dict[str, Any]:
    """``K_v``, wrapped to a workspace-scope holder's confirmed public key."""
    if not isinstance(records_key, RecordsKey):
        raise RecordsEncryptionError("RECORDS_KEY_INVALID")
    return _seal_key_wrap(public_key, {"purpose": "records-key", "recordsKeyId": records_key.id}, export_key_bytes(records_key))


def wrap_record_key(public_key: bytes, record_key: RecordKey, record_type: str, wire_record_id: str) -> Dict[str, Any]:
    """One record's ``RK``, wrapped to a record-scope holder or a counterparty."""
    if not isinstance(record_key, RecordKey):
        raise RecordsEncryptionError("RECORDS_KEY_INVALID")
    binding = {"purpose": "record-key", "recordType": record_type, "wireRecordId": wire_record_id}
    return _seal_key_wrap(public_key, binding, export_key_bytes(record_key))


def wrap_disclosure_key(public_key: bytes, disclosure_key: bytes, handle: str) -> Dict[str, Any]:
    """A disclosure key, wrapped to a reader's confirmed public key."""
    return _seal_key_wrap(public_key, {"purpose": "disclosure-key", "handle": handle}, disclosure_key)


def read_key_wrap_shape(wrap: Any, form: int = 1) -> Dict[str, Any]:
    """The keyless checks every reader runs first; ``form`` 2 reads a wrap v2 only. Never raises."""
    if not isinstance(wrap, dict) or sorted(wrap.keys()) != ["ct", "enc", "suite", "to", "v"]:
        return _refuse("KEY_WRAP_MALFORMED")
    v = wrap["v"]
    if not (type(v) in (int, float) and v == form) or not isinstance(wrap["suite"], str):
        return _refuse("KEY_WRAP_MALFORMED")
    if wrap["suite"] != KEY_WRAP_SUITE:
        return _refuse("KEY_WRAP_SUITE")
    if not isinstance(wrap["to"], str) or _HEX64.fullmatch(wrap["to"]) is None:
        return _refuse("KEY_WRAP_MALFORMED")
    enc, ct = b64url_decode(wrap["enc"]), b64url_decode(wrap["ct"])
    if enc is None or len(enc) != KEY_WRAP_ENC_BYTES or ct is None or len(ct) != KEY_WRAP_CT_BYTES:
        return _refuse("KEY_WRAP_MALFORMED")
    return {"ok": True, "to": wrap["to"], "enc": enc, "ct": ct}


def _open_key_wrap(seed: Any, wrap: Any, binding: Dict[str, Any], form: int = 1) -> Dict[str, Any]:
    shape = read_key_wrap_shape(wrap, form)
    if not shape["ok"]:
        return shape
    if not isinstance(seed, WorkspaceSeed) or shape["to"] != seed.public_key_id:
        return _refuse("KEY_WRAP_WRONG_HOLDER")
    try:
        info = key_wrap_info_v2(binding) if form == 2 else key_wrap_info(binding)
    except Exception:
        return _refuse("KEY_WRAP_BINDING_INVALID")
    try:
        m, x = _xwing_halves(_held(seed, "WORKSPACE_SEED_INVALID"))
        key_bytes = _SUITE.decrypt(shape["enc"] + shape["ct"], hpke.MLKEM768X25519PrivateKey(m, x), info=info)
    except Exception:
        return _refuse("KEY_WRAP_AUTH_FAILED")
    if len(key_bytes) != 32:
        return _refuse("KEY_WRAP_AUTH_FAILED")
    return {"ok": True, "keyBytes": key_bytes}


def unwrap_records_key(seed: WorkspaceSeed, wrap: Any, version: int, records_key_id: str) -> Dict[str, Any]:
    """``K_v`` from a wrap, its id recomputed from the unwrapped bytes before use. Never raises."""
    try:
        if not isinstance(version, int) or isinstance(version, bool) or not 1 <= version <= _SAFE_MAX:
            return _refuse("KEY_WRAP_BINDING_INVALID")
        opened = _open_key_wrap(seed, wrap, {"purpose": "records-key", "recordsKeyId": records_key_id})
        if not opened["ok"]:
            return opened
        records_key = records_key_from_bytes(opened["keyBytes"], version)
        if records_key.id != records_key_id:
            return _refuse("KEY_WRAP_KEY_MISMATCH")
        return {"ok": True, "recordsKey": records_key}
    except Exception:
        return _refuse("KEY_WRAP_AUTH_FAILED")


def unwrap_record_key(seed: WorkspaceSeed, wrap: Any, record_type: str, wire_record_id: str) -> Dict[str, Any]:
    """One record's ``RK`` from a wrap. Never raises."""
    try:
        opened = _open_key_wrap(seed, wrap, {"purpose": "record-key", "recordType": record_type, "wireRecordId": wire_record_id})
        if not opened["ok"]:
            return opened
        return {"ok": True, "recordKey": record_key_from_bytes(opened["keyBytes"])}
    except Exception:
        return _refuse("KEY_WRAP_AUTH_FAILED")


def unwrap_disclosure_key(seed: WorkspaceSeed, wrap: Any, handle: str) -> Dict[str, Any]:
    """A disclosure key from a wrap. Never raises."""
    try:
        opened = _open_key_wrap(seed, wrap, {"purpose": "disclosure-key", "handle": handle})
        if not opened["ok"]:
            return opened
        return {"ok": True, "disclosureKey": opened["keyBytes"]}
    except Exception:
        return _refuse("KEY_WRAP_AUTH_FAILED")


# ------------------------------------------------------------ wraps v2 (card 10, F3)

# A workspace id as PacSpace makes them (cuid): checked before it is hashed.
KEY_WRAP_OWNER_V2 = re.compile(r"[a-z0-9]{20,32}")


def _binding_bytes_v2(binding: Any) -> bytes:
    owner = binding.get("owner") if isinstance(binding, dict) else None
    if not isinstance(owner, str) or KEY_WRAP_OWNER_V2.fullmatch(owner) is None:
        raise RecordsAsymmetricError("KEY_WRAP_BINDING_INVALID")
    head = owner.encode("ascii") + _SEP
    purpose = binding.get("purpose")
    if purpose == "records-key":
        version, key_id = binding.get("version"), binding.get("recordsKeyId")
        if type(version) is int and 1 <= version <= 0xFFFF and isinstance(key_id, str) and _HEX64.fullmatch(key_id):
            return head + version.to_bytes(2, "big") + bytes.fromhex(key_id)
    elif purpose == "record-key":
        record_type, wire_id, rkid = binding.get("recordType"), binding.get("wireRecordId"), binding.get("recordKeyId")
        if (
            isinstance(record_type, str)
            and _PRINTABLE_ASCII.fullmatch(record_type)
            and isinstance(wire_id, str)
            and _WIRE_ID.fullmatch(wire_id)
            and isinstance(rkid, str)
            and _HEX64.fullmatch(rkid)
        ):
            return head + record_type.encode("ascii") + _SEP + wire_id.encode("ascii") + _SEP + bytes.fromhex(rkid)
    elif purpose == "disclosure-key":
        handle = binding.get("handle")
        if isinstance(handle, str) and _PRINTABLE_ASCII.fullmatch(handle):
            return head + handle.encode("ascii")
    raise RecordsAsymmetricError("KEY_WRAP_BINDING_INVALID")


def key_wrap_info_v2(binding: Dict[str, Any]) -> bytes:
    """``"pacspace:wrap:v2" || 0x00 || purpose || 0x00 || SHA-256(binding)``; the binding names the owner."""
    data = _binding_bytes_v2(binding)
    return LABELS["wrapV2"].encode("ascii") + _SEP + binding["purpose"].encode("ascii") + _SEP + hashlib.sha256(data).digest()


def wrap_records_key_v2(public_key: bytes, records_key: RecordsKey, owner: str) -> Dict[str, Any]:
    """``K_v``, wrapped to a workspace-scope holder of ``owner``'s records."""
    if not isinstance(records_key, RecordsKey):
        raise RecordsEncryptionError("RECORDS_KEY_INVALID")
    binding = {"purpose": "records-key", "owner": owner, "version": records_key.version, "recordsKeyId": records_key.id}
    return _seal_key_wrap(public_key, binding, export_key_bytes(records_key), 2)


def wrap_record_key_v2(public_key: bytes, record_key: RecordKey, record_type: str, wire_record_id: str, owner: str) -> Dict[str, Any]:
    """One of ``owner``'s records' ``RK``, wrapped to a record-scope holder or a counterparty."""
    if not isinstance(record_key, RecordKey):
        raise RecordsEncryptionError("RECORDS_KEY_INVALID")
    binding = {"purpose": "record-key", "owner": owner, "recordType": record_type, "wireRecordId": wire_record_id, "recordKeyId": record_key.id}
    return _seal_key_wrap(public_key, binding, export_key_bytes(record_key), 2)


def wrap_disclosure_key_v2(public_key: bytes, disclosure_key: bytes, handle: str, owner: str) -> Dict[str, Any]:
    """A disclosure key ``owner`` made, wrapped to a reader's confirmed public key."""
    return _seal_key_wrap(public_key, {"purpose": "disclosure-key", "owner": owner, "handle": handle}, disclosure_key, 2)


def unwrap_records_key_v2(seed: WorkspaceSeed, wrap: Any, owner: str, version: int, records_key_id: str) -> Dict[str, Any]:
    """``K_v`` of ``owner`` from a wrap v2, its id recomputed from the bytes. Never raises."""
    try:
        binding = {"purpose": "records-key", "owner": owner, "version": version, "recordsKeyId": records_key_id}
        opened = _open_key_wrap(seed, wrap, binding, 2)
        if not opened["ok"]:
            return opened
        records_key = records_key_from_bytes(opened["keyBytes"], version)
        if records_key.id != records_key_id:
            return _refuse("KEY_WRAP_KEY_MISMATCH")
        return {"ok": True, "recordsKey": records_key}
    except Exception:
        return _refuse("KEY_WRAP_AUTH_FAILED")


def unwrap_record_key_v2(seed: WorkspaceSeed, wrap: Any, owner: str, record_type: str, wire_record_id: str, record_key_id: str) -> Dict[str, Any]:
    """One of ``owner``'s records' ``RK`` from a wrap v2; its id must be ``record_key_id``. Never raises."""
    try:
        binding = {"purpose": "record-key", "owner": owner, "recordType": record_type, "wireRecordId": wire_record_id, "recordKeyId": record_key_id}
        opened = _open_key_wrap(seed, wrap, binding, 2)
        if not opened["ok"]:
            return opened
        record_key = record_key_from_bytes(opened["keyBytes"])
        if record_key.id != record_key_id:
            return _refuse("KEY_WRAP_KEY_MISMATCH")
        return {"ok": True, "recordKey": record_key}
    except Exception:
        return _refuse("KEY_WRAP_AUTH_FAILED")


def unwrap_disclosure_key_v2(seed: WorkspaceSeed, wrap: Any, owner: str, handle: str) -> Dict[str, Any]:
    """A disclosure key ``owner`` made, from a wrap v2. Never raises."""
    try:
        opened = _open_key_wrap(seed, wrap, {"purpose": "disclosure-key", "owner": owner, "handle": handle}, 2)
        if not opened["ok"]:
            return opened
        return {"ok": True, "disclosureKey": opened["keyBytes"]}
    except Exception:
        return _refuse("KEY_WRAP_AUTH_FAILED")


# ------------------------------------------------------------------ ML-DSA-65


def mldsa_signing_key_from_seed(seed: bytes) -> MldsaSigningKey:
    """The signing key a 32-byte seed makes (FIPS 204 ML-DSA.KeyGen_internal)."""
    if not _is_bytes(seed) or len(seed) != MLDSA65_SEED_BYTES:
        raise RecordsAsymmetricError("MLDSA_KEY_INVALID")
    public_key = mldsa.MLDSA65PrivateKey.from_seed_bytes(bytes(seed)).public_key().public_bytes_raw()
    return MldsaSigningKey(bytes(seed), public_key)


def generate_mldsa_signing_key() -> MldsaSigningKey:
    """A new signing key from 32 random bytes this code draws."""
    return mldsa_signing_key_from_seed(os.urandom(MLDSA65_SEED_BYTES))


def export_mldsa_seed_bytes(key: MldsaSigningKey) -> bytes:
    """The seed's 32 bytes, for storage on the key-page origin and the published vectors."""
    return bytes(_held(key, "MLDSA_KEY_INVALID"))


def sign_mldsa65(key: MldsaSigningKey, message: bytes) -> bytes:
    """ML-DSA-65 over the message, hedged (FIPS 204's default), empty context."""
    if not isinstance(key, MldsaSigningKey) or not _is_bytes(message):
        raise RecordsAsymmetricError("MLDSA_KEY_INVALID")
    return mldsa.MLDSA65PrivateKey.from_seed_bytes(_held(key, "MLDSA_KEY_INVALID")).sign(bytes(message))


def verify_mldsa65(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Sizes first, then the signature, empty context. Never raises."""
    try:
        if not _is_bytes(public_key) or len(public_key) != MLDSA65_PUBLIC_KEY_BYTES:
            return False
        if not _is_bytes(signature) or len(signature) != MLDSA65_SIGNATURE_BYTES or not _is_bytes(message):
            return False
        mldsa.MLDSA65PublicKey.from_public_bytes(bytes(public_key)).verify(bytes(signature), bytes(message))
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False
