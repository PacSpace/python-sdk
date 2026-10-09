"""Level 2's symmetric layer (ADR 0015, formats note N1 to N8), as the
TypeScript in packages/shared/src/records-crypto/records-encryption-v1.ts
and records/record-history-bundle-v3.ts does it, against the same vectors.

This module imports only the standard library, so AES-256-GCM is not here: every
call that seals or opens an envelope takes an ``aead`` with ``encrypt(key,
iv, plaintext, aad)`` and ``decrypt(key, iv, sealed, aad)``, the second
raising on a bad tag. Everything around it is here: the derivations, wire
ids, the content tag, padding and its checks, the envelope's shape, the
caps, the outside-copy check, the keyring file, and opening a history or a
copy file up to each entry's record hash. Python has no keccak256, so the
bundle digest, the receipt forms and the seals are the TypeScript
verifier's and the checker's.

No key's bytes are printed: key objects keep them in a module table, so
``repr`` and ``str`` show the version and the id only. Refusals carry a code
and no sentence; nothing here logs.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import os
import re
import weakref
from typing import Any, Dict, List, Optional, Protocol, Sequence, Tuple, Union

from .record_disclosure import _is_hex32, _utf8, canonicalize_jcs, commit_record_content_v2

LABELS = {
    "idKey": "pacspace:id-key:v1",
    "recordsKey": "pacspace:records-key:v1",
    "wrapKey": "pacspace:wrap-key:v1",
    "recordKey": "pacspace:record-key:v1",
    "recordsKeyId": "pacspace:records-key-id:v1",
    "wrapKeyId": "pacspace:wrap-key-id:v1",
    "recordKeyId": "pacspace:record-key-id:v1",
    "recordId": "pacspace:record-id:v1",
    "referenceId": "pacspace:reference-id:v1",
    "contentTag": "pacspace:content-tag:v1",
    "entry": "pacspace:record-entry:v1",
}

PAD_BLOCK = 256
PLAINTEXT_MAX_BYTES = 47104
CIPHERTEXT_MAX_BYTES = PLAINTEXT_MAX_BYTES + 16
CIPHERTEXT_MAX_CHARS = math.ceil(CIPHERTEXT_MAX_BYTES * 4 / 3)
BODY_MAX_BYTES = 65536
KEYRING_MAX_BYTES = 65536
KEYRING_SCHEMA = "pacspace-workspace-secret/v1"
WORKSPACE_SECRET_BYTES = 32

SEMANTIC_RECEIPT_SCHEMA_V3 = "semantic-receipt/v3"
SEMANTIC_RECEIPT_SCHEMA_V4 = "semantic-receipt/v4"
RECORD_HISTORY_BUNDLE_SCHEMA_V3 = "record-history-bundle/v3"
RECORD_COPY_SCHEMA_V1 = "pacspace-record-copy/v1"

_KEY_BYTES = 32
_IV_BYTES = 12
_TAG_BYTES = 16
_SEP = b"\x00"
_SPACE = 0x20
_HEX64 = re.compile(r"[0-9a-f]{64}")
_WIRE_ID = re.compile(r"[A-Za-z0-9_-]{22}")
_B64URL = re.compile(r"[A-Za-z0-9_-]*")
_SAFE_MAX = 9007199254740991


class RecordsEncryptionError(ValueError):
    """Raised by the writing side only; its message is the code."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class Aead(Protocol):
    def encrypt(self, key: bytes, iv: bytes, plaintext: bytes, aad: bytes) -> bytes: ...

    def decrypt(self, key: bytes, iv: bytes, sealed: bytes, aad: bytes) -> bytes: ...


def _refuse(code: str, seq: Optional[int] = None) -> Dict[str, Any]:
    return {"ok": False, "code": code} if seq is None else {"ok": False, "code": code, "seq": seq}


# --------------------------------------------------------------- base64url


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64url_decode(text: Any) -> Optional[bytes]:
    """Canonical unpadded base64url only, or None."""
    if not isinstance(text, str) or _B64URL.fullmatch(text) is None or len(text) % 4 == 1:
        return None
    data = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    return data if b64url_encode(data) == text else None


def _b64url_length(byte_count: int) -> int:
    return math.ceil(byte_count * 4 / 3)


# --------------------------------------------------------------------- keys

_HELD: "weakref.WeakKeyDictionary[_HiddenKey, bytes]" = weakref.WeakKeyDictionary()


class _HiddenKey:
    __slots__ = ("__weakref__", "id", "version")
    _kind = "key"

    def __init__(self, data: bytes, key_id: Optional[str], version: Optional[int]) -> None:
        _HELD[self] = bytes(data)
        self.id = key_id
        self.version = version

    def __repr__(self) -> str:
        version = "" if self.version is None else f" v{self.version}"
        key_id = "" if self.id is None else f" {self.id[:8]}"
        return f"[{self._kind}{version}{key_id}]"

    __str__ = __repr__


class RecordsIdKey(_HiddenKey):
    __slots__ = ()
    _kind = "records id key"


class RecordsKey(_HiddenKey):
    __slots__ = ()
    _kind = "records key"


class RecordsWrapKey(_HiddenKey):
    __slots__ = ()
    _kind = "wrap key"


class RecordKey(_HiddenKey):
    __slots__ = ("records_key_id",)
    _kind = "record key"

    def __init__(self, data: bytes, key_id: str, records_key_id: Optional[str]) -> None:
        super().__init__(data, key_id, None)
        self.records_key_id = records_key_id


def export_key_bytes(key: _HiddenKey) -> bytes:
    """A key's raw bytes, for a copy file, a wrap to a holder, and the published vectors."""
    return bytes(_HELD[key])


def _bytes_of(key: _HiddenKey) -> bytes:
    return _HELD[key]


# --------------------------------------------------------------- derivations


def _hkdf32(ikm: bytes, salt: bytes, info: str) -> bytes:
    prk = hmac.new(salt or b"\x00" * 32, ikm, hashlib.sha256).digest()
    return hmac.new(prk, info.encode("ascii") + b"\x01", hashlib.sha256).digest()


def _key_id(label: str, key: bytes) -> str:
    return hashlib.sha256(label.encode("ascii") + _SEP + key).hexdigest()


def _assert_secret(secret: Any, version: Any) -> None:
    if not isinstance(secret, (bytes, bytearray)) or len(secret) != WORKSPACE_SECRET_BYTES:
        raise RecordsEncryptionError("RECORDS_KEY_INVALID")
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        raise RecordsEncryptionError("RECORDS_KEY_INVALID")


def generate_workspace_secret() -> bytes:
    """32 fresh random bytes: a new workspace secret. It is the customer's; it never reaches PacSpace."""
    return os.urandom(WORKSPACE_SECRET_BYTES)


def derive_records_id_key(secret_v1: bytes) -> RecordsIdKey:
    _assert_secret(secret_v1, 1)
    return RecordsIdKey(_hkdf32(bytes(secret_v1), b"", LABELS["idKey"]), None, None)


def derive_records_keys(secret: bytes, version: int) -> Tuple[RecordsKey, RecordsWrapKey]:
    _assert_secret(secret, version)
    k = _hkdf32(bytes(secret), b"", LABELS["recordsKey"])
    w = _hkdf32(bytes(secret), b"", LABELS["wrapKey"])
    return (
        RecordsKey(k, _key_id(LABELS["recordsKeyId"], k), version),
        RecordsWrapKey(w, _key_id(LABELS["wrapKeyId"], w), version),
    )


def record_key_of(records_key: RecordsKey, wire_record_id: str) -> RecordKey:
    if not isinstance(records_key, RecordsKey) or not isinstance(wire_record_id, str) or _WIRE_ID.fullmatch(wire_record_id) is None:
        raise RecordsEncryptionError("RECORDS_KEY_INVALID")
    rk = _hkdf32(_bytes_of(records_key), wire_record_id.encode("ascii"), LABELS["recordKey"])
    return RecordKey(rk, _key_id(LABELS["recordKeyId"], rk), records_key.id)


def records_key_from_bytes(data: bytes, version: int) -> RecordsKey:
    """``K_v`` that arrived in a wrap: 32 bytes, its id recomputed from them."""
    if not isinstance(data, (bytes, bytearray)) or len(data) != _KEY_BYTES:
        raise RecordsEncryptionError("RECORDS_KEY_INVALID")
    if not isinstance(version, int) or isinstance(version, bool) or not 1 <= version <= _SAFE_MAX:
        raise RecordsEncryptionError("RECORDS_KEY_INVALID")
    return RecordsKey(bytes(data), _key_id(LABELS["recordsKeyId"], bytes(data)), version)


def record_key_from_bytes(data: bytes, records_key_id: Optional[str] = None) -> RecordKey:
    """``RK`` that arrived as bytes, with the version's id when it is known."""
    if not isinstance(data, (bytes, bytearray)) or len(data) != _KEY_BYTES:
        raise RecordsEncryptionError("RECORDS_KEY_INVALID")
    if records_key_id is not None and (not isinstance(records_key_id, str) or _HEX64.fullmatch(records_key_id) is None):
        raise RecordsEncryptionError("RECORDS_KEY_INVALID")
    return RecordKey(bytes(data), _key_id(LABELS["recordKeyId"], bytes(data)), records_key_id)


# -------------------------------------------------- wire ids and the content tag


def _wire16(id_key: RecordsIdKey, message: bytes) -> str:
    return b64url_encode(hmac.new(_bytes_of(id_key), message, hashlib.sha256).digest()[:16])


def wire_record_id(id_key: RecordsIdKey, record_type: str, entity_id: str) -> str:
    return _wire16(id_key, LABELS["recordId"].encode("ascii") + _SEP + _utf8(record_type) + _SEP + _utf8(entity_id))


def wire_reference_id(id_key: RecordsIdKey, reference_id: str) -> str:
    return _wire16(id_key, LABELS["referenceId"].encode("ascii") + _SEP + _utf8(reference_id))


def content_tag(id_key: RecordsIdKey, record_type: str, wire_record_id: str, content: Dict[str, Any], lifecycle: str) -> str:
    message = (
        LABELS["contentTag"].encode("ascii") + _SEP + _utf8(record_type) + _SEP + _utf8(wire_record_id) + _SEP
        + _utf8(canonicalize_jcs({"content": content, "lifecycle": lifecycle}))
    )
    return b64url_encode(hmac.new(_bytes_of(id_key), message, hashlib.sha256).digest())


# ------------------------------------------------------------------ envelope


def record_entry_plaintext(content: Dict[str, Any], salt_key: str) -> bytes:
    if not isinstance(content, dict) or not _is_hex32(salt_key):
        raise RecordsEncryptionError("RECORD_ENTRY_MALFORMED")
    plaintext = _utf8(canonicalize_jcs({"content": content, "saltKey": salt_key}))
    if len(plaintext) > PLAINTEXT_MAX_BYTES:
        raise RecordsEncryptionError("RECORD_ENTRY_TOO_LARGE")
    return plaintext


def pad_record_entry(plaintext: bytes) -> bytes:
    return plaintext + b" " * (-len(plaintext) % PAD_BLOCK)


def _aad(record_type: str, wire_record_id: str) -> bytes:
    return LABELS["entry"].encode("ascii") + _SEP + _utf8(record_type) + _SEP + _utf8(wire_record_id)


def _seal_padded_entry(
    aead: Aead, record_key: RecordKey, records_key_id: str, record_type: str, wire_record_id: str, padded: bytes, iv: bytes
) -> Dict[str, Any]:
    """Seals already padded bytes under a given IV; vectors and seal_record_entry only."""
    if _HEX64.fullmatch(records_key_id or "") is None or len(iv) != _IV_BYTES:
        raise RecordsEncryptionError("RECORDS_KEY_INVALID")
    sealed = aead.encrypt(_bytes_of(record_key), iv, padded, _aad(record_type, wire_record_id))
    return {"v": 1, "alg": "A256GCM", "kid": records_key_id, "iv": b64url_encode(iv), "ct": b64url_encode(sealed)}


def seal_record_entry(
    aead: Aead, record_key: RecordKey, record_type: str, wire_record_id: str, content: Dict[str, Any], salt_key: str
) -> Dict[str, Any]:
    """Seals one entry under its record key with a fresh IV. The record key must come from a records key."""
    if not isinstance(record_key, RecordKey) or record_key.records_key_id is None:
        raise RecordsEncryptionError("RECORDS_KEY_INVALID")
    padded = pad_record_entry(record_entry_plaintext(content, salt_key))
    return _seal_padded_entry(aead, record_key, record_key.records_key_id, record_type, wire_record_id, padded, os.urandom(_IV_BYTES))


def read_record_envelope_shape(envelope: Any) -> Dict[str, Any]:
    """The keyless checks every reader runs first. Never raises."""
    if not isinstance(envelope, dict) or sorted(envelope.keys()) != ["alg", "ct", "iv", "kid", "v"]:
        return _refuse("RECORD_ENVELOPE_MALFORMED")
    v = envelope["v"]
    if not (type(v) in (int, float) and v == 1) or envelope["alg"] != "A256GCM":
        return _refuse("RECORD_ENVELOPE_MALFORMED")
    kid, iv_text, ct_text = envelope["kid"], envelope["iv"], envelope["ct"]
    if not isinstance(kid, str) or _HEX64.fullmatch(kid) is None:
        return _refuse("RECORD_ENVELOPE_MALFORMED")
    if not isinstance(ct_text, str) or not isinstance(iv_text, str):
        return _refuse("RECORD_ENVELOPE_MALFORMED")
    if len(ct_text) > CIPHERTEXT_MAX_CHARS:
        return _refuse("RECORD_ENVELOPE_TOO_LARGE")
    iv, ct = b64url_decode(iv_text), b64url_decode(ct_text)
    if iv is None or len(iv) != _IV_BYTES or ct is None:
        return _refuse("RECORD_ENVELOPE_MALFORMED")
    body = len(ct) - _TAG_BYTES
    if body <= 0 or body % PAD_BLOCK != 0:
        return _refuse("RECORD_ENVELOPE_MALFORMED")
    return {"ok": True, "kid": kid, "iv": iv, "ct": ct}


def _reject_constant(_: str) -> Any:
    raise ValueError("not JSON")


def _unpad(plain: bytes) -> Dict[str, Any]:
    end = len(plain)
    while end > 0 and plain[end - 1] == _SPACE:
        end -= 1
    if len(plain) - end >= PAD_BLOCK:
        return _refuse("RECORD_ENVELOPE_PADDING")
    trimmed = plain[:end]
    try:
        value = json.loads(trimmed.decode("utf-8"), parse_constant=_reject_constant)
        if _utf8(canonicalize_jcs(value)) != trimmed:
            return _refuse("RECORD_ENVELOPE_PADDING")
    except Exception:
        return _refuse("RECORD_ENVELOPE_PADDING")
    if not isinstance(value, dict) or sorted(value.keys()) != ["content", "saltKey"]:
        return _refuse("RECORD_ENVELOPE_PADDING")
    if not isinstance(value["content"], dict) or not _is_hex32(value["saltKey"]):
        return _refuse("RECORD_ENVELOPE_PADDING")
    return {"ok": True, "content": value["content"], "saltKey": value["saltKey"]}


def open_record_entry_envelope(
    aead: Aead,
    envelope: Any,
    record_type: str,
    wire_record_id: str,
    record_key: Optional[RecordKey] = None,
    keyring: Optional["RecordsKeyring"] = None,
) -> Dict[str, Any]:
    """Opens one envelope with a record key, or with a keyring whose records key ``kid`` names. Never raises."""
    shape = read_record_envelope_shape(envelope)
    if not shape["ok"]:
        return shape
    rk = record_key
    try:
        if keyring is not None:
            k = keyring.by_id(shape["kid"])
            if k is None:
                return _refuse("RECORD_ENVELOPE_WRONG_KEY")
            rk = record_key_of(k, wire_record_id)
        if not isinstance(rk, RecordKey):
            return _refuse("RECORD_ENVELOPE_AUTH_FAILED")
        aad = _aad(record_type, wire_record_id)
    except Exception:
        return _refuse("RECORD_ENVELOPE_PADDING")
    try:
        plain = aead.decrypt(_bytes_of(rk), shape["iv"], shape["ct"], aad)
    except Exception:
        return _refuse("RECORD_ENVELOPE_AUTH_FAILED")
    opened = _unpad(plain)
    if opened["ok"]:
        opened["recordsKeyId"] = shape["kid"]
    return opened


# ------------------------------------------------------------- the write body


def encrypted_write_body_bytes(body: Dict[str, Any], records_key_id: str, plaintext_bytes: int) -> int:
    padded = math.ceil(plaintext_bytes / PAD_BLOCK) * PAD_BLOCK
    envelope = {
        "v": 1,
        "alg": "A256GCM",
        "kid": records_key_id,
        "iv": "A" * _b64url_length(_IV_BYTES),
        "ct": "A" * _b64url_length(padded + _TAG_BYTES),
    }
    return len(_utf8(canonicalize_jcs({**body, "envelope": envelope})))


def check_encrypted_write_size(body: Dict[str, Any], records_key_id: str, plaintext_bytes: int) -> Dict[str, Any]:
    if plaintext_bytes > PLAINTEXT_MAX_BYTES:
        return {**_refuse("RECORD_ENTRY_TOO_LARGE"), "bodyBytes": None}
    body_bytes = encrypted_write_body_bytes(body, records_key_id, plaintext_bytes)
    if body_bytes > BODY_MAX_BYTES:
        return {**_refuse("RECORD_ENTRY_BODY_TOO_LARGE"), "bodyBytes": body_bytes}
    return {"ok": True, "bodyBytes": body_bytes}


_ABSENT = object()


def entry_refs_match(content: Dict[str, Any], outside: Dict[str, Any]) -> Dict[str, Any]:
    """``amends`` and ``references`` inside the content equal the copies outside the envelope."""
    try:
        for member in ("amends", "references"):
            inside = (content or {}).get(member, _ABSENT)
            out = (outside or {}).get(member, _ABSENT)
            a = None if inside is _ABSENT else canonicalize_jcs(inside)
            b = None if out is _ABSENT else canonicalize_jcs(out)
            if a != b:
                return _refuse("RECORD_ENTRY_REFS_MISMATCH")
        return {"ok": True}
    except Exception:
        return _refuse("RECORD_ENTRY_REFS_MISMATCH")


# ---------------------------------------------------------------- the keyring


class RecordsKeyProvider(Protocol):
    def versions(self) -> List[int]: ...

    def secret(self, version: int) -> bytes: ...


class RecordsKeyring:
    """Every version of a workspace's keys, made once from a provider."""

    __slots__ = ("id_key", "_by_id", "_by_version", "_wrap")

    def __init__(self, id_key: RecordsIdKey) -> None:
        self.id_key = id_key
        self._by_id: Dict[str, RecordsKey] = {}
        self._by_version: Dict[int, RecordsKey] = {}
        self._wrap: Dict[int, RecordsWrapKey] = {}

    @classmethod
    def from_provider(cls, provider: RecordsKeyProvider) -> "RecordsKeyring":
        versions = provider.versions()
        if not isinstance(versions, list) or not versions or any(v != i + 1 for i, v in enumerate(versions)):
            raise RecordsEncryptionError("RECORDS_KEY_INVALID")
        ring = cls(derive_records_id_key(provider.secret(1)))
        for version in versions:
            records_key, wrap_key = derive_records_keys(provider.secret(version), version)
            ring._by_id[records_key.id] = records_key
            ring._by_version[version] = records_key
            ring._wrap[version] = wrap_key
        return ring

    @property
    def current(self) -> RecordsKey:
        return self._by_version[len(self._by_version)]

    @property
    def versions(self) -> List[int]:
        return list(self._by_version.keys())

    def by_id(self, key_id: str) -> Optional[RecordsKey]:
        return self._by_id.get(key_id)

    def by_version(self, version: int) -> Optional[RecordsKey]:
        return self._by_version.get(version)

    def wrap_key(self, version: int) -> Optional[RecordsWrapKey]:
        return self._wrap.get(version)

    def __repr__(self) -> str:
        return f"[records keyring v1..v{len(self._by_version)}]"

    __str__ = __repr__


class _LocalProvider:
    __slots__ = ("_held",)

    def __init__(self, secrets: Sequence[Tuple[int, bytes]]) -> None:
        self._held = {version: bytes(secret) for version, secret in secrets}

    def versions(self) -> List[int]:
        return list(self._held.keys())

    def secret(self, version: int) -> bytes:
        if version not in self._held:
            raise RecordsEncryptionError("RECORDS_KEY_INVALID")
        return bytes(self._held[version])

    def __repr__(self) -> str:
        return f"[local records key provider v1..v{len(self._held)}]"

    __str__ = __repr__


def _secrets_are_a_keyring(secrets: Sequence[Tuple[Any, Any]]) -> bool:
    return len(secrets) > 0 and all(
        version == i + 1 and isinstance(secret, (bytes, bytearray)) and len(secret) == WORKSPACE_SECRET_BYTES
        for i, (version, secret) in enumerate(secrets)
    )


def local_records_key_provider(source: Union[str, Sequence[Tuple[int, bytes]]]) -> _LocalProvider:
    """A provider over secrets held in memory: a keyring file's text, or ``(version, secret)`` pairs."""
    if isinstance(source, str):
        parsed = parse_records_keyring_file(source)
        if not parsed["ok"]:
            raise RecordsEncryptionError(parsed["code"])
        secrets = parsed["secrets"]
    else:
        secrets = [(version, bytes(secret)) for version, secret in source]
        if not _secrets_are_a_keyring(secrets):
            raise RecordsEncryptionError("RECORDS_KEY_INVALID")
    return _LocalProvider(secrets)


def serialize_records_keyring_file(secrets: Sequence[Tuple[int, bytes]]) -> str:
    if not _secrets_are_a_keyring(secrets):
        raise RecordsEncryptionError("RECORDS_KEY_INVALID")
    return canonicalize_jcs(
        {"schema": KEYRING_SCHEMA, "secrets": [{"version": v, "secret": b64url_encode(bytes(s))} for v, s in secrets]}
    )


def _safe_integer(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, float) and value.is_integer():
        value = int(value)
    if isinstance(value, int) and -_SAFE_MAX <= value <= _SAFE_MAX:
        return value
    return None


def parse_records_keyring_file(text: Any) -> Dict[str, Any]:
    """Reads a keyring file: any JSON of the shape, up to 65,536 bytes. Never raises."""
    if not isinstance(text, str):
        return _refuse("RECORDS_KEYRING_MALFORMED")
    if len(_utf8(text)) > KEYRING_MAX_BYTES:
        return _refuse("RECORDS_KEYRING_TOO_LARGE")
    try:
        doc = json.loads(text, parse_constant=_reject_constant)
    except Exception:
        return _refuse("RECORDS_KEYRING_MALFORMED")
    if not isinstance(doc, dict) or sorted(doc.keys()) != ["schema", "secrets"]:
        return _refuse("RECORDS_KEYRING_MALFORMED")
    if doc["schema"] != KEYRING_SCHEMA or not isinstance(doc["secrets"], list):
        return _refuse("RECORDS_KEYRING_MALFORMED")
    secrets: List[Tuple[int, bytes]] = []
    for item in doc["secrets"]:
        if not isinstance(item, dict) or sorted(item.keys()) != ["secret", "version"]:
            return _refuse("RECORDS_KEYRING_MALFORMED")
        version = _safe_integer(item["version"])
        data = b64url_decode(item["secret"])
        if version is None or data is None:
            return _refuse("RECORDS_KEYRING_MALFORMED")
        secrets.append((version, data))
    if not _secrets_are_a_keyring(secrets):
        return _refuse("RECORDS_KEYRING_MALFORMED")
    return {"ok": True, "secrets": secrets}


# ------------------------------------------ receipts, histories and copy files


def _record_hash_of(content: Dict[str, Any], salt_key: str) -> Optional[str]:
    try:
        return commit_record_content_v2(content, salt_key)["recordHash"]
    except Exception:
        return None


def _seq_of(value: Any) -> Optional[int]:
    seq = value.get("seq") if isinstance(value, dict) else None
    return seq if isinstance(seq, int) and not isinstance(seq, bool) else None


def open_receipt_v4(aead: Aead, receipt: Any, record_key: RecordKey, record_type: str, wire_record_id: str) -> Dict[str, Any]:
    """The envelope this record key opens (each in turn), its record hash, and the outside copies of the references."""
    seq = _seq_of(receipt)
    if (
        not isinstance(receipt, dict)
        or receipt.get("schema") != SEMANTIC_RECEIPT_SCHEMA_V4
        or receipt.get("itemKind") != "slot-v1"
        or not _is_hex32(receipt.get("recordHash"))
        or not isinstance(receipt.get("envelopes"), list)
        or not receipt["envelopes"]
    ):
        return _refuse("RECORD_HISTORY_RECEIPT_FORM", seq)
    kids = [e.get("kid") if isinstance(e, dict) else None for e in receipt["envelopes"]]
    if len({json.dumps(k) for k in kids}) != len(kids):
        return _refuse("RECORD_ENVELOPE_MALFORMED", seq)
    last = _refuse("RECORD_ENVELOPE_AUTH_FAILED", seq)
    for envelope in receipt["envelopes"]:
        opened = open_record_entry_envelope(aead, envelope, record_type, wire_record_id, record_key=record_key)
        if not opened["ok"]:
            if opened["code"] != "RECORD_ENVELOPE_AUTH_FAILED":
                return _refuse(opened["code"], seq)
            last = _refuse(opened["code"], seq)
            continue
        record_hash = _record_hash_of(opened["content"], opened["saltKey"])
        if record_hash is None or record_hash != receipt["recordHash"]:
            return _refuse("RECORD_ENTRY_HASH_MISMATCH", seq)
        outside = {m: receipt[m] for m in ("amends", "references") if m in receipt}
        refs = entry_refs_match(opened["content"], outside)
        if not refs["ok"]:
            return _refuse(refs["code"], seq)
        return {"ok": True, "recordHash": record_hash, "content": opened["content"], "saltKey": opened["saltKey"]}
    return last


def open_record_history_v3(
    aead: Aead,
    bundle: Any,
    record_key: RecordKey,
    expect: Optional[Dict[str, str]] = None,
    record_keys: Optional[Sequence[RecordKey]] = None,
) -> Dict[str, Any]:
    """
    Opens a record-history-bundle/v3 with the record's key: every v4 entry and
    every refused envelope, each up to its record hash. It does not check the
    bundle digest, the receipt forms or the seals (see the module note).

    A re-key leaves an attempt's refused envelope under its original version.
    It is opened with the held key its ``kid`` names (``record_key`` or one of
    ``record_keys``); one no held key opens is ``opened: False``, and the
    history is still read.
    """
    if (
        not isinstance(bundle, dict)
        or bundle.get("schema") != RECORD_HISTORY_BUNDLE_SCHEMA_V3
        or not isinstance(bundle.get("receipts"), list)
        or not isinstance(bundle.get("refused"), list)
    ):
        return _refuse("RECORD_HISTORY_RECEIPT_FORM")
    record_type, entity_id = bundle.get("recordType"), bundle.get("entityId")
    if not isinstance(record_type, str) or not isinstance(entity_id, str):
        return _refuse("RECORD_HISTORY_RECEIPT_FORM")
    if expect is not None and (record_type != expect.get("recordType") or entity_id != expect.get("wireRecordId")):
        return _refuse("RECORD_HISTORY_WRONG_RECORD")
    receipts = bundle["receipts"]
    for receipt in receipts:
        if _seq_of(receipt) is None or receipt.get("schema") not in (SEMANTIC_RECEIPT_SCHEMA_V3, SEMANTIC_RECEIPT_SCHEMA_V4):
            return _refuse("RECORD_HISTORY_RECEIPT_FORM", _seq_of(receipt))

    opened: List[Dict[str, Any]] = []
    for receipt in sorted(receipts, key=lambda r: r["seq"]):
        if receipt["schema"] == SEMANTIC_RECEIPT_SCHEMA_V4:
            entry = open_receipt_v4(aead, receipt, record_key, record_type, entity_id)
            if not entry["ok"]:
                return entry
            opened.append({"seq": receipt["seq"], "recordHash": entry["recordHash"], "content": entry["content"], "saltKey": entry["saltKey"]})
        else:
            opened.append({"seq": receipt["seq"], "plaintext": True})

    row_seqs = {r["seq"] for r in receipts if r["schema"] == SEMANTIC_RECEIPT_SCHEMA_V3}
    held = [k for k in [record_key, *(record_keys or [])] if isinstance(k, RecordKey)]
    refused: List[Dict[str, Any]] = []
    for item in bundle["refused"]:
        seq = _seq_of(item)
        if (
            not isinstance(item, dict)
            or sorted(item.keys()) != ["envelope", "recordHash", "seq"]
            or seq not in row_seqs
            or not _is_hex32(item["recordHash"])
        ):
            return _refuse("RECORD_HISTORY_RECEIPT_FORM", seq)
        shape = read_record_envelope_shape(item["envelope"])
        if not shape["ok"]:
            return _refuse(shape["code"], seq)
        named = [k for k in held if k.records_key_id == shape["kid"]]
        entry: Optional[Dict[str, Any]] = None
        for key in named or [k for k in held if k.records_key_id is None]:
            entry = open_record_entry_envelope(aead, item["envelope"], record_type, entity_id, record_key=key)
            if entry["ok"] or entry["code"] != "RECORD_ENVELOPE_AUTH_FAILED":
                break
        if entry is None or (not entry["ok"] and entry["code"] == "RECORD_ENVELOPE_AUTH_FAILED" and not named):
            refused.append({"seq": seq, "recordHash": item["recordHash"], "opened": False})
            continue
        if not entry["ok"]:
            return _refuse(entry["code"], seq)
        record_hash = _record_hash_of(entry["content"], entry["saltKey"])
        if record_hash is None or record_hash != item["recordHash"]:
            return _refuse("RECORD_ENTRY_HASH_MISMATCH", seq)
        refused.append({"seq": seq, "recordHash": record_hash, "opened": True})
    return {"ok": True, "opened": opened, "refused": refused}


def read_record_copy_v1(copy: Any) -> Dict[str, Any]:
    """A pacspace-record-copy/v1 file's shape and its record key. Never raises."""
    if not isinstance(copy, dict) or sorted(copy.keys()) != ["history", "recordKey", "schema"]:
        return _refuse("RECORD_COPY_MALFORMED")
    if copy["schema"] != RECORD_COPY_SCHEMA_V1 or not isinstance(copy["recordKey"], str):
        return _refuse("RECORD_COPY_MALFORMED")
    data = b64url_decode(copy["recordKey"])
    if data is None or len(data) != _KEY_BYTES:
        return _refuse("RECORD_COPY_MALFORMED")
    history = copy["history"]
    if not isinstance(history, dict) or not isinstance(history.get("bundleDigest"), str):
        return _refuse("RECORD_COPY_MALFORMED")
    return {"ok": True, "recordKey": record_key_from_bytes(data), "history": history}


def open_record_copy_v1(aead: Aead, copy: Any, expect: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """Opens a copy file's history with its own record key, as open_record_history_v3 does."""
    read = read_record_copy_v1(copy)
    if not read["ok"]:
        return read
    return open_record_history_v3(aead, read["history"], read["recordKey"], expect)
