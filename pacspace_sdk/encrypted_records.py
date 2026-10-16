"""The encrypted paths of ``pac.records`` (ADR 0015; L2d's design), as the
TypeScript SDK runs them. Keys stay in this process: requests carry wire ids,
record hashes, content tags, envelopes and wraps only.

Python reads up to each entry's record hash, as its other readers do: every
envelope is opened and its record hash recomputed, and the ``amends`` and
``references`` copies compared, but no seal or ledger is checked here.

This module runs on ``cryptography``; ``records.py`` imports it on first use,
so ``import pacspace_sdk`` does not load it.
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
from urllib.parse import quote

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import records_asymmetric as A
from . import records_encryption as R
from .errors import PacSpaceError
from .record_disclosure import RECORD_DISCLOSURE_MAX_BYTES_V1, canonicalize_jcs, commit_record_content_v2, commit_record_content_v3
from .records_admission import admit_record_entry
from .records_pins import RecordsPinStore
from .records_words import RecordsEncryptionError

RECORDS_SUPPORT_HEADER = "X-PacSpace-Records-Encryption"
RECORDS_GRANT_HEADER = "X-PacSpace-Grant"
RECORDS_HOLDER_HEADER = "X-PacSpace-Holder-For"
_ENCRYPTION = "/api/v1/records/encryption"

# Intake's sentences for the two caps (L2b), reused word for word before anything is sent.
_SIZE_WORDS = {
    "RECORD_ENTRY_TOO_LARGE": "An encrypted entry fits in 47,104 bytes once encoded. Reference bulk payloads by digest instead.",
    "RECORD_ENTRY_BODY_TOO_LARGE": "An encrypted write fits in 65,536 bytes. Shorten its references, or split the entry.",
}

SecretSource = Union[str, Dict[str, Any]]


class _AesGcm:
    def encrypt(self, key: bytes, iv: bytes, plaintext: bytes, aad: bytes) -> bytes:
        return AESGCM(key).encrypt(iv, plaintext, aad)

    def decrypt(self, key: bytes, iv: bytes, sealed: bytes, aad: bytes) -> bytes:
        return AESGCM(key).decrypt(iv, sealed, aad)


AEAD = _AesGcm()


def record_path(record_type: str, entity_id: str, suffix: str) -> str:
    return f"/api/v1/records/{quote(record_type, safe='')}/{quote(entity_id, safe='')}{suffix}"


def _unwrap(body: Any) -> Any:
    if isinstance(body, dict) and "schema" not in body and "data" in body:
        return body["data"]
    return body


def _api_body(error: BaseException) -> Dict[str, Any]:
    body = getattr(error, "api_body", None)
    return body if isinstance(body, dict) else {}


def read_refusal(refusal: Dict[str, Any]) -> PacSpaceError:
    """A refusal of the opener, as the SDK's sentence; entries count from 1."""
    seq = refusal.get("seq")
    entry = seq + 1 if isinstance(seq, int) else None
    code = refusal.get("code")
    if code == "RECORD_HISTORY_WRONG_RECORD":
        return RecordsEncryptionError("RECORDS_HISTORY_OTHER_RECORD")
    if code == "RECORD_ENTRY_HASH_MISMATCH":
        return RecordsEncryptionError("RECORDS_ENTRY_HASH_MISMATCH", seq=entry)
    if code == "RECORD_ENTRY_REFS_MISMATCH":
        return RecordsEncryptionError("RECORDS_ENTRY_REFS_MISMATCH", seq=entry)
    if entry is not None:
        return RecordsEncryptionError("RECORDS_ENTRY_UNOPENED", seq=entry)
    return PacSpaceError(str(code), 0, str(code))


def _receipts_of(history: Any) -> List[Dict[str, Any]]:
    receipts = history.get("receipts") if isinstance(history, dict) else None
    return [r for r in receipts if isinstance(r, dict)] if isinstance(receipts, list) else []


def _kids_of(receipts: List[Dict[str, Any]]) -> List[str]:
    kids: List[str] = []
    for receipt in receipts:
        for envelope in receipt.get("envelopes") or []:
            kid = envelope.get("kid") if isinstance(envelope, dict) else None
            if isinstance(kid, str) and kid not in kids:
                kids.append(kid)
    return kids


# ------------------------------------------------------------ the workspace secret


def _text_of(source: SecretSource) -> str:
    if isinstance(source, str):
        return source
    if not isinstance(source, dict) or not isinstance(source.get("secrets"), list):
        raise RecordsEncryptionError("RECORDS_SECRET_INVALID")
    pairs: List[Tuple[int, bytes]] = []
    for item in source["secrets"]:
        data = R.b64url_decode(str(item.get("secret")) if isinstance(item, dict) else None)
        if data is None:
            raise RecordsEncryptionError("RECORDS_SECRET_INVALID")
        pairs.append((item.get("version"), data))
    return R.serialize_records_keyring_file(pairs)


def keyring_of(source: SecretSource) -> Tuple[R.RecordsKeyring, str]:
    """Parses a workspace secret into a keyring, or refuses with W-L2d-24."""
    try:
        text = _text_of(source)
        return R.RecordsKeyring.from_provider(R.local_records_key_provider(text)), text
    except Exception:
        raise RecordsEncryptionError("RECORDS_SECRET_INVALID") from None


class RecordsKeys:
    """The client's workspace secret, loaded on first use. Without ``secret``
    or ``secret_provider`` nothing is configured and records are written as
    0.5.0 wrote them."""

    __slots__ = ("_secret", "_provider", "_loaded")

    def __init__(self, secret: Optional[SecretSource] = None, secret_provider: Optional[Callable[[], SecretSource]] = None) -> None:
        self._secret = secret
        self._provider = secret_provider
        self._loaded: Optional[Tuple[R.RecordsKeyring, str]] = None

    @property
    def configured(self) -> bool:
        return self._secret is not None or callable(self._provider)

    def ring(self) -> R.RecordsKeyring:
        """The keyring, or W-L2d-23 when no workspace secret is configured."""
        if not self.configured:
            raise RecordsEncryptionError("RECORDS_SECRET_REQUIRED")
        if self._loaded is None:
            source = self._secret if self._secret is not None else self._provider()  # type: ignore[misc]
            self._loaded = keyring_of(source)
        return self._loaded[0]

    def replace(self, loaded: Tuple[R.RecordsKeyring, str]) -> None:
        """After a rotation: the next keyring is used from here on."""
        self._loaded = loaded

    def __repr__(self) -> str:
        return "[records keys]"

    __str__ = __repr__


# ------------------------------------------------------------ disclosure links

_DISCLOSURE_AAD_LABEL = b"pacspace:record-disclosure:v1"
_DISCLOSURE_PAD_BLOCK = 4096
_DISCLOSURE_HEADER_BYTES = 13
_DISCLOSURE_ENVELOPE_MAX_CHARS = -(-((1 + 12 + RECORD_DISCLOSURE_MAX_BYTES_V1 + 16) * 4) // 3)
_DISCLOSURE_REASONS = {
    "DISCLOSURE_ENVELOPE_MALFORMED": "This link's sealed disclosure is not in a form this version can open.",
    "DISCLOSURE_ENVELOPE_TOO_LARGE": "This link's sealed disclosure is larger than a disclosure may be.",
    "DISCLOSURE_ENVELOPE_AUTH_FAILED": (
        "This disclosure could not be opened with this link. The link may be incomplete, or the disclosure belongs to another link."
    ),
}


def read_disclosure_fragment(fragment: str) -> Optional[bytes]:
    """The key in a link's ``#dk=`` part, or None."""
    if not isinstance(fragment, str):
        return None
    text = fragment[1:] if fragment.startswith("#") else fragment
    if not text.startswith("dk=") or len(text) != 46:
        return None
    key = R.b64url_decode(text[3:])
    return key if key is not None and len(key) == 32 else None


_LINK_FRAGMENT_V2 = re.compile(r"^(dk|dd)=([A-Za-z0-9_-]{43})$")


def read_link_fragment(fragment: str) -> Optional[Dict[str, Any]]:
    """A link's fragment in format 2: exactly one of ``dk=`` (the key) or
    ``dd=`` (the disclosure's digest, when the key comes from a wrap), as the
    shared ``readDisclosureLinkFragmentV2``. Anything else is None."""
    if not isinstance(fragment, str):
        return None
    match = _LINK_FRAGMENT_V2.fullmatch(fragment[1:] if fragment.startswith("#") else fragment)
    if match is None:
        return None
    raw = R.b64url_decode(match.group(2))
    if raw is None or len(raw) != 32 or R.b64url_encode(raw) != match.group(2):
        return None
    if match.group(1) == "dk":
        return {"kind": "key", "key": raw}
    return {"kind": "digest", "digest": "0x" + raw.hex()}


def disclosure_digest_fragment(digest: str) -> str:
    """``dd=`` plus the disclosure digest's 43 base64url characters."""
    if not isinstance(digest, str) or re.fullmatch(r"0x[0-9a-f]{64}", digest) is None:
        raise ValueError("DISCLOSURE_MALFORMED")
    return "dd=" + R.b64url_encode(bytes.fromhex(digest[2:]))


def disclosure_key_of(value: Union[bytes, str]) -> Optional[bytes]:
    """A disclosure key from bytes, a link, its ``#dk=`` part, or the key as base64url."""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value) if len(value) == 32 else None
    text = str(value).strip()
    if text.lower().startswith(("http:", "https:")):
        fragment = "#" + text.split("#", 1)[1] if "#" in text else ""
    elif text.startswith("#"):
        fragment = text
    elif text.startswith("dk="):
        fragment = "#" + text
    else:
        fragment = "#dk=" + text
    return read_disclosure_fragment(fragment)


def decrypt_disclosure(envelope: Any, key: bytes, handle: str) -> Dict[str, Any]:
    """Opens a link's sealed disclosure, as the shared ``decryptDisclosureV1``. Never raises."""

    def refuse(code: str) -> Dict[str, Any]:
        return {"ok": False, "code": code, "reason": _DISCLOSURE_REASONS[code]}

    try:
        if not isinstance(envelope, str):
            return refuse("DISCLOSURE_ENVELOPE_MALFORMED")
        if len(envelope) > _DISCLOSURE_ENVELOPE_MAX_CHARS:
            return refuse("DISCLOSURE_ENVELOPE_TOO_LARGE")
        data = R.b64url_decode(envelope)
        if data is None or data[:1] != b"\x01":
            return refuse("DISCLOSURE_ENVELOPE_MALFORMED")
        cipher_length = len(data) - _DISCLOSURE_HEADER_BYTES - 16
        if cipher_length <= 0 or cipher_length % _DISCLOSURE_PAD_BLOCK != 0:
            return refuse("DISCLOSURE_ENVELOPE_MALFORMED")
        if not isinstance(key, (bytes, bytearray)) or len(key) != 32 or not isinstance(handle, str):
            return refuse("DISCLOSURE_ENVELOPE_AUTH_FAILED")
        try:
            plain = AESGCM(bytes(key)).decrypt(data[1:_DISCLOSURE_HEADER_BYTES], data[_DISCLOSURE_HEADER_BYTES:], _DISCLOSURE_AAD_LABEL + b"\x00" + handle.encode("utf-8"))
        except Exception:
            return refuse("DISCLOSURE_ENVELOPE_AUTH_FAILED")
        trimmed = plain.rstrip(b" ")
        if len(plain) - len(trimmed) >= _DISCLOSURE_PAD_BLOCK:
            return refuse("DISCLOSURE_ENVELOPE_MALFORMED")
        disclosure = json.loads(trimmed.decode("utf-8"))
        if canonicalize_jcs(disclosure).encode("utf-8") != trimmed:
            return refuse("DISCLOSURE_ENVELOPE_MALFORMED")
        return {"ok": True, "disclosure": disclosure}
    except Exception:
        return refuse("DISCLOSURE_ENVELOPE_MALFORMED")


# ------------------------------------------------------------ the encrypted paths


def _owner_of(value: Any) -> str:
    """An owner workspace id a wrap is bound to (card 10, F3), or W-C10-B-17 before any key is used."""
    if not isinstance(value, str) or A.KEY_WRAP_OWNER_V2.fullmatch(value) is None:
        raise RecordsEncryptionError("RECORDS_OWNER_INVALID")
    return value


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class EncryptedRecords:
    def __init__(self, client: Any, keys: RecordsKeys, pins: RecordsPinStore) -> None:
        self._client = client
        self.keys = keys
        self.pins = pins
        # A record's version, once known: (record type, wire record id) to version.
        self._version_of: Dict[Tuple[str, str], int] = {}
        # Card 10, F1: the record hash version intake took last; 2 sends 0.13.0's body.
        self._hash_version = 2
        self._workspace_id: Optional[str] = None

    # ------------------------------------------------------------ ids

    def wire_id(self, record_type: str, record: str) -> str:
        return R.wire_record_id(self.keys.ring().id_key, record_type, record)

    def wire_reference_id(self, reference_id: str) -> str:
        return R.wire_reference_id(self.keys.ring().id_key, reference_id)

    def target(self, record_type: str, record: Optional[str], read: Dict[str, Any]) -> Tuple[str, bool]:
        """The id a read or a write puts in the path, and whether the record is read as encrypted."""
        if read.get("wire_record_id"):
            return read["wire_record_id"], True
        if record is None:
            return "", False
        encrypted = read.get("encrypted") is not False and (self.keys.configured or read.get("record_key") is not None)
        if not encrypted:
            return record, False
        return self.wire_id(record_type, record), True

    # ------------------------------------------------------------ write

    def emit(
        self, record_type: str, record: str, lifecycle: str, content: Dict[str, Any], idempotency_key: Optional[str], options: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        ring = self.keys.ring()
        refused = admit_record_entry(record_type, lifecycle, content)
        if refused is not None:
            raise PacSpaceError(refused[1], 400, refused[0])
        wire_record_id = R.wire_record_id(ring.id_key, record_type, record)
        salt_key = "0x" + os.urandom(32).hex()
        record_hashes = {
            2: commit_record_content_v2(content, salt_key)["recordHash"],
            3: commit_record_content_v3(content, salt_key)["recordHash"],
        }
        outside = {m: content[m] for m in ("amends", "references") if m in content}
        try:
            plaintext_bytes = len(R.record_entry_plaintext(content, salt_key))
        except R.RecordsEncryptionError as error:
            if error.code != "RECORD_ENTRY_TOO_LARGE":
                raise
            raise PacSpaceError(_SIZE_WORDS["RECORD_ENTRY_TOO_LARGE"], 413, "RECORD_ENTRY_TOO_LARGE") from None

        # Card 10, F2: the tag is keyed by the record's version, and the default
        # reference is made from it, so it deduplicates within one version only.
        sent = {"wireReferenceId": ""}

        def body_under(version: int, hash_version: int) -> Dict[str, Any]:
            records_key = ring.by_version(version)
            tag_key = ring.content_tag_key(version)
            if records_key is None or tag_key is None:
                raise RecordsEncryptionError("RECORDS_VERSION_NOT_HELD", v=version)
            tag = R.content_tag_v2(tag_key, record_type, wire_record_id, content, lifecycle)
            sent["wireReferenceId"] = R.wire_reference_id(ring.id_key, idempotency_key or tag)
            fields: Dict[str, Any] = {"lifecycle": lifecycle, "referenceId": sent["wireReferenceId"], "recordHash": record_hashes[hash_version]}
            if hash_version == 3:
                fields["recordHashVersion"] = 3
            fields.update({"contentTag": tag, **outside})
            size = R.check_encrypted_write_size(fields, records_key.id, plaintext_bytes)
            if not size["ok"]:
                raise PacSpaceError(_SIZE_WORDS[size["code"]], 413, size["code"])
            record_key = R.record_key_of(records_key, wire_record_id)
            return {**fields, "envelope": R.seal_record_entry(AEAD, record_key, record_type, wire_record_id, content, salt_key)}

        cache_key = (record_type, wire_record_id)
        version = self._version_of.get(cache_key, ring.current.version)
        hash_version = self._hash_version
        key_retried = hash_retried = claim_retried = False
        path = record_path(record_type, wire_record_id, "/transitions")
        while True:
            try:
                response = self._client.post(path, body_under(version, hash_version), options)
                break
            except PacSpaceError as error:
                other_hash = (error.code == "RECORD_HASH_VERSION_NOT_ENABLED" and hash_version == 3) or (
                    error.code == "RECORD_FORMAT_RETIRED" and hash_version == 2
                )
                if other_hash and not hash_retried:
                    hash_retried = True
                    hash_version = 2 if hash_version == 3 else 3
                    continue
                body = _api_body(error)
                claim_kid = body.get("claimKid")
                if error.code == "IDEMPOTENCY_CONFLICT" and isinstance(claim_kid, str) and not claim_retried:
                    claimed = ring.by_id(claim_kid)
                    if claimed is None:
                        raise RecordsEncryptionError("RECORDS_VERSION_NOT_HELD", v=self._version_number_of(claim_kid), write=True) from None
                    if claimed.version == version:
                        raise
                    claim_retried = True
                    version = claimed.version
                    continue
                record_kid = body.get("recordKid")
                if key_retried or error.code != "RECORD_ENCRYPTION_VERSION_MISMATCH" or not isinstance(record_kid, str):
                    raise
                held = ring.by_id(record_kid)
                if held is None:
                    raise RecordsEncryptionError("RECORDS_VERSION_NOT_HELD", v=self._version_number_of(record_kid)) from None
                key_retried = True
                version = held.version
        self._version_of[cache_key] = version
        self._hash_version = hash_version
        wire_reference_id = sent["wireReferenceId"]
        return {"response": response, "wireRecordId": wire_record_id, "wireReferenceId": wire_reference_id}

    def _version_number_of(self, kid: str) -> Union[int, str]:
        """A kid's version, from this workspace's own registry; '?' when it isn't there."""
        try:
            versions = _unwrap(self._client.get(f"{_ENCRYPTION}/versions")).get("versions") or []
            return next((v["version"] for v in versions if v.get("kid") == kid), "?")
        except Exception:
            return "?"

    # ------------------------------------------------------------ read

    def read_headers(self, read: Dict[str, Any]) -> Dict[str, str]:
        """The support header always, and the grant or holder the caller named."""
        headers = {RECORDS_SUPPORT_HEADER: "1"}
        if read.get("grant"):
            headers[RECORDS_GRANT_HEADER] = read["grant"]
        if read.get("holder_for"):
            headers[RECORDS_HOLDER_HEADER] = read["holder_for"]
        return headers

    def request_options(self, read: Dict[str, Any], options: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        return {**(options or {}), "headers": self.read_headers(read)}

    def record_key_for(
        self, record_type: str, wire_record_id: str, receipts: List[Dict[str, Any]], read: Dict[str, Any], options: Optional[Dict[str, Any]] = None
    ) -> Tuple[R.RecordKey, List[R.RecordKey]]:
        """The record's key for these receipts, and its keys under other
        versions: the caller's, a grant's wrap, a holder's wraps, or the keyring."""
        if read.get("record_key") is not None:
            data = R.b64url_decode(read["record_key"])
            if data is None or len(data) != 32:
                raise RecordsEncryptionError("RECORDS_ENTRY_UNOPENED", seq=1)
            return R.record_key_from_bytes(data), []
        ring = self.keys.ring()
        kids = _kids_of(receipts)
        if read.get("grant"):
            owner = _owner_of(read.get("owner"))
            seeds = self.own_seeds()
            got = _unwrap(
                self._client.get(
                    record_path(record_type, wire_record_id, "/grant-key"),
                    {**(options or {}), "headers": {RECORDS_GRANT_HEADER: read["grant"]}},
                )
            )
            rkid = (got or {}).get("rkid")
            for seed in seeds if isinstance(rkid, str) else []:
                opened = A.unwrap_record_key_v2(seed, (got or {}).get("wrap"), owner, record_type, wire_record_id, rkid)
                if opened["ok"]:
                    return opened["recordKey"], []
            raise RecordsEncryptionError("RECORDS_ENTRY_UNOPENED", seq=1)
        if read.get("holder_for"):
            owner = _owner_of(read["holder_for"])
            seeds = self.own_seeds()
            holdings = _unwrap(self._client.get(f"{_ENCRYPTION}/holdings", options)).get("holdings") or []
            versions: List[Tuple[int, R.RecordKey]] = []
            for holding in holdings:
                if holding.get("ownerWorkspaceId") != owner:
                    continue
                held_record = holding.get("record") or {}
                for w in holding.get("wraps") or []:
                    if w.get("state") == "refused":
                        continue
                    for seed in seeds:
                        if (
                            holding.get("scope") == "record"
                            and isinstance(w.get("rkid"), str)
                            and held_record.get("entityId") == wire_record_id
                            and held_record.get("recordType") == record_type
                        ):
                            opened = A.unwrap_record_key_v2(seed, w.get("wrap"), owner, record_type, wire_record_id, w["rkid"])
                            if opened["ok"]:
                                return opened["recordKey"], []
                        version, kid = w.get("version"), w.get("kid")
                        if holding.get("scope") == "workspace" and isinstance(version, int) and isinstance(kid, str) and (not kids or kid in kids):
                            opened = A.unwrap_records_key_v2(seed, w.get("wrap"), owner, version, kid)
                            if opened["ok"]:
                                versions.append((version, R.record_key_of(opened["recordsKey"], wire_record_id)))
                                break
            if not versions:
                raise RecordsEncryptionError("RECORDS_ENTRY_UNOPENED", seq=1)
            versions.sort(key=lambda pair: -pair[0])
            return versions[0][1], [key for _, key in versions[1:]]
        held = [k for k in (ring.by_id(kid) for kid in kids) if k is not None]
        if not held and kids:
            raise RecordsEncryptionError("RECORDS_VERSION_NOT_HELD", v=self._version_number_of(kids[0]))
        held.sort(key=lambda k: -k.version)
        newest = held[0] if held else ring.current
        return R.record_key_of(newest, wire_record_id), [R.record_key_of(k, wire_record_id) for k in held[1:]]

    def open_history(
        self, body: Dict[str, Any], record_type: str, wire_record_id: str, read: Dict[str, Any], options: Optional[Dict[str, Any]] = None
    ) -> Tuple[List[Dict[str, Any]], R.RecordKey]:
        """Opens a v3 history: every v4 receipt and refused envelope, each checked against its record hash."""
        if body.get("recordType") != record_type or body.get("entityId") != wire_record_id:
            raise RecordsEncryptionError("RECORDS_HISTORY_OTHER_RECORD")
        refused = body.get("refused") if isinstance(body.get("refused"), list) else []
        receipts = [*_receipts_of(body), *({"envelopes": [r.get("envelope")]} for r in refused if isinstance(r, dict))]
        record_key, others = self.record_key_for(record_type, wire_record_id, receipts, read, options)
        result = R.open_record_history_v3(
            AEAD, body, record_key, {"recordType": record_type, "wireRecordId": wire_record_id}, record_keys=others
        )
        if not result["ok"]:
            raise read_refusal(result)
        opened = [
            {"entry": e["seq"] + 1, "seq": e["seq"], "recordHash": e["recordHash"], "content": e["content"], "saltKey": e["saltKey"]}
            for e in result["opened"]
            if "content" in e
        ]
        return opened, record_key

    def open_receipt(
        self, receipt: Dict[str, Any], record_type: str, wire_record_id: str, read: Dict[str, Any], options: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Opens one v4 receipt, or a v3 record's v5 (card 10)."""
        record_key, _ = self.record_key_for(record_type, wire_record_id, [receipt], read, options)
        open_receipt = R.open_receipt_v5 if receipt.get("schema") == R.SEMANTIC_RECEIPT_SCHEMA_V5 else R.open_receipt_v4
        opened = open_receipt(AEAD, receipt, record_key, record_type, wire_record_id)
        if not opened["ok"]:
            raise read_refusal(opened)
        return {"entry": receipt["seq"] + 1, "recordHash": opened["recordHash"], "content": opened["content"]}

    def copy_of(self, body: Dict[str, Any], record_key: R.RecordKey) -> bytes:
        """N8's copy file: the history with its record key, for a reader with no workspace."""
        copy = {"schema": R.RECORD_COPY_SCHEMA_V1, "recordKey": R.b64url_encode(R.export_key_bytes(record_key)), "history": body}
        return (json.dumps(copy, indent=2) + "\n").encode("utf-8")

    def own_history(self, record_type: str, wire_record_id: str, options: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        """The record's own history, as the owner reads it; None when it has no entries yet."""
        try:
            raw = self._client.get_raw(
                record_path(record_type, wire_record_id, "/bundle"), {**(options or {}), "headers": {RECORDS_SUPPORT_HEADER: "1"}}
            )
        except PacSpaceError as error:
            if error.status_code == 404:
                return None
            raise
        return _unwrap(raw.get("body"))

    def own_record_key(
        self, record_type: str, wire_record_id: str, options: Optional[Dict[str, Any]] = None
    ) -> Tuple[R.RecordKey, Optional[Dict[str, Any]]]:
        """The owner's key for one record: the version its entries carry, or the current one before its first entry."""
        history = self.own_history(record_type, wire_record_id, options)
        if history is not None and history.get("schema") != R.RECORD_HISTORY_BUNDLE_SCHEMA_V3:
            raise RecordsEncryptionError("RECORDS_NOT_ENCRYPTED")
        receipts = [r for r in _receipts_of(history) if isinstance(r.get("envelopes"), list)] if history else []
        record_key, _ = self.record_key_for(record_type, wire_record_id, receipts, {}, options)
        return record_key, history

    def export_record_key(self, record_key: R.RecordKey) -> str:
        return R.b64url_encode(R.export_key_bytes(record_key))

    # ------------------------------------------------------------ identity and pins

    def own_identity(self) -> Dict[str, Any]:
        return _unwrap(self._client.get(f"{_ENCRYPTION}/identity")) or {}

    def own_workspace_id(self) -> str:
        """This workspace's own id, as the API names it: the owner every wrap it makes is bound to."""
        if self._workspace_id is None:
            self._workspace_id = _owner_of(self.own_identity().get("workspaceId"))
        return self._workspace_id

    @staticmethod
    def _open_seed_of(keyring: R.RecordsKeyring, identity: Dict[str, Any], mismatch: str) -> Union[A.WorkspaceSeed, str, None]:
        """One identity's seed opened with ``keyring``: None when no wrap
        opens, "outdated" when every wrap is under a version the keyring
        doesn't hold. A seed that opens to other key bytes is ``mismatch``."""
        if not identity.get("xwingPublicId"):
            return None
        wraps = [w for w in identity.get("seedWraps") or [] if isinstance(w, dict)]
        held = [w for w in wraps if w.get("version") in keyring.versions]
        for seed_wrap in held:
            opened = A.open_seed_wrap(seed_wrap.get("wrap"), identity["xwingPublicId"], keyring=keyring)
            if not opened["ok"]:
                continue
            if identity.get("xwingPublic") != R.b64url_encode(opened["seed"].public_key):
                raise RecordsEncryptionError(mismatch)
            return opened["seed"]
        return "outdated" if wraps and not held else None

    def own_seed(self, ring: Optional[R.RecordsKeyring] = None) -> Optional[A.WorkspaceSeed]:
        """This workspace's seed, opened with its own secret; None when it has no current identity."""
        own = self.own_identity()
        if not own.get("xwingPublicId"):
            return None
        seed = self._open_seed_of(ring or self.keys.ring(), own, "RECORDS_IDENTITY_OTHER")
        if seed == "outdated":
            raise RecordsEncryptionError("RECORDS_SECRET_FILE_OUTDATED")
        if not isinstance(seed, A.WorkspaceSeed):
            raise RecordsEncryptionError("RECORDS_IDENTITY_OTHER")
        return seed

    def own_seeds(self) -> List[A.WorkspaceSeed]:
        """Every seed this workspace's secret opens, current first, then each
        retired one (card 10, F4): a wrap made to a key before it was
        replaced still opens. A server still on the file from before a
        replacement opens the retired seeds only; with none, W-C10-B-18."""
        ring = self.keys.ring()
        own = self.own_identity()
        current = self._open_seed_of(ring, own, "RECORDS_IDENTITY_OTHER")
        seeds = [current] if isinstance(current, A.WorkspaceSeed) else []
        for retired in own.get("retiredIdentities") or []:
            seed = self._open_seed_of(ring, retired, "RECORDS_RETIRED_KEY_MISMATCH")
            if isinstance(seed, A.WorkspaceSeed):
                seeds.append(seed)
        if current == "outdated" and not seeds:
            raise RecordsEncryptionError("RECORDS_SECRET_FILE_OUTDATED")
        if own.get("xwingPublicId") and current is None and not seeds:
            raise RecordsEncryptionError("RECORDS_IDENTITY_OTHER")
        return seeds

    def _seed_wraps_for(self, ring: R.RecordsKeyring, version: int) -> Optional[Dict[str, Any]]:
        """The seed of each key this workspace has had, sealed under
        ``version`` (card 10, F4): the current one must open; a retired one
        that doesn't is left out. None before the first identity."""
        own = self.own_identity()
        seeds: List[A.WorkspaceSeed] = []
        if own.get("xwingPublicId"):
            current = self._open_seed_of(ring, own, "RECORDS_IDENTITY_OTHER")
            if current == "outdated":
                raise RecordsEncryptionError("RECORDS_SECRET_FILE_OUTDATED")
            if not isinstance(current, A.WorkspaceSeed):
                # A next file made from one older than a replacement reuses the
                # replacement's version number; the file it came from lacks it.
                served = self.keys.ring()
                if served is not ring and self._open_seed_of(served, own, "RECORDS_IDENTITY_OTHER") == "outdated":
                    raise RecordsEncryptionError("RECORDS_SECRET_FILE_OUTDATED")
                raise RecordsEncryptionError("RECORDS_IDENTITY_OTHER")
            seeds.append(current)
        for retired in own.get("retiredIdentities") or []:
            seed = self._open_seed_of(ring, retired, "RECORDS_RETIRED_KEY_MISMATCH")
            if isinstance(seed, A.WorkspaceSeed):
                seeds.append(seed)
        if not seeds:
            return None
        wrap_key = ring.wrap_key(version)
        return {seed.public_key_id: A.seal_seed_wrap(wrap_key, seed) for seed in seeds}

    def register_versions(self) -> None:
        """Registers each version of the secret the API doesn't list yet."""
        ring = self.keys.ring()
        listed = _unwrap(self._client.get(f"{_ENCRYPTION}/versions")) or {}
        registered = {v.get("version") for v in listed.get("versions") or [] if isinstance(v, dict)}
        for version in ring.versions:
            if version not in registered:
                self._put_version(ring, version)

    def _put_version(self, ring: R.RecordsKeyring, version: int) -> Dict[str, Any]:
        """PUT versions in format 2 (card 10, F3): the version's records key
        wrapped to each workspace holder whose pin is held, with the holder
        set those wraps were made for; read again once if that set changed."""
        records_key = ring.by_version(version)
        owner = self.own_workspace_id()
        seed_wraps = self._seed_wraps_for(ring, version)
        attempt = 0
        while True:
            listed = _unwrap(self._client.get(f"{_ENCRYPTION}/holders")) or {}
            holders: List[Dict[str, Any]] = []
            holder_wraps: List[Dict[str, Any]] = []
            for holder in listed.get("holders") or []:
                if holder.get("scope") != "workspace" or holder.get("removedAt"):
                    continue
                try:
                    public_key, pinned_id = self.pinned(holder["holderWorkspaceId"])
                    if pinned_id != holder.get("pinnedId"):
                        raise RecordsEncryptionError("RECORDS_PIN_CHANGED")
                    wrap = A.wrap_records_key_v2(public_key, records_key, owner)
                    holder_wraps.append({"holderId": holder["holderId"], "pinnedId": pinned_id, "wrap": wrap})
                    holders.append({"holderId": holder["holderId"], "workspaceId": holder["holderWorkspaceId"], "wrapped": True})
                except RecordsEncryptionError as error:
                    holders.append({"holderId": holder["holderId"], "workspaceId": holder["holderWorkspaceId"], "wrapped": False, "code": error.code})
            body = {"kid": records_key.id, "wrapFormat": 2, "holderSet": listed.get("holderSet"), "holderWraps": holder_wraps}
            if seed_wraps:
                body["seedWraps"] = seed_wraps
            try:
                put = _unwrap(self._client.put(f"{_ENCRYPTION}/versions/{version}", body)) or {}
            except PacSpaceError as error:
                if attempt == 0 and error.code == "RECORDS_HOLDER_SET_CHANGED":
                    attempt += 1
                    continue
                raise
            return {"holders": holders, "holdersNeedingConfirmation": list(put.get("holdersNeedingConfirmation") or [])}

    def register_identity(self) -> Dict[str, Any]:
        """Registers this workspace's identity and every version of its secret. Idempotent."""
        ring = self.keys.ring()
        own = self.own_identity()
        if own.get("xwingPublicId") and own.get("xwingPublic"):
            seed = self.own_seed()
            if seed is None:
                raise RecordsEncryptionError("RECORDS_IDENTITY_OTHER")
            result = {"xwingPublicId": seed.public_key_id, "code": A.holder_key_code(seed.public_key), "created": False}
        else:
            seed = A.generate_workspace_seed()
            version = ring.current.version
            wrap = A.seal_seed_wrap(ring.wrap_key(version), seed)
            put = _unwrap(
                self._client.put(f"{_ENCRYPTION}/identity", {"xwingPublic": R.b64url_encode(seed.public_key), "seedWrap": {"version": version, "wrap": wrap}})
            )
            if put.get("xwingPublicId") != seed.public_key_id:
                raise RecordsEncryptionError("RECORDS_IDENTITY_OTHER")
            result = {"xwingPublicId": seed.public_key_id, "code": A.holder_key_code(seed.public_key), "created": put.get("created") is True}
        self.register_versions()
        return result

    def pinned(self, workspace_id: str, confirmed_code: Optional[str] = None) -> Tuple[bytes, str]:
        """Another workspace's public key and its id, pinned: the code is
        computed here from the bytes fetched, never read from an API field.
        With ``confirmed_code`` it must equal that code and is then pinned;
        without, the pin must exist and still name the key served. Refuses
        before any wrap."""
        served = _unwrap(self._client.get(f"{_ENCRYPTION}/workspaces/{quote(workspace_id, safe='')}/identity")) or {}
        public_key = R.b64url_decode(served.get("xwingPublic") or "") or b""
        try:
            key_id: Optional[str] = A.public_key_id(public_key) if public_key else None
        except Exception:
            key_id = None
        pin = self.pins.get(workspace_id)
        if confirmed_code is None:
            if not pin:
                raise RecordsEncryptionError("RECORDS_CODE_REQUIRED")
            if not key_id or key_id != served.get("xwingPublicId") or key_id != pin.get("publicKeyId"):
                raise RecordsEncryptionError("RECORDS_PIN_CHANGED")
            return public_key, key_id
        normalized = " ".join(str(confirmed_code).split())
        code = A.holder_key_code(public_key) if key_id else None
        if not key_id or key_id != served.get("xwingPublicId") or code != normalized:
            raise RecordsEncryptionError("RECORDS_CODE_MISMATCH")
        self.pins.set(workspace_id, {"publicKeyId": key_id, "confirmedAt": _now()})
        return public_key, key_id

    # ------------------------------------------------------------ holders

    def add_holder(
        self, workspace_id: str, scope: str, required: bool, record: Optional[Tuple[str, str]], confirmed_code: Optional[str]
    ) -> Dict[str, Any]:
        ring = self.keys.ring()
        public_key, pinned_id = self.pinned(workspace_id, confirmed_code)
        owner = self.own_workspace_id()
        self.register_versions()
        body: Dict[str, Any] = {"workspaceId": workspace_id, "scope": scope, "required": required, "pinnedId": pinned_id}
        if record:
            body["record"] = {"recordType": record[0], "entityId": record[1]}
        added = _unwrap(self._client.post(f"{_ENCRYPTION}/holders", body))
        holder_path = f"{_ENCRYPTION}/holders/{quote(added['holderId'], safe='')}/wraps"
        wraps: List[Dict[str, Any]] = []
        if scope == "workspace":
            for version in ring.versions:
                wrap = A.wrap_records_key_v2(public_key, ring.by_version(version), owner)
                stored = _unwrap(self._client.put(holder_path, {"version": version, "pinnedId": pinned_id, "wrap": wrap}))
                wraps.append({"version": version, "state": stored.get("state")})
        elif record:
            record_key, _ = self.own_record_key(record[0], record[1])
            wrap = A.wrap_record_key_v2(public_key, record_key, record[0], record[1], owner)
            stored = _unwrap(self._client.put(holder_path, {"pinnedId": pinned_id, "rkid": record_key.id, "wrap": wrap}))
            wraps.append({"version": None, "state": stored.get("state")})
        return {"holderId": added["holderId"], "created": added.get("created") is True, "wraps": wraps}

    def confirm_holdings(self) -> List[Dict[str, Any]]:
        """Opens each stored wrap with this workspace's seed and confirms it,
        or refuses it so the writer is told. A workspace wrap's key id is
        recomputed from the opened bytes; a record wrap is confirmed by
        opening one of the record's entries, and waits while the record has none."""
        # A wrap made to a key before it was replaced still opens with that key's seed (card 10, F4).
        seeds = self.own_seeds()
        if not seeds:
            return []
        holdings = _unwrap(self._client.get(f"{_ENCRYPTION}/holdings")).get("holdings") or []
        results: List[Dict[str, Any]] = []
        for holding in holdings:
            holder_id = holding["holderId"]
            base = f"{_ENCRYPTION}/holdings/{quote(holder_id, safe='')}"
            owner = _owner_of(holding.get("ownerWorkspaceId"))
            for w in holding.get("wraps") or []:
                version = w.get("version")
                if w.get("state") != "stored":
                    results.append({"holderId": holder_id, "version": version, "state": w.get("state")})
                    continue
                kid: Optional[str] = None
                reason = "unopened"
                held_record = holding.get("record")
                if holding.get("scope") == "workspace" and isinstance(version, int) and isinstance(w.get("kid"), str):
                    for seed in seeds:
                        opened = A.unwrap_records_key_v2(seed, w.get("wrap"), owner, version, w["kid"])
                        if opened["ok"]:
                            kid = w["kid"]
                            break
                        if opened.get("code") == "KEY_WRAP_KEY_MISMATCH":
                            reason = "kid_mismatch"
                elif holding.get("scope") == "record" and held_record and isinstance(w.get("rkid"), str):
                    record_type, wire_record_id = held_record["recordType"], held_record["entityId"]
                    for seed in seeds:
                        opened = A.unwrap_record_key_v2(seed, w.get("wrap"), owner, record_type, wire_record_id, w["rkid"])
                        if opened["ok"]:
                            kid = self._kid_opened_by(opened["recordKey"], record_type, wire_record_id, owner)
                            break
                    if kid == "none-yet":
                        results.append({"holderId": holder_id, "version": None, "state": "stored"})
                        continue
                named = {"version": version} if version is not None else {}
                if kid:
                    self._client.post(f"{base}/confirm", {**named, "kid": kid})
                    results.append({"holderId": holder_id, "version": version, "state": "confirmed"})
                else:
                    self._client.post(f"{base}/refuse", {**named, "reason": reason})
                    results.append({"holderId": holder_id, "version": version, "state": "refused", "reason": reason})
        return results

    def _kid_opened_by(self, record_key: R.RecordKey, record_type: str, wire_record_id: str, owner: str) -> Optional[str]:
        """The kid of the first envelope this record key opens, read as a holder; 'none-yet' before any entry."""
        try:
            raw = self._client.get_raw(
                record_path(record_type, wire_record_id, "/bundle"),
                {"headers": {RECORDS_SUPPORT_HEADER: "1", RECORDS_HOLDER_HEADER: owner}},
            )
        except PacSpaceError as error:
            if error.status_code == 404:
                return "none-yet"
            raise
        envelopes = [e for r in _receipts_of(_unwrap(raw.get("body"))) for e in (r.get("envelopes") or [])]
        if not envelopes:
            return "none-yet"
        for envelope in envelopes:
            opened = R.open_record_entry_envelope(AEAD, envelope, record_type, wire_record_id, record_key=record_key)
            if opened["ok"] and isinstance(envelope.get("kid"), str):
                return envelope["kid"]
        return None

    # ------------------------------------------------------------ grants and disclosure wraps

    def grant_reader_wrap(self, record_type: str, wire_record_id: str, workspace_id: str, confirmed_code: Optional[str]) -> Optional[Dict[str, Any]]:
        record_key, history = self.own_record_key(record_type, wire_record_id)
        if history is None:
            return None
        public_key, pinned_id = self.pinned(workspace_id, confirmed_code)
        owner = self.own_workspace_id()
        return {"pinnedId": pinned_id, "rkid": record_key.id, "wrap": A.wrap_record_key_v2(public_key, record_key, record_type, wire_record_id, owner)}

    def disclosure_wrap(self, handle: str, disclosure_key: bytes, workspace_id: str, confirmed_code: Optional[str]) -> Dict[str, Any]:
        self.keys.ring()
        public_key, pinned_id = self.pinned(workspace_id, confirmed_code)
        owner = self.own_workspace_id()
        return {"workspaceId": workspace_id, "pinnedId": pinned_id, "wrap": A.wrap_disclosure_key_v2(public_key, disclosure_key, handle, owner)}

    def disclosure_key_from_wrap(self, handle: str) -> Optional[bytes]:
        """A disclosure link's key from this workspace's wrap, or None when the sharer stored none for it."""
        if not self.keys.configured:
            return None
        self.keys.ring()
        try:
            got = _unwrap(self._client.post("/api/v1/records/disclosures/key-wrap", {"handle": handle}))
        except PacSpaceError as error:
            if error.status_code in (404, 409):
                return None
            raise
        owner = _owner_of((got or {}).get("ownerWorkspaceId"))
        for seed in self.own_seeds():
            opened = A.unwrap_disclosure_key_v2(seed, (got or {}).get("wrap"), owner, handle)
            if opened["ok"]:
                return opened["disclosureKey"]
        return None

    # ------------------------------------------------------------ rotate and re-key

    def rotate(self, next_source: SecretSource) -> Dict[str, Any]:
        ring = self.keys.ring()
        following = keyring_of(next_source)
        next_ring = following[0]
        newest = max(next_ring.versions)
        expected = [*ring.versions, max(ring.versions) + 1]
        same_earlier = all(
            next_ring.by_version(v) is not None and next_ring.by_version(v).id == ring.by_version(v).id for v in ring.versions
        )
        if next_ring.versions != expected or not same_earlier:
            raise RecordsEncryptionError("RECORDS_ROTATE_NOT_NEXT")
        records_key = next_ring.by_version(newest)
        # The new version carries the seed of each key this workspace holds (card 10, F4).
        added = self._put_version(next_ring, newest)
        self.keys.replace(following)
        return {"version": newest, "kid": records_key.id, **added}

    def rekey(self, record_type: str, wire_record_id: str, to_version: int) -> Dict[str, Any]:
        """Re-seals each stored entry's same plaintext under the version's
        record key, latest entry first (same salt key, so each record hash is
        unchanged), then wraps the new record key to the record's grants and
        record holders whose pins are held. Stops at the first refusal."""
        ring = self.keys.ring()
        owner = self.own_workspace_id()
        to_key = ring.by_version(to_version)
        if to_key is None:
            raise RecordsEncryptionError("RECORDS_VERSION_NOT_HELD", v=to_version)
        history = self.own_history(record_type, wire_record_id)
        if history is None or history.get("schema") != R.RECORD_HISTORY_BUNDLE_SCHEMA_V3:
            raise RecordsEncryptionError("RECORDS_NOT_ENCRYPTED")
        opened, _ = self.open_history(history, record_type, wire_record_id, {})
        new_key = R.record_key_of(to_key, wire_record_id)
        by_seq = {r.get("seq"): r for r in _receipts_of(history)}
        entries: List[Dict[str, Any]] = []
        for entry in sorted(opened, key=lambda e: -e["seq"]):
            receipt = by_seq.get(entry["seq"]) or {}
            if any(isinstance(e, dict) and e.get("kid") == to_key.id for e in receipt.get("envelopes") or []):
                entries.append({"entry": entry["entry"], "state": "already"})
                continue
            try:
                envelope = R.seal_record_entry(AEAD, new_key, record_type, wire_record_id, entry["content"], entry["saltKey"])
                self._client.put(record_path(record_type, wire_record_id, f"/entries/{entry['seq']}/envelope"), {"envelope": envelope})
            except Exception:
                raise RecordsEncryptionError("RECORDS_REKEY_STOPPED", seq=entry["entry"]) from None
            entries.append({"entry": entry["entry"], "state": "swapped"})

        grants: List[Dict[str, Any]] = []
        for grant in _unwrap(self._client.get(record_path(record_type, wire_record_id, "/grants"))).get("grants") or []:
            if grant.get("status") != "ACTIVE" or grant.get("kind") != "TENANT_BOUND" or not grant.get("counterpartyWorkspaceId") or not grant.get("readerWrap"):
                continue
            try:
                public_key, pinned_id = self.pinned(grant["counterpartyWorkspaceId"])
                wrap = A.wrap_record_key_v2(public_key, new_key, record_type, wire_record_id, owner)
                self._client.put(
                    record_path(record_type, wire_record_id, f"/grants/{quote(grant['grantId'], safe='')}/key-wrap"),
                    {"pinnedId": pinned_id, "rkid": new_key.id, "wrap": wrap},
                )
                grants.append({"grantId": grant["grantId"], "wrapped": True})
            except RecordsEncryptionError as error:
                grants.append({"grantId": grant["grantId"], "wrapped": False, "code": error.code})

        holders: List[Dict[str, Any]] = []
        for holder in _unwrap(self._client.get(f"{_ENCRYPTION}/holders")).get("holders") or []:
            held_record = holder.get("record") or {}
            if (
                holder.get("scope") != "record"
                or holder.get("removedAt")
                or held_record.get("entityId") != wire_record_id
                or held_record.get("recordType") != record_type
            ):
                continue
            try:
                public_key, pinned_id = self.pinned(holder["holderWorkspaceId"])
                if pinned_id != holder.get("pinnedId"):
                    raise RecordsEncryptionError("RECORDS_PIN_CHANGED")
                wrap = A.wrap_record_key_v2(public_key, new_key, record_type, wire_record_id, owner)
                self._client.put(
                    f"{_ENCRYPTION}/holders/{quote(holder['holderId'], safe='')}/wraps", {"pinnedId": pinned_id, "rkid": new_key.id, "wrap": wrap}
                )
                holders.append({"holderId": holder["holderId"], "wrapped": True})
            except RecordsEncryptionError as error:
                holders.append({"holderId": holder["holderId"], "wrapped": False, "code": error.code})
        return {"entries": entries, "grants": grants, "holders": holders}
