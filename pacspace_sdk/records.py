from __future__ import annotations

import json
import re
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union
from urllib.parse import quote, unquote, urlencode, urljoin, urlparse

from .client import HttpClient
from .errors import PacSpaceError, ValidationError, map_api_error
from .fingerprint import BLINDING_FILE_SCHEMA, Blinding, Fingerprint, _digests
from .record_disclosure import _REASONS as _DISCLOSURE_REASONS
from .record_disclosure import (
    RECORDS_LAYOUT_NOT_READ_SENTENCE,
    _disclosure_form_of,
    carried_layout,
    compute_record_disclosure_digest,
    is_json_number,
    seal_history_refusal,
    verify_record_disclosure_v1,
)
from .records_labels import label_pairs
from .records_words import RECORD_HISTORY_DIGEST_SENTENCE, RECORD_HISTORY_SEAL_SENTENCE, RecordsEncryptionError

_ENCRYPTION = "/api/v1/records/encryption"
_GRANT_HEADER = "X-PacSpace-Grant"


def _malformed_disclosure() -> PacSpaceError:
    return PacSpaceError(_DISCLOSURE_REASONS["DISCLOSURE_MALFORMED"](0), 0, "DISCLOSURE_MALFORMED")

DEFAULT_RECORD_TYPE = "machine-action-record"

_MATERIAL = (
    "This payload includes a blinding file or its value. Pass the fingerprint's ref as the payload, "
    "and keep its blinding file with the file. Nothing was sent."
)
_EXTRA_FIELD = "A blinded fingerprint carries only alg, digest and byteLength. Move any other field out of it. Nothing was sent."
_ROW_NOT_READABLE = "Each expected row is a dict with an entry number."
_ITEM_NOT_READABLE = "Each expected item is a payload reference dict. Pass the fingerprint's ref."
_NOT_A_FILE = "This is not a valid blinding file."
_CHECK_NOTE = "A blinded entry was not matched. Pass each file with its blinding file to check it."
_CLOSE_NO_ENTRY = "records.close found no entry on this record. Pass last_entry, the number of its last entry, counted from 1."
_REF_FIELDS = frozenset(("alg", "digest", "byteLength"))
_ALGS = ("sha-256", "hmac-sha-256")

Refusal = Tuple[str, int, str]


def _payload_ref_reason(ref: Dict[str, Any]) -> Optional[Refusal]:
    """payload-ref/v1's rule for a blinded reference, as the API applies it."""
    if ref.get("alg") not in _ALGS:
        return (f"payload alg is not supported; use one of {', '.join(_ALGS)}", 400, "RECORD_PAYLOAD_ALG_UNSUPPORTED")
    digest = ref.get("digest")
    if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        return ("payload digest must be 64 lowercase hex characters", 400, "RECORD_CONTENT_INVALID")
    byte_length = ref.get("byteLength")
    if not isinstance(byte_length, str) or re.fullmatch(r"[0-9]+", byte_length) is None:
        return ("payload byteLength must be a decimal string", 400, "RECORD_CONTENT_INVALID")
    if ref.get("alg") == "hmac-sha-256" and re.fullmatch(r"0|[1-9][0-9]*", byte_length) is None:
        return ("payload byteLength must be a decimal string with no leading zero", 400, "RECORD_CONTENT_INVALID")
    return None


def _rule_b_reason(obj: Dict[str, Any]) -> Optional[Refusal]:
    """Rule B at one object, in order B1, B2, B3 (slot-encoding-v1 section 6.1)."""
    if obj.get("schema") == BLINDING_FILE_SCHEMA:
        return (_MATERIAL, 400, "RECORD_BLINDING_INCLUDED")
    ref = obj.get("ref")
    if isinstance(ref, dict) and ref.get("alg") == "hmac-sha-256" and "blinding" in obj and obj["blinding"] is not None:
        return (_MATERIAL, 400, "RECORD_BLINDING_INCLUDED")
    if obj.get("alg") == "hmac-sha-256":
        if any(key not in _REF_FIELDS for key in obj):
            return (_EXTRA_FIELD, 400, "RECORD_BLINDING_INCLUDED")
        return _payload_ref_reason(obj)
    return None


def _holds_sdk_instance(value: Any, seen: set) -> bool:
    if isinstance(value, (Blinding, Fingerprint)):
        return True
    if not isinstance(value, (list, tuple, dict)) or id(value) in seen:
        return False
    seen.add(id(value))
    fields = value.values() if isinstance(value, dict) else value
    return any(_holds_sdk_instance(field, seen) for field in fields)


def _rule_b_walk(value: Any) -> Optional[Refusal]:
    if isinstance(value, (list, tuple)):
        for item in value:
            reason = _rule_b_walk(item)
            if reason is not None:
                return reason
        return None
    if not isinstance(value, dict):
        return None
    reason = _rule_b_reason(value)
    if reason is not None:
        return reason
    for field in value.values():
        reason = _rule_b_walk(field)
        if reason is not None:
            return reason
    return None


def _blinding_material_reason(value: Any) -> Optional[Refusal]:
    """A Blinding or a Fingerprint anywhere, then Rule B at every object and
    every depth. Returns the refusal rather than raising, so the caller can
    drop what it holds first."""
    if _holds_sdk_instance(value, set()):
        return (_MATERIAL, 400, "RECORD_BLINDING_INCLUDED")
    return _rule_b_walk(value)


def _refusal(reason: Refusal) -> PacSpaceError:
    message, status, code = reason
    return ValidationError(message) if code == "VALIDATION_ERROR" else PacSpaceError(message, status, code)


def _match_held_file(items: Any, held: Dict[str, Any]) -> Dict[str, Any]:
    """The held-file rule (records-crypto's matchHeldFile): top-level
    payloads only; a blinded item matches only with its blinding."""
    none = {"matched": False, "matchedIndex": None, "blinded": False, "blindingNeeded": False}
    blinded = held.get("hmac")
    if blinded is not None:
        if blinded["blindingByteLength"] != held["byteLength"]:
            return {**none, "refused": "blinding-length"}
        if blinded["blindingDigest"] != blinded["digest"]:
            return {**none, "refused": "blinding-digest"}
    listed = items if isinstance(items, list) else []
    for index, item in enumerate(listed):
        if not isinstance(item, dict):
            continue
        alg, digest, byte_length = item.get("alg"), item.get("digest"), item.get("byteLength")
        if alg == "hmac-sha-256":
            if blinded is not None and digest == blinded["digest"] and _js_string(byte_length) == held["byteLength"]:
                return {"matched": True, "matchedIndex": index, "blinded": True, "blindingNeeded": False, "refused": None}
            continue
        if digest == held["sha256"] and (byte_length is None or _js_string(byte_length) == held["byteLength"]):
            return {"matched": True, "matchedIndex": index, "blinded": False, "blindingNeeded": False, "refused": None}
    needed = blinded is None and any(isinstance(item, dict) and item.get("alg") == "hmac-sha-256" for item in listed)
    return {**none, "blindingNeeded": needed, "refused": None}


def _js_string(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value)


def _held_file(source: Any, blinding: Optional[Blinding]) -> Dict[str, Any]:
    digests = _digests(source, blinding)
    held: Dict[str, Any] = {"sha256": digests["sha256"], "byteLength": digests["byteLength"]}
    if blinding is not None:
        held["hmac"] = {
            "digest": digests["hmac"],
            "blindingDigest": blinding.digest,
            "blindingByteLength": blinding.byteLength,
        }
    return held


def _expect_reason(rows: List[Any]) -> Optional[Refusal]:
    """Why an expect list cannot be read, or None."""
    for row in rows:
        if not isinstance(row, dict) or "entry" not in row:
            return (_ROW_NOT_READABLE, 400, "VALIDATION_ERROR")
        for item in row.get("payloads") or []:
            if not isinstance(item, dict):
                return (_ITEM_NOT_READABLE, 400, "VALIDATION_ERROR")
        reason = _blinding_material_reason(list(row.get("payloads") or []))
        if reason is not None:
            return reason
        for held in row.get("files") or []:
            if not isinstance(held, dict) or "source" not in held:
                return (_ITEM_NOT_READABLE, 400, "VALIDATION_ERROR")
            if held.get("blinding") is not None and (not isinstance(held["blinding"], Blinding) or not held["blinding"].digest):
                return (_NOT_A_FILE, 400, "VALIDATION_ERROR")
    return None


def _record_path(record_type: Optional[str], record: str, suffix: str) -> str:
    typed = quote(record_type or DEFAULT_RECORD_TYPE, safe="")
    entity = quote(record, safe="")
    return f"/api/v1/records/{typed}/{entity}{suffix}"


def _seq_of(entry: Any, field: str) -> int:
    """The SDK counts entries from 1, as every PacSpace page does; the wire
    counts the same positions from 0 as ``seq``. This is the whole
    conversion, so no caller sends or reads a ``seq``. An entry below 1 is
    refused with the sentence that teaches the rule rather than sent as the
    wrong entry (0.3 took the wire number under the name ``entry``, so
    ``entry=1`` named the second entry; this is the correction, 0.4.0)."""
    if isinstance(entry, bool) or not isinstance(entry, int) or entry < 1:
        raise ValidationError(
            f"{field} is {entry!r}. Entries count from 1: the first entry is entry 1. "
            "(The HTTP API's seq counts the same positions from 0.)"
        )
    return entry - 1


def _entry_of(seq: Any) -> Optional[int]:
    return seq + 1 if isinstance(seq, int) and not isinstance(seq, bool) else None


def _wire_ref(ref: Dict[str, Any], field: str) -> Dict[str, Any]:
    """A committed entry named by ``recordKey`` and ``entry`` (counted from
    1). ``seq`` is accepted as the wire number itself, for a caller reading
    it straight off a history or a webhook."""
    if "entry" in ref:
        seq = _seq_of(ref["entry"], f"{field}.entry")
    elif "seq" in ref:
        seq = ref["seq"]
    else:
        raise ValidationError(f"{field} names no entry. Give entry (counted from 1) with the recordKey.")
    return {"recordKey": ref["recordKey"], "seq": seq}


def _fingerprint_key(ref: Dict[str, Any]) -> str:
    return f"{ref.get('alg', '')}:{str(ref.get('digest', '')).lower()}:{ref.get('byteLength', '')}"


def _plaintext_refusal(history: Any) -> Optional[Tuple[str, Optional[str]]]:
    """What stops a plaintext history (v1, v2) before its entries are read:
    a digest it carries that does not match its contents, then a layout id,
    its own or a receipt's, that this package does not carry. A history that
    states no digest or no layout id is read as it was given."""
    if not isinstance(history, dict):
        return None
    if "bundleDigest" in history:
        from .records_encryption import history_bundle_digest_matches

        if not history_bundle_digest_matches(history):
            return ("schema", RECORD_HISTORY_DIGEST_SENTENCE)
    layout = history.get("layout")
    named = [layout.get("layoutId") if isinstance(layout, dict) else None]
    named += [receipt.get("layoutId") for receipt in history.get("receipts") or [] if isinstance(receipt, dict)]
    if any(is_json_number(layout_id) and carried_layout(layout_id) is None for layout_id in named):
        return ("semantic", RECORDS_LAYOUT_NOT_READ_SENTENCE)
    return None


_HISTORY_SCHEMAS = ("record-history-bundle/v1", "record-history-bundle/v2")
_ENCRYPTED_HISTORY_SCHEMA = "record-history-bundle/v3"
# An encrypted history's attempt and failure rows, which PacSpace writes in plaintext (record hash v2, record hash v3).
_ROW_RECEIPT_SCHEMAS = ("semantic-receipt/v3", "semantic-receipt/v6")
# The refusals of an encrypted history that are about the file's form, not about what an entry holds, as the TypeScript SDK lists them.
_ENCRYPTED_FORM_REFUSALS = frozenset(
    ("RECORD_HISTORY_RECEIPT_FORM", "RECORD_HISTORY_WRONG_RECORD", "RECORD_HISTORY_DIGEST", "RECORD_COPY_MALFORMED")
)
# The TypeScript SDK's words for a check that raised, word for word.
_CHECK_DID_NOT_FINISH = "The check did not finish: "
_PAYLOAD_POINTER = re.compile(r"/payloads/(0|[1-9][0-9]*)")


def _revealed_of(receipt: Dict[str, Any]) -> List[Dict[str, Any]]:
    revealed = receipt.get("revealed")
    return [leaf for leaf in revealed if isinstance(leaf, dict)] if isinstance(revealed, list) else []


def _content_of(receipt: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    content = receipt.get("recordContent")
    if not isinstance(content, dict):
        sealed = receipt.get("sealedRecord")
        content = sealed.get("content") if isinstance(sealed, dict) else None
    return content if isinstance(content, dict) else None


def _payloads_of(receipt: Dict[str, Any]) -> List[Dict[str, Any]]:
    """A semantic-receipt/v3 entry's payloads are its revealed values at
    ``/payloads/<i>``, in index order (record hash v2); an earlier entry's are
    its content's ``payloads``. No seal or leaf is checked here."""
    if receipt.get("schema") == "semantic-receipt/v3":
        indexed = []
        for leaf in _revealed_of(receipt):
            pointer = leaf.get("pointer")
            found = _PAYLOAD_POINTER.fullmatch(pointer) if isinstance(pointer, str) else None
            if found is not None:
                indexed.append((int(found.group(1)), leaf.get("value")))
        return [value for _, value in sorted(indexed, key=lambda pair: pair[0])]
    content = _content_of(receipt)
    payloads = content.get("payloads") if content is not None else None
    return payloads if isinstance(payloads, list) else []


def _kind_of(receipt: Optional[Dict[str, Any]]) -> Optional[str]:
    """Whether the entry names an attempted target or a failure class, from
    the field's presence and never its value. A listing aid: no seal is
    checked."""
    if not isinstance(receipt, dict):
        return None
    if receipt.get("schema") == "semantic-receipt/v3":
        names = {leaf.get("pointer") for leaf in _revealed_of(receipt)}
        attempt, failure = "/attemptedTarget" in names, "/failureClass" in names
    else:
        content = _content_of(receipt)
        if content is None:
            return None
        attempt, failure = "attemptedTarget" in content, "failureClass" in content
    return _kind_named(attempt, failure)


def _kind_named(attempt: bool, failure: bool) -> str:
    if attempt:
        return "attempt"
    if failure:
        return "failure"
    return "transition"


def _encrypted_kind_of(receipt: Optional[Dict[str, Any]], content: Optional[Dict[str, Any]]) -> Optional[str]:
    """An encrypted record's entry, as ``_kind_of`` reads a plaintext one:
    from the content opened here, or, for an attempt or failure row, from
    which fields the row reveals."""
    if content is not None:
        return _kind_named("attemptedTarget" in content, "failureClass" in content)
    if isinstance(receipt, dict) and receipt.get("schema") in _ROW_RECEIPT_SCHEMAS:
        names = {leaf.get("pointer") for leaf in _revealed_of(receipt)}
        return _kind_named("/attemptedTarget" in names, "/failureClass" in names)
    return None


def _payloads_of_content(content: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """The payloads of an encrypted entry's content, as it was opened here."""
    payloads = content.get("payloads") if content is not None else None
    return payloads if isinstance(payloads, list) else []


def _history_entries(history: Dict[str, Any]) -> List[Dict[str, Any]]:
    entries = history.get("entries")
    if isinstance(entries, list) and entries:
        return entries
    committed = []
    for receipt in history.get("receipts") or []:
        if not isinstance(receipt, dict):
            continue
        committed.append(
            {
                "seq": receipt.get("seq"),
                "status": receipt.get("status") or "committed",
                "receiptId": receipt.get("receiptId"),
            }
        )
    pending = history.get("pendingEntries") or []
    return sorted(
        [*committed, *pending] if isinstance(pending, list) else committed,
        key=lambda row: row.get("seq") if isinstance(row.get("seq"), int) else 0,
    )


def _normalized_handle(handle: str) -> str:
    return unquote(handle).strip().lower()


def _link_refusal(response: Any, path: str) -> PacSpaceError:
    """A link route's refusal, with the API's own sentence and code."""
    try:
        body = json.loads(response.body.decode("utf-8")) if response.body else None
    except (UnicodeDecodeError, ValueError):
        body = None
    nested = body.get("error") if isinstance(body, dict) and isinstance(body.get("error"), dict) else {}
    message = nested.get("message") or (body.get("message") if isinstance(body, dict) else None)
    code = nested.get("code") or (body.get("code") if isinstance(body, dict) else None)
    return map_api_error(
        response.status_code,
        message if isinstance(message, str) else str(response.status_code),
        request_path=path,
        headers=response.headers,
        api_error={"code": code if isinstance(code, str) else None},
    )


def _json_of(response: Any) -> Any:
    try:
        return json.loads(response.body.decode("utf-8")) if response.body else None
    except (UnicodeDecodeError, ValueError):
        return None


class _Identity:
    """This workspace's identity for encrypted records (ADR 0015, N14)."""

    def __init__(self, records: "RecordsResource") -> None:
        self._records = records

    def register(self) -> Dict[str, Any]:
        """Draws the seed, registers its public part and the seed wrapped under
        the current version, and every version's id. Idempotent."""
        return self._records._encrypted().register_identity()


class _Holders:
    """The workspaces this workspace's keys are wrapped to. Wraps go only to a workspace whose code you confirmed."""

    def __init__(self, records: "RecordsResource") -> None:
        self._records = records

    def add(
        self,
        *,
        workspace_id: str,
        scope: str = "workspace",
        required: bool = False,
        record: Optional[str] = None,
        record_type: Optional[str] = None,
        wire_record_id: Optional[str] = None,
        confirmed_code: Optional[str] = None,
    ) -> Dict[str, Any]:
        enc = self._records._encrypted()
        target = None
        if scope == "record" and (record is not None or wire_record_id is not None):
            typed = record_type or DEFAULT_RECORD_TYPE
            target = (typed, self._records._target(typed, record, {"wire_record_id": wire_record_id})[0])
        return enc.add_holder(workspace_id, scope, required is True, target, confirmed_code)

    def list(self) -> Dict[str, Any]:
        return self._records._client.get(f"{_ENCRYPTION}/holders")

    def remove(self, holder_id: str) -> Dict[str, Any]:
        return self._records._client.delete(f"{_ENCRYPTION}/holders/{quote(holder_id, safe='')}")


class _Holdings:
    """The wraps other workspaces stored for this one."""

    def __init__(self, records: "RecordsResource") -> None:
        self._records = records

    def list(self) -> Dict[str, Any]:
        return self._records._client.get(f"{_ENCRYPTION}/holdings")

    def confirm(self) -> List[Dict[str, Any]]:
        """Opens each stored wrap, checks it, and confirms it or refuses it so the writer is told."""
        return self._records._encrypted().confirm_holdings()


class _Grants:
    """Grants on a record. A grant to a named workspace of an encrypted record carries the record's key, wrapped to it."""

    def __init__(self, records: "RecordsResource") -> None:
        self._records = records

    def create(
        self,
        *,
        kind: str,
        record: Optional[str] = None,
        record_type: Optional[str] = None,
        wire_record_id: Optional[str] = None,
        encrypted: Optional[bool] = None,
        recipient_email: Optional[str] = None,
        counterparty_workspace_id: Optional[str] = None,
        authorizes: Optional[Any] = None,
        ttl_hours: Optional[int] = None,
        max_uses: Optional[int] = None,
        label: Optional[str] = None,
        confirmed_code: Optional[str] = None,
    ) -> Dict[str, Any]:
        records = self._records
        typed = record_type or DEFAULT_RECORD_TYPE
        entity_id, is_encrypted = records._target(typed, record, {"wire_record_id": wire_record_id, "encrypted": encrypted})
        body: Dict[str, Any] = {"kind": kind}
        for name, value in (
            ("recipientEmail", recipient_email),
            ("counterpartyTenantId", counterparty_workspace_id),
            ("authorizes", authorizes),
            ("ttlHours", ttl_hours),
            ("maxUses", max_uses),
            ("label", label),
        ):
            if value is not None:
                body[name] = value
        if is_encrypted and records._configured and kind == "TENANT_BOUND" and counterparty_workspace_id:
            reader_wrap = records._encrypted().grant_reader_wrap(typed, entity_id, counterparty_workspace_id, confirmed_code)
            if reader_wrap:
                body["readerWrap"] = reader_wrap
        return records._client.post(_record_path(typed, entity_id, "/grants"), body)

    def list(
        self, *, record: Optional[str] = None, record_type: Optional[str] = None, wire_record_id: Optional[str] = None, encrypted: Optional[bool] = None
    ) -> Dict[str, Any]:
        typed = record_type or DEFAULT_RECORD_TYPE
        entity_id, _ = self._records._target(typed, record, {"wire_record_id": wire_record_id, "encrypted": encrypted})
        return self._records._client.get(_record_path(typed, entity_id, "/grants"))

    def revoke(
        self,
        *,
        grant_id: str,
        record: Optional[str] = None,
        record_type: Optional[str] = None,
        wire_record_id: Optional[str] = None,
        encrypted: Optional[bool] = None,
    ) -> Dict[str, Any]:
        typed = record_type or DEFAULT_RECORD_TYPE
        entity_id, _ = self._records._target(typed, record, {"wire_record_id": wire_record_id, "encrypted": encrypted})
        return self._records._client.post(_record_path(typed, entity_id, f"/grants/{quote(grant_id, safe='')}/revoke"), {})


class RecordsResource:
    def __init__(self, client: HttpClient, encryption: Optional[Dict[str, Any]] = None) -> None:
        self._client = client
        options = encryption or {}
        self._secret = options.get("secret")
        self._secret_provider = options.get("secret_provider")
        self._pin_store = options.get("pin_store")
        self._enc: Any = None
        # The highest wire seq a write in this process was given: (record type, path id) to seq.
        self._last_seq: Dict[Tuple[str, str], int] = {}
        self.identity = _Identity(self)
        self.holders = _Holders(self)
        self.holdings = _Holdings(self)
        self.grants = _Grants(self)

    @property
    def _configured(self) -> bool:
        return self._secret is not None or callable(self._secret_provider)

    def _encrypted(self) -> Any:
        """The encrypted paths, loaded on first use (they run on ``cryptography``)."""
        if self._enc is None:
            from .encrypted_records import EncryptedRecords, RecordsKeys
            from .records_pins import memory_pin_store

            keys = RecordsKeys(self._secret, self._secret_provider)
            self._enc = EncryptedRecords(self._client, keys, self._pin_store or memory_pin_store())
        return self._enc

    def _target(self, record_type: str, record: Optional[str], read: Dict[str, Any]) -> Tuple[str, bool]:
        """The id a read or a write puts in the path, and whether the record is read as encrypted."""
        if read.get("wire_record_id"):
            return read["wire_record_id"], True
        if record is None:
            return "", False
        if read.get("encrypted") is False or (not self._configured and read.get("record_key") is None):
            return record, False
        return self._encrypted().target(record_type, record, read)

    def wire_id(self, record: str, record_type: Optional[str] = None) -> str:
        """The wire id PacSpace knows a record by, as a webhook names it. Needs the workspace secret."""
        return self._encrypted().wire_id(record_type or DEFAULT_RECORD_TYPE, record)

    def wire_reference_id(self, reference_id: str) -> str:
        """The wire id of an entry's reference id. Needs the workspace secret."""
        return self._encrypted().wire_reference_id(reference_id)

    def emit(
        self,
        *,
        record: str,
        title: str,
        occurred_at: str,
        actor_id: str,
        payloads: Iterable[Dict[str, Any]],
        record_type: Optional[str] = None,
        lifecycle: Optional[str] = None,
        kind: Optional[str] = None,
        instructed_by: Optional[str] = None,
        references: Optional[Iterable[Dict[str, Any]]] = None,
        amends: Optional[Dict[str, Any]] = None,
        description: Optional[str] = None,
        note: Optional[str] = None,
        idempotency_key: Optional[str] = None,
        options: Optional[Dict[str, Any]] = None,
        encrypt: Optional[bool] = None,
        labels: Optional[Union[Dict[str, str], str]] = None,
    ) -> Dict[str, Any]:
        """Writes one entry. With a workspace secret set, the entry is
        encrypted (``encrypt=False`` writes plaintext, for records written
        before) and the answer carries ``recordId``, ``wireRecordId`` and
        ``wireReferenceId`` beside it. ``labels`` go on the record, never in
        the entry's content; with a workspace secret set each is blinded
        before it is sent. The answer's ``entry`` is the number this entry
        will have in its record, counted from 1."""
        content: Dict[str, Any] = {
            "title": title,
            "occurredAt": occurred_at,
            "actorId": actor_id,
            "payloads": list(payloads),
        }
        if kind is not None:
            content["kind"] = kind
        if instructed_by is not None:
            content["instructedBy"] = instructed_by
        if description is not None:
            content["description"] = description
        if note is not None:
            content["note"] = note
        if references is not None:
            content["references"] = [
                _wire_ref(ref, f"references[{index}]") for index, ref in enumerate(references)
            ]
        if amends is not None:
            content["amends"] = _wire_ref(amends, "amends")
        reason = _blinding_material_reason(content)
        if reason is not None:
            del content, payloads
            raise _refusal(reason)
        pairs = label_pairs(labels) if labels is not None else None
        typed = record_type or DEFAULT_RECORD_TYPE

        if self._configured and encrypt is not False:
            sent = self._encrypted().emit(typed, record, lifecycle or "recorded", content, idempotency_key, options, pairs)
            response = sent["response"] if isinstance(sent["response"], dict) else {}
            return {
                **self._tracked(typed, sent["wireRecordId"], response),
                "referenceId": idempotency_key,
                "recordId": record,
                "wireRecordId": sent["wireRecordId"],
                "wireReferenceId": sent["wireReferenceId"],
                "encrypted": True,
            }

        body: Dict[str, Any] = {
            "lifecycle": lifecycle or "recorded",
            "content": content,
        }
        if idempotency_key:
            body["referenceId"] = idempotency_key
        if pairs:
            body["labels"] = dict(pairs)

        response = self._client.post(
            _record_path(record_type, record, "/transitions"),
            body,
            options,
        )
        return self._tracked(typed, record, response)

    def _tracked(self, record_type: str, entity_id: str, response: Any) -> Any:
        """Keeps the write's ``seq`` for ``close`` and adds its ``entry``, counted from 1."""
        seq = response.get("seq") if isinstance(response, dict) else None
        if not isinstance(seq, int) or isinstance(seq, bool):
            return response
        key = (record_type, entity_id)
        self._last_seq[key] = max(seq, self._last_seq.get(key, -1))
        return {**response, "entry": seq + 1}

    def close(
        self,
        record: str,
        record_type: Optional[str] = None,
        last_entry: Optional[int] = None,
        *,
        encrypted: Optional[bool] = None,
        options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Closes a record as a fact about it (D-7): no entry is written. The
        close names the record's last entry, so it is refused while entries
        are still arriving. Left out, ``last_entry`` is the last entry this
        process wrote to the record, or the record's own last entry, read
        from PacSpace. With a workspace secret set, ``encrypted=False``
        closes a plaintext record by its own id."""
        typed = record_type or DEFAULT_RECORD_TYPE
        last_seq = _seq_of(last_entry, "last_entry") if last_entry is not None else None
        entity_id, is_encrypted = self._target(typed, record, {"encrypted": encrypted})
        if last_seq is None:
            last_seq = self._last_seq.get((typed, entity_id))
        if last_seq is None:
            state = self._client.get(
                _record_path(typed, entity_id, ""),
                self._encrypted().request_options({}, options) if is_encrypted else options,
            )
            served = state.get("lastSeq") if isinstance(state, dict) else None
            if not isinstance(served, int) or isinstance(served, bool):
                raise ValidationError(_CLOSE_NO_ENTRY)
            last_seq = served
        response = self._client.post(_record_path(typed, entity_id, "/close"), {"lastSeq": last_seq}, options)
        response = response if isinstance(response, dict) else {}
        answered = response.get("lastSeq")
        result = {**response, "lastEntry": answered + 1 if isinstance(answered, int) and not isinstance(answered, bool) else last_seq + 1}
        if is_encrypted:
            result.update({"recordId": record, "wireRecordId": entity_id, "encrypted": True})
        return result

    def receipt(
        self,
        record: Optional[str],
        entry: int,
        record_type: Optional[str] = None,
        options: Optional[Dict[str, Any]] = None,
        *,
        wire_record_id: Optional[str] = None,
        grant: Optional[str] = None,
        owner: Optional[str] = None,
        holder_for: Optional[str] = None,
        record_key: Optional[str] = None,
        encrypted: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """One entry's receipt. An encrypted entry is opened with the
        workspace secret, a holder wrap, a grant's wrap or a record key, and
        checked against its sealed record hash (``opened``)."""
        typed = record_type or DEFAULT_RECORD_TYPE
        read = {
            "wire_record_id": wire_record_id,
            "grant": grant,
            "owner": owner,
            "holder_for": holder_for,
            "record_key": record_key,
            "encrypted": encrypted,
        }
        entity_id, is_encrypted = self._target(typed, record, read)
        path = _record_path(typed, entity_id, f"/receipts/{_seq_of(entry, 'entry')}")
        if not is_encrypted:
            return self._client.get(path, {**(options or {}), "headers": {_GRANT_HEADER: grant}} if grant else options)
        enc = self._encrypted()
        response = self._client.get(path, enc.request_options(read, options))
        receipt = response.get("receipt") if isinstance(response, dict) else None
        if not isinstance(receipt, dict) or receipt.get("schema") not in ("semantic-receipt/v4", "semantic-receipt/v5"):
            return response
        if response.get("recordType") != typed or response.get("entityId") != entity_id:
            raise RecordsEncryptionError("RECORDS_HISTORY_OTHER_RECORD")
        return {**response, "opened": enc.open_receipt(receipt, typed, entity_id, read, options)}

    def history(
        self,
        record: Optional[str],
        from_entry: Optional[int] = None,
        to_entry: Optional[int] = None,
        record_type: Optional[str] = None,
        options: Optional[Dict[str, Any]] = None,
        *,
        wire_record_id: Optional[str] = None,
        grant: Optional[str] = None,
        owner: Optional[str] = None,
        holder_for: Optional[str] = None,
        record_key: Optional[str] = None,
        encrypted: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """The record's history. An encrypted record's entries are opened and
        each checked against its sealed record hash and its stored references
        (``opened``); a history served for another record is refused."""
        read = {
            "wire_record_id": wire_record_id,
            "grant": grant,
            "owner": owner,
            "holder_for": holder_for,
            "record_key": record_key,
            "encrypted": encrypted,
        }
        return self._read_history(record, from_entry, to_entry, record_type, options, read, "/history")

    def bundle(
        self,
        record: Optional[str],
        from_entry: Optional[int] = None,
        to_entry: Optional[int] = None,
        record_type: Optional[str] = None,
        options: Optional[Dict[str, Any]] = None,
        *,
        wire_record_id: Optional[str] = None,
        grant: Optional[str] = None,
        owner: Optional[str] = None,
        holder_for: Optional[str] = None,
        record_key: Optional[str] = None,
        encrypted: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """The history as the downloadable file; opened as ``history()`` opens it."""
        read = {
            "wire_record_id": wire_record_id,
            "grant": grant,
            "owner": owner,
            "holder_for": holder_for,
            "record_key": record_key,
            "encrypted": encrypted,
        }
        return self._read_history(record, from_entry, to_entry, record_type, options, read, "/bundle")

    def _read_history(
        self,
        record: Optional[str],
        from_entry: Optional[int],
        to_entry: Optional[int],
        record_type: Optional[str],
        options: Optional[Dict[str, Any]],
        read: Dict[str, Any],
        route: str,
    ) -> Dict[str, Any]:
        typed = record_type or DEFAULT_RECORD_TYPE
        entity_id, is_encrypted = self._target(typed, record, read)
        query: Dict[str, Any] = {}
        if from_entry is not None:
            query["fromSeq"] = _seq_of(from_entry, "from_entry")
        if to_entry is not None:
            query["toSeq"] = _seq_of(to_entry, "to_entry")
        suffix = route
        if query:
            suffix += "?" + urlencode(query)
        if is_encrypted:
            request_options = self._encrypted().request_options(read, options)
        elif read.get("grant"):
            request_options = {**(options or {}), "headers": {_GRANT_HEADER: read["grant"]}}
        else:
            request_options = options
        raw = self._client.get_raw(_record_path(typed, entity_id, suffix), request_options)
        body = raw["body"] if isinstance(raw, dict) and "body" in raw else raw
        headers = raw.get("headers") if isinstance(raw, dict) else {}
        if isinstance(body, dict):
            next_from = None
            if isinstance(headers, dict):
                next_from = headers.get("x-next-from-seq")
            if next_from is not None:
                try:
                    body = {**body, "nextFromSeq": int(next_from)}
                except (TypeError, ValueError):
                    body = {**body, "nextFromSeq": next_from}
        if not is_encrypted or not isinstance(body, dict) or body.get("schema") != "record-history-bundle/v3":
            return body
        opened, _ = self._encrypted().open_history(body, typed, entity_id, read, options)
        return {**body, "opened": [{"entry": e["entry"], "recordHash": e["recordHash"], "content": e["content"]} for e in opened]}

    def keep_copy(
        self,
        record: Optional[str] = None,
        *,
        record_type: Optional[str] = None,
        wire_record_id: Optional[str] = None,
        options: Optional[Dict[str, Any]] = None,
        encrypted: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """A copy of one encrypted record (pacspace-record-copy/v1): its
        history with its record key, for a reader with no workspace. Whoever
        holds the file can read the record."""
        typed = record_type or DEFAULT_RECORD_TYPE
        entity_id, is_encrypted = self._target(typed, record, {"wire_record_id": wire_record_id, "encrypted": encrypted})
        if not is_encrypted:
            raise RecordsEncryptionError("RECORDS_NOT_ENCRYPTED")
        enc = self._encrypted()
        key, history = enc.own_record_key(typed, entity_id, options)
        if history is None:
            raise RecordsEncryptionError("RECORDS_NOT_ENCRYPTED")
        enc.open_history(history, typed, entity_id, {}, options)
        return {"schema": "pacspace-record-copy/v1", "bytes": enc.copy_of(history, key)}

    def record_key(
        self,
        record: Optional[str] = None,
        *,
        record_type: Optional[str] = None,
        wire_record_id: Optional[str] = None,
        options: Optional[Dict[str, Any]] = None,
        encrypted: Optional[bool] = None,
    ) -> str:
        """One record's key, base64url, for a recipient with no workspace:
        with a grant on the record they read it as ``history(None,
        wire_record_id=..., grant=..., record_key=...)``. It opens this record only."""
        typed = record_type or DEFAULT_RECORD_TYPE
        entity_id, is_encrypted = self._target(typed, record, {"wire_record_id": wire_record_id, "encrypted": encrypted})
        if not is_encrypted:
            raise RecordsEncryptionError("RECORDS_NOT_ENCRYPTED")
        enc = self._encrypted()
        key, _ = enc.own_record_key(typed, entity_id, options)
        return enc.export_record_key(key)

    def share_key_wrap(
        self,
        *,
        handle: str,
        disclosure_key: Union[bytes, str],
        workspace_id: str,
        confirmed_code: Optional[str] = None,
        access_code: Optional[str] = None,
        record: Optional[str] = None,
        record_type: Optional[str] = None,
        wire_record_id: Optional[str] = None,
        options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Stores a disclosure link's key wrapped to a reader workspace whose
        code you confirmed, so it opens the link without the key after #.
        Give them the link with ``#`` and the returned ``fragment`` (``dd=``,
        the disclosure's digest): their client opens only the disclosure
        that digest names."""
        from .encrypted_records import decrypt_disclosure, disclosure_digest_fragment, disclosure_key_of

        typed = record_type or DEFAULT_RECORD_TYPE
        entity_id, _ = self._target(typed, record, {"wire_record_id": wire_record_id})
        key = disclosure_key_of(disclosure_key)
        if key is None:
            raise RecordsEncryptionError("RECORDS_LINK_NO_KEY")
        normalized = _normalized_handle(handle)
        _, envelope = self._link_disclosure(normalized, access_code)
        opened = decrypt_disclosure(envelope, key, normalized) if isinstance(envelope, str) else None
        if not opened or not opened["ok"]:
            raise RecordsEncryptionError("RECORDS_DISCLOSURE_LINK_MISMATCH")
        digest = compute_record_disclosure_digest(opened["disclosure"])
        if digest != opened["disclosure"].get("digest"):
            raise RecordsEncryptionError("RECORDS_DISCLOSURE_LINK_MISMATCH")
        body = self._encrypted().disclosure_wrap(normalized, key, workspace_id, confirmed_code)
        stored = self._client.put(_record_path(typed, entity_id, f"/share/{quote(normalized, safe='')}/key-wraps"), body, options)
        return {**(stored if isinstance(stored, dict) else {}), "fragment": disclosure_digest_fragment(digest)}

    def _link_disclosure(self, handle: str, access_code: Optional[str]) -> Tuple[Dict[str, Any], Any]:
        """A link's seal history and sealed disclosure, read as anyone with the link reads them."""

        def path(tail: str) -> str:
            return f"/api/v1/c/{quote(handle, safe='')}{tail}"

        headers = {"Accept": "application/json"}
        if access_code:
            verified = self._client.request_public(
                "POST",
                path("/access/verify"),
                {**headers, "Content-Type": "application/json"},
                json.dumps({"factor": "ACCESS_HINT", "value": access_code}),
            )
            if not 200 <= verified.status_code < 300:
                raise _link_refusal(verified, path("/access/verify"))
            cookie = (verified.headers.get("set-cookie") or "").split(";")[0]
            if cookie:
                headers["Cookie"] = cookie
        seals = self._client.request_public("GET", path("/history"), {**headers, "X-Record-Entries": "all"})
        if not 200 <= seals.status_code < 300:
            raise _link_refusal(seals, path("/history"))
        form = _json_of(seals)
        if not isinstance(form, dict):
            raise _malformed_disclosure()
        answer = self._client.request_public("GET", path("/disclosure"), headers)
        served = _json_of(answer) if 200 <= answer.status_code < 300 else None
        return form, served.get("envelope") if isinstance(served, dict) else None

    def open(self, link: str, access_code: Optional[str] = None) -> Dict[str, Any]:
        """Opens a disclosure link: its seal history and its disclosure,
        opened with the key after # or, when there is none, with this
        workspace's wrap, then checked up to each entry's record hash. A
        seal history whose digest does not match its contents is refused,
        and one under a layout this version does not carry is not read. The
        seals and the ledger are not checked here."""
        from .encrypted_records import decrypt_disclosure, read_link_fragment

        url = urlparse(urljoin(self._client.base_url + "/", link))
        found = re.search(r"/c/([^/]+)/?$", url.path)
        if found is None:
            raise _malformed_disclosure()
        handle = _normalized_handle(found.group(1))
        form, envelope = self._link_disclosure(handle, access_code)
        # The seal history's own digest, then the layout it names, before any key and before a link with no disclosure is answered.
        stopped = seal_history_refusal(form)
        if stopped == "RECORDS_LAYOUT_NOT_READ":
            raise RecordsEncryptionError("RECORDS_LAYOUT_NOT_READ")
        if stopped is not None:
            raise _malformed_disclosure()
        if not isinstance(envelope, str):
            return {"handle": handle, "sealHistory": form, "disclosure": None, "entries": []}

        # Card 10, D1 a: a key from a wrap opens only the disclosure the link's dd= names.
        fragment = read_link_fragment("#" + url.fragment) if url.fragment else None
        key = fragment["key"] if fragment and fragment["kind"] == "key" else None
        expected_digest = None if key is not None else (fragment["digest"] if fragment else "")
        if key is None and self._configured:
            key = self._encrypted().disclosure_key_from_wrap(handle)
        if key is None:
            raise RecordsEncryptionError("RECORDS_LINK_NO_KEY")
        opened = decrypt_disclosure(envelope, key, handle)
        if not opened["ok"]:
            raise PacSpaceError(opened["reason"], 0, opened["code"])
        disclosure = opened["disclosure"]
        disclosure_form = _disclosure_form_of(form, disclosure)
        if disclosure_form is None:
            raise _malformed_disclosure()
        checked = verify_record_disclosure_v1(disclosure_form, disclosure)
        if checked["ok"] is False:
            raise PacSpaceError(checked["reason"] or checked["code"], 0, checked["code"])
        if expected_digest is not None and disclosure.get("digest") != expected_digest:
            raise RecordsEncryptionError("RECORDS_DISCLOSURE_LINK_MISMATCH")
        return {
            "handle": handle,
            "sealHistory": form,
            "disclosure": disclosure,
            "entries": [
                {"entry": e["seq"] + 1, "fields": e["fields"], "content": e["content"], "withheld": e["withheld"]} for e in checked["entries"]
            ],
            "chainCheck": checked["chainCheck"],
            "chainCheckNote": checked["chainCheckNote"],
        }

    def rotate(self, next_keyring: str) -> Dict[str, Any]:
        """Moves to the next workspace secret: registers its new version,
        wraps that version's key to every workspace holder whose pin is held,
        and wraps this workspace's seed under it. Writes under it wait for
        required holders to confirm."""
        return self._encrypted().rotate(next_keyring)

    def rekey(
        self,
        *,
        to_version: int,
        record: Optional[str] = None,
        record_type: Optional[str] = None,
        wire_record_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Re-encrypts a record's stored entries under a newer version, latest
        first; seals and record hashes are unchanged. Then wraps the record's
        new key to its grants and record holders whose pins are held."""
        typed = record_type or DEFAULT_RECORD_TYPE
        entity_id, is_encrypted = self._target(typed, record, {"wire_record_id": wire_record_id})
        if not is_encrypted:
            raise RecordsEncryptionError("RECORDS_NOT_ENCRYPTED")
        return self._encrypted().rekey(typed, entity_id, to_version)

    def check(
        self,
        history: Dict[str, Any],
        expect: Optional[Iterable[Dict[str, Any]]] = None,
        source: Optional[Dict[str, Any]] = None,
        *,
        grant: Optional[str] = None,
        owner: Optional[str] = None,
        holder_for: Optional[str] = None,
        record_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Lists a history's entries with each one's status and kind, and
        compares the fingerprints or files named in ``expect`` (by entry,
        counted from 1) with the ones each entry holds.

        A plaintext history (record-history-bundle/v1 or v2) is held to the
        digest it carries, and to the layouts this version carries, and is
        then read as it was given: no seal or leaf is checked here.

        An encrypted record's history (record-history-bundle/v3) is held to
        its digest and to the layouts this version carries, then opened
        here with the record's key: the workspace secret's, or the one
        ``grant`` and ``owner``, ``record_key`` or ``holder_for`` name, as
        ``history()`` took them. Every entry is opened and checked against
        its sealed record hash and its stored references, and each refused
        envelope against its record hash. In a record hash v3 history, each
        entry's seal is also recomputed and compared with its word. The
        fingerprints compared with ``expect`` are read from what was opened
        here, never from the ``opened`` list passed in. A history that does
        not open, or whose key is not found, is not ``ok``.

        A history changed after it was exported is not ``ok`` ("Bundle
        digest does not match the bundle contents."), and one written under
        a layout this version does not carry is not read.

        On an encrypted history it does not check the layout's words, the
        Merkle paths, the chain between entries or the ledger, and it reads
        no ``source``. In a record hash v2 history it
        checks no seal, and not the fields an attempt or failure row
        reveals. Those checks are the TypeScript SDK's and the checker's."""
        schema = history.get("schema") if isinstance(history, dict) else None
        encrypted = schema == _ENCRYPTED_HISTORY_SCHEMA
        if schema is not None and not encrypted and schema not in _HISTORY_SCHEMAS:
            return {
                "ok": False,
                "entries": [],
                "failedCheck": "schema",
                "sourceChecked": False,
                "reason": "Not a record-history-bundle/v1.",
                "note": None,
            }
        rows = list(expect or [])
        reason = _expect_reason(rows)
        if reason is not None:
            del rows, expect
            raise _refusal(reason)
        entries = _history_entries(history)
        receipts_by_seq = {
            receipt.get("seq"): receipt
            for receipt in history.get("receipts") or []
            if isinstance(receipt, dict) and isinstance(receipt.get("seq"), int)
        }
        expect_by_seq = {
            _seq_of(row["entry"], f"expect[{index}].entry"): (
                row.get("payloads") or [],
                [_held_file(held["source"], held.get("blinding")) for held in row.get("files") or []],
            )
            for index, row in enumerate(rows)
        }

        # An encrypted record's history is opened first with the record's key,
        # each entry checked against its sealed record hash. Its fingerprints
        # and kinds are read from what was opened here, never from what the
        # caller passed as ``opened``. An open that raises confirms nothing;
        # the result says so and is not ok.
        opened_by_seq: Dict[Any, Dict[str, Any]] = {}
        refusal: Optional[Tuple[str, Optional[str]]] = None
        if not encrypted:
            refusal = _plaintext_refusal(history)
        if encrypted:
            # ``opened`` and ``nextFromSeq`` are this SDK's additions to what was served.
            served = {key: value for key, value in history.items() if key not in ("opened", "nextFromSeq")}
            read = {"grant": grant, "owner": owner, "holder_for": holder_for, "record_key": record_key}
            try:
                from .encrypted_records import read_refusal

                result, _ = self._encrypted().try_open_history(served, read)
            except Exception as error:  # noqa: BLE001 - whatever stopped the open, the check did not pass
                refusal = ("schema", _CHECK_DID_NOT_FINISH + (error.message if isinstance(error, PacSpaceError) else str(error)))
            else:
                if not result["ok"]:
                    refusal = ("schema" if result["code"] in _ENCRYPTED_FORM_REFUSALS else "semantic", read_refusal(result).message)
                elif result["sealsVerified"] is False:
                    # A record hash v3 history with a seal that does not reproduce its word's seal tag: nothing it holds is confirmed.
                    refusal = ("semantic", RECORD_HISTORY_SEAL_SENTENCE)
                else:
                    opened_by_seq = {item["seq"]: item["content"] for item in result["opened"] if "content" in item}

        results = []
        expect_failed = False
        blinding_file_needed: List[int] = []
        for entry in entries:
            seq = entry.get("seq")
            status = entry.get("status") or "queued"
            if status != "committed" or refusal is not None:
                kind = None
            elif encrypted:
                kind = _encrypted_kind_of(receipts_by_seq.get(seq), opened_by_seq.get(seq))
            else:
                kind = _kind_of(receipts_by_seq.get(seq))
            row = {
                # The result speaks entry numbers as the pages do: the wire's seq 0 is entry 1.
                "entry": _entry_of(seq),
                "status": status,
                "kind": kind,
                "code": entry.get("code"),
                "sentence": entry.get("sentence"),
            }
            if seq in expect_by_seq:
                wanted, held_files = expect_by_seq[seq]
                payloads = _payloads_of_content(opened_by_seq.get(seq)) if encrypted else _payloads_of(receipts_by_seq.get(seq) or {})
                committed = {_fingerprint_key(ref) for ref in payloads if isinstance(ref, dict)}
                files_ok = True
                for held in held_files:
                    match = _match_held_file(payloads, held)
                    if match["matched"]:
                        continue
                    files_ok = False
                    if match["blindingNeeded"] and seq + 1 not in blinding_file_needed:
                        blinding_file_needed.append(seq + 1)
                row["expected"] = files_ok and all(_fingerprint_key(ref) in committed for ref in wanted)
                if row["expected"] is False:
                    expect_failed = True
            results.append(row)

        failed = [row for row in entries if row.get("status") == "failed"]
        committed = [row for row in entries if row.get("status") == "committed"]
        if encrypted:
            # The status list is outside what was opened: a committed entry is one whose receipt is in this history.
            committed = [row for row in committed if row.get("seq") in receipts_by_seq]
        failed_check = None
        reason = None
        if refusal is not None:
            failed_check, reason = refusal
        elif failed:
            failed_check = "schema"
            reason = failed[0].get("sentence") or "A queued write did not commit."
        elif not committed:
            failed_check = "schema"
            reason = "No committed entries."
        elif expect_failed:
            failed_check = "semantic"
            reason = "A fingerprint you hold is not among the committed payloads."

        result = {
            "ok": failed_check is None,
            "entries": results,
            "failedCheck": failed_check,
            "sourceChecked": False,
            "reason": reason,
            "note": (
                None
                if source is None
                else "Check from code is available in TypeScript today."
            ),
        }
        if blinding_file_needed:
            result["blindingFileNeeded"] = blinding_file_needed
            result["note"] = _CHECK_NOTE
        return result
