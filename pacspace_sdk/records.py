from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import quote, urlencode

from .client import HttpClient
from .errors import PacSpaceError, ValidationError
from .fingerprint import BLINDING_FILE_SCHEMA, Blinding, Fingerprint, _digests

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


_HISTORY_SCHEMAS = ("record-history-bundle/v1", "record-history-bundle/v2")
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
    if attempt:
        return "attempt"
    if failure:
        return "failure"
    return "transition"


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


class RecordsResource:
    def __init__(self, client: HttpClient) -> None:
        self._client = client

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
    ) -> Dict[str, Any]:
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

        body: Dict[str, Any] = {
            "lifecycle": lifecycle or "recorded",
            "content": content,
        }
        if idempotency_key:
            body["referenceId"] = idempotency_key

        return self._client.post(
            _record_path(record_type, record, "/transitions"),
            body,
            options,
        )

    def receipt(
        self,
        record: str,
        entry: int,
        record_type: Optional[str] = None,
        options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return self._client.get(
            _record_path(record_type, record, f"/receipts/{_seq_of(entry, 'entry')}"),
            options,
        )

    def history(
        self,
        record: str,
        from_entry: Optional[int] = None,
        to_entry: Optional[int] = None,
        record_type: Optional[str] = None,
        options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        query: Dict[str, Any] = {}
        if from_entry is not None:
            query["fromSeq"] = _seq_of(from_entry, "from_entry")
        if to_entry is not None:
            query["toSeq"] = _seq_of(to_entry, "to_entry")
        suffix = "/history"
        if query:
            suffix += "?" + urlencode(query)
        raw = self._client.get_raw(_record_path(record_type, record, suffix), options)
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
        return body

    def check(
        self,
        history: Dict[str, Any],
        expect: Optional[Iterable[Dict[str, Any]]] = None,
        source: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        schema = history.get("schema") if isinstance(history, dict) else None
        if schema is not None and schema not in _HISTORY_SCHEMAS:
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

        results = []
        expect_failed = False
        blinding_file_needed: List[int] = []
        for entry in entries:
            seq = entry.get("seq")
            status = entry.get("status") or "queued"
            row = {
                # The result speaks entry numbers as the pages do: the wire's seq 0 is entry 1.
                "entry": _entry_of(seq),
                "status": status,
                "kind": _kind_of(receipts_by_seq.get(seq)) if status == "committed" else None,
                "code": entry.get("code"),
                "sentence": entry.get("sentence"),
            }
            if seq in expect_by_seq:
                wanted, held_files = expect_by_seq[seq]
                payloads = _payloads_of(receipts_by_seq.get(seq) or {})
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
        failed_check = None
        reason = None
        if failed:
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
