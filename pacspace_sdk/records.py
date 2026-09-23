from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import quote, urlencode

from .client import HttpClient
from .errors import ValidationError

DEFAULT_RECORD_TYPE = "machine-action-record"


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


def _payloads_of(receipt: Dict[str, Any]) -> List[Dict[str, Any]]:
    content = receipt.get("recordContent")
    if not isinstance(content, dict):
        sealed = receipt.get("sealedRecord")
        content = sealed.get("content") if isinstance(sealed, dict) else None
    payloads = content.get("payloads") if isinstance(content, dict) else None
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
        entries = _history_entries(history)
        receipts_by_seq = {
            receipt.get("seq"): receipt
            for receipt in history.get("receipts") or []
            if isinstance(receipt, dict) and isinstance(receipt.get("seq"), int)
        }
        expect_by_seq = {
            _seq_of(row["entry"], f"expect[{index}].entry"): row.get("payloads") or []
            for index, row in enumerate(expect or [])
            if isinstance(row, dict) and "entry" in row
        }

        results = []
        expect_failed = False
        for entry in entries:
            seq = entry.get("seq")
            row = {
                # The result speaks entry numbers as the pages do: the wire's seq 0 is entry 1.
                "entry": _entry_of(seq),
                "status": entry.get("status") or "queued",
                "code": entry.get("code"),
                "sentence": entry.get("sentence"),
            }
            if seq in expect_by_seq:
                wanted = expect_by_seq[seq]
                committed = {
                    _fingerprint_key(ref)
                    for ref in _payloads_of(receipts_by_seq.get(seq) or {})
                    if isinstance(ref, dict)
                }
                row["expected"] = all(
                    _fingerprint_key(ref) in committed
                    for ref in wanted
                    if isinstance(ref, dict)
                )
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

        return {
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
