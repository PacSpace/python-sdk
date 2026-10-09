"""Intake's admission of an entry (shared ``admitRecordEntryV1``), run before
an entry is encrypted, because intake cannot read encrypted content. The SDK
sends a lifecycle and content only, so the state is the lifecycle word with
no flags and no other field: the checks are the layout's sealed-content
schema, the record hash's leaf cap, the payload references (Rule B included)
and the state, in intake's order and with intake's codes and messages.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from .published_layouts import PUBLISHED_LAYOUT_DOCUMENTS_V1, PUBLISHED_RECORD_CONTENT_SCHEMAS_V1
from .record_disclosure import record_leaves_v2

_RESERVED_CONTENT_FIELDS = ("seq", "previousWord", "newWord", "anchorId", "itemIndex", "recordKey", "batchSeed", "recordOpening", "itemOpening")
_TOO_MANY_LEAVES = "This entry has more than 65535 fields and list items. Split it across entries."
_MATERIAL = (
    "This write includes a blinding file or its value. Send only the fingerprint's alg, digest and byteLength; "
    "the blinding file stays with you."
)
_EXTRA_FIELD = "A blinded fingerprint carries only alg, digest and byteLength. Move any other field out of it."
_BLINDING_FILE_SCHEMA = "pacspace-blinding/v1"
_PAYLOAD_REF_ALGS = ("sha-256", "hmac-sha-256")
_PAYLOAD_REF_FIELDS = frozenset(("alg", "digest", "byteLength"))

_BYTES32 = re.compile(r"0x[0-9a-f]{64}", re.IGNORECASE)
_RFC3339_UTC = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z")
_SIGNED_DECIMAL = re.compile(r"-?\d+(\.\d+)?")
_ISO_4217 = re.compile(r"[A-Z]{3}")
_LOWERCASE_HYPHEN = re.compile(r"[a-z0-9]+(-[a-z0-9]+)*")


class RecordIntakeError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) or isinstance(value, float) and value.is_integer()


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and value == value and value not in (float("inf"), float("-inf"))


def _is_record_ref(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and isinstance(value.get("recordKey"), str)
        and _BYTES32.fullmatch(value["recordKey"]) is not None
        and _is_int(value.get("seq"))
        and value["seq"] >= 0
    )


def _is_adjusts_ref(value: Any) -> bool:
    if not isinstance(value, dict) or len(value) != 1:
        return False
    key = next(iter(value))
    return key in ("referenceId", "recordId") and isinstance(value[key], str) and len(value[key]) > 0


def _item_matches(items: Optional[str], value: Any) -> bool:
    if items == "record-ref/v1":
        return _is_record_ref(value)
    if items == "payload-ref/v1":
        return isinstance(value, dict)
    if items == "string":
        return isinstance(value, str)
    return True


def _type_matches(spec: Dict[str, Any], value: Any) -> bool:
    kind, fmt = spec.get("type"), spec.get("format")
    if kind == "string":
        if not isinstance(value, str):
            return False
        pattern = {"rfc3339-utc": _RFC3339_UTC, "signed-decimal": _SIGNED_DECIMAL, "iso-4217": _ISO_4217, "lowercase-hyphen": _LOWERCASE_HYPHEN}.get(fmt)
        return pattern is None or pattern.fullmatch(value) is not None
    if kind == "number":
        return _is_number(value)
    if kind == "integer":
        return _is_number(value) and _is_int(value)
    if kind == "boolean":
        return isinstance(value, bool)
    if kind == "array":
        return isinstance(value, list) and all(_item_matches(spec.get("items"), v) for v in value)
    if kind in ("object", "payload-ref/v1"):
        return isinstance(value, dict)
    if kind == "bytes32-hex":
        return isinstance(value, str) and _BYTES32.fullmatch(value) is not None
    if kind == "record-ref/v1":
        return _is_record_ref(value)
    if kind == "adjusts-ref/v1":
        return _is_adjusts_ref(value)
    return True


def _describe_type(spec: Dict[str, Any]) -> str:
    if spec.get("type") == "array" and spec.get("items"):
        return f"an array of {spec['items']}"
    if spec.get("type") == "record-ref/v1":
        return "{ recordKey, seq }"
    if spec.get("type") == "adjusts-ref/v1":
        return "{ referenceId } or { recordId }"
    return f"{spec.get('type')}{' (' + spec['format'] + ')' if spec.get('format') else ''}"


def _minimum(field: str, spec: Dict[str, Any]) -> RecordIntakeError:
    count = spec["minItems"]
    code = "RECORD_PAYLOADS_REQUIRED" if field == "payloads" else "RECORD_CONTENT_INVALID"
    return RecordIntakeError(code, f"content.{field} must carry at least {count} {spec.get('items') or 'item'}{'' if count == 1 else 's'}")


def _validate_content(schema_name: str, content: Any) -> None:
    schema = next((s for s in PUBLISHED_RECORD_CONTENT_SCHEMAS_V1 if s["name"] == schema_name), None)
    if schema is None:
        raise RecordIntakeError("RECORD_LAYOUT_INVALID", f"record-content schema {schema_name} is not published")
    if not isinstance(content, dict):
        raise RecordIntakeError("RECORD_CONTENT_INVALID", "content must be an object")
    fields: Dict[str, Dict[str, Any]] = schema["fields"]
    for field in schema["requiredFields"]:
        if content.get(field) is None:
            spec = fields.get(field)
            if spec and spec.get("type") == "array" and spec.get("minItems"):
                raise _minimum(field, spec)
            raise RecordIntakeError("RECORD_CONTENT_INVALID", f"content.{field} is required by {schema['name']}")
    for field in _RESERVED_CONTENT_FIELDS:
        if field in content:
            raise RecordIntakeError("RECORD_CONTENT_INVALID", f"content.{field} is PacSpace bookkeeping and is never part of a sealed record")
    for field, spec in fields.items():
        if field not in content:
            continue
        if spec.get("when") and re.search(r"attempt record|failure record", spec["when"]):
            raise RecordIntakeError("RECORD_CONTENT_INVALID", f"content.{field} is written by PacSpace and cannot be supplied")
        value = content[field]
        if not _type_matches(spec, value):
            raise RecordIntakeError("RECORD_CONTENT_INVALID", f"content.{field} must be {_describe_type(spec)}")
        if spec.get("type") == "array" and spec.get("minItems") and len(value) < spec["minItems"]:
            raise _minimum(field, spec)
        if spec.get("type") == "string" and spec.get("maxLength") and _utf16_length(value) > spec["maxLength"]:
            code = "RECORD_TITLE_TOO_LONG" if field == "title" else "RECORD_CONTENT_INVALID"
            raise RecordIntakeError(code, f"content.{field} is longer than {spec['maxLength']} characters")


def _utf16_length(text: str) -> int:
    return len(text.encode("utf-16-le")) // 2


def _leaf_count(content: Dict[str, Any]) -> None:
    try:
        record_leaves_v2(content)
    except ValueError as error:
        if str(error) == _TOO_MANY_LEAVES:
            raise RecordIntakeError("RECORD_CONTENT_INVALID", _TOO_MANY_LEAVES) from None


def _validate_payload_ref(ref: Dict[str, Any]) -> None:
    if ref.get("alg") not in _PAYLOAD_REF_ALGS:
        raise RecordIntakeError("RECORD_PAYLOAD_ALG_UNSUPPORTED", f"payload alg is not supported; use one of {', '.join(_PAYLOAD_REF_ALGS)}")
    digest, byte_length = ref.get("digest"), ref.get("byteLength")
    if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise RecordIntakeError("RECORD_CONTENT_INVALID", "payload digest must be 64 lowercase hex characters")
    if not isinstance(byte_length, str) or re.fullmatch(r"\d+", byte_length) is None:
        raise RecordIntakeError("RECORD_CONTENT_INVALID", "payload byteLength must be a decimal string")
    if ref.get("alg") == "hmac-sha-256" and re.fullmatch(r"0|[1-9][0-9]*", byte_length) is None:
        raise RecordIntakeError("RECORD_CONTENT_INVALID", "payload byteLength must be a decimal string with no leading zero")


def _rule_b(obj: Dict[str, Any]) -> None:
    if obj.get("schema") == _BLINDING_FILE_SCHEMA:
        raise RecordIntakeError("RECORD_BLINDING_INCLUDED", _MATERIAL)
    ref = obj.get("ref")
    if isinstance(ref, dict) and ref.get("alg") == "hmac-sha-256" and "blinding" in obj and obj["blinding"] is not None:
        raise RecordIntakeError("RECORD_BLINDING_INCLUDED", _MATERIAL)
    if obj.get("alg") == "hmac-sha-256":
        if any(key not in _PAYLOAD_REF_FIELDS for key in obj):
            raise RecordIntakeError("RECORD_BLINDING_INCLUDED", _EXTRA_FIELD)
        _validate_payload_ref(obj)


def _payload_refs(value: Any, inside_reference_extras: bool = False) -> None:
    if isinstance(value, list):
        for item in value:
            _payload_refs(item, inside_reference_extras)
        return
    if not isinstance(value, dict):
        return
    _rule_b(value)
    if "alg" in value and "digest" in value and "byteLength" in value:
        if not inside_reference_extras:
            _validate_payload_ref(value)
        for key, field in value.items():
            if inside_reference_extras or key not in _PAYLOAD_REF_FIELDS:
                _payload_refs(field, True)
        return
    for field in value.values():
        _payload_refs(field, inside_reference_extras)


def _pack_state(doc: Dict[str, Any], lifecycle: Any) -> None:
    values: Dict[str, Any] = {"layoutId": doc["layoutId"], "layoutVersion": doc["layoutVersion"], doc["lifecycle"]["field"]: lifecycle, "flags": [], "seq": 0}
    for f in doc["fields"]:
        name, kind = f["name"], f["type"]
        if kind == "enum":
            word = values.get(name)
            if not isinstance(word, str) or word not in f["values"]:
                raise RecordIntakeError("RECORD_STATE_UNKNOWN", f"{name}={_js_string(word)} is not in the layout")
        elif kind == "flags":
            for flag in values.get(name) or []:
                if flag not in f["bitNames"]:
                    raise RecordIntakeError("RECORD_FLAG_UNKNOWN", f"{name}:{flag} is not in the layout")
        elif kind in ("counter", "quantity"):
            fixed = f.get("fixed") if kind == "counter" else None
            value = values.get(name, fixed)
            v = 0 if value is None else int(value)
            if fixed is not None and v != fixed:
                raise RecordIntakeError("RECORD_LAYOUT_MISMATCH", f"{name} must be {fixed}")
            if v < 0 or v >= 1 << f["bits"]:
                raise RecordIntakeError("RECORD_QUANTITY_OVERFLOW", f"{name}={v} exceeds {f['bits']} bits")


def _js_string(value: Any) -> str:
    if value is None:
        return "undefined"
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _admit(doc: Dict[str, Any], lifecycle: str, content: Dict[str, Any]) -> Optional[RecordIntakeError]:
    try:
        _validate_content(doc["sealedRecordSchema"], content)
        _leaf_count(content)
        if not isinstance(content, dict):
            raise RecordIntakeError("RECORD_CONTENT_INVALID", "content must be an object")
        _payload_refs(content)
        _pack_state(doc, lifecycle)
        _validate_content(doc["sealedRecordSchema"], content)
    except RecordIntakeError as error:
        return error
    return None


def layouts_for(record_type: str) -> List[Dict[str, Any]]:
    """The published layouts of a record type, by layout id."""
    docs = [d for d in PUBLISHED_LAYOUT_DOCUMENTS_V1 if d.get("recordTypeId") == record_type]
    return sorted(docs, key=lambda d: d["layoutId"])


def admit_record_entry(record_type: str, lifecycle: str, content: Dict[str, Any]) -> Optional[Tuple[str, str]]:
    """``(code, message)`` of the first layout's refusal when no layout of the
    record type admits the entry; None when one does, or the type has no
    published layout (intake decides then)."""
    first: Optional[RecordIntakeError] = None
    for doc in layouts_for(record_type):
        refused = _admit(doc, lifecycle, content)
        if refused is None:
            return None
        first = first or refused
    return (first.code, first.message) if first is not None else None
