"""record-disclosure/v1 and v2, checked up to the record hash and the seal
(record hash v2 and v3).

A disclosure shows chosen fields of chosen entries of one record. This module
checks each shown field against its entry's leaves or items, those against
the record hash the record's seal history gives for that entry, and the seal
over that hash against the entry's word (record_seal.py). It does not
recompute an item hash's Merkle path and reads no ledger. Every result says
so in ``chainCheck`` and ``chainCheckNote``; the ledger check is
``@pacspace-io/check``'s. It uses ``hashlib``, ``hmac`` and the module's own
keccak256 only, and its own RFC 8785 serializer.
"""

from __future__ import annotations

import hashlib
import hmac
import math
import re
from decimal import Decimal
from typing import Any, Dict, List, Optional, Tuple

__all__ = [
    "canonicalize_jcs",
    "commit_record_content_v2",
    "commit_record_content_v3",
    "compute_leaf_hash_v2",
    "compute_leaf_hash_v3",
    "compute_record_disclosure_digest",
    "compute_record_disclosure_digest_v1",
    "compute_record_hash_v2",
    "compute_record_hash_v3",
    "derive_leaf_salt_v2",
    "derive_leaf_salt_v3",
    "member_tag_v3",
    "open_record_entry_v3",
    "record_leaves_v2",
    "validate_record_items_v3",
    "verify_record_disclosure_v1",
    "verify_record_link_copy_v1",
]

RECORD_DISCLOSURE_SCHEMA_V1 = "record-disclosure/v1"
RECORD_DISCLOSURE_SCHEMA_V2 = "record-disclosure/v2"
RECORD_LINK_COPY_SCHEMA_V1 = "record-link-copy/v1"
RECORD_SEAL_HISTORY_SCHEMA_V1 = "record-seal-history/v1"
RECORD_DISCLOSURE_MAX_BYTES_V1 = 1048576
RECORD_LEAVES_MAX_V2 = 65535
RECORD_ITEMS_MAX_V3 = 65535
RECORD_SLOT_WHOLE_V3 = 0xFFFF
_ELEMENT_INDEX_MAX_V3 = 65534

_LABEL_SALT = b"pacspace:record-leaf-salt:v2"
_LABEL_LEAF = b"pacspace:record-leaf:v2"
_LABEL_RECORD = b"pacspace:record:v2"
_LABEL_DIGEST = b"pacspace:record-disclosure-digest:v1"
_LABEL_DIGEST_V2 = b"pacspace:record-disclosure-digest:v2"
_LABEL_MEMBER_V3 = b"pacspace:record-member:v3"
_LABEL_SALT_V3 = b"pacspace:record-leaf-salt:v3"
_LABEL_LEAF_V3 = b"pacspace:record-leaf:v3"
_LABEL_RECORD_V3 = b"pacspace:record:v3"

_HEX32 = re.compile(r"0x[0-9a-f]{64}")
_ADDRESS = re.compile(r"0x[0-9a-f]{40}")
_CANONICAL_INDEX = re.compile(r"0|[1-9][0-9]*")
_FIRST_SEGMENT = re.compile(r"(?:[^~]|~[01])*")
_UINT32_MAX = 4294967295
_SAFE_MAX = 9007199254740991

_REASONS = {
    "DISCLOSURE_MALFORMED": lambda n: "This is not a record disclosure this version can read.",
    "DISCLOSURE_TOO_LARGE": lambda n: "This disclosure is larger than 1 MiB, the most one disclosure may hold.",
    "DISCLOSURE_DIGEST_MISMATCH": lambda n: "This disclosure was changed after it was made: its digest does not match its contents.",
    "DISCLOSURE_RECORD_MISMATCH": lambda n: "This disclosure is for a different record than the history it was checked against.",
    "DISCLOSURE_ENTRY_NOT_IN_HISTORY": lambda n: f"Entry {n} of this disclosure is not in the record's sealed history.",
    "DISCLOSURE_LEAF_MISMATCH": lambda n: f"A shown field of entry {n} does not match the fields sealed for that entry.",
    "DISCLOSURE_SEAL_MISMATCH": lambda n: f"Entry {n} of this disclosure does not reproduce the seal recorded on the ledger for it.",
    "RECORD_HASH_VERSION_MISMATCH": lambda n: "This shared record's format doesn't match the record on the ledger.",
}


def _record_hash_mismatch(n: int) -> str:
    return f"Entry {n} of this disclosure does not match the record hash in the record's sealed history."



_CHAIN_CHECK_NOTE = (
    "This check covers each shown field up to its record hash and its seal, and compares them with the record's seal history. "
    "It does not check the ledger; run @pacspace-io/check for that."
)
_NOTE_V1 = "This entry was sealed before record hash v2; check it with @pacspace-io/check."
_NOTE_NO_RECORD_HASH = (
    "The record's sealed history gives no record hash for this entry to compare with; check it with @pacspace-io/check."
)


class JcsError(ValueError):
    pass


# ------------------------------------------------------------------ RFC 8785


def _utf16_key(text: str) -> bytes:
    return text.encode("utf-16-be", "surrogatepass")


def _jcs_string(text: str) -> str:
    out = ['"']
    for ch in text:
        code = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\f":
            out.append("\\f")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif code < 0x20 or 0xD800 <= code <= 0xDFFF:
            out.append(f"\\u{code:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _jcs_number(value: Any) -> str:
    """ECMAScript Number.prototype.toString for a finite double, which RFC 8785 uses."""
    try:
        number = float(value)
    except OverflowError as error:
        raise JcsError("JCS cannot encode a non-finite number.") from error
    if not math.isfinite(number):
        raise JcsError("JCS cannot encode a non-finite number.")
    if number == 0:
        return "0"
    sign = "-" if number < 0 else ""
    _, digit_tuple, exponent = Decimal(repr(abs(number))).as_tuple()
    digits = "".join(str(d) for d in digit_tuple).rstrip("0") or "0"
    k = len(digits)
    n = len(digit_tuple) + int(exponent)
    if k <= n <= 21:
        body = digits + "0" * (n - k)
    elif 0 < n <= 21:
        body = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        body = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        mantissa = digits if k == 1 else digits[0] + "." + digits[1:]
        body = f"{mantissa}e{'+' if e >= 0 else '-'}{abs(e)}"
    return sign + body


def canonicalize_jcs(value: Any) -> str:
    """RFC 8785 over the JSON value space, as ECMAScript's JSON.stringify writes strings and numbers."""
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _jcs_string(value)
    if isinstance(value, (int, float)):
        return _jcs_number(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(canonicalize_jcs(item) for item in value) + "]"
    if isinstance(value, dict):
        for key in value:
            if not isinstance(key, str):
                raise JcsError("JCS member names are strings.")
        keys = sorted(value.keys(), key=_utf16_key)
        return "{" + ",".join(f"{_jcs_string(key)}:{canonicalize_jcs(value[key])}" for key in keys) + "}"
    raise JcsError(f"JCS cannot encode a value of type {type(value).__name__}.")


def _utf8(text: str) -> bytes:
    return text.encode("utf-8", "surrogatepass")


# ------------------------------------------------------------ record hash v2


def _has_lone_surrogate(value: Any) -> bool:
    if isinstance(value, str):
        return any(0xD800 <= ord(ch) <= 0xDFFF for ch in value)
    if isinstance(value, (list, tuple)):
        return any(_has_lone_surrogate(item) for item in value)
    if isinstance(value, dict):
        return any(_has_lone_surrogate(key) or _has_lone_surrogate(item) for key, item in value.items())
    return False


def _is_hex32(value: Any) -> bool:
    return isinstance(value, str) and _HEX32.fullmatch(value) is not None


def _escape_segment(key: str) -> str:
    return key.replace("~", "~0").replace("/", "~1")


def _unescape_segment(segment: str) -> str:
    return segment.replace("~1", "/").replace("~0", "~")


def _parse_pointer(pointer: Any) -> Optional[Tuple[str, Optional[int]]]:
    """A v2 pointer's member name and element index, or None when it is not canonical."""
    if not isinstance(pointer, str) or not pointer.startswith("/") or _has_lone_surrogate(pointer):
        return None
    segments = pointer[1:].split("/")
    if len(segments) > 2 or _FIRST_SEGMENT.fullmatch(segments[0]) is None:
        return None
    if len(segments) == 1:
        return (_unescape_segment(segments[0]), None)
    if _CANONICAL_INDEX.fullmatch(segments[1]) is None or len(segments[1]) > 5:
        return None
    return (_unescape_segment(segments[0]), int(segments[1]))


def record_leaves_v2(content: Any) -> List[Dict[str, Any]]:
    """The leaves of one content object, sorted by pointer: each top-level
    member, and each element of a non-empty top-level list. Raises ValueError
    for content that has no v2 form."""
    if not isinstance(content, dict):
        raise ValueError("content must be an object")
    if _has_lone_surrogate(content):
        raise ValueError("This entry's sealed fields are not in their canonical form.")
    leaves: List[Dict[str, Any]] = []
    for key, value in content.items():
        base = "/" + _escape_segment(key)
        if isinstance(value, list) and value:
            if len(leaves) + len(value) > RECORD_LEAVES_MAX_V2:
                raise ValueError("This entry has more than 65535 fields and list items. Split it across entries.")
            leaves.extend({"pointer": f"{base}/{index}", "value": item} for index, item in enumerate(value))
        else:
            leaves.append({"pointer": base, "value": value})
        if len(leaves) > RECORD_LEAVES_MAX_V2:
            raise ValueError("This entry has more than 65535 fields and list items. Split it across entries.")
    return sorted(leaves, key=lambda leaf: _utf16_key(leaf["pointer"]))


def _record_content_from_leaves(fields: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    whole: Dict[str, Any] = {}
    arrays: Dict[str, Dict[int, Any]] = {}
    for leaf in fields:
        parsed = _parse_pointer(leaf.get("pointer"))
        if parsed is None or "value" not in leaf:
            return None
        key, index = parsed
        if index is None:
            if key in whole or key in arrays:
                return None
            whole[key] = leaf["value"]
        else:
            if key in whole:
                return None
            elements = arrays.setdefault(key, {})
            if index in elements:
                return None
            elements[index] = leaf["value"]
    content: Dict[str, Any] = dict(whole)
    for key, elements in arrays.items():
        if sorted(elements) != list(range(len(elements))):
            return None
        content[key] = [elements[i] for i in range(len(elements))]
    try:
        again = record_leaves_v2(content)
    except ValueError:
        return None
    given = sorted(fields, key=lambda leaf: _utf16_key(leaf["pointer"]))
    if len(again) != len(given):
        return None
    for mine, theirs in zip(again, given):
        if mine["pointer"] != theirs["pointer"]:
            return None
        try:
            if canonicalize_jcs(mine["value"]) != canonicalize_jcs(theirs["value"]):
                return None
        except JcsError:
            return None
    return content


def derive_leaf_salt_v2(salt_key: str, pointer: str) -> str:
    if not _is_hex32(salt_key):
        raise ValueError("a salt key is 0x plus 64 lowercase hex")
    message = _LABEL_SALT + b"\x00" + _utf8(pointer)
    return "0x" + hmac.new(bytes.fromhex(salt_key[2:]), message, hashlib.sha256).hexdigest()


def compute_leaf_hash_v2(leaf: Dict[str, Any]) -> str:
    salt = leaf.get("salt")
    if not _is_hex32(salt):
        raise ValueError("a leaf salt is 0x plus 64 lowercase hex")
    message = _utf8(canonicalize_jcs([leaf["pointer"], leaf["value"]]))
    return "0x" + hashlib.sha256(_LABEL_LEAF + b"\x00" + bytes.fromhex(salt[2:]) + message).hexdigest()


def compute_record_hash_v2(leaves: List[str]) -> str:
    """SHA-256 over the leaf count and the leaf hashes, which must be strictly ascending."""
    if not isinstance(leaves, list) or len(leaves) > RECORD_LEAVES_MAX_V2:
        raise ValueError("a record hash takes 0 to 65535 leaves")
    for index, leaf in enumerate(leaves):
        if not _is_hex32(leaf) or (index > 0 and not leaves[index - 1] < leaf):
            raise ValueError("leaf hashes must be 0x lowercase hex, strictly ascending")
    body = _LABEL_RECORD + b"\x00" + len(leaves).to_bytes(2, "big") + b"".join(bytes.fromhex(leaf[2:]) for leaf in leaves)
    return "0x" + hashlib.sha256(body).hexdigest()


def commit_record_content_v2(content: Dict[str, Any], salt_key: str) -> Dict[str, Any]:
    """The record hash, every leaf hash (sorted) and every leaf with its salt (by pointer)."""
    revealed = []
    leaves = []
    for field in record_leaves_v2(content):
        leaf = {"pointer": field["pointer"], "value": field["value"], "salt": derive_leaf_salt_v2(salt_key, field["pointer"])}
        revealed.append(leaf)
        leaves.append(compute_leaf_hash_v2(leaf))
    leaves.sort()
    return {"recordHash": compute_record_hash_v2(leaves), "leaves": leaves, "revealed": revealed}


# ------------------------------------------------------------ record hash v3

_NOT_CANONICAL_V3 = "This entry's sealed fields are not in their canonical form."


def _parse_pointer_v3(pointer: Any) -> Optional[Tuple[str, Optional[int]]]:
    """A v3 pointer's member name and element index (at most 65534), or None."""
    parsed = _parse_pointer(pointer)
    if parsed is None or (parsed[1] is not None and parsed[1] > _ELEMENT_INDEX_MAX_V3):
        return None
    return parsed


def member_tag_v3(key: str) -> str:
    """SHA-256("pacspace:record-member:v3" || 0x00 || UTF-8(escaped member name))."""
    return "0x" + hashlib.sha256(_LABEL_MEMBER_V3 + b"\x00" + _utf8(_escape_segment(key))).hexdigest()


def derive_leaf_salt_v3(salt_key: str, pointer: str) -> str:
    if not _is_hex32(salt_key):
        raise ValueError("a salt key is 0x plus 64 lowercase hex")
    message = _LABEL_SALT_V3 + b"\x00" + _utf8(pointer)
    return "0x" + hmac.new(bytes.fromhex(salt_key[2:]), message, hashlib.sha256).hexdigest()


def compute_leaf_hash_v3(leaf: Dict[str, Any]) -> str:
    salt = leaf.get("salt")
    if not _is_hex32(salt):
        raise ValueError("a leaf salt is 0x plus 64 lowercase hex")
    message = _utf8(canonicalize_jcs([leaf["pointer"], leaf["value"]]))
    return "0x" + hashlib.sha256(_LABEL_LEAF_V3 + b"\x00" + bytes.fromhex(salt[2:]) + message).hexdigest()


def _is_slot(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= RECORD_SLOT_WHOLE_V3


def validate_record_items_v3(items: Any) -> bool:
    """True when the items are well formed, strictly ascending, and every group is one whole item or slots 0..m-1."""
    if not isinstance(items, list) or len(items) > RECORD_ITEMS_MAX_V3:
        return False
    group_tag: Optional[str] = None
    group_whole = False
    next_slot = 0
    for index, item in enumerate(items):
        if not isinstance(item, list) or len(item) != 3:
            return False
        tag, slot, leaf_hash = item
        if not _is_hex32(tag) or not _is_slot(slot) or not _is_hex32(leaf_hash):
            return False
        if index > 0 and (items[index - 1][0], items[index - 1][1]) >= (tag, slot):
            return False
        if tag != group_tag:
            group_tag = tag
            group_whole = slot == RECORD_SLOT_WHOLE_V3
            if not group_whole and slot != 0:
                return False
            next_slot = 1
            continue
        if group_whole or slot == RECORD_SLOT_WHOLE_V3 or slot != next_slot:
            return False
        next_slot += 1
    return True


def compute_record_hash_v3(items: List[List[Any]]) -> str:
    """SHA-256("pacspace:record:v3" || 0x00 || u16be(n) || item_1 || ... || item_n)."""
    if not validate_record_items_v3(items):
        raise ValueError("record items must be well formed, strictly ascending and grouped")
    body = b"".join(bytes.fromhex(tag[2:]) + slot.to_bytes(2, "big") + bytes.fromhex(leaf[2:]) for tag, slot, leaf in items)
    return "0x" + hashlib.sha256(_LABEL_RECORD_V3 + b"\x00" + len(items).to_bytes(2, "big") + body).hexdigest()


def _item_of_v3(leaf: Dict[str, Any]) -> Optional[List[Any]]:
    parsed = _parse_pointer_v3(leaf.get("pointer"))
    if parsed is None:
        return None
    key, index = parsed
    return [member_tag_v3(key), RECORD_SLOT_WHOLE_V3 if index is None else index, compute_leaf_hash_v3(leaf)]


def commit_record_content_v3(content: Dict[str, Any], salt_key: str) -> Dict[str, Any]:
    """The record hash, every item (sorted) and every leaf with its salt (by pointer)."""
    revealed = []
    items = []
    for field in record_leaves_v2(content):
        if _parse_pointer_v3(field["pointer"]) is None:
            raise ValueError(_NOT_CANONICAL_V3)
        leaf = {"pointer": field["pointer"], "value": field["value"], "salt": derive_leaf_salt_v3(salt_key, field["pointer"])}
        revealed.append(leaf)
        items.append(_item_of_v3(leaf))
    items.sort(key=lambda item: (item[0], item[1]))
    return {"recordHash": compute_record_hash_v3(items), "items": items, "revealed": revealed}


def open_record_entry_v3(entry: Any, every: bool) -> Dict[str, Any]:
    """Opens a v3 entry ({items, revealed}): each shown leaf's recomputed item
    must equal one item exactly; a whole leaf holding a non-empty list is
    refused; ``every`` requires all items shown and the content canonical.
    ``failure`` is ``malformed``, ``leaf-mismatch`` or ``not-canonical``."""
    items = entry.get("items") if isinstance(entry, dict) else None
    revealed = entry.get("revealed") if isinstance(entry, dict) else None
    if not validate_record_items_v3(items) or not isinstance(revealed, list) or len(revealed) > len(items):
        return {"ok": False, "failure": "malformed"}
    for index, leaf in enumerate(revealed):
        if not isinstance(leaf, dict) or not _is_hex32(leaf.get("salt")) or "value" not in leaf:
            return {"ok": False, "failure": "malformed"}
        parsed = _parse_pointer_v3(leaf.get("pointer"))
        if parsed is None:
            return {"ok": False, "failure": "malformed"}
        if index > 0 and not _utf16_key(revealed[index - 1]["pointer"]) < _utf16_key(leaf["pointer"]):
            return {"ok": False, "failure": "malformed"}
        if parsed[1] is None and isinstance(leaf["value"], list) and leaf["value"]:
            return {"ok": False, "failure": "malformed"}
        if _has_lone_surrogate(leaf["value"]):
            return {"ok": False, "failure": "malformed"}
        try:
            canonicalize_jcs(leaf["value"])
        except (JcsError, RecursionError):
            return {"ok": False, "failure": "malformed"}
    by_prefix = {(tag, slot): leaf_hash for tag, slot, leaf_hash in items}
    for leaf in revealed:
        tag, slot, leaf_hash = _item_of_v3(leaf)
        if by_prefix.get((tag, slot)) != leaf_hash:
            return {"ok": False, "failure": "leaf-mismatch"}
    fields = [{"pointer": leaf["pointer"], "value": leaf["value"]} for leaf in revealed]
    full = len(revealed) == len(items)
    content = _record_content_from_leaves(fields) if full else None
    if every and (not full or content is None):
        return {"ok": False, "failure": "not-canonical"}
    return {
        "ok": True,
        "recordHash": compute_record_hash_v3(items),
        "fields": fields,
        "withheld": len(items) - len(revealed),
        "content": content,
    }


# --------------------------------------------------------- record-disclosure/v1


def _digest_under(label: bytes, disclosure: Dict[str, Any]) -> str:
    rest = {key: value for key, value in disclosure.items() if key != "digest"}
    return "0x" + hashlib.sha256(label + b"\x00" + _utf8(canonicalize_jcs(rest))).hexdigest()


def compute_record_disclosure_digest_v1(disclosure: Dict[str, Any]) -> str:
    return _digest_under(_LABEL_DIGEST, disclosure)


def compute_record_disclosure_digest(disclosure: Dict[str, Any]) -> str:
    """A disclosure's digest under its own schema's label (v1 or v2)."""
    v2 = disclosure.get("schema") == RECORD_DISCLOSURE_SCHEMA_V2
    return _digest_under(_LABEL_DIGEST_V2 if v2 else _LABEL_DIGEST, disclosure)


def _is_int(value: Any) -> bool:
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return True
    return isinstance(value, float) and math.isfinite(value) and value.is_integer()


def _is_uint32(value: Any) -> bool:
    return _is_int(value) and 0 <= value <= _UINT32_MAX


def _is_safe_natural(value: Any) -> bool:
    return _is_int(value) and 0 <= value <= _SAFE_MAX


def _has_exactly(value: Dict[str, Any], keys: Tuple[str, ...]) -> bool:
    return len(value) == len(keys) and all(key in value for key in keys)


def _chain_ok(chain: Any, exact: bool) -> bool:
    return (
        isinstance(chain, dict)
        and (not exact or _has_exactly(chain, ("chainId", "contractAddress")))
        and _is_safe_natural(chain.get("chainId"))
        and isinstance(chain.get("contractAddress"), str)
        and _ADDRESS.fullmatch(chain["contractAddress"]) is not None
    )


def _layout_ok(layout: Any, exact: bool) -> bool:
    return (
        isinstance(layout, dict)
        and (not exact or _has_exactly(layout, ("layoutId", "layoutVersion", "layoutDigest")))
        and _is_safe_natural(layout.get("layoutId"))
        and _is_safe_natural(layout.get("layoutVersion"))
        and _is_hex32(layout.get("layoutDigest"))
    )


def _leaves_ok(leaves: Any) -> bool:
    if not isinstance(leaves, list) or len(leaves) > RECORD_LEAVES_MAX_V2:
        return False
    return all(_is_hex32(leaf) and (index == 0 or leaves[index - 1] < leaf) for index, leaf in enumerate(leaves))


def _revealed_ok(revealed: Any, leaf_count: int, parse_pointer: Any = _parse_pointer) -> bool:
    if not isinstance(revealed, list) or len(revealed) > leaf_count:
        return False
    for index, leaf in enumerate(revealed):
        if not isinstance(leaf, dict) or not _has_exactly(leaf, ("pointer", "value", "salt")):
            return False
        if parse_pointer(leaf["pointer"]) is None or not _is_hex32(leaf["salt"]) or _has_lone_surrogate(leaf["value"]):
            return False
        if index > 0 and not _utf16_key(revealed[index - 1]["pointer"]) < _utf16_key(leaf["pointer"]):
            return False
    return True


def _entry_ok(entry: Any, version: int) -> bool:
    if not isinstance(entry, dict) or not _is_uint32(entry.get("seq")) or not _is_hex32(entry.get("recordOpening")):
        return False
    if version == 3:
        return (
            _has_exactly(entry, ("seq", "recordOpening", "items", "revealed"))
            and validate_record_items_v3(entry["items"])
            and _revealed_ok(entry["revealed"], len(entry["items"]), _parse_pointer_v3)
        )
    if version == 1:
        content = entry.get("recordContent")
        return (
            _has_exactly(entry, ("seq", "recordOpening", "recordContent"))
            and isinstance(content, dict)
            and not _has_lone_surrogate(content)
        )
    if not _has_exactly(entry, ("seq", "recordOpening", "leaves", "revealed")):
        return False
    return _leaves_ok(entry["leaves"]) and _revealed_ok(entry["revealed"], len(entry["leaves"]))


def _disclosure_ok(d: Dict[str, Any]) -> bool:
    keys = ("schema", "recordKey", "chain", "layout", "recordHashVersion", "entries", "digest")
    if not _has_exactly(d, keys) or not _is_hex32(d["recordKey"]) or not _is_hex32(d["digest"]):
        return False
    if not _chain_ok(d["chain"], True) or not _layout_ok(d["layout"], True):
        return False
    version = d["recordHashVersion"]
    allowed = (3,) if d["schema"] == RECORD_DISCLOSURE_SCHEMA_V2 else (1, 2)
    if isinstance(version, bool) or version not in allowed:
        return False
    entries = d["entries"]
    if not isinstance(entries, list) or not entries:
        return False
    for index, entry in enumerate(entries):
        if not _entry_ok(entry, version):
            return False
        if index > 0 and not entries[index - 1]["seq"] < entry["seq"]:
            return False
    return True


def _form_ok(form: Any) -> bool:
    if not isinstance(form, dict) or not _is_hex32(form.get("recordKey")):
        return False
    if "recordHashVersion" in form and (isinstance(form["recordHashVersion"], bool) or form["recordHashVersion"] != 3):
        return False
    if not _chain_ok(form.get("chain"), False) or not _layout_ok(form.get("layout"), False):
        return False
    entries = form.get("entries")
    if not isinstance(entries, list):
        return False
    for index, e in enumerate(entries):
        if not isinstance(e, dict) or not _is_uint32(e.get("seq")) or not _is_uint32(e.get("itemIndex")):
            return False
        if not _is_safe_natural(e.get("batchId")):
            return False
        if not all(_is_hex32(e.get(name)) for name in ("previousWord", "newWord", "itemOpening")):
            return False
        if "recordHash" in e and not _is_hex32(e["recordHash"]):
            return False
        proof = e.get("merkleProof")
        if not isinstance(proof, list) or len(proof) > 32 or not all(_is_hex32(p) for p in proof):
            return False
        if index > 0 and not entries[index - 1]["seq"] < e["seq"]:
            return False
    return True


def _result(
    ok: Optional[bool],
    entries: List[Dict[str, Any]],
    code: Optional[str] = None,
    seq: Optional[int] = None,
    reason: Optional[str] = None,
) -> Dict[str, Any]:
    if code is not None and reason is None:
        reason = _REASONS[code](0 if seq is None else seq + 1)
    return {
        "ok": ok,
        "code": code,
        "seq": seq,
        "reason": reason,
        "entries": entries,
        "chainCheck": "not-checked",
        "chainCheckNote": _CHAIN_CHECK_NOTE,
    }


def _refuse(code: str, seq: Optional[int] = None, reason: Optional[str] = None) -> Dict[str, Any]:
    return _result(False, [], code, seq, reason)


def _not_checked(seq: int, note: str) -> Dict[str, Any]:
    return {"seq": seq, "status": "not-checked", "fields": None, "withheld": None, "content": None, "note": note}


def verify_record_disclosure_v1(form: Any, disclosure: Any) -> Dict[str, Any]:
    """Checks a record-disclosure/v1 or v2 against the record's seal history
    form (the ``SealHistoryFormForDisclosureV1`` shape), up to each entry's
    record hash and seal. ``ok`` is True only when every entry is
    ``checked``, False on a refusal, and None otherwise. Never raises."""
    try:
        return _verify(form, disclosure)
    except Exception:  # noqa: BLE001 - the verifier returns a result and never raises
        return _refuse("DISCLOSURE_MALFORMED")


def _verify(form: Any, d: Any) -> Dict[str, Any]:
    if not isinstance(d, dict) or d.get("schema") not in (RECORD_DISCLOSURE_SCHEMA_V1, RECORD_DISCLOSURE_SCHEMA_V2):
        return _refuse("DISCLOSURE_MALFORMED")
    try:
        canonical = canonicalize_jcs(d)
    except (JcsError, RecursionError):
        return _refuse("DISCLOSURE_MALFORMED")
    if len(_utf8(canonical)) > RECORD_DISCLOSURE_MAX_BYTES_V1:
        return _refuse("DISCLOSURE_TOO_LARGE")
    if not _disclosure_ok(d) or not _form_ok(form):
        return _refuse("DISCLOSURE_MALFORMED")
    if compute_record_disclosure_digest(d) != d["digest"]:
        return _refuse("DISCLOSURE_DIGEST_MISMATCH")
    if (
        d["recordKey"] != form["recordKey"]
        or d["chain"]["chainId"] != form["chain"]["chainId"]
        or d["chain"]["contractAddress"] != form["chain"]["contractAddress"]
        or d["layout"]["layoutId"] != form["layout"]["layoutId"]
        or d["layout"]["layoutVersion"] != form["layout"]["layoutVersion"]
        or d["layout"]["layoutDigest"] != form["layout"]["layoutDigest"]
    ):
        return _refuse("DISCLOSURE_RECORD_MISMATCH")
    if (form.get("recordHashVersion") == 3) != (d["schema"] == RECORD_DISCLOSURE_SCHEMA_V2):
        return _refuse("RECORD_HASH_VERSION_MISMATCH")

    by_seq = {e["seq"]: e for e in form["entries"]}
    out: List[Dict[str, Any]] = []
    for entry in d["entries"]:
        seq = entry["seq"]
        form_entry = by_seq.get(seq)
        if form_entry is None:
            return _refuse("DISCLOSURE_ENTRY_NOT_IN_HISTORY", seq)
        if "recordContent" in entry:
            out.append(_not_checked(seq, _NOTE_V1))
            continue
        if "items" in entry:
            opened = open_record_entry_v3(entry, every=False)
            if not opened["ok"]:
                return _refuse("DISCLOSURE_LEAF_MISMATCH" if opened["failure"] == "leaf-mismatch" else "DISCLOSURE_MALFORMED", seq)
            record_hash, fields, withheld, content = opened["recordHash"], opened["fields"], opened["withheld"], opened["content"]
        else:
            known = set(entry["leaves"])
            for leaf in entry["revealed"]:
                canonicalize_jcs(leaf["value"])
                if compute_leaf_hash_v2(leaf) not in known:
                    return _refuse("DISCLOSURE_LEAF_MISMATCH", seq)
            fields = [{"pointer": leaf["pointer"], "value": leaf["value"]} for leaf in entry["revealed"]]
            full = len(entry["revealed"]) == len(entry["leaves"])
            record_hash = compute_record_hash_v2(entry["leaves"])
            withheld = len(entry["leaves"]) - len(entry["revealed"])
            content = _record_content_from_leaves(fields) if full else None
        if "recordHash" not in form_entry:
            out.append(_not_checked(seq, _NOTE_NO_RECORD_HASH))
            continue
        if record_hash != form_entry["recordHash"]:
            return _refuse("DISCLOSURE_SEAL_MISMATCH", seq, _record_hash_mismatch(seq + 1))
        if not _seal_reproduces(d, entry, form_entry, record_hash):
            return _refuse("DISCLOSURE_SEAL_MISMATCH", seq)
        out.append(
            {"seq": seq, "status": "checked", "fields": fields, "withheld": withheld, "content": content, "note": None}
        )
    every = all(entry["status"] == "checked" for entry in out)
    return _result(True if every else None, out)


def _seal_reproduces(d: Dict[str, Any], entry: Dict[str, Any], form_entry: Dict[str, Any], record_hash: str) -> bool:
    """The seal over the entry's record hash (wrapped for version 3) carries the form word's seal tag."""
    from .record_seal import compute_seal_v1, seal_input_hash, seal_tag_of_v1, split_word_v1

    state96, seal_tag = split_word_v1(form_entry["newWord"])
    layout = d["layout"]
    seal = compute_seal_v1(
        layout["layoutId"],
        layout["layoutVersion"],
        layout["layoutDigest"],
        state96,
        seal_input_hash(d["recordHashVersion"], record_hash),
        entry["recordOpening"],
    )
    return seal_tag_of_v1(seal) == seal_tag


def _disclosure_form_of(seal_history: Dict[str, Any], disclosure: Any) -> Optional[Dict[str, Any]]:
    """The form ``disclosureFormOfV1`` builds from a seal history: record key,
    chain and layout from the history (and ``recordHashVersion: 3`` when the
    history has it), and the history's entries for the disclosed seqs, in seq
    order, with ``recordHash`` for a v2 or v3 disclosure. None when a
    disclosed seq is not in the history, or such a disclosure meets a history
    entry with no record hash."""
    if not isinstance(disclosure, dict) or not isinstance(disclosure.get("entries"), list):
        return None
    by_seq = {e.get("seq"): e for e in seal_history.get("entries") or [] if isinstance(e, dict)}
    seqs = sorted({entry.get("seq") for entry in disclosure["entries"] if isinstance(entry, dict)})
    v2 = disclosure.get("recordHashVersion") in (2, 3)
    out = []
    for seq in seqs:
        e = by_seq.get(seq)
        if e is None or (v2 and "recordHash" not in e):
            return None
        entry = {"seq": e.get("seq"), "previousWord": e.get("previousWord"), "newWord": e.get("newWord")}
        if v2:
            entry["recordHash"] = e["recordHash"]
        entry.update(
            {
                "itemIndex": e.get("itemIndex"),
                "itemOpening": e.get("itemOpening"),
                "merkleProof": list(e.get("merkleProof") or []),
                "batchId": e.get("batchId"),
            }
        )
        out.append(entry)
    form: Dict[str, Any] = {
        "recordKey": seal_history.get("recordKey"),
        "chain": dict(seal_history.get("chain") or {}),
        "layout": dict(seal_history.get("layout") or {}),
    }
    if seal_history.get("recordHashVersion") == 3:
        form["recordHashVersion"] = 3
    form["entries"] = out
    return form


def verify_record_link_copy_v1(copy: Any) -> Dict[str, Any]:
    """Reads a record-link-copy/v1 and checks its disclosure against its own
    seal history, as ``verify_record_disclosure_v1`` does. A copy that is not
    one, or that carries no disclosure, is refused as malformed. Never raises."""
    try:
        if not isinstance(copy, dict) or set(copy) != {"schema", "sealHistory", "disclosure"}:
            return _refuse("DISCLOSURE_MALFORMED")
        history = copy["sealHistory"]
        if copy["schema"] != RECORD_LINK_COPY_SCHEMA_V1 or not isinstance(history, dict):
            return _refuse("DISCLOSURE_MALFORMED")
        if history.get("schema") != RECORD_SEAL_HISTORY_SCHEMA_V1 or not isinstance(copy["disclosure"], dict):
            return _refuse("DISCLOSURE_MALFORMED")
        form = _disclosure_form_of(history, copy["disclosure"])
        if form is None:
            return _refuse("DISCLOSURE_MALFORMED")
        return verify_record_disclosure_v1(form, copy["disclosure"])
    except Exception:  # noqa: BLE001 - the reader returns a result and never raises
        return _refuse("DISCLOSURE_MALFORMED")
