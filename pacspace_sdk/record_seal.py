"""The seal of a record entry, as packages/shared/src/proof/slot-encoding-v1.ts
and seal-input.ts compute it (card 10, F1; design v4, B4).

seal = keccak256("pacspace:slot-commit:v1" || 0x00 || u16be(layoutId) ||
u8(layoutVersion) || layoutDigest || u96be(state96) || sealInput ||
recordOpening), where sealInput is the record hash for versions 1 and 2 and
SHA-256("pacspace:record-hash-version:v1" || 0x00 || u8(3) || recordHash) for
version 3. A word is u96 state above a 160-bit seal tag.
"""

from __future__ import annotations

import hashlib
from typing import Any, Tuple

from .keccak import keccak256
from .record_disclosure import _is_hex32, _utf8, canonicalize_jcs

__all__ = [
    "compute_record_hash_v1",
    "compute_seal_v1",
    "compute_slot_item_hash_v1",
    "seal_input_hash",
    "seal_tag_of_v1",
    "split_word_v1",
]

_SEP = b"\x00"
_DOMAIN_RECORD = b"pacspace:record:v1"
_DOMAIN_COMMIT = b"pacspace:slot-commit:v1"
_DOMAIN_ITEM = b"pacspace:slot-item:v1"
_LABEL_SEAL_INPUT = b"pacspace:record-hash-version:v1"
_TAG_MASK = (1 << 160) - 1


def _hex(data: bytes) -> str:
    return "0x" + data.hex()


def _bytes32(value: Any, name: str) -> bytes:
    if not _is_hex32(value):
        raise ValueError(f"{name} is not 0x plus 64 lowercase hex")
    return bytes.fromhex(value[2:])


def _uint_be(value: int, bits: int) -> bytes:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0 or value >= 1 << bits:
        raise ValueError(f"value out of uint{bits} range")
    return value.to_bytes(bits // 8, "big")


def _word(value: Any) -> int:
    word = int(value, 16) if isinstance(value, str) else value
    if isinstance(word, bool) or not isinstance(word, int) or word < 0 or word >= 1 << 256:
        raise ValueError("word out of uint256 range")
    return word


def compute_record_hash_v1(content: Any) -> str:
    """keccak256("pacspace:record:v1" || 0x00 || JCS(content))."""
    return _hex(keccak256(_DOMAIN_RECORD + _SEP + _utf8(canonicalize_jcs(content))))


def seal_input_hash(version: int, record_hash: str) -> str:
    """The hash a seal is over: the record hash itself for versions 1 and 2, wrapped for 3."""
    raw = _bytes32(record_hash, "recordHash")
    if version in (1, 2) and not isinstance(version, bool):
        return record_hash
    if version != 3 or isinstance(version, bool):
        raise ValueError("this record hash version has no seal input")
    return _hex(hashlib.sha256(_LABEL_SEAL_INPUT + _SEP + b"\x03" + raw).digest())


def compute_seal_v1(
    layout_id: int, layout_version: int, layout_digest: str, state96: int, record_hash: str, record_opening: str
) -> str:
    """The seal, over a seal input already chosen (see ``seal_input_hash``)."""
    return _hex(
        keccak256(
            _DOMAIN_COMMIT
            + _SEP
            + _uint_be(layout_id, 16)
            + _uint_be(layout_version, 8)
            + _bytes32(layout_digest, "layoutDigest")
            + _uint_be(state96, 96)
            + _bytes32(record_hash, "recordHash")
            + _bytes32(record_opening, "recordOpening")
        )
    )


def seal_tag_of_v1(seal: str) -> str:
    """The low 160 bits of a seal, as a word carries them."""
    return "0x" + format(int.from_bytes(_bytes32(seal, "seal"), "big") & _TAG_MASK, "040x")


def split_word_v1(word: Any) -> Tuple[int, str]:
    """A word's state96 and its seal tag."""
    value = _word(word)
    return value >> 160, "0x" + format(value & _TAG_MASK, "040x")


def compute_slot_item_hash_v1(record_key: str, seq: int, previous_word: Any, new_word: Any, seal: str) -> str:
    """keccak256("pacspace:slot-item:v1" || 0x00 || recordKey || u32be(seq) || u256be(previousWord) || u256be(newWord) || seal)."""
    return _hex(
        keccak256(
            _DOMAIN_ITEM
            + _SEP
            + _bytes32(record_key, "recordKey")
            + _uint_be(seq, 32)
            + _uint_be(_word(previous_word), 256)
            + _uint_be(_word(new_word), 256)
            + _bytes32(seal, "seal")
        )
    )
