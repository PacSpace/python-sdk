from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
from typing import Any, BinaryIO, Dict, Iterable, Iterator, Optional, Union

from .errors import PacSpaceError, ValidationError

FingerprintSource = Union[bytes, bytearray, memoryview, BinaryIO, Iterable[bytes]]

BLINDING_VALUE_BYTES = 32
BLINDING_FILE_SCHEMA = "pacspace-blinding/v1"
_HEX_64 = re.compile(r"[0-9a-f]{64}")
_DECIMAL = re.compile(r"0|[1-9][0-9]*")
_MAX_SAFE_INTEGER = 9007199254740991

_HIDDEN = "<Blinding: value hidden>"
_NOT_A_FILE = "This is not a valid blinding file."
_OTHER_BYTES = "This blinding file does not match these bytes."
_VALUE_SIZE = "A blinding value is exactly 32 bytes."
_DISAGREE = "alg and blind disagree. Pass one of them."
_UNSUPPORTED = "A fingerprint is made with sha-256 or hmac-sha-256."
_NOT_BYTES = "fingerprint needs bytes or an iterable of bytes"


def _is_decimal(text: Any) -> bool:
    return isinstance(text, str) and _DECIMAL.fullmatch(text) is not None and int(text) <= _MAX_SAFE_INTEGER


def _blinding_reason(value: Any, digest: Any, byte_length: Any) -> Optional[str]:
    if not isinstance(value, (bytes, bytearray)) or len(value) != BLINDING_VALUE_BYTES:
        return _VALUE_SIZE
    if not isinstance(digest, str) or _HEX_64.fullmatch(digest) is None or not _is_decimal(byte_length):
        return _NOT_A_FILE
    return None


class Blinding:
    """The blinding value of one blinded fingerprint, beside the digest and
    size it was made for. It shows no value: ``repr`` and ``str`` hide it,
    and ``json.dumps`` refuses it. ``blinding_file_text`` is the one way to
    get the file's text."""

    __slots__ = ("_value", "digest", "byteLength")

    def __init__(self, value: bytes, digest: str, byteLength: str) -> None:  # noqa: N803 - the wire's name
        reason = _blinding_reason(value, digest, byteLength)
        if reason is not None:
            del value
            raise ValidationError(reason)
        self._value = bytes(value)
        del value
        self.digest = digest
        self.byteLength = byteLength

    @classmethod
    def _fresh(cls) -> "Blinding":
        made = cls.__new__(cls)
        made._value = secrets.token_bytes(BLINDING_VALUE_BYTES)
        made.digest = ""
        made.byteLength = ""
        return made

    def __repr__(self) -> str:
        return _HIDDEN

    __str__ = __repr__


class Fingerprint:
    """What ``fingerprint`` returns: send ``.ref`` as the payload and keep
    ``.blinding`` beside the file with ``write_blinding_file``."""

    __slots__ = ("ref", "blinding")

    def __init__(self, ref: Dict[str, str], blinding: Optional[Blinding]) -> None:
        self.ref = ref
        self.blinding = blinding

    def __repr__(self) -> str:
        return f"Fingerprint(ref={self.ref!r}, blinding={self.blinding!r})"


def _canonical_text(value_hex: str, digest: str, byte_length: str) -> str:
    return (
        json.dumps(
            {
                "schema": BLINDING_FILE_SCHEMA,
                "alg": "hmac-sha-256",
                "value": value_hex,
                "digest": digest,
                "byteLength": byte_length,
            },
            indent=2,
            separators=(",", ": "),
            ensure_ascii=True,
        )
        + "\n"
    )


def blinding_file_text(blinding: Blinding) -> str:
    """The blinding file's canonical text. This is the one function that
    yields the value: keep the text as private as the file it belongs to."""
    if not isinstance(blinding, Blinding) or not blinding.digest:
        raise ValidationError(_NOT_A_FILE)
    return _canonical_text(blinding._value.hex(), blinding.digest, blinding.byteLength)


def _chunks(source: FingerprintSource) -> Iterator[bytes]:
    if isinstance(source, (bytes, bytearray, memoryview)):
        yield bytes(source)
        return
    if hasattr(source, "read"):
        while True:
            chunk = source.read(65536)  # type: ignore[union-attr]
            if not chunk:
                return
            if not isinstance(chunk, (bytes, bytearray)):
                raise PacSpaceError(_NOT_BYTES, 0, "RECORD_CONTENT_INVALID")
            yield bytes(chunk)
    try:
        iterator = iter(source)  # type: ignore[arg-type]
    except TypeError as exc:
        raise PacSpaceError(_NOT_BYTES, 0, "RECORD_CONTENT_INVALID") from exc
    for chunk in iterator:
        if not isinstance(chunk, (bytes, bytearray)):
            raise PacSpaceError(_NOT_BYTES, 0, "RECORD_CONTENT_INVALID")
        yield bytes(chunk)


def _digests(source: FingerprintSource, blinding: Optional[Blinding]) -> Dict[str, str]:
    """The sha-256 digest, the length and, with a blinding, the HMAC, in one pass."""
    plain = hashlib.sha256()
    mac = hmac.new(blinding._value, digestmod=hashlib.sha256) if blinding is not None else None
    byte_length = 0
    for chunk in _chunks(source):
        plain.update(chunk)
        if mac is not None:
            mac.update(chunk)
        byte_length += len(chunk)
    out = {"sha256": plain.hexdigest(), "byteLength": str(byte_length)}
    if mac is not None:
        out["hmac"] = mac.hexdigest()
    return out


def _blinds_by(alg: Optional[str], blind: Optional[bool], blinding: Any) -> Optional[tuple]:
    """Whether to blind, or the refusal as (message, status, code)."""
    if alg is not None and alg not in ("sha-256", "hmac-sha-256"):
        return (_UNSUPPORTED, 0, "RECORD_PAYLOAD_ALG_UNSUPPORTED")
    by_alg = None if alg is None else alg == "hmac-sha-256"
    if blind is not None and not isinstance(blind, bool):
        return (_DISAGREE, 400, "VALIDATION_ERROR")
    if by_alg is not None and blind is not None and by_alg != blind:
        return (_DISAGREE, 400, "VALIDATION_ERROR")
    blinds = blind if blind is not None else (by_alg if by_alg is not None else True)
    if blinding is not None:
        if not blinds:
            return (_DISAGREE, 400, "VALIDATION_ERROR")
        if not isinstance(blinding, Blinding) or not blinding.digest:
            return (_NOT_A_FILE, 400, "VALIDATION_ERROR")
    return (blinds,)


def _refuse(message: str, status: int, code: str) -> PacSpaceError:
    return ValidationError(message) if code == "VALIDATION_ERROR" else PacSpaceError(message, status, code)


def fingerprint(
    source: FingerprintSource,
    alg: Optional[str] = None,
    *,
    blind: Optional[bool] = None,
    blinding: Optional[Blinding] = None,
) -> Fingerprint:
    """Fingerprint bytes where they live. PacSpace receives the digest and
    size, never the file. Blinded by default: an HMAC-SHA256 under a fresh
    32-byte value, returned as a Fingerprint; send ``.ref`` and keep
    ``.blinding`` beside the file. ``blind=False`` (or ``"sha-256"``) gives
    the plain sha-256 reference with ``blinding=None``."""
    decided = _blinds_by(alg, blind, blinding)
    if len(decided) == 3:
        raise _refuse(*decided)
    if not decided[0]:
        plain = _digests(source, None)
        return Fingerprint({"alg": "sha-256", "digest": plain["sha256"], "byteLength": plain["byteLength"]}, None)
    if blinding is not None:
        again = _digests(source, blinding)
        if again["hmac"] != blinding.digest or again["byteLength"] != blinding.byteLength:
            raise ValidationError(_OTHER_BYTES)
        return Fingerprint({"alg": "hmac-sha-256", "digest": again["hmac"], "byteLength": again["byteLength"]}, blinding)
    made = Blinding._fresh()
    fresh = _digests(source, made)
    made.digest = fresh["hmac"]
    made.byteLength = fresh["byteLength"]
    return Fingerprint({"alg": "hmac-sha-256", "digest": fresh["hmac"], "byteLength": fresh["byteLength"]}, made)
