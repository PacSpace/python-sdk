from __future__ import annotations

import hashlib
from typing import BinaryIO, Iterable, Union

from .errors import PacSpaceError

FingerprintSource = Union[bytes, bytearray, memoryview, BinaryIO, Iterable[bytes]]


def fingerprint(source: FingerprintSource, alg: str = "sha-256") -> dict:
    if alg != "sha-256":
        raise PacSpaceError(
            "A fingerprint is made with sha-256.",
            0,
            "RECORD_PAYLOAD_ALG_UNSUPPORTED",
        )

    digest = hashlib.sha256()
    byte_length = 0

    if isinstance(source, (bytes, bytearray, memoryview)):
        data = bytes(source)
        digest.update(data)
        byte_length = len(data)
    elif hasattr(source, "read"):
        handle = source  # type: ignore[assignment]
        while True:
            chunk = handle.read(65536)
            if not chunk:
                break
            if not isinstance(chunk, (bytes, bytearray)):
                raise PacSpaceError(
                    "fingerprint needs bytes or an iterable of bytes",
                    0,
                    "RECORD_CONTENT_INVALID",
                )
            digest.update(chunk)
            byte_length += len(chunk)
    else:
        try:
            iterator = iter(source)  # type: ignore[arg-type]
        except TypeError as exc:
            raise PacSpaceError(
                "fingerprint needs bytes or an iterable of bytes",
                0,
                "RECORD_CONTENT_INVALID",
            ) from exc
        for chunk in iterator:
            if not isinstance(chunk, (bytes, bytearray)):
                raise PacSpaceError(
                    "fingerprint needs bytes or an iterable of bytes",
                    0,
                    "RECORD_CONTENT_INVALID",
                )
            digest.update(chunk)
            byte_length += len(chunk)

    return {
        "alg": "sha-256",
        "digest": digest.hexdigest(),
        "byteLength": str(byte_length),
    }
