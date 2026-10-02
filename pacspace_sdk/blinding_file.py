from __future__ import annotations

import json
import os
import stat
from typing import Optional, Union

from .errors import ValidationError
from .fingerprint import (
    BLINDING_FILE_SCHEMA,
    _HEX_64,
    _canonical_text,
    _is_decimal,
    Blinding,
    blinding_file_text,
)

BLINDING_FILE_SUFFIX = ".pacspace.json"
BLINDING_FILE_MAX_BYTES = 1024
_FIELDS = ("schema", "alg", "value", "digest", "byteLength")

_NOT_A_FILE = "This is not a valid blinding file."
_DIFFERENT = "A different blinding file already exists at this path. Nothing was written."
_NOT_REGULAR = "The path for the blinding file is a link or not a regular file. Nothing was written."

PathLike = Union[str, "os.PathLike[str]"]


def _existing(target: str, blinding: Blinding) -> str:
    """'absent', 'same', 'different' or 'not-regular' for what is at the target."""
    try:
        info = os.lstat(target)
    except FileNotFoundError:
        return "absent"
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        return "not-regular"
    with open(target, "rb") as handle:
        return "same" if handle.read() == blinding_file_text(blinding).encode("ascii") else "different"


def _write(target: str, blinding: Blinding) -> Optional[str]:
    """Write the file, or return why not; nothing that holds the value outlives this frame."""
    found = _existing(target, blinding)
    if found == "same":
        return None
    if found != "absent":
        return found
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0)
    if os.name != "nt":
        flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(target, flags, 0o600)
    except FileExistsError:
        found = _existing(target, blinding)
        return None if found == "same" else found
    with os.fdopen(fd, "wb") as handle:
        handle.write(blinding_file_text(blinding).encode("ascii"))
    return None


def write_blinding_file(file_path: PathLike, blinding: Blinding) -> str:
    """Write the blinding beside its file, as ``<file_path>.pacspace.json``,
    readable by you only (mode 0600; not enforced on Windows). A link or
    anything but a regular file at that path is refused. The same bytes
    already there are left as they are; other bytes are refused. Returns
    the path."""
    if not isinstance(blinding, Blinding) or not blinding.digest:
        raise ValidationError(_NOT_A_FILE)
    target = os.fspath(file_path) + BLINDING_FILE_SUFFIX
    reason = _write(target, blinding)
    if reason == "different":
        raise ValidationError(_DIFFERENT)
    if reason == "not-regular":
        raise ValidationError(_NOT_REGULAR)
    return target


def _parse(data: bytes) -> Optional[Blinding]:
    """The exact reader: strict UTF-8, the five string fields, then the
    canonical form rewritten from the parsed fields must equal the input."""
    if len(data) > BLINDING_FILE_MAX_BYTES:
        return None
    try:
        text = data.decode("utf-8")
        parsed = json.loads(text)
    except (UnicodeDecodeError, ValueError):
        return None
    if not isinstance(parsed, dict) or len(parsed) != len(_FIELDS) or set(parsed) != set(_FIELDS):
        return None
    if parsed["schema"] != BLINDING_FILE_SCHEMA or parsed["alg"] != "hmac-sha-256":
        return None
    for field in ("value", "digest"):
        if not isinstance(parsed[field], str) or _HEX_64.fullmatch(parsed[field]) is None:
            return None
    if not _is_decimal(parsed["byteLength"]):
        return None
    if _canonical_text(parsed["value"], parsed["digest"], parsed["byteLength"]) != text:
        return None
    return Blinding(bytes.fromhex(parsed["value"]), parsed["digest"], parsed["byteLength"])


def _read(path: PathLike) -> Optional[Blinding]:
    with open(path, "rb") as handle:
        return _parse(handle.read(BLINDING_FILE_MAX_BYTES + 1))


def read_blinding_file(path: PathLike) -> Blinding:
    """Read a blinding file exactly (at most 1024 bytes, the canonical form only)."""
    blinding = _read(path)
    if blinding is None:
        raise ValidationError(_NOT_A_FILE)
    return blinding
