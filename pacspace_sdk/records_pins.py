"""Pins: a workspace whose code the person confirmed outside PacSpace, as the
id of the public key that made the code, and when. Wraps go only to a
pinned key; a later wrap that finds another key there is refused before
anything is wrapped. A pin holds no secret."""

from __future__ import annotations

import json
import os
import re
from typing import Dict, Optional, Protocol

_PIN_FILE_SCHEMA = "pacspace-pins/v1"
_HEX64 = re.compile(r"[0-9a-f]{64}")


class RecordsPinStore(Protocol):
    def get(self, workspace_id: str) -> Optional[Dict[str, str]]: ...

    def set(self, workspace_id: str, pin: Dict[str, str]) -> None: ...


class _MemoryPinStore:
    def __init__(self) -> None:
        self._pins: Dict[str, Dict[str, str]] = {}

    def get(self, workspace_id: str) -> Optional[Dict[str, str]]:
        pin = self._pins.get(workspace_id)
        return dict(pin) if pin else None

    def set(self, workspace_id: str, pin: Dict[str, str]) -> None:
        self._pins[workspace_id] = {"publicKeyId": pin["publicKeyId"], "confirmedAt": pin["confirmedAt"]}


def memory_pin_store() -> RecordsPinStore:
    """Pins held for this process only."""
    return _MemoryPinStore()


class _FilePinStore:
    def __init__(self, path: str) -> None:
        self._path = path

    def _read(self) -> Dict[str, Dict[str, str]]:
        try:
            with open(self._path, "r", encoding="utf-8") as handle:
                text = handle.read()
        except FileNotFoundError:
            return {}
        try:
            parsed = json.loads(text)
        except ValueError:
            return {}
        pins = parsed.get("pins") if isinstance(parsed, dict) and parsed.get("schema") == _PIN_FILE_SCHEMA else None
        return pins if isinstance(pins, dict) else {}

    def get(self, workspace_id: str) -> Optional[Dict[str, str]]:
        pin = self._read().get(workspace_id)
        if isinstance(pin, dict) and isinstance(pin.get("publicKeyId"), str) and _HEX64.fullmatch(pin["publicKeyId"]):
            return dict(pin)
        return None

    def set(self, workspace_id: str, pin: Dict[str, str]) -> None:
        pins = self._read()
        pins[workspace_id] = {"publicKeyId": pin["publicKeyId"], "confirmedAt": pin["confirmedAt"]}
        folder = os.path.dirname(self._path)
        if folder:
            os.makedirs(folder, exist_ok=True)
        following = f"{self._path}.{os.getpid()}.tmp"
        descriptor = os.open(following, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(json.dumps({"schema": _PIN_FILE_SCHEMA, "pins": pins}, indent=2) + "\n")
        os.chmod(following, 0o600)
        os.replace(following, self._path)


def file_pin_store(path: str) -> RecordsPinStore:
    """Pins kept in a JSON file, readable by its owner only (mode 0600). Each
    write replaces the file whole, so a crash leaves the previous pins. A file
    that can't be read as pins holds none: every code is confirmed again."""
    return _FilePinStore(path)
