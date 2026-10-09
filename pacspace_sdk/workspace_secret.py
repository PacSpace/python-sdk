"""The workspace secret's file (pacspace-workspace-secret/v1), drawn here."""

from __future__ import annotations

from . import records_encryption as R
from .records_words import RecordsEncryptionError


def generate_workspace_secret() -> str:
    """A new workspace secret: a pacspace-workspace-secret/v1 file with version
    1, drawn in this process. Keep it where the workspace keeps its other
    secrets; PacSpace never receives it, and a lost secret can't be recovered."""
    return R.serialize_records_keyring_file([(1, R.generate_workspace_secret())])


def next_workspace_secret(keyring: str) -> str:
    """The same file with the next version added, drawn here: the input to ``records.rotate()``."""
    parsed = R.parse_records_keyring_file(keyring)
    if not parsed["ok"]:
        raise RecordsEncryptionError("RECORDS_SECRET_INVALID")
    secrets = parsed["secrets"]
    following = max(version for version, _ in secrets) + 1
    return R.serialize_records_keyring_file([*secrets, (following, R.generate_workspace_secret())])
