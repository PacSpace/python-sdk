"""The workspace secret's file (pacspace-workspace-secret/v1), drawn here."""

from __future__ import annotations

import os
from typing import Union

from . import records_encryption as R
from .records_words import RecordsEncryptionError

PathLike = Union[str, "os.PathLike[str]"]


def workspace_secret_file_name(version: int, environment: str = "production") -> str:
    """The name the dashboard downloads a workspace secret file under. Sandbox's
    says so, so the two environments' files never share a name (EN1, D-20):
    ``pacspace-workspace-secret-sandbox-v1.json``, and
    ``pacspace-workspace-secret-v1.json`` for Production."""
    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        raise RecordsEncryptionError("RECORDS_SECRET_INVALID")
    return "pacspace-workspace-secret-%sv%d.json" % ("sandbox-" if environment == "sandbox" else "", version)


def read_workspace_secret_file(path: PathLike) -> str:
    """Read a workspace secret file, for ``records={"secret": ...}``. The file's
    name doesn't matter: Sandbox's ``pacspace-workspace-secret-sandbox-vN.json``
    and the SDK's own ``pacspace-workspace-secret-vN.json`` read the same.
    Anything that isn't a pacspace-workspace-secret/v1 file raises
    RECORDS_SECRET_INVALID. The text is returned and kept nowhere else."""
    with open(path, "rb") as handle:
        data = handle.read(R.KEYRING_MAX_BYTES + 1)
    if len(data) > R.KEYRING_MAX_BYTES:
        raise RecordsEncryptionError("RECORDS_SECRET_INVALID")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise RecordsEncryptionError("RECORDS_SECRET_INVALID") from None
    if not R.parse_records_keyring_file(text)["ok"]:
        raise RecordsEncryptionError("RECORDS_SECRET_INVALID")
    return text


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
