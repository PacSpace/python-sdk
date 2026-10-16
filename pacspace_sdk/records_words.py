"""The SDK's refusals for encrypted records (L2d words list, W-L2d-23 to 37):
the same codes and sentences in TypeScript and Python. A sentence never
carries key bytes; an entry is named by its number, counting from 1."""

from __future__ import annotations

from typing import Optional, Union

from .errors import PacSpaceError

RECORDS_ENCRYPTION_WORDS = {
    "RECORDS_SECRET_REQUIRED": "Encrypted records need the workspace secret. Pass it as records.secret or records.secretProvider.",
    "RECORDS_SECRET_INVALID": "The workspace secret isn't a pacspace-workspace-secret/v1 file this version reads.",
    "RECORDS_VERSION_NOT_HELD": "This record is under version {v}, which this workspace secret doesn't hold.",
    "RECORDS_ENTRY_UNOPENED": "Entry {seq} didn't open. The record or the workspace secret is not the one expected.",
    "RECORDS_ENTRY_HASH_MISMATCH": "Entry {seq} opened, but its content doesn't match its sealed record hash.",
    "RECORDS_ENTRY_REFS_MISMATCH": "Entry {seq} opened, but the entries it amends or references don't match the ones stored with it.",
    "RECORDS_HISTORY_OTHER_RECORD": "The history served is for another record. Nothing was opened.",
    "RECORDS_CODE_REQUIRED": "Confirm this workspace's code with them outside PacSpace first, then pass it as confirmedCode.",
    "RECORDS_CODE_MISMATCH": "The code computed for this workspace doesn't match the one confirmed. Nothing was wrapped. Confirm the code with them again.",
    "RECORDS_PIN_CHANGED": "This workspace's identity changed since its code was confirmed. Nothing was wrapped. Confirm the new code with them.",
    "RECORDS_NOT_ENCRYPTED": "This record isn't encrypted. Keep its history file instead.",
    "RECORDS_LINK_NO_KEY": "This link has no key after # and no wrap for your workspace.",
    "RECORDS_REKEY_STOPPED": "Re-encryption stopped at entry {seq}. Entries after it are done; run it again to finish.",
    "RECORDS_ROTATE_NOT_NEXT": "The new workspace secret must add exactly the next version and keep every earlier one.",
    "RECORDS_IDENTITY_OTHER": "This workspace already registered another identity, which this workspace secret doesn't open.",
    "RECORDS_OWNER_INVALID": "This workspace id isn't in the expected form.",
    "RECORDS_DISCLOSURE_LINK_MISMATCH": "This shared record doesn't match the link it came from.",
    "RECORDS_SECRET_FILE_OUTDATED": "This workspace replaced its key. Use its new secret file on this server.",
    "RECORDS_RETIRED_KEY_MISMATCH": "A retired key for this workspace doesn't match its listed code. Don't use it; contact PacSpace.",
}

# RECORDS_VERSION_NOT_HELD's sentence when a write's claim names a version this client doesn't hold (card 10, W-C10-B-2).
RECORDS_WRITE_VERSION_NOT_HELD = (
    "This write was first made under encryption version {v}, which this client doesn't hold. Open that version first, or use a new reference."
)


class RecordsEncryptionError(PacSpaceError):
    """A client-side refusal on an encrypted path: a code and its sentence, never a key."""

    def __init__(
        self, code: str, v: Optional[Union[int, str]] = None, seq: Optional[Union[int, str]] = None, write: bool = False
    ) -> None:
        template = RECORDS_WRITE_VERSION_NOT_HELD if code == "RECORDS_VERSION_NOT_HELD" and write else RECORDS_ENCRYPTION_WORDS[code]
        sentence = template.replace("{v}", "" if v is None else str(v)).replace("{seq}", "" if seq is None else str(seq))
        super().__init__(sentence, 0, code)
