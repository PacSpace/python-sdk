"""Record labels (R3; D-4, D-23), as the TypeScript SDK reads them.

A label is a ``name=value`` pair your code puts on a record. Labels are
metadata on the record: never in an entry's content, never committed. In an
encrypted workspace each is blinded before it is sent
(``records_encryption.blinded_label``), so PacSpace learns which records
share a label, never the label. The grammar and limits are the platform's
(packages/shared/src/records/labels.ts)."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from .errors import PacSpaceError

LABELS_MAX = 10
_PAIR = re.compile(r"\s*([a-z0-9_.-]+)\s*[=:]\s*(.+?)\s*", re.IGNORECASE)
_KEY = re.compile(r"[a-z0-9_.-]{1,32}")
_VALUE = re.compile(r"[A-Za-z0-9._:/-]{1,64}")
_PARTS = re.compile(r"[,;\n]+")
# The API's sentence for RECORD_LABELS_INVALID, reused word for word before anything is sent.
LABELS_INVALID = "Labels are up to 10 key=value pairs. Keys are lowercase."


def parse_labels(text: str) -> Optional[Dict[str, str]]:
    """The prototype's grammar: pairs split on ``,``, ``;`` or a newline, each
    ``k=v`` or ``k:v``, keys lowercased. None when a part does not read as a
    pair, since a dropped label would quietly change what was meant."""
    out: Dict[str, str] = {}
    for part in _PARTS.split(text):
        if not part.strip():
            continue
        found = _PAIR.fullmatch(part)
        if found is None:
            return None
        out[found.group(1).lower()] = found.group(2)
    return out


def label_pairs(labels: Any) -> List[Tuple[str, str]]:
    """The labels as name and value pairs, checked as the API checks them;
    refused with RECORD_LABELS_INVALID before anything is sent."""
    parsed = parse_labels(labels) if isinstance(labels, str) else labels
    if not isinstance(parsed, dict) or not 1 <= len(parsed) <= LABELS_MAX:
        raise PacSpaceError(LABELS_INVALID, 422, "RECORD_LABELS_INVALID")
    for key, value in parsed.items():
        if not isinstance(key, str) or not isinstance(value, str) or _KEY.fullmatch(key) is None or _VALUE.fullmatch(value) is None:
            raise PacSpaceError(LABELS_INVALID, 422, "RECORD_LABELS_INVALID")
    return list(parsed.items())
