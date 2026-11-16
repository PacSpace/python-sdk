# pacspace-sdk (Python)

Official Python SDK for the PacSpace API.

## Install

```bash
pip install pacspace-sdk
```

## Quick Start

```python
from pacspace_sdk import PacSpace

pac = PacSpace.init("pk_test_xxx")
# Every request goes to https://app.pacspace.io; the key selects the environment
# (pk_test_ sandbox, pk_live_ production). Pass sandbox_url= for a private sandbox host.

entry = pac.records.emit(
    record="build-1",
    title="Handoff restated",
    occurred_at="2026-09-14T10:02:00Z",
    actor_id="ci",
    payloads=[{"alg": "sha-256", "digest": "bb" * 32, "byteLength": "1"}],
    amends={"recordKey": "0xab", "entry": 1},
    note="handoff restated",
    lifecycle="amended",
)
```

`amends` names a committed records entry by `recordKey` and `entry`. The SDK counts entries from 1, as every PacSpace page does: `"entry": 1` is the first entry of the record, the one the record page calls "Entry 1". The HTTP API and the history file carry the same position as `seq`, counted from 0; the SDK converts at its boundary (`seq = entry - 1`), so you never send a `seq`. An `entry` below 1 raises `ValidationError` before anything is sent. `receipt(record, entry)`, `history(record, from_entry=, to_entry=)`, and `check`'s `expect[]["entry"]` count the same way; a `"seq"` read straight off a history or a webhook may be given in place of `"entry"` and goes on the wire as it is. The history file keeps the wire's `seq`; `check` reports each result as `entry` (`seq + 1`). The answer to `emit` carries `entry`, the number this entry will have in its record, counted from 1.

## Labels and closing a record

```python
pac.records.emit(
    record="session-12",
    title="Session 12",
    occurred_at="2026-10-19T09:00:00Z",
    actor_id="agent-7",
    payloads=[ref],
    labels={"model": "m-0926"},
)
closed = pac.records.close("session-12")
# closed["lastEntry"], closed["closedAt"], closed["lastSeal"]
```

`labels=` puts up to 10 `name=value` pairs on the record, as a dict or a string (`"model=m-0926, site=press-line-4"`, split on commas, semicolons or new lines, names lowercased). Labels go on the record, never in an entry, and are never committed. Names are lowercase letters, digits, `_`, `.` and `-`, up to 32 characters; values are letters, digits and `._:/-`, up to 64. Labels outside those limits are refused with `RECORD_LABELS_INVALID` before anything is sent. With a workspace secret set, each label is blinded under your workspace's key before it is sent: PacSpace can tell which records share a label, never what the label says.

`records.close(record, record_type=None, last_entry=None)` closes a record. A close is a fact about the record, not an entry: nothing is written into the record. The close names the record's last entry, counted from 1. Left out, `last_entry` is the last entry this process wrote to the record, or the record's own last entry, read from PacSpace. A close made while entries are still on their way is refused with `RECORD_CLOSE_SEQ_MISMATCH`; a write to a closed record is refused with `RECORD_CLOSED`. Closing again after the same entry returns `"idempotent": True`. With a workspace secret set, the record is closed by its wire id; `encrypted=False` closes a plaintext record.

## `fingerprint(source, alg=None, *, blind=None, blinding=None)`

fingerprint() blinds by default: it mixes a random 32-byte value into the fingerprint, so the fingerprint cannot be matched to a guessed file without the file's blinding file.

It returns a Fingerprint with ref and blinding. Send ref as the payload. Save blinding beside the file with write_blinding_file(path, blinding); anyone checking the file later needs it.

To check a file later, pass it with its blinding file: in records.check, expect=[{"entry": 1, "files": [{"source": f, "blinding": b}]}], or fingerprint(f, blinding=b). A blinding belongs to one file; another file is refused.

The blinding file is as private as the file: whoever holds both can confirm the file is in the record. The file's size is stored as before.

blind=False, or fingerprint(source, "sha-256"), gives today's plain sha-256 fingerprint as a Fingerprint with blinding None. It is not blinded.

On Windows the blinding file's permissions are not restricted to you; keep it somewhere only you can read.

## `read_workspace_secret_file(path)`

read_workspace_secret_file() reads a workspace secret file and returns its text, for `records={"secret": ...}`.

```python
import os

from pacspace_sdk import PacSpace, read_workspace_secret_file

pac = PacSpace.init(
    os.environ["PACSPACE_API_KEY"],
    records={"secret": read_workspace_secret_file("pacspace-workspace-secret-sandbox-v1.json")},
)
```

It reads the file under either name: Sandbox's `pacspace-workspace-secret-sandbox-v1.json`, or `pacspace-workspace-secret-v1.json`. A file that isn't a workspace secret raises RECORDS_SECRET_INVALID. workspace_secret_file_name(version, environment) gives the name the dashboard downloads it under.

## Verify source selection

```python
verification = pac.verify(
    "0xproof_root_here",
    source="both",  # "db" (default), "chain", or "both"
)
```

## Webhook Verification

```python
from pacspace_sdk import Webhooks

webhooks = Webhooks("whsec_xxx")
event = webhooks.verify(signature, timestamp, raw_body)
```

`record.closed` arrives when a record is closed, by your code or by PacSpace after the source's timeout: `{ recordType, entityId, closedBy, lastSeq, lastSeal, closedOn }`, where `closedBy` is `code` or `timeout` and `lastSeq` counts from 0, as the wire does.
