# pacspace-sdk (Python)

Official Python SDK for the PacSpace Balance API.

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

emit = pac.balance.emit("cust_123", -42, "usage")
status = pac.balance.wait_for_verified(emit["recordId"])
usage = pac.balance.usage()

adjustment = pac.balance.emit(
    "cust_123",
    -10,
    "adjustment",
    {"adjusts": {"referenceId": "inv_001"}},
)
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

`adjusts` names the committed Balance entry this delta adjusts. `amends` names a committed records entry by `recordKey` and `entry`. The SDK counts entries from 1, as every PacSpace page does: `"entry": 1` is the first entry of the record, the one the record page calls "Entry 1". The HTTP API and the history file carry the same position as `seq`, counted from 0; the SDK converts at its boundary (`seq = entry - 1`), so you never send a `seq`. An `entry` below 1 raises `ValidationError` before anything is sent. `receipt(record, entry)`, `history(record, from_entry=, to_entry=)`, and `check`'s `expect[]["entry"]` count the same way; a `"seq"` read straight off a history or a webhook may be given in place of `"entry"` and goes on the wire as it is. The history file keeps the wire's `seq`; `check` reports each result as `entry` (`seq + 1`).

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
