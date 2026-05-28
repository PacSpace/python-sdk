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

emit = pac.balance.emit("cust_123", -42, "usage")
status = pac.balance.wait_for_verified(emit["recordId"])
usage = pac.balance.usage()
```

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
