from __future__ import annotations

from typing import Any, Dict, Literal, Optional, TypedDict, Union

KnownWebhookEventType = Literal[
    "delta.verified",
    "delta.failed",
    "record.committed",
    "record.failed",
    "record.closed",
]
WebhookEventType = Union[KnownWebhookEventType, str]


class DeltaVerifiedPayload(TypedDict, total=False):
    recordId: str
    receiptId: str
    verificationReference: str
    customerId: str
    delta: float
    sequenceNumber: str
    referenceId: str
    blockTimestamp: str


class DeltaFailedPayload(TypedDict, total=False):
    recordId: str
    customerId: str
    delta: float
    error: str
    failedAt: str


class RecordCommittedPayload(TypedDict, total=False):
    receiptId: str
    status: str
    verifiedAt: str
    verificationId: str
    itemCount: int
    records: list
    verification: Dict[str, Any]


class RecordFailedPayload(TypedDict, total=False):
    recordType: str
    entityId: str
    seq: int
    code: str
    sentence: str


class RecordClosedPayload(TypedDict, total=False):
    """A record was closed, by your code (``records.close``) or by PacSpace
    after the source's timeout. A close writes no entry. ``entityId`` is the
    wire id of an encrypted record; ``lastSeq`` is the wire's number, counted
    from 0. ``closedOn`` is the day of the close, YYYY-MM-DD (UTC)."""

    recordType: str
    entityId: str
    closedBy: str
    lastSeq: int
    lastSeal: Optional[str]
    closedOn: str


class WebhookEvent(TypedDict, total=False):
    id: str
    event: WebhookEventType
    tenantId: str
    createdAt: str
    data: Union[
        DeltaVerifiedPayload,
        DeltaFailedPayload,
        RecordCommittedPayload,
        RecordFailedPayload,
        RecordClosedPayload,
        Dict[str, Any],
    ]
