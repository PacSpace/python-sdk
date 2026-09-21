from __future__ import annotations

from typing import Any, Dict, Literal, TypedDict, Union

KnownWebhookEventType = Literal[
    "delta.verified",
    "delta.failed",
    "record.committed",
    "record.failed",
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
        Dict[str, Any],
    ]
