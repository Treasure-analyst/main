"""Validation for the canonical verification-receipt input contract.

The frontend owns receipt versioning and signing. The backend only returns the
same unsigned input shape, so there is one protocol contract and no second
backend-specific receipt envelope.

Public signing-key history is served as read-only metadata: each entry carries a
key identifier, the public key, and a validity interval. Private signing keys
are never loaded or handled by the backend.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable, Literal, Mapping, TypedDict

# Upper bound on how many key-history entries a single response may carry.
MAX_KEY_HISTORY_ENTRIES = 100


class VerificationReceiptInput(TypedDict):
    """Unsigned fields consumed by the frontend receipt signer."""

    result: Literal["verified", "unverified"]
    verifiedAt: str
    proofId: str
    videoHash: str
    metadataHash: str
    tier: Literal["silent", "source", "seal"]
    networkPassphrase: str
    contractId: str
    ledgerSequence: int | None
    transactionHash: str | None
    circuitVersion: str
    verifierVersion: str


class SigningKeyRecord(TypedDict):
    """Public metadata for one historical receipt signing key."""

    keyId: str
    publicKey: str
    validFrom: str
    validUntil: str | None


class SigningKeyHistory(TypedDict):
    """Bounded, read-only public signing-key history response."""

    keys: list[SigningKeyRecord]
    truncated: bool


def build_verification_receipt(
    context: Mapping[str, object],
    *,
    result: Literal["verified", "unverified"] = "unverified",
) -> VerificationReceiptInput:
    """Validate and build the canonical unsigned receipt input.

    A receipt is only emitted when the caller supplies the complete canonical
    evidence context. This prevents the selective-disclosure endpoint from
    inventing proof IDs or hashes from unrelated request fields.
    """

    return {
        "result": result,
        "verifiedAt": datetime.now(timezone.utc).isoformat(),
        "proofId": _hex32(context.get("proofId"), "proofId"),
        "videoHash": _hex32(context.get("videoHash"), "videoHash"),
        "metadataHash": _hex32(context.get("metadataHash"), "metadataHash"),
        "tier": _choice(context.get("tier"), "tier", ("silent", "source", "seal")),
        "networkPassphrase": _text(context.get("networkPassphrase"), "networkPassphrase"),
        "contractId": _text(context.get("contractId"), "contractId"),
        "ledgerSequence": _optional_int(context.get("ledgerSequence"), "ledgerSequence"),
        "transactionHash": _optional_hex32(context.get("transactionHash"), "transactionHash"),
        "circuitVersion": _text(context.get("circuitVersion"), "circuitVersion"),
        "verifierVersion": _text(context.get("verifierVersion"), "verifierVersion"),
    }


def build_signing_key_history(
    records: Iterable[Mapping[str, object]],
    *,
    limit: int = MAX_KEY_HISTORY_ENTRIES,
) -> SigningKeyHistory:
    """Build a bounded public signing-key history from public key metadata.

    Each record must provide ``keyId``, ``publicKey`` and ``validFrom``, and may
    provide ``validUntil`` (``None`` means still valid). Records with a validity
    interval whose end precedes its start are rejected. Output is sorted by
    ``validFrom`` ascending and capped at ``limit`` entries; ``truncated`` is set
    when additional entries were dropped.
    """

    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        raise ValueError("limit must be a positive integer")

    parsed: list[SigningKeyRecord] = []
    for index, record in enumerate(records):
        if not isinstance(record, Mapping):
            raise ValueError(f"signing key record {index} must be a mapping")
        valid_from = _timestamp(record.get("validFrom"), "validFrom")
        valid_until_raw = record.get("validUntil")
        valid_until = (
            None if valid_until_raw is None else _timestamp(valid_until_raw, "validUntil")
        )
        if valid_until is not None and valid_until < valid_from:
            raise ValueError("validUntil must not precede validFrom")
        parsed.append(
            {
                "keyId": _text(record.get("keyId"), "keyId"),
                "publicKey": _text(record.get("publicKey"), "publicKey"),
                "validFrom": valid_from.isoformat(),
                "validUntil": None if valid_until is None else valid_until.isoformat(),
            }
        )

    parsed.sort(key=lambda entry: entry["validFrom"])
    truncated = len(parsed) > limit
    return {"keys": parsed[:limit], "truncated": truncated}


def _text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    return value


def _timestamp(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be an ISO 8601 timestamp string")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"{field} must be an ISO 8601 timestamp string") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{field} must include a timezone offset")
    return parsed.astimezone(timezone.utc)


def _hex32(value: object, field: str) -> str:
    if not isinstance(value, str) or len(value) != 64:
        raise ValueError(f"{field} must be a 32-byte hex string")
    try:
        int(value, 16)
    except ValueError as exc:
        raise ValueError(f"{field} must be a 32-byte hex string") from exc
    return value.lower()


def _optional_hex32(value: object, field: str) -> str | None:
    if value is None:
        return None
    return _hex32(value, field)


def _optional_int(value: object, field: str) -> int | None:
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"{field} must be a non-negative integer or null")
    return value


def _choice(value: object, field: str, choices: tuple[str, ...]) -> str:
    if value not in choices:
        raise ValueError(f"{field} must be one of: {', '.join(choices)}")
    return value
