"""Validation for the canonical verification-receipt input contract.

The frontend owns receipt versioning and signing. The backend only returns the
same unsigned input shape, so there is one protocol contract and no second
backend-specific receipt envelope.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal, Mapping, TypedDict


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


# Receipt metadata extensions are keyed by name. A key prefixed with "critical:"
# marks an extension the verifier MUST understand; unknown critical extensions
# cause the receipt to be rejected (fail closed). Non-critical (optional)
# extensions are preserved verbatim so they survive round trips.
CRITICAL_EXTENSION_PREFIX = "critical:"

# Critical extensions this verifier implements. Empty today: any critical
# extension is unsupported and must be rejected.
SUPPORTED_CRITICAL_EXTENSIONS: frozenset[str] = frozenset()


def build_verification_receipt(
    context: Mapping[str, object],
    *,
    result: Literal["verified", "unverified"] = "unverified",
) -> VerificationReceiptInput:
    """Validate and build the canonical unsigned receipt input.

    A receipt is only emitted when the caller supplies the complete canonical
    evidence context. This prevents the selective-disclosure endpoint from
    inventing proof IDs or hashes from unrelated request fields.

    Any metadata extensions present in ``context['extensions']`` are checked:
    unknown critical extensions are rejected, while optional extensions are
    preserved in the returned mapping under ``extensions``.
    """

    receipt: VerificationReceiptInput = {
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
    extensions = _extensions(context.get("extensions"))
    if extensions:
        receipt["extensions"] = extensions  # type: ignore[typeddict-unknown-key]
    return receipt


def _extensions(value: object) -> dict[str, object]:
    """Validate receipt metadata extensions, failing closed on unknown critical ones."""

    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ValueError("extensions must be a mapping or null")
    preserved: dict[str, object] = {}
    for key, item in value.items():
        if not isinstance(key, str) or not key.strip():
            raise ValueError("extension names must be non-empty strings")
        if key.startswith(CRITICAL_EXTENSION_PREFIX):
            if key not in SUPPORTED_CRITICAL_EXTENSIONS:
                raise ValueError(f"unsupported critical extension: {key}")
        preserved[key] = item
    return preserved


def _text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    return value


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
