import pytest

from verification_receipt import build_verification_receipt


def context() -> dict[str, object]:
    return {
        "proofId": "a" * 64,
        "videoHash": "b" * 64,
        "metadataHash": "c" * 64,
        "tier": "source",
        "networkPassphrase": "Test SDF Network ; September 2015",
        "contractId": "C" + "d" * 55,
        "ledgerSequence": 42,
        "transactionHash": "e" * 64,
        "circuitVersion": "1",
        "verifierVersion": "2026.09",
    }


def test_receipt_matches_the_frontend_unsigned_model():
    receipt = build_verification_receipt(context())

    assert receipt["result"] == "unverified"
    assert receipt["proofId"] == "a" * 64
    assert receipt["videoHash"] == "b" * 64
    assert receipt["metadataHash"] == "c" * 64
    assert receipt["ledgerSequence"] == 42
    assert "protocol" not in receipt
    assert "signature" not in receipt
    assert "proof" not in receipt


@pytest.mark.parametrize(
    ("field", "value"),
    [("proofId", "short"), ("transactionHash", "not-hex")],
)
def test_rejects_invalid_digest_fields(field: str, value: str):
    invalid = context()
    invalid[field] = value

    with pytest.raises(ValueError, match=field):
        build_verification_receipt(invalid)


def test_rejects_incomplete_context_without_inventing_receipt_fields():
    with pytest.raises(ValueError, match="videoHash"):
        build_verification_receipt({"proofId": "a" * 64})


def test_rejects_unsupported_critical_extension_in_metadata():
    critical = context()
    critical["extensions"] = {
        "critical": ["x-unknown-required"],
        "x-unknown-required": {"mode": "strict"},
    }

    with pytest.raises(ValueError, match="x-unknown-required"):
        build_verification_receipt(critical)


def test_preserves_compatible_optional_extension_fields():
    optional = context()
    optional["extensions"] = {
        "critical": [],
        "x-display-hint": {"locale": "en-US"},
    }

    receipt = build_verification_receipt(optional)

    assert receipt["extensions"]["x-display-hint"] == {"locale": "en-US"}
    assert receipt["extensions"]["critical"] == []
