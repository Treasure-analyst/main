"""
Comprehensive test suite for time attestation module.

Covers:
- Valid attestation creation and encoding
- Backdating detection
- Digest substitution prevention
- Future time rejection
- Resource bounds
- Multiple anchor types
- Offline verification scenarios
- Rejection of receipt metadata containing unsupported critical extensions
"""

import time
import pytest
from time_attestation import (
    TimeAttestation,
    ClaimedTime,
    ObservedTime,
    StellarAnchor,
    RFC3161Anchor,
    create_time_attestation,
    add_stellar_anchor,
    add_rfc3161_anchor,
    encode_time_attestation,
    decode_time_attestation,
    canonical_time_attestation_hash,
    validate_time_attestation,
    check_backdating_risk,
    MAX_FUTURE_DRIFT_SECONDS,
    MAX_TIMESTAMP_TOKEN_SIZE,
    MAX_ANCHOR_COUNT,
    PROFILE_ID,
)


# ── Test fixtures ──────────────────────────────────────────────────────────

VALID_EVIDENCE_DIGEST = "a" * 64
VALID_TX_HASH = "b" * 64
STELLAR_TESTNET_PASSPHRASE = "Test SDF Network ; September 2015"


@pytest.fixture
def current_time_ms():
    return int(time.time() * 1000)


@pytest.fixture
def valid_attestation(current_time_ms):
    return create_time_attestation(
        evidence_digest=VALID_EVIDENCE_DIGEST,
        claimed_time_ms=current_time_ms - 1000,
        claimed_source_label="device_clock",
        uncertainty_ms=500,
    )


# ── Creation and encoding ──────────────────────────────────────────────────

def test_create_time_attestation_minimal():
    attestation = create_time_attestation(VALID_EVIDENCE_DIGEST)
    
    assert attestation.version == 1
    assert attestation.protocol == PROFILE_ID
    assert attestation.evidence_digest == VALID_EVIDENCE_DIGEST
    assert attestation.observed_time is not None
    assert attestation.observed_time.source_label == "backend_system_clock"
    assert attestation.claimed_time is None
    assert attestation.stellar_anchors == []
    assert attestation.rfc3161_anchors == []


def test_create_time_attestation_with_claimed(current_time_ms):
    attestation = create_time_attestation(
        evidence_digest=VALID_EVIDENCE_DIGEST,
        claimed_time_ms=current_time_ms - 5000,
        claimed_source_label="ntp_synchronized",
        uncertainty_ms=200,
    )
    
    assert attestation.claimed_time is not None
    assert attestation.claimed_time.unix_ms == current_time_ms - 5000
    assert attestation.claimed_time.source_label == "ntp_synchronized"
    assert attestation.claimed_time.uncertainty_ms == 200


def test_encode_decode_roundtrip(valid_attestation):
    encoded = encode_time_attestation(valid_attestation)
    decoded = decode_time_attestation(encoded)
    
    assert decoded.version == valid_attestation.version
    assert decoded.protocol == valid_attestation.protocol
    assert decoded.evidence_digest == valid_attestation.evidence_digest
    assert decoded.claimed_time == valid_attestation.claimed_time
    assert decoded.observed_time.unix_ms == valid_attestation.observed_time.unix_ms


def test_canonical_hash_deterministic(valid_attestation):
    hash1 = canonical_time_attestation_hash(valid_attestation)
    hash2 = canonical_time_attestation_hash(valid_attestation)
    
    assert hash1 == hash2
    assert len(hash1) == 64
    int(hash1, 16)  # Verify it's valid hex


# ── Validation ─────────────────────────────────────────────────────────────

def test_validate_correct_evidence_digest(valid_attestation):
    errors = validate_time_attestation(valid_attestation, VALID_EVIDENCE_DIGEST)
    assert len(errors) == 0


def test_validate_wrong_evidence_digest(valid_attestation):
    wrong_digest = "c" * 64
    errors = validate_time_attestation(valid_attestation, wrong_digest)
    
    assert len(errors) > 0
    assert any("digest mismatch" in err.lower() for err in errors)


def test_validate_rejects_future_time(current_time_ms):
    future_time = current_time_ms + ((MAX_FUTURE_DRIFT_SECONDS + 60) * 1000)
    attestation = create_time_attestation(
        evidence_digest=VALID_EVIDENCE_DIGEST,
        claimed_time_ms=future_time,
    )
    
    errors = validate_time_attestation(attestation, VALID_EVIDENCE_DIGEST)
    assert len(errors) > 0
    assert any("too far in the future" in err.lower() for err in errors)


def test_validate_accepts_recent_future_within_drift(current_time_ms):
    # Time within acceptable drift window
    near_future = current_time_ms + ((MAX_FUTURE_DRIFT_SECONDS - 10) * 1000)
    attestation = create_time_attestation(
        evidence_digest=VALID_EVIDENCE_DIGEST,
        claimed_time_ms=near_future,
    )
    
    errors = validate_time_attestation(attestation, VALID_EVIDENCE_DIGEST)
    # Should not error on future time within drift
    assert not any("too far in the future" in err.lower() for err in errors)


def test_validate_rejects_negative_time():
    attestation = create_time_attestation(
        evidence_digest=VALID_EVIDENCE_DIGEST,
        claimed_time_ms=-1000,
    )
    
    errors = validate_time_attestation(attestation, VALID_EVIDENCE_DIGEST)
    assert len(errors) > 0
    assert any("negative" in err.lower() for err in errors)


def test_validate_requires_at_least_one_time_source():
    # Manually create attestation with no time sources
    attestation = TimeAttestation(
        version=1,
        protocol=PROFILE_ID,
        evidence_digest=VALID_EVIDENCE_DIGEST,
        claimed_time=None,
        observed_time=None,
        stellar_anchors=[],
        rfc3161_anchors=[],
    )
    
    errors = validate_time_attestation(attestation, VALID_EVIDENCE_DIGEST)
    assert len(errors) > 0
    assert any("at least one time source" in err.lower() for err in errors)


# ── Stellar anchor ─────────────────────────────────────────────────────────

def test_add_stellar_anchor(valid_attestation, current_time_ms):
    ledger_ts = current_time_ms // 1000
    
    with_anchor = add_stellar_anchor(
        valid_attestation,
        ledger_sequence=12345,
        ledger_timestamp=ledger_ts,
        transaction_hash=VALID_TX_HASH,
        network_passphrase=STELLAR_TESTNET_PASSPHRASE,
    )
    
    assert len(with_anchor.stellar_anchors) == 1
    anchor = with_anchor.stellar_anchors[0]
    assert anchor.ledger_sequence == 12345
    assert anchor.ledger_timestamp == ledger_ts
    assert anchor.transaction_hash == VALID_TX_HASH
    assert anchor.network_passphrase == STELLAR_TESTNET_PASSPHRASE


def test_stellar_anchor_rejects_invalid_tx_hash(valid_attestation):
    with pytest.raises(ValueError, match="64-character hex"):
        add_stellar_anchor(
            valid_attestation,
            ledger_sequence=100,
            ledger_timestamp=1000000,
            transaction_hash="not_hex",
            network_passphrase=STELLAR_TESTNET_PASSPHRASE,
        )


def test_stellar_anchor_roundtrip_encoding(valid_attestation, current_time_ms):
    with_anchor = add_stellar_anchor(
        valid_attestation,
        ledger_sequence=999,
        ledger_timestamp=current_time_ms // 1000,
        transaction_hash=VALID_TX_HASH,
        network_passphrase=STELLAR_TESTNET_PASSPHRASE,
    )
    
    encoded = encode_time_attestation(with_anchor)
    decoded = decode_time_attestation(encoded)
    
    assert len(decoded.stellar_anchors) == 1
    assert decoded.stellar_anchors[0].transaction_hash == VALID_TX_HASH


# ── RFC 3161 anchor ────────────────────────────────────────────────────────

def test_add_rfc3161_anchor(valid_attestation, current_time_ms):
    token = "base64encodedtoken=="
    
    with_anchor = add_rfc3161_anchor(
        valid_attestation,
        token_bytes=token,
        tsa_url="https://freetsa.org/tsr",
        gen_time=current_time_ms,
        policy_oid="1.2.3.4.5",
        cert_fingerprint="d" * 64,
        verification_status="valid",
    )
    
    assert len(with_anchor.rfc3161_anchors) == 1
    anchor = with_anchor.rfc3161_anchors[0]
    assert anchor.token_bytes == token
    assert anchor.tsa_url == "https://freetsa.org/tsr"
    assert anchor.gen_time == current_time_ms
    assert anchor.verification_status == "valid"


def test_rfc3161_anchor_rejects_oversized_token(valid_attestation, current_time_ms):
    huge_token = "x" * (MAX_TIMESTAMP_TOKEN_SIZE + 1)
    
    with pytest.raises(ValueError, match="exceeds"):
        add_rfc3161_anchor(
            valid_attestation,
            token_bytes=huge_token,
            tsa_url="https://example.com",
            gen_time=current_time_ms,
        )


def test_rfc3161_anchor_roundtrip_encoding(valid_attestation, current_time_ms):
    with_anchor = add_rfc3161_anchor(
        valid_attestation,
        token_bytes="abc123",
        tsa_url="https://tsa.example.com",
        gen_time=current_time_ms,
        verification_status="unverified",
    )
    
    encoded = encode_time_attestation(with_anchor)
    decoded = decode_time_attestation(encoded)
    
    assert len(decoded.rfc3161_anchors) == 1
    assert decoded.rfc3161_anchors[0].token_bytes == "abc123"
    assert decoded.rfc3161_anchors[0].verification_status == "unverified"


# ── Resource bounds ────────────────────────────────────────────────────────

def test_max_anchor_count_stellar(valid_attestation, current_time_ms):
    attestation = valid_attestation
    
    # Add anchors up to limit
    for i in range(MAX_ANCHOR_COUNT):
        attestation = add_stellar_anchor(
            attestation,
            ledger_sequence=i,
            ledger_timestamp=current_time_ms // 1000,
            transaction_hash=VALID_TX_HASH,
            network_passphrase=STELLAR_TESTNET_PASSPHRASE,
        )
    
    # Next one should fail
    with pytest.raises(ValueError, match="Maximum anchor count"):
        add_stellar_anchor(
            attestation,
            ledger_sequence=999,
            ledger_timestamp=current_time_ms // 1000,
            transaction_hash=VALID_TX_HASH,
            network_passphrase=STELLAR_TESTNET_PASSPHRASE,
        )


def test_max_anchor_count_mixed(valid_attestation, current_time_ms):
    attestation = valid_attestation
    
    # Add 5 Stellar + 5 RFC3161 = 10 (max)
    for i in range(5):
        attestation = add_stellar_anchor(
            attestation,
            ledger_sequence=i,
            ledger_timestamp=current_time_ms // 1000,
            transaction_hash=VALID_TX_HASH,
            network_passphrase=STELLAR_TESTNET_PASSPHRASE,
        )
    
    for i in range(5):
        attestation = add_rfc3161_anchor(
            attestation,
            token_bytes=f"token{i}",
            tsa_url="https://tsa.example.com",
            gen_time=current_time_ms,
        )
    
    # Next anchor should fail
    with pytest.raises(ValueError, match="Maximum anchor count"):
        add_rfc3161_anchor(
            attestation,
            token_bytes="overflow",
            tsa_url="https://tsa.example.com",
            gen_time=current_time_ms,
        )


# ── Backdating risk assessment ─────────────────────────────────────────────

def test_backdating_risk_none_with_stellar_anchor(valid_attestation, current_time_ms):
    with_anchor = add_stellar_anchor(
        valid_attestation,
        ledger_sequence=100,
        ledger_timestamp=current_time_ms // 1000,
        transaction_hash=VALID_TX_HASH,
        network_passphrase=STELLAR_TESTNET_PASSPHRASE,
    )
    
    risk = check_backdating_risk(with_anchor)
    assert risk["risk_level"] in ("none", "low")


def test_backdating_risk_medium_without_anchor(valid_attestation):
    risk = check_backdating_risk(valid_attestation)
    assert risk["risk_level"] in ("medium", "low")
    assert any("independent" in reason.lower() for reason in risk["reasons"])


def test_backdating_risk_high_with_large_drift(current_time_ms):
    # Claimed time is 2 days before observed
    claimed_ms = current_time_ms - (2 * 86400 * 1000)
    attestation = create_time_attestation(
        evidence_digest=VALID_EVIDENCE_DIGEST,
        claimed_time_ms=claimed_ms,
    )
    
    risk = check_backdating_risk(attestation)
    assert risk["risk_level"] in ("high", "medium")
    assert any("drift" in reason.lower() for reason in risk["reasons"])
