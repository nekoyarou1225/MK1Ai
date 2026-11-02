"""QKD Key Material Validation (MK1AI_QKD_KEY_MANAGEMENT.md Section 3.4).

Validates:
- Exact 256-bit (32-byte) key length
- Rejection of all-zero, all-one, single-byte repetition, and short period patterns
- Minimum Shannon entropy (>= 3.8 bits/byte) and distinct byte diversity (>= 16)
- Key ID UUIDv4 canonical formatting
- Key TTL freshness (`issued_at_ns < expires_at_ns` and `now_ns < expires_at_ns`)
- Peer KME mTLS SPKI SHA-256 pin verification
"""

from __future__ import annotations

from collections import Counter
import hmac
import math
import time
import uuid

QKD_KEY_SIZE_BYTES = 32
MIN_SHANNON_ENTROPY_BITS = 3.8
MIN_DISTINCT_BYTES = 16


class QKDValidationError(ValueError):
    """Raised when QKD key material or metadata fails security validation."""


def compute_shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def validate_canonical_key_id(key_id: str) -> str:
    if not isinstance(key_id, str) or not key_id.strip():
        raise QKDValidationError("key_id must be a non-empty UUID string.")
    try:
        parsed = uuid.UUID(key_id.strip())
    except ValueError as exc:
        raise QKDValidationError(f"Invalid QKD key_id UUID format: {key_id}") from exc
    return str(parsed)


def validate_qkd_key_material(
    raw_key: bytes | bytearray,
    *,
    key_id: str,
    issued_at_ns: int,
    expires_at_ns: int,
    now_ns: int | None = None,
    expected_kme_spki_sha256: str | None = None,
    presented_kme_spki_sha256: str | None = None,
) -> None:
    """Perform strict health, freshness, and authenticity checks on QKD key material."""
    validate_canonical_key_id(key_id)

    if not isinstance(raw_key, (bytes, bytearray)):
        raise QKDValidationError("QKD raw_key must be bytes or bytearray.")
    if len(raw_key) != QKD_KEY_SIZE_BYTES:
        raise QKDValidationError(
            f"QKD key material must be exactly {QKD_KEY_SIZE_BYTES} bytes (256 bits), got {len(raw_key)}."
        )

    key_bytes = bytes(raw_key)
    if key_bytes == b"\x00" * QKD_KEY_SIZE_BYTES:
        raise QKDValidationError("All-zero QKD key material rejected (hardware fault).")
    if key_bytes == b"\xff" * QKD_KEY_SIZE_BYTES:
        raise QKDValidationError("All-one QKD key material rejected (hardware fault).")

    # Reject periodic 2-byte or 4-byte repeating sequences
    if key_bytes == key_bytes[:2] * (QKD_KEY_SIZE_BYTES // 2):
        raise QKDValidationError("Periodic 2-byte repeating QKD key material rejected.")
    if key_bytes == key_bytes[:4] * (QKD_KEY_SIZE_BYTES // 4):
        raise QKDValidationError("Periodic 4-byte repeating QKD key material rejected.")

    distinct_count = len(set(key_bytes))
    if distinct_count < MIN_DISTINCT_BYTES:
        raise QKDValidationError(
            f"QKD key material failed byte diversity check: {distinct_count} < {MIN_DISTINCT_BYTES}."
        )

    entropy = compute_shannon_entropy(key_bytes)
    if entropy < MIN_SHANNON_ENTROPY_BITS:
        raise QKDValidationError(
            f"QKD key material failed Shannon entropy check: {entropy:.2f} < {MIN_SHANNON_ENTROPY_BITS}."
        )

    current_ns = time.time_ns() if now_ns is None else int(now_ns)
    if issued_at_ns >= expires_at_ns:
        raise QKDValidationError("QKD key issued_at_ns must be strictly less than expires_at_ns.")
    if current_ns >= expires_at_ns:
        raise QKDValidationError("QKD key material has already expired.")

    if expected_kme_spki_sha256 is not None:
        if not presented_kme_spki_sha256 or not hmac.compare_digest(
            expected_kme_spki_sha256.lower().strip(),
            presented_kme_spki_sha256.lower().strip(),
        ):
            raise QKDValidationError("KME peer mTLS SPKI SHA-256 pin mismatch.")
