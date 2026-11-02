"""QKD-PQC-Classic Hybrid Transport Bridge (NIST SP 800-56C Rev. 2 Two-Stage HKDF-SHA384).

Implements `MK1AI_QKD_ARCHITECTURE.md` Section 5.2 and `MK1AI_QKD_KEY_MANAGEMENT.md` Section 5:
- Combines:
  1. `K_QKD` (32 bytes from QKDKeyRegistry, consumed & wiped on use)
  2. `SS_MLKEM` (32 bytes from ML-KEM-1024 or ML-KEM-768)
  3. `SS_X25519` (32 bytes from X25519 ECDH)
- Stage 1 Extract (`HKDF-Extract-SHA384`):
  `PRK_hybrid = HMAC-SHA384(key=SHA384(context_transcript), msg=len(K_QKD)||K_QKD || len(SS_MLKEM)||SS_MLKEM || len(SS_X25519)||SS_X25519)`
- Stage 2 Expand (`HKDF-Expand-SHA384`):
  `K_final = HKDF-Expand-SHA384(PRK_hybrid, info="MK1AI-HYBRID-QKD-PQC-V1|" || zone_id || "|" || purpose || "|" || key_id_bytes || epoch_be64, L=32)`
- Immediately zeroizes `K_QKD`, `IKM`, and `PRK_hybrid` via `mk1_memory_guard.wipe_buffer()`.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import struct
import uuid

import mk1_memory_guard
from mk1_qkd.key_registry import (
    QKDKeyPurpose,
    QKDKeyRegistry,
    validate_qkd_zone_policy,
)
from mk1_qkd.key_validation import validate_canonical_key_id
from mk1_session_ratchet import SessionRatchet


def _hkdf_extract_sha384(salt: bytes, ikm: bytes | bytearray) -> bytearray:
    effective_salt = salt if salt else (b"\x00" * 48)
    return bytearray(hmac.new(effective_salt, ikm, hashlib.sha384).digest())


def _hkdf_expand_sha384(prk: bytes | bytearray, info: bytes, length: int = 32) -> bytes:
    if length <= 0 or length > 255 * 48:
        raise ValueError("Invalid HKDF-SHA384 output length.")
    blocks: list[bytes] = []
    prev = b""
    counter = 1
    total = 0
    while total < length:
        prev = hmac.new(bytes(prk), prev + info + bytes([counter]), hashlib.sha384).digest()
        blocks.append(prev)
        total += len(prev)
        counter += 1
    return b"".join(blocks)[:length]


@dataclass(frozen=True)
class HybridDerivationResult:
    derived_key: bytes
    key_id: str
    zone_id: str
    purpose: str
    session_epoch: int
    algorithm_suite: str


class QKDTransportBridge:
    """Combines QKD key material with ML-KEM and X25519 shared secrets."""

    def __init__(self, registry: QKDKeyRegistry) -> None:
        self._registry = registry

    def derive_hybrid_secret(
        self,
        *,
        key_id: str,
        zone_id: str,
        purpose: QKDKeyPurpose,
        ml_kem_shared_secret: bytes,
        x25519_shared_secret: bytes,
        context_transcript: bytes,
        session_epoch: int = 1,
        pqc_algorithm: str = "ML-KEM-1024",
        now_ns: int | None = None,
    ) -> HybridDerivationResult:
        validate_qkd_zone_policy(zone_id)
        canonical_id = validate_canonical_key_id(key_id)
        if pqc_algorithm not in ("ML-KEM-768", "ML-KEM-1024"):
            raise ValueError(f"Unsupported PQC KEM algorithm for QKD bridge: {pqc_algorithm}")
        if not isinstance(ml_kem_shared_secret, (bytes, bytearray)) or len(ml_kem_shared_secret) != 32:
            raise ValueError("ml_kem_shared_secret must be 32 bytes.")
        if not isinstance(x25519_shared_secret, (bytes, bytearray)) or len(x25519_shared_secret) != 32:
            raise ValueError("x25519_shared_secret must be 32 bytes.")
        if not isinstance(context_transcript, (bytes, bytearray)) or len(context_transcript) == 0:
            raise ValueError("context_transcript must be non-empty bytes.")

        qkd_key_buf = self._registry.consume_and_wipe(
            canonical_id,
            requester_zone_id=zone_id,
            expected_purpose=purpose,
            now_ns=now_ns,
        )

        ikm = bytearray()
        prk_hybrid = bytearray()
        try:
            ikm.extend(struct.pack(">I", len(qkd_key_buf)))
            ikm.extend(qkd_key_buf)
            ikm.extend(struct.pack(">I", len(ml_kem_shared_secret)))
            ikm.extend(ml_kem_shared_secret)
            ikm.extend(struct.pack(">I", len(x25519_shared_secret)))
            ikm.extend(x25519_shared_secret)

            salt = hashlib.sha384(bytes(context_transcript)).digest()
            prk_hybrid = _hkdf_extract_sha384(salt, ikm)

            key_uuid_bytes = uuid.UUID(canonical_id).bytes
            info = (
                b"MK1AI-HYBRID-QKD-PQC-V1|"
                + zone_id.encode("ascii")
                + b"|"
                + purpose.value.encode("ascii")
                + b"|"
                + pqc_algorithm.encode("ascii")
                + b"|"
                + key_uuid_bytes
                + struct.pack(">Q", int(session_epoch))
            )
            derived = _hkdf_expand_sha384(prk_hybrid, info, length=32)
            return HybridDerivationResult(
                derived_key=derived,
                key_id=canonical_id,
                zone_id=zone_id,
                purpose=purpose.value,
                session_epoch=session_epoch,
                algorithm_suite=f"QKD+{pqc_algorithm}+X25519+HKDF-SHA384",
            )
        finally:
            if len(qkd_key_buf) > 0:
                mk1_memory_guard.wipe_buffer(qkd_key_buf)
            if len(ikm) > 0:
                mk1_memory_guard.wipe_buffer(ikm)
            if len(prk_hybrid) > 0:
                mk1_memory_guard.wipe_buffer(prk_hybrid)

    def create_hybrid_session_ratchet(
        self,
        *,
        key_id: str,
        zone_id: str,
        ml_kem_shared_secret: bytes,
        x25519_shared_secret: bytes,
        context_transcript: bytes,
        role: str = "client",
        session_epoch: int = 1,
        pqc_algorithm: str = "ML-KEM-1024",
        now_ns: int | None = None,
    ) -> tuple[SessionRatchet, HybridDerivationResult]:
        """Derive a QKD+PQC+X25519 hybrid root key and initialize a SessionRatchet."""
        result = self.derive_hybrid_secret(
            key_id=key_id,
            zone_id=zone_id,
            purpose=QKDKeyPurpose.SESSION_RATCHET_ROOT_SEED,
            ml_kem_shared_secret=ml_kem_shared_secret,
            x25519_shared_secret=x25519_shared_secret,
            context_transcript=context_transcript,
            session_epoch=session_epoch,
            pqc_algorithm=pqc_algorithm,
            now_ns=now_ns,
        )
        ratchet_ctx = (
            f"qkd-{zone_id.lower()}-{result.key_id}-e{session_epoch}|".encode("ascii")
            + bytes(context_transcript)[:512]
        )
        ratchet = SessionRatchet(
            bytearray(result.derived_key),
            context=ratchet_ctx,
            role=role,
        )
        return ratchet, result
