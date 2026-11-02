"""QKD Session Manager for Classical-Channel KSID Synchronization (MK1AI_QKD_ARCHITECTURE.md Section 5.1)."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import struct

from mk1_qkd.key_registry import QKDKeyPurpose, QKDKeyRegistry, validate_qkd_zone_policy
from mk1_qkd.key_validation import validate_canonical_key_id
from mk1_qkd.kmi_etsi import ETSIKMIClient


@dataclass(frozen=True)
class QKDSessionSyncMetadata:
    """Classical control-plane metadata containing key_id (NEVER secret key bytes)."""

    key_id: str
    zone_id: str
    purpose: str
    session_epoch: int
    source_kme_id: str
    target_kme_id: str
    transcript_binding_sha384: bytes


class QKDSessionManager:
    """Coordinates initiator/responder QKD key acquisition and registration by key_id."""

    def __init__(
        self,
        kmi_client: ETSIKMIClient,
        registry: QKDKeyRegistry,
    ) -> None:
        self._kmi = kmi_client
        self._registry = registry

    @staticmethod
    def build_context_transcript(
        *,
        key_id: str,
        zone_id: str,
        purpose: QKDKeyPurpose,
        session_epoch: int,
        initiator_nonce: bytes,
        responder_nonce: bytes,
    ) -> bytes:
        canonical_id = validate_canonical_key_id(key_id)
        payload = (
            b"MK1AI-QKD-SESSION-TRANSCRIPT-V1|"
            + canonical_id.encode("ascii")
            + b"|"
            + zone_id.encode("ascii")
            + b"|"
            + purpose.value.encode("ascii")
            + b"|"
            + struct.pack(">Q", int(session_epoch))
            + b"|"
            + bytes(initiator_nonce)
            + b"|"
            + bytes(responder_nonce)
        )
        return hashlib.sha384(payload).digest()

    def initiate_session_key(
        self,
        *,
        zone_id: str,
        purpose: QKDKeyPurpose,
        session_epoch: int,
        initiator_nonce: bytes,
        responder_nonce: bytes,
        now_ns: int | None = None,
    ) -> QKDSessionSyncMetadata:
        validate_qkd_zone_policy(zone_id)
        containers = self._kmi.get_key(number=1, size_bits=256, now_ns=now_ns)
        container = containers[0]
        self._registry.register_key(
            key_id=container.key_id,
            raw_key=container.raw_key,
            source_kme_id=container.source_kme_id,
            target_kme_id=container.target_kme_id,
            zone_id=zone_id,
            purpose=purpose,
            issued_at_ns=container.issued_at_ns,
            expires_at_ns=container.expires_at_ns,
            session_epoch=session_epoch,
            is_simulated=container.is_simulated,
            now_ns=now_ns,
        )
        transcript_hash = self.build_context_transcript(
            key_id=container.key_id,
            zone_id=zone_id,
            purpose=purpose,
            session_epoch=session_epoch,
            initiator_nonce=initiator_nonce,
            responder_nonce=responder_nonce,
        )
        return QKDSessionSyncMetadata(
            key_id=container.key_id,
            zone_id=zone_id,
            purpose=purpose.value,
            session_epoch=session_epoch,
            source_kme_id=container.source_kme_id,
            target_kme_id=container.target_kme_id,
            transcript_binding_sha384=transcript_hash,
        )

    def accept_session_key(
        self,
        sync_metadata: QKDSessionSyncMetadata,
        *,
        responder_registry: QKDKeyRegistry | None = None,
        now_ns: int | None = None,
    ) -> str:
        validate_qkd_zone_policy(sync_metadata.zone_id)
        purpose = QKDKeyPurpose(sync_metadata.purpose)
        containers = self._kmi.get_key_with_key_ids([sync_metadata.key_id], now_ns=now_ns)
        container = containers[0]
        target_reg = responder_registry or self._registry
        target_reg.register_key(
            key_id=container.key_id,
            raw_key=container.raw_key,
            source_kme_id=container.source_kme_id,
            target_kme_id=container.target_kme_id,
            zone_id=sync_metadata.zone_id,
            purpose=purpose,
            issued_at_ns=container.issued_at_ns,
            expires_at_ns=container.expires_at_ns,
            session_epoch=sync_metadata.session_epoch,
            is_simulated=container.is_simulated,
            now_ns=now_ns,
        )
        return container.key_id
