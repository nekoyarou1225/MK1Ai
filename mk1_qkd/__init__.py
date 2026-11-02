"""MK1Ai Quantum Key Distribution (QKD) 8-Module / 9-State / 9-Zone Package.

Implements `MK1AI_QKD_ARCHITECTURE.md` and `MK1AI_QKD_KEY_MANAGEMENT.md`:
1. `device_adapter`   : Hardware/Simulated KME adapter & 9-State Machine (`QKDState`)
2. `kmi_etsi`         : ETSI GS QKD 014 v1.1.1 & 004 Key Management Interface
3. `key_validation`   : 256-bit length, constant-pattern, entropy, TTL & SPKI pin checks
4. `key_registry`     : 9-Zone isolation (`HONMARU`, `INNER_1..4` allowed; `OUTER_1..4` prohibited),
                        One-Time Use enforcement, and `mk1_memory_guard.wipe_buffer` zeroization
5. `session_manager`  : Classical channel KSID (`key_id`) peer synchronization
6. `policy_controller`: Transport mode enforcement & M-of-N quorum anti-downgrade guard
7. `transport_bridge` : NIST SP 800-56C Rev. 2 Two-Stage `HKDF-SHA384` hybrid combiner
8. `audit_monitor`    : SHA-256 hash-chained audit monitor with zero raw-key leakage
"""

from mk1_qkd.audit_monitor import QKDAuditEntry, QKDAuditMonitor
from mk1_qkd.device_adapter import QKDDeviceAdapter, QKDLinkMetrics, QKDState
from mk1_qkd.key_registry import (
    ALL_NINE_ZONES,
    QKD_ALLOWED_ZONES,
    QKD_PROHIBITED_ZONES,
    QKDKeyLifecycleState,
    QKDKeyPurpose,
    QKDKeyRecord,
    QKDKeyRegistry,
    validate_qkd_zone_policy,
)
from mk1_qkd.key_validation import (
    QKD_KEY_SIZE_BYTES,
    QKDValidationError,
    compute_shannon_entropy,
    validate_canonical_key_id,
    validate_qkd_key_material,
)
from mk1_qkd.kmi_etsi import ETSIKMIClient, ETSIQKDKeyContainer, ETSIQKDStatus
from mk1_qkd.policy_controller import QKDPolicyController, QKDTransportMode
from mk1_qkd.session_manager import QKDSessionManager, QKDSessionSyncMetadata
from mk1_qkd.transport_bridge import HybridDerivationResult, QKDTransportBridge

__all__ = [
    "ALL_NINE_ZONES",
    "ETSIKMIClient",
    "ETSIQKDKeyContainer",
    "ETSIQKDStatus",
    "HybridDerivationResult",
    "QKD_ALLOWED_ZONES",
    "QKD_KEY_SIZE_BYTES",
    "QKD_PROHIBITED_ZONES",
    "QKDAuditEntry",
    "QKDAuditMonitor",
    "QKDDeviceAdapter",
    "QKDKeyLifecycleState",
    "QKDKeyPurpose",
    "QKDKeyRecord",
    "QKDKeyRegistry",
    "QKDLinkMetrics",
    "QKDPolicyController",
    "QKDSessionManager",
    "QKDSessionSyncMetadata",
    "QKDState",
    "QKDTransportBridge",
    "QKDTransportMode",
    "QKDValidationError",
    "compute_shannon_entropy",
    "validate_canonical_key_id",
    "validate_qkd_key_material",
    "validate_qkd_zone_policy",
]
