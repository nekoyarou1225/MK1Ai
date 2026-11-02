"""QKD 9-Zone Key Registry, One-Time Use Enforcement, and Memory Zeroization.

Implements `MK1AI_QKD_KEY_MANAGEMENT.md`:
- 9-Environment Isolation (`HONMARU`, `INNER_1..4`, `OUTER_1..4`):
  - `OUTER_1..4` are strictly prohibited from holding QKD keys.
  - Cross-zone QKD key import into `HONMARU` is strictly prohibited.
- Strict Purpose Limitation (`QKDKeyPurpose`).
- Strict One-Time Use (`AVAILABLE -> RESERVED -> CONSUMED -> WIPED`).
- Immediate zeroization via `mk1_memory_guard.wipe_buffer()`.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import threading
import time

import mk1_memory_guard
from mk1_qkd.audit_monitor import QKDAuditMonitor
from mk1_qkd.key_validation import (
    validate_canonical_key_id,
    validate_qkd_key_material,
)

QKD_ALLOWED_ZONES = frozenset({"HONMARU", "INNER_1", "INNER_2", "INNER_3", "INNER_4"})
QKD_PROHIBITED_ZONES = frozenset({"OUTER_1", "OUTER_2", "OUTER_3", "OUTER_4"})
ALL_NINE_ZONES = QKD_ALLOWED_ZONES | QKD_PROHIBITED_ZONES


class QKDKeyPurpose(Enum):
    TRANSPORT_HYBRID_COMBINER = "TRANSPORT_HYBRID_COMBINER"
    SESSION_RATCHET_ROOT_SEED = "SESSION_RATCHET_ROOT_SEED"
    ONE_TAP_KEK_WRAP = "ONE_TAP_KEK_WRAP"
    AUDIT_SEAL_MAC = "AUDIT_SEAL_MAC"


class QKDKeyLifecycleState(Enum):
    AVAILABLE = "AVAILABLE"
    RESERVED = "RESERVED"
    CONSUMED = "CONSUMED"
    WIPED = "WIPED"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"


@dataclass
class QKDKeyRecord:
    key_id: str
    raw_key: bytearray
    source_kme_id: str
    target_kme_id: str
    zone_id: str
    purpose: QKDKeyPurpose
    issued_at_ns: int
    expires_at_ns: int
    session_epoch: int
    state: QKDKeyLifecycleState = QKDKeyLifecycleState.AVAILABLE
    is_simulated: bool = False
    consumed_at_ns: int | None = None


def validate_qkd_zone_policy(zone_id: str) -> str:
    if not isinstance(zone_id, str) or zone_id not in ALL_NINE_ZONES:
        raise ValueError(f"Unknown MK1Ai security zone: {zone_id!r}")
    if zone_id in QKD_PROHIBITED_ZONES:
        raise PermissionError(
            f"Security Zone Violation: {zone_id} is an untrusted OUTER honeypot zone and is strictly prohibited from accessing QKD key material."
        )
    return zone_id


class QKDKeyRegistry:
    """In-memory QKD key store enforcing 9-zone isolation and One-Time Use."""

    def __init__(self, audit_monitor: QKDAuditMonitor | None = None) -> None:
        self._lock = threading.RLock()
        self._records: dict[str, QKDKeyRecord] = {}
        self._consumed_history: set[str] = set()
        self._audit = audit_monitor or QKDAuditMonitor()

    @property
    def audit_monitor(self) -> QKDAuditMonitor:
        return self._audit

    def register_key(
        self,
        *,
        key_id: str,
        raw_key: bytes | bytearray,
        source_kme_id: str,
        target_kme_id: str,
        zone_id: str,
        purpose: QKDKeyPurpose,
        issued_at_ns: int,
        expires_at_ns: int,
        session_epoch: int = 1,
        is_simulated: bool = False,
        now_ns: int | None = None,
    ) -> QKDKeyRecord:
        validate_qkd_zone_policy(zone_id)
        if not isinstance(purpose, QKDKeyPurpose):
            raise TypeError("purpose must be a QKDKeyPurpose enum.")

        canonical_id = validate_canonical_key_id(key_id)
        validate_qkd_key_material(
            raw_key,
            key_id=canonical_id,
            issued_at_ns=issued_at_ns,
            expires_at_ns=expires_at_ns,
            now_ns=now_ns,
        )

        with self._lock:
            if canonical_id in self._records or canonical_id in self._consumed_history:
                raise RuntimeError(
                    f"QKD key_id replay / duplicate registration rejected: {canonical_id}"
                )

            key_buf = bytearray(raw_key)
            record = QKDKeyRecord(
                key_id=canonical_id,
                raw_key=key_buf,
                source_kme_id=source_kme_id,
                target_kme_id=target_kme_id,
                zone_id=zone_id,
                purpose=purpose,
                issued_at_ns=issued_at_ns,
                expires_at_ns=expires_at_ns,
                session_epoch=session_epoch,
                state=QKDKeyLifecycleState.AVAILABLE,
                is_simulated=bool(is_simulated),
            )
            self._records[canonical_id] = record
            self._audit.record_event(
                "KEY_REGISTERED",
                zone_id=zone_id,
                qkd_state="QKD_SIMULATED" if is_simulated else "QKD_READY",
                key_id=canonical_id,
                details={
                    "purpose": purpose.value,
                    "source_kme_id": source_kme_id,
                    "target_kme_id": target_kme_id,
                    "session_epoch": session_epoch,
                },
            )
            return record

    def reserve_key(
        self,
        key_id: str,
        *,
        requester_zone_id: str,
        expected_purpose: QKDKeyPurpose,
        now_ns: int | None = None,
    ) -> QKDKeyRecord:
        validate_qkd_zone_policy(requester_zone_id)
        canonical_id = validate_canonical_key_id(key_id)
        current_ns = time.time_ns() if now_ns is None else int(now_ns)

        with self._lock:
            record = self._records.get(canonical_id)
            if record is None:
                raise KeyError(f"Unknown QKD key_id: {canonical_id}")

            if record.zone_id != requester_zone_id:
                if requester_zone_id == "HONMARU":
                    raise PermissionError(
                        f"Cross-zone QKD key import into HONMARU from {record.zone_id} is strictly prohibited."
                    )
                raise PermissionError(
                    f"Cross-zone QKD key access denied: key belongs to {record.zone_id}, requested by {requester_zone_id}."
                )

            if record.purpose != expected_purpose:
                raise PermissionError(
                    f"QKD key purpose mismatch: key bound to {record.purpose.value}, requested for {expected_purpose.value}."
                )

            if current_ns >= record.expires_at_ns:
                self._wipe_record_locked(record, QKDKeyLifecycleState.EXPIRED)
                raise RuntimeError(f"QKD key {canonical_id} has expired and was zeroized.")

            if record.state != QKDKeyLifecycleState.AVAILABLE:
                raise RuntimeError(
                    f"QKD key One-Time Use violation: key {canonical_id} is in state {record.state.value}, not AVAILABLE."
                )

            record.state = QKDKeyLifecycleState.RESERVED
            self._audit.record_event(
                "KEY_RESERVED",
                zone_id=requester_zone_id,
                qkd_state="QKD_SIMULATED" if record.is_simulated else "QKD_READY",
                key_id=canonical_id,
                details={"purpose": expected_purpose.value},
            )
            return record

    def consume_and_wipe(
        self,
        key_id: str,
        *,
        requester_zone_id: str,
        expected_purpose: QKDKeyPurpose,
        now_ns: int | None = None,
    ) -> bytearray:
        """Return a transient copy of the 32-byte key for immediate KDF input and wipe the registry buffer."""
        validate_qkd_zone_policy(requester_zone_id)
        canonical_id = validate_canonical_key_id(key_id)
        current_ns = time.time_ns() if now_ns is None else int(now_ns)

        with self._lock:
            record = self._records.get(canonical_id)
            if record is None:
                raise KeyError(f"Unknown QKD key_id: {canonical_id}")

            if record.zone_id != requester_zone_id:
                raise PermissionError(
                    f"Cross-zone QKD key consumption denied ({record.zone_id} -> {requester_zone_id})."
                )
            if record.purpose != expected_purpose:
                raise PermissionError(
                    f"QKD key purpose mismatch ({record.purpose.value} != {expected_purpose.value})."
                )
            if current_ns >= record.expires_at_ns:
                self._wipe_record_locked(record, QKDKeyLifecycleState.EXPIRED)
                raise RuntimeError(f"QKD key {canonical_id} expired before consumption.")

            if record.state not in (QKDKeyLifecycleState.AVAILABLE, QKDKeyLifecycleState.RESERVED):
                raise RuntimeError(
                    f"QKD key One-Time Use violation: key {canonical_id} already in state {record.state.value}."
                )

            transient_copy = bytearray(record.raw_key)
            record.state = QKDKeyLifecycleState.CONSUMED
            record.consumed_at_ns = current_ns
            self._wipe_record_locked(record, QKDKeyLifecycleState.WIPED)
            self._consumed_history.add(canonical_id)

            self._audit.record_event(
                "KEY_CONSUMED_AND_WIPED",
                zone_id=requester_zone_id,
                qkd_state="QKD_SIMULATED" if record.is_simulated else "QKD_READY",
                key_id=canonical_id,
                details={"purpose": expected_purpose.value},
            )
            return transient_copy

    def revoke_key(self, key_id: str, *, reason: str = "manual_revocation") -> None:
        canonical_id = validate_canonical_key_id(key_id)
        with self._lock:
            record = self._records.get(canonical_id)
            if record is None:
                raise KeyError(f"Unknown QKD key_id: {canonical_id}")
            self._wipe_record_locked(record, QKDKeyLifecycleState.REVOKED)
            self._consumed_history.add(canonical_id)
            self._audit.record_event(
                "KEY_REVOKED",
                zone_id=record.zone_id,
                qkd_state="QKD_REVOKED",
                key_id=canonical_id,
                details={"reason": reason},
            )

    def purge_zone_keys(self, zone_id: str, *, reason: str = "zone_compromise_purge") -> int:
        with self._lock:
            count = 0
            for record in self._records.values():
                if record.zone_id == zone_id and record.state not in (
                    QKDKeyLifecycleState.WIPED,
                    QKDKeyLifecycleState.REVOKED,
                ):
                    self._wipe_record_locked(record, QKDKeyLifecycleState.REVOKED)
                    self._consumed_history.add(record.key_id)
                    count += 1
            self._audit.record_event(
                "ZONE_KEYS_PURGED",
                zone_id=zone_id,
                qkd_state="QKD_REVOKED",
                details={"purged_count": count, "reason": reason},
            )
            return count

    def _wipe_record_locked(
        self,
        record: QKDKeyRecord,
        target_state: QKDKeyLifecycleState,
    ) -> None:
        if len(record.raw_key) > 0:
            mk1_memory_guard.wipe_buffer(record.raw_key)
        record.state = target_state
