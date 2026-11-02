"""QKD Device Adapter and 9-State Machine (MK1AI_QKD_ARCHITECTURE.md Section 6).

Enforces strict separation between:
- `QKD_UNAVAILABLE` (No QKD hardware attached)
- `QKD_SIMULATED` (Software test generator; can NEVER transition to `QKD_READY`)
- `QKD_READY` (Physical KME hardware link attested, mTLS verified, QBER < 11%)
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hmac
import threading


class QKDState(Enum):
    QKD_UNAVAILABLE = "QKD_UNAVAILABLE"
    QKD_SIMULATED = "QKD_SIMULATED"
    QKD_CONNECTING = "QKD_CONNECTING"
    QKD_READY = "QKD_READY"
    QKD_DEGRADED = "QKD_DEGRADED"
    QKD_KEY_EXHAUSTED = "QKD_KEY_EXHAUSTED"
    QKD_AUTH_FAILED = "QKD_AUTH_FAILED"
    QKD_REVOKED = "QKD_REVOKED"
    QKD_ERROR = "QKD_ERROR"


@dataclass(frozen=True)
class QKDLinkMetrics:
    qber: float
    sifted_key_rate_bps: float
    optical_loss_db: float
    available_keys: int
    qber_abort_threshold: float = 0.11

    @property
    def is_quantum_channel_healthy(self) -> bool:
        return (
            0.0 <= self.qber < self.qber_abort_threshold
            and self.sifted_key_rate_bps > 0.0
            and self.available_keys > 0
        )


class QKDDeviceAdapter:
    """Hardware abstraction layer for QKD Key Management Entities (KME)."""

    def __init__(
        self,
        *,
        vendor_name: str = "NONE",
        kme_endpoint: str | None = None,
        expected_kme_spki_sha256: str | None = None,
        is_simulated: bool = False,
        hardware_present: bool = False,
    ) -> None:
        self._lock = threading.RLock()
        self._vendor_name = vendor_name
        self._kme_endpoint = kme_endpoint
        self._expected_spki_sha256 = expected_kme_spki_sha256
        self._is_simulated = bool(is_simulated)
        self._hardware_present = bool(hardware_present)
        self._metrics: QKDLinkMetrics | None = None

        if self._is_simulated:
            self._state = QKDState.QKD_SIMULATED
        elif not self._hardware_present or not self._kme_endpoint:
            self._state = QKDState.QKD_UNAVAILABLE
        else:
            self._state = QKDState.QKD_CONNECTING

    @property
    def state(self) -> QKDState:
        with self._lock:
            return self._state

    @property
    def is_simulated(self) -> bool:
        with self._lock:
            return self._is_simulated

    @property
    def is_production_qkd_active(self) -> bool:
        """True ONLY when real hardware is in QKD_READY state (never True for simulated)."""
        with self._lock:
            return not self._is_simulated and self._hardware_present and self._state == QKDState.QKD_READY

    def connect_hardware_kme(
        self,
        *,
        presented_spki_sha256: str,
        metrics: QKDLinkMetrics,
    ) -> QKDState:
        """Authenticate KME classical channel and verify quantum link metrics."""
        with self._lock:
            if self._is_simulated:
                raise PermissionError(
                    "Simulated QKD source is permanently restricted to QKD_SIMULATED and cannot transition to QKD_READY."
                )
            if not self._hardware_present or not self._kme_endpoint:
                self._state = QKDState.QKD_UNAVAILABLE
                return self._state

            if not self._expected_spki_sha256 or not hmac.compare_digest(
                presented_spki_sha256.lower().strip(),
                self._expected_spki_sha256.lower().strip(),
            ):
                self._state = QKDState.QKD_AUTH_FAILED
                return self._state

            self._metrics = metrics
            if metrics.qber >= metrics.qber_abort_threshold:
                self._state = QKDState.QKD_DEGRADED
                return self._state
            if metrics.available_keys <= 0:
                self._state = QKDState.QKD_KEY_EXHAUSTED
                return self._state
            if not metrics.is_quantum_channel_healthy:
                self._state = QKDState.QKD_ERROR
                return self._state

            self._state = QKDState.QKD_READY
            return self._state

    def mark_revoked(self) -> QKDState:
        with self._lock:
            self._state = QKDState.QKD_REVOKED
            return self._state

    def mark_key_exhausted(self) -> QKDState:
        with self._lock:
            if not self._is_simulated:
                self._state = QKDState.QKD_KEY_EXHAUSTED
            return self._state

    def get_status_report(self) -> dict[str, object]:
        with self._lock:
            return {
                "vendor_name": self._vendor_name,
                "kme_endpoint": self._kme_endpoint,
                "state": self._state.value,
                "is_simulated": self._is_simulated,
                "hardware_present": self._hardware_present,
                "is_production_qkd_active": self.is_production_qkd_active,
                "qber": self._metrics.qber if self._metrics else None,
                "sifted_key_rate_bps": self._metrics.sifted_key_rate_bps if self._metrics else None,
            }
