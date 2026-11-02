"""QKD Policy Controller & Anti-Downgrade Quorum Enforcement (MK1AI_QKD_ARCHITECTURE.md Section 7)."""

from __future__ import annotations

from collections.abc import Mapping
from enum import Enum
import threading

import mk1_quorum
from mk1_qkd.audit_monitor import QKDAuditMonitor
from mk1_qkd.device_adapter import QKDDeviceAdapter, QKDState


class QKDTransportMode(Enum):
    QKD_MANDATORY = "QKD_MANDATORY"
    HYBRID_QKD_PQC = "HYBRID_QKD_PQC"
    PQC_ONLY = "PQC_ONLY"
    SIMULATED_HYBRID_TEST = "SIMULATED_HYBRID_TEST"


class QKDPolicyController:
    """Enforces QKD/PQC transport mode selection and blocks silent downgrade attacks."""

    def __init__(
        self,
        adapter: QKDDeviceAdapter,
        *,
        initial_mode: QKDTransportMode = QKDTransportMode.PQC_ONLY,
        audit_monitor: QKDAuditMonitor | None = None,
    ) -> None:
        self._lock = threading.RLock()
        self._adapter = adapter
        self._mode = initial_mode
        self._audit = audit_monitor or QKDAuditMonitor()

    @property
    def mode(self) -> QKDTransportMode:
        with self._lock:
            return self._mode

    def can_establish_session(self) -> tuple[bool, str]:
        """Evaluate whether a transport session may proceed under the current policy and QKD state."""
        with self._lock:
            state = self._adapter.state
            if self._mode == QKDTransportMode.QKD_MANDATORY:
                if self._adapter.is_production_qkd_active:
                    return True, "QKD_MANDATORY satisfied by hardware QKD_READY."
                return (
                    False,
                    f"Fail-Closed: QKD_MANDATORY requires hardware QKD_READY, current state is {state.value}.",
                )

            if self._mode == QKDTransportMode.HYBRID_QKD_PQC:
                if self._adapter.is_production_qkd_active:
                    return True, "HYBRID_QKD_PQC active with hardware QKD_READY."
                return (
                    False,
                    f"Fail-Closed: HYBRID_QKD_PQC blocks automatic fallback to PQC_ONLY in state {state.value}; explicit M-of-N quorum approval required.",
                )

            if self._mode == QKDTransportMode.SIMULATED_HYBRID_TEST:
                if state == QKDState.QKD_SIMULATED:
                    return True, "SIMULATED_HYBRID_TEST active with QKD_SIMULATED source."
                return False, f"SIMULATED_HYBRID_TEST requires QKD_SIMULATED state, got {state.value}."

            if self._mode == QKDTransportMode.PQC_ONLY:
                return True, "PQC_ONLY mode active (no QKD claimed)."

            return False, "Unsupported QKD transport mode."

    def change_mode(
        self,
        target_mode: QKDTransportMode,
        *,
        quorum_bundle: Mapping[str, object] | None = None,
        challenge_document: Mapping[str, object] | None = None,
        trusted_keys: Mapping[str, bytes] | None = None,
        now: int | None = None,
    ) -> QKDTransportMode:
        """Transition policy mode; downgrading from QKD modes to PQC_ONLY requires M-of-N Ed25519 quorum."""
        if not isinstance(target_mode, QKDTransportMode):
            raise TypeError("target_mode must be a QKDTransportMode enum.")

        with self._lock:
            current = self._mode
            is_downgrade = (
                current in (QKDTransportMode.QKD_MANDATORY, QKDTransportMode.HYBRID_QKD_PQC)
                and target_mode in (QKDTransportMode.PQC_ONLY, QKDTransportMode.SIMULATED_HYBRID_TEST)
            )

            if is_downgrade:
                if quorum_bundle is None or challenge_document is None or trusted_keys is None:
                    self._audit.record_event(
                        "DOWNGRADE_REJECTED",
                        qkd_state=self._adapter.state.value,
                        details={
                            "from_mode": current.value,
                            "to_mode": target_mode.value,
                            "reason": "missing_quorum_approval",
                        },
                    )
                    raise PermissionError(
                        f"Silent downgrade from {current.value} to {target_mode.value} is prohibited without M-of-N Ed25519 quorum approval."
                    )

                if challenge_document.get("operation") != "qkd_fallback_to_pqc_only":
                    raise PermissionError(
                        "Quorum challenge operation must be 'qkd_fallback_to_pqc_only'."
                    )

                mk1_quorum.verify_quorum_bundle(
                    quorum_bundle,
                    challenge_document=challenge_document,
                    trusted_keys=trusted_keys,
                    now=now,
                )

            self._mode = target_mode
            self._audit.record_event(
                "POLICY_TRANSITION",
                qkd_state=self._adapter.state.value,
                details={
                    "from_mode": current.value,
                    "to_mode": target_mode.value,
                    "quorum_verified": is_downgrade,
                },
            )
            return self._mode
