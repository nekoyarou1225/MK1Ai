"""ETSI GS QKD 014 v1.1.1 & ETSI GS QKD 004 Key Management Interface (KMI) Client."""

from __future__ import annotations

from dataclasses import dataclass
import os
import time
import uuid

from mk1_qkd.device_adapter import QKDDeviceAdapter, QKDState
from mk1_qkd.key_validation import QKD_KEY_SIZE_BYTES, validate_canonical_key_id


@dataclass(frozen=True)
class ETSIQKDStatus:
    source_kme_id: str
    target_kme_id: str
    master_sae_id: str
    slave_sae_id: str
    key_size_bits: int
    stored_key_count: int
    max_key_count: int
    max_key_per_request: int
    qkd_state: str


@dataclass
class ETSIQKDKeyContainer:
    key_id: str
    raw_key: bytearray
    source_kme_id: str
    target_kme_id: str
    sae_id: str
    issued_at_ns: int
    expires_at_ns: int
    is_simulated: bool


class ETSIKMIClient:
    """ETSI 014 / 004 KME client bound to a QKDDeviceAdapter."""

    def __init__(
        self,
        adapter: QKDDeviceAdapter,
        *,
        source_kme_id: str = "KME-HONMARU-01",
        target_kme_id: str = "KME-PEER-01",
        master_sae_id: str = "SAE-HONMARU-CORE",
        slave_sae_id: str = "SAE-PEER-CORE",
        default_ttl_seconds: int = 300,
    ) -> None:
        self._adapter = adapter
        self._source_kme_id = source_kme_id
        self._target_kme_id = target_kme_id
        self._master_sae_id = master_sae_id
        self._slave_sae_id = slave_sae_id
        self._default_ttl_ns = max(1, int(default_ttl_seconds)) * 1_000_000_000
        self._peer_key_cache: dict[str, bytearray] = {}

    def get_status(self) -> ETSIQKDStatus:
        state = self._adapter.state
        stored = 64 if state in (QKDState.QKD_READY, QKDState.QKD_SIMULATED) else 0
        return ETSIQKDStatus(
            source_kme_id=self._source_kme_id,
            target_kme_id=self._target_kme_id,
            master_sae_id=self._master_sae_id,
            slave_sae_id=self._slave_sae_id,
            key_size_bits=QKD_KEY_SIZE_BYTES * 8,
            stored_key_count=stored,
            max_key_count=1024,
            max_key_per_request=16,
            qkd_state=state.value,
        )

    def get_key(
        self,
        *,
        number: int = 1,
        size_bits: int = 256,
        now_ns: int | None = None,
    ) -> list[ETSIQKDKeyContainer]:
        """ETSI GS QKD 014 `Get_key` for initiator SAE."""
        if size_bits != 256:
            raise ValueError("MK1Ai requires 256-bit QKD keys (size_bits=256).")
        if number < 1 or number > 16:
            raise ValueError("number must be between 1 and 16.")

        state = self._adapter.state
        if state not in (QKDState.QKD_READY, QKDState.QKD_SIMULATED):
            raise RuntimeError(
                f"Cannot acquire QKD key via ETSI 014 Get_key in state {state.value}."
            )

        issued_ns = time.time_ns() if now_ns is None else int(now_ns)
        expires_ns = issued_ns + self._default_ttl_ns
        containers: list[ETSIQKDKeyContainer] = []

        for _ in range(number):
            key_id = str(uuid.uuid4())
            key_bytes = bytearray(os.urandom(QKD_KEY_SIZE_BYTES))
            # Store synchronized copy in simulated/paired KME buffer for responder lookup by key_id
            self._peer_key_cache[key_id] = bytearray(key_bytes)
            containers.append(
                ETSIQKDKeyContainer(
                    key_id=key_id,
                    raw_key=key_bytes,
                    source_kme_id=self._source_kme_id,
                    target_kme_id=self._target_kme_id,
                    sae_id=self._master_sae_id,
                    issued_at_ns=issued_ns,
                    expires_at_ns=expires_ns,
                    is_simulated=self._adapter.is_simulated,
                )
            )
        return containers

    def get_key_with_key_ids(
        self,
        key_ids: list[str],
        *,
        now_ns: int | None = None,
    ) -> list[ETSIQKDKeyContainer]:
        """ETSI GS QKD 014 `Get_key_with_key_IDs` for responder SAE."""
        if not key_ids:
            raise ValueError("key_ids list must not be empty.")
        state = self._adapter.state
        if state not in (QKDState.QKD_READY, QKDState.QKD_SIMULATED):
            raise RuntimeError(
                f"Cannot retrieve QKD key by ID in state {state.value}."
            )

        issued_ns = time.time_ns() if now_ns is None else int(now_ns)
        expires_ns = issued_ns + self._default_ttl_ns
        results: list[ETSIQKDKeyContainer] = []

        for kid in key_ids:
            canonical_kid = validate_canonical_key_id(kid)
            cached = self._peer_key_cache.pop(canonical_kid, None)
            if cached is None:
                raise KeyError(f"QKD key_id not found or already retrieved on responder KME: {canonical_kid}")
            results.append(
                ETSIQKDKeyContainer(
                    key_id=canonical_kid,
                    raw_key=cached,
                    source_kme_id=self._target_kme_id,
                    target_kme_id=self._source_kme_id,
                    sae_id=self._slave_sae_id,
                    issued_at_ns=issued_ns,
                    expires_at_ns=expires_ns,
                    is_simulated=self._adapter.is_simulated,
                )
            )
        return results
