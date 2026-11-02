"""QKD Audit Monitor with SHA-256 hash chaining and zero-key-leakage enforcement."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import threading
import time
from typing import Any

FORBIDDEN_METADATA_KEYS = frozenset(
    {"raw_key", "key_bytes", "secret_key", "shared_secret", "ikm", "prk"}
)


@dataclass(frozen=True)
class QKDAuditEntry:
    seq: int
    timestamp_ns: int
    event_type: str
    zone_id: str
    qkd_state: str
    key_id: str | None
    details: dict[str, Any]
    prev_hash: str
    entry_hash: str


class QKDAuditMonitor:
    """Hash-chained QKD event logger that forbids logging raw secret key material."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._entries: list[QKDAuditEntry] = []
        self._last_hash: str = "0" * 64

    def record_event(
        self,
        event_type: str,
        *,
        zone_id: str = "HONMARU",
        qkd_state: str = "QKD_UNAVAILABLE",
        key_id: str | None = None,
        details: dict[str, Any] | None = None,
        timestamp_ns: int | None = None,
    ) -> QKDAuditEntry:
        clean_details: dict[str, Any] = {}
        if details:
            for k, v in details.items():
                key_lower = str(k).lower()
                if key_lower in FORBIDDEN_METADATA_KEYS:
                    raise ValueError(
                        f"Security violation: forbidden secret field '{k}' in QKD audit log."
                    )
                if isinstance(v, (bytes, bytearray, memoryview)):
                    raise ValueError(
                        f"Security violation: raw bytes value for '{k}' prohibited in QKD audit log."
                    )
                clean_details[str(k)] = v

        with self._lock:
            seq = len(self._entries) + 1
            ts = time.time_ns() if timestamp_ns is None else int(timestamp_ns)
            prev_hash = self._last_hash
            canonical = json.dumps(
                {
                    "seq": seq,
                    "timestamp_ns": ts,
                    "event_type": event_type,
                    "zone_id": zone_id,
                    "qkd_state": qkd_state,
                    "key_id": key_id,
                    "details": clean_details,
                    "prev_hash": prev_hash,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            entry_hash = hashlib.sha256(canonical).hexdigest()
            entry = QKDAuditEntry(
                seq=seq,
                timestamp_ns=ts,
                event_type=event_type,
                zone_id=zone_id,
                qkd_state=qkd_state,
                key_id=key_id,
                details=clean_details,
                prev_hash=prev_hash,
                entry_hash=entry_hash,
            )
            self._entries.append(entry)
            self._last_hash = entry_hash
            return entry

    def verify_chain(self) -> bool:
        with self._lock:
            expected_prev = "0" * 64
            for entry in self._entries:
                if entry.prev_hash != expected_prev:
                    return False
                canonical = json.dumps(
                    {
                        "seq": entry.seq,
                        "timestamp_ns": entry.timestamp_ns,
                        "event_type": entry.event_type,
                        "zone_id": entry.zone_id,
                        "qkd_state": entry.qkd_state,
                        "key_id": entry.key_id,
                        "details": entry.details,
                        "prev_hash": entry.prev_hash,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
                if hashlib.sha256(canonical).hexdigest() != entry.entry_hash:
                    return False
                expected_prev = entry.entry_hash
            return True

    def entries(self) -> list[QKDAuditEntry]:
        with self._lock:
            return list(self._entries)
