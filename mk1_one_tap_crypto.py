"""MK1Ai One-Tap Envelope Encryption, 9-Zone Key Isolation, and QKD/PQC Posture Engine.

Implements:
- Strict 9-Zone Cryptographic Key Isolation:
  - ZONE_CORE_MAIN (CORE defense & audit vault)
  - ZONE_HONEYPOT_1 .. ZONE_HONEYPOT_8 (per-honeypot isolated key domains)
  Compromising or exporting any honeypot zone key mathematically cannot derive
  ZONE_CORE_MAIN or any other honeypot zone key, and cross-zone decryption is
  rejected fail-closed.
- One-Tap Envelope Encryption & Decryption:
  - Authenticated envelope header binding zone_id, key_id, epoch, nonce, and caller AAD
  - Ephemeral per-envelope subkey derivation and automatic buffer wiping via mk1_memory_guard
- Strict Separation of Cryptographic Posture:
  - QKD (ETSI GS QKD 014 hardware KME link status — reported as QKD_UNAVAILABLE when no
    physical KME device is connected; NEVER conflated with PQC or SessionRatchet)
  - PQC (ML-KEM-768 status)
  - Classical Key Exchange / Signatures (X25519 / Ed25519)
  - Symmetric AEAD + Forward-Secure Ratchet
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import hmac
import json
import os
import struct
from typing import Any

import mk1_memory_guard


class OneTapCryptoError(RuntimeError):
    """Base error for one-tap encryption, authentication, or key isolation failures."""


class ZoneIsolationViolationError(OneTapCryptoError):
    """Raised when attempting to use a key or decrypt an envelope across security zones."""


class EnvelopeTamperError(OneTapCryptoError):
    """Raised when an encrypted envelope fails authentication tag or header integrity checks."""


class SecurityZone(str, Enum):
    ZONE_CORE_MAIN = "ZONE_CORE_MAIN"
    ZONE_HONEYPOT_1 = "ZONE_HONEYPOT_1"
    ZONE_HONEYPOT_2 = "ZONE_HONEYPOT_2"
    ZONE_HONEYPOT_3 = "ZONE_HONEYPOT_3"
    ZONE_HONEYPOT_4 = "ZONE_HONEYPOT_4"
    ZONE_HONEYPOT_5 = "ZONE_HONEYPOT_5"
    ZONE_HONEYPOT_6 = "ZONE_HONEYPOT_6"
    ZONE_HONEYPOT_7 = "ZONE_HONEYPOT_7"
    ZONE_HONEYPOT_8 = "ZONE_HONEYPOT_8"


ALL_9_SECURITY_ZONES: tuple[SecurityZone, ...] = tuple(SecurityZone)


def _hkdf_sha256(ikm: bytes | bytearray, *, salt: bytes, info: bytes, length: int = 32) -> bytearray:
    """RFC 5869 HKDF-SHA256 returning a mutable bytearray for deterministic zeroization."""
    prk = bytearray(hmac.new(salt, bytes(ikm), hashlib.sha256).digest())
    okm = bytearray()
    t = b""
    counter = 1
    try:
        while len(okm) < length:
            t = hmac.new(bytes(prk), t + info + bytes([counter]), hashlib.sha256).digest()
            okm.extend(t)
            counter += 1
        return bytearray(okm[:length])
    finally:
        mk1_memory_guard.wipe_buffer(prk)


def _stream_xor_sha256_ctr(key32: bytes | bytearray, nonce16: bytes, data: bytes) -> bytes:
    """Deterministic counter-mode keystream for stdlib authenticated envelope encryption."""
    out = bytearray(len(data))
    key_bytes = bytes(key32)
    block_count = (len(data) + 31) // 32
    for blk in range(block_count):
        ks = hmac.new(
            key_bytes,
            b"MK1AI-AEAD-STREAM-v1:" + nonce16 + struct.pack("!Q", blk),
            hashlib.sha256,
        ).digest()
        start = blk * 32
        end = min(len(data), start + 32)
        for i in range(start, end):
            out[i] = data[i] ^ ks[i - start]
    return bytes(out)


class NineZoneKeyVault:
    """Maintains cryptographically isolated keys across ZONE_CORE_MAIN and ZONE_HONEYPOT_1..8."""

    def __init__(self, root_seed32: bytes | None = None) -> None:
        raw_seed = bytearray(root_seed32 if root_seed32 is not None else os.urandom(32))
        if len(raw_seed) != 32:
            mk1_memory_guard.wipe_buffer(raw_seed)
            raise ValueError("root_seed32 must be exactly 32 bytes")
        self._zone_epochs: dict[SecurityZone, int] = {z: 1 for z in ALL_9_SECURITY_ZONES}
        self._zone_master_keys: dict[SecurityZone, bytearray] = {}
        try:
            for zone in ALL_9_SECURITY_ZONES:
                salt = hashlib.sha256(b"MK1AI-9ZONE-SALT-v1:" + zone.value.encode("utf-8")).digest()
                info = f"MK1AI-9ZONE-MASTER-v1|{zone.value}|epoch=1".encode("utf-8")
                self._zone_master_keys[zone] = _hkdf_sha256(raw_seed, salt=salt, info=info, length=32)
        finally:
            mk1_memory_guard.wipe_buffer(raw_seed)

    def zone_epoch(self, zone: SecurityZone) -> int:
        return self._zone_epochs[zone]

    def rotate_zone_key(self, zone: SecurityZone, entropy: bytes | None = None) -> int:
        """Rotate a single zone's key without affecting or exposing any other zone."""
        old_key = self._zone_master_keys[zone]
        extra = entropy if entropy is not None else os.urandom(32)
        new_epoch = self._zone_epochs[zone] + 1
        salt = hashlib.sha256(b"MK1AI-9ZONE-ROTATE-v1:" + zone.value.encode("utf-8") + extra).digest()
        info = f"MK1AI-9ZONE-MASTER-v1|{zone.value}|epoch={new_epoch}".encode("utf-8")
        new_key = _hkdf_sha256(old_key, salt=salt, info=info, length=32)
        mk1_memory_guard.wipe_buffer(old_key)
        self._zone_master_keys[zone] = new_key
        self._zone_epochs[zone] = new_epoch
        return new_epoch

    def destroy_zone_key(self, zone: SecurityZone) -> None:
        """Zeroize a specific zone key (e.g. when a honeypot is compromised)."""
        buf = self._zone_master_keys.get(zone)
        if buf is not None:
            mk1_memory_guard.wipe_buffer(buf)

    def derive_envelope_subkey(
        self,
        zone: SecurityZone,
        *,
        caller_zone: SecurityZone,
        envelope_nonce: bytes,
        epoch: int | None = None,
    ) -> tuple[bytearray, str, int]:
        """Derive a single-use envelope subkey; fail closed on cross-zone access."""
        if zone != caller_zone:
            raise ZoneIsolationViolationError(
                f"Cross-zone key access denied: caller_zone={caller_zone.value} requested zone={zone.value}"
            )
        master_key = self._zone_master_keys.get(zone)
        if master_key is None or all(b == 0 for b in master_key):
            raise OneTapCryptoError(f"Zone key for {zone.value} has been destroyed or zeroized")
        active_epoch = self._zone_epochs[zone]
        if epoch is not None and epoch != active_epoch:
            raise OneTapCryptoError(f"Envelope epoch {epoch} does not match active zone epoch {active_epoch}")
        info = f"MK1AI-ONETAP-SUBKEY-v1|{zone.value}|epoch={active_epoch}".encode("utf-8")
        subkey = _hkdf_sha256(master_key, salt=envelope_nonce, info=info, length=32)
        key_id = hashlib.sha256(bytes(master_key) + zone.value.encode("utf-8")).hexdigest()[:16]
        return subkey, key_id, active_epoch


@dataclass(frozen=True)
class OneTapEnvelope:
    """Authenticated One-Tap encrypted envelope bound to a specific SecurityZone."""

    version: int
    zone: SecurityZone
    key_id: str
    epoch: int
    nonce_hex: str
    ciphertext_hex: str
    tag_hex: str
    aad_sha256_hex: str

    def header_bytes(self) -> bytes:
        hdr = {
            "version": self.version,
            "zone": self.zone.value,
            "key_id": self.key_id,
            "epoch": self.epoch,
            "nonce_hex": self.nonce_hex,
            "aad_sha256_hex": self.aad_sha256_hex,
        }
        return json.dumps(hdr, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def to_bytes(self) -> bytes:
        doc = {
            "version": self.version,
            "zone": self.zone.value,
            "key_id": self.key_id,
            "epoch": self.epoch,
            "nonce_hex": self.nonce_hex,
            "ciphertext_hex": self.ciphertext_hex,
            "tag_hex": self.tag_hex,
            "aad_sha256_hex": self.aad_sha256_hex,
        }
        return json.dumps(doc, sort_keys=True, separators=(",", ":")).encode("utf-8")

    @classmethod
    def from_bytes(cls, raw: bytes) -> "OneTapEnvelope":
        try:
            doc = json.loads(raw.decode("utf-8"))
            return cls(
                version=int(doc["version"]),
                zone=SecurityZone(doc["zone"]),
                key_id=str(doc["key_id"]),
                epoch=int(doc["epoch"]),
                nonce_hex=str(doc["nonce_hex"]),
                ciphertext_hex=str(doc["ciphertext_hex"]),
                tag_hex=str(doc["tag_hex"]),
                aad_sha256_hex=str(doc["aad_sha256_hex"]),
            )
        except Exception as exc:
            raise EnvelopeTamperError("Malformed One-Tap envelope structure") from exc


def one_tap_encrypt(
    vault: NineZoneKeyVault,
    *,
    zone: SecurityZone,
    plaintext: bytes,
    aad: bytes = b"",
) -> OneTapEnvelope:
    """Encrypt payload in one call with zone-isolated key derivation and immediate subkey wiping."""
    if not isinstance(plaintext, (bytes, bytearray)):
        raise TypeError("plaintext must be bytes")
    nonce = os.urandom(16)
    subkey, key_id, epoch = vault.derive_envelope_subkey(
        zone, caller_zone=zone, envelope_nonce=nonce
    )
    enc_key = bytearray()
    mac_key = bytearray()
    try:
        enc_key = _hkdf_sha256(subkey, salt=nonce, info=b"MK1AI-ONETAP-ENC-v1", length=32)
        mac_key = _hkdf_sha256(subkey, salt=nonce, info=b"MK1AI-ONETAP-MAC-v1", length=32)
        ciphertext = _stream_xor_sha256_ctr(enc_key, nonce, bytes(plaintext))
        aad_hash = hashlib.sha256(aad).hexdigest()
        envelope_unsigned = OneTapEnvelope(
            version=1,
            zone=zone,
            key_id=key_id,
            epoch=epoch,
            nonce_hex=nonce.hex(),
            ciphertext_hex=ciphertext.hex(),
            tag_hex="",
            aad_sha256_hex=aad_hash,
        )
        tag = hmac.new(
            bytes(mac_key),
            b"MK1AI-ONETAP-TAG-v1:" + envelope_unsigned.header_bytes() + aad + ciphertext,
            hashlib.sha256,
        ).hexdigest()
        return OneTapEnvelope(
            version=1,
            zone=zone,
            key_id=key_id,
            epoch=epoch,
            nonce_hex=nonce.hex(),
            ciphertext_hex=ciphertext.hex(),
            tag_hex=tag,
            aad_sha256_hex=aad_hash,
        )
    finally:
        mk1_memory_guard.wipe_buffer(subkey)
        mk1_memory_guard.wipe_buffer(enc_key)
        mk1_memory_guard.wipe_buffer(mac_key)


def one_tap_decrypt(
    vault: NineZoneKeyVault,
    *,
    caller_zone: SecurityZone,
    envelope: OneTapEnvelope,
    aad: bytes = b"",
) -> bytes:
    """Verify and decrypt a One-Tap envelope; fail closed on cross-zone access or any tampering."""
    if envelope.version != 1:
        raise EnvelopeTamperError(f"Unsupported envelope version: {envelope.version}")
    if envelope.zone != caller_zone:
        raise ZoneIsolationViolationError(
            f"Cross-zone decryption denied: caller_zone={caller_zone.value} cannot decrypt {envelope.zone.value}"
        )
    try:
        nonce = bytes.fromhex(envelope.nonce_hex)
        ciphertext = bytes.fromhex(envelope.ciphertext_hex)
    except ValueError as exc:
        raise EnvelopeTamperError("Invalid hex in envelope nonce or ciphertext") from exc
    if len(nonce) != 16:
        raise EnvelopeTamperError("Invalid nonce length")

    aad_hash = hashlib.sha256(aad).hexdigest()
    if not hmac.compare_digest(aad_hash, envelope.aad_sha256_hex):
        raise EnvelopeTamperError("Envelope AAD digest mismatch")

    subkey, expected_key_id, _ = vault.derive_envelope_subkey(
        envelope.zone,
        caller_zone=caller_zone,
        envelope_nonce=nonce,
        epoch=envelope.epoch,
    )
    enc_key = bytearray()
    mac_key = bytearray()
    try:
        if not hmac.compare_digest(expected_key_id, envelope.key_id):
            raise EnvelopeTamperError("Envelope key_id mismatch")
        enc_key = _hkdf_sha256(subkey, salt=nonce, info=b"MK1AI-ONETAP-ENC-v1", length=32)
        mac_key = _hkdf_sha256(subkey, salt=nonce, info=b"MK1AI-ONETAP-MAC-v1", length=32)
        expected_tag = hmac.new(
            bytes(mac_key),
            b"MK1AI-ONETAP-TAG-v1:" + envelope.header_bytes() + aad + ciphertext,
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(expected_tag.lower(), envelope.tag_hex.lower()):
            raise EnvelopeTamperError("Envelope authentication tag verification failed")
        return _stream_xor_sha256_ctr(enc_key, nonce, ciphertext)
    finally:
        mk1_memory_guard.wipe_buffer(subkey)
        mk1_memory_guard.wipe_buffer(enc_key)
        mk1_memory_guard.wipe_buffer(mac_key)


class CryptoPostureTracker:
    """Strictly separates QKD, PQC, Classical KEX/Signatures, and Symmetric Ratchet status."""

    def __init__(
        self,
        *,
        qkd_kme_connected: bool = False,
        qkd_authenticated_channel: bool = False,
        pqc_ml_kem_768_available: bool = False,
        classical_ed25519_available: bool = True,
        symmetric_ratchet_active: bool = True,
    ) -> None:
        self._qkd_kme_connected = bool(qkd_kme_connected)
        self._qkd_authenticated_channel = bool(qkd_authenticated_channel)
        self._pqc_ml_kem_768_available = bool(pqc_ml_kem_768_available)
        self._classical_ed25519_available = bool(classical_ed25519_available)
        self._symmetric_ratchet_active = bool(symmetric_ratchet_active)

    def get_posture_report(self) -> dict[str, Any]:
        """Return non-conflated cryptographic posture report across all 4 dimensions."""
        qkd_ready = self._qkd_kme_connected and self._qkd_authenticated_channel
        return {
            "qkd": {
                "status": "QKD_ACTIVE_ETSI_014" if qkd_ready else "QKD_UNAVAILABLE",
                "kme_hardware_connected": self._qkd_kme_connected,
                "authenticated_classical_channel": self._qkd_authenticated_channel,
                "conflated_with_pqc": False,
            },
            "pqc": {
                "algorithm": "ML-KEM-768",
                "status": "PQC_ACTIVE" if self._pqc_ml_kem_768_available else "PQC_LIB_NOT_INSTALLED",
            },
            "classical_asymmetric": {
                "signature_algorithm": "Ed25519 (RFC 8032)",
                "status": "ACTIVE" if self._classical_ed25519_available else "UNAVAILABLE",
            },
            "symmetric_and_ratchet": {
                "one_tap_aead": "ACTIVE_9ZONE_ISOLATED",
                "session_ratchet": "ACTIVE_FORWARD_SECURE" if self._symmetric_ratchet_active else "INACTIVE",
            },
        }
