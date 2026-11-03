"""Hybrid ML-KEM-1024 and X25519 agreement with WireGuard-PSK binding."""

from __future__ import annotations

import hashlib
import hmac
import importlib.machinery
import os
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path

import mk1_memory_guard

_WORKSPACE_ROOT = str(Path(__file__).resolve().parent)


def _prioritize_native_site_packages() -> None:
    """Reorder sys.path so compiled C-extension site-packages precede workspace fallbacks."""
    workspace_entries: list[str] = []
    system_entries: list[str] = []
    for entry in sys.path:
        resolved = str(Path(entry or ".").resolve())
        if resolved == _WORKSPACE_ROOT:
            workspace_entries.append(entry)
        else:
            system_entries.append(entry)
    if system_entries and workspace_entries:
        sys.path[:] = system_entries + workspace_entries


_prioritize_native_site_packages()

import cryptography as _cryptography_mod
import pqcrypto as _pqcrypto_mod
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pqcrypto.kem.ml_kem_1024 import decaps, encaps


class HybridKEMError(ValueError):
    """Raised when hybrid key material or protocol context is invalid."""


def _is_native_c_extension_loaded(module: object, package_name: str) -> bool:
    if getattr(module, "_MK1_PURE_PYTHON_FALLBACK", False):
        return False
    mod_file = getattr(module, "__file__", "") or ""
    if mod_file and str(Path(mod_file).resolve()).startswith(_WORKSPACE_ROOT + os.sep):
        return False
    for name, loaded in list(sys.modules.items()):
        if name == package_name or name.startswith(package_name + "."):
            loaded_file = getattr(loaded, "__file__", "") or ""
            if any(
                loaded_file.endswith(ext)
                for ext in importlib.machinery.EXTENSION_SUFFIXES
            ):
                return True
    return not getattr(module, "_MK1_PURE_PYTHON_FALLBACK", False)


def verify_crypto_provider_integrity(
    *,
    production_mode: bool | None = None,
) -> dict[str, object]:
    """Verify whether native C-extension crypto providers are active vs workspace fallbacks.

    In production mode (`production_mode=True` or `MK1_PRODUCTION_MODE=1`), raises
    RuntimeError (FAIL_CLOSED_BLOCK) if native C extensions are absent or shadowed.
    """
    if production_mode is None:
        production_mode = os.environ.get("MK1_PRODUCTION_MODE", "0").strip() in (
            "1",
            "true",
            "TRUE",
            "yes",
        )
    pqcrypto_native = _is_native_c_extension_loaded(_pqcrypto_mod, "pqcrypto")
    cryptography_native = _is_native_c_extension_loaded(_cryptography_mod, "cryptography")
    status = {
        "pqcrypto_native_c_extension": pqcrypto_native,
        "cryptography_native_c_extension": cryptography_native,
        "production_mode": bool(production_mode),
        "fallback_shadowing_detected": not (pqcrypto_native and cryptography_native),
    }
    if production_mode and not (pqcrypto_native and cryptography_native):
        raise RuntimeError(
            "FAIL_CLOSED_BLOCK: Production mode requires native C-extension providers for "
            f"pqcrypto and cryptography (status={status})"
        )
    return status


SUITE_ID = b"MK1-HYBRID-ML-KEM-1024-X25519-WG-PSK-v1"
ML_KEM_1024_PUBLIC_KEY_BYTES = 1568
ML_KEM_1024_SECRET_KEY_BYTES = 3168
ML_KEM_1024_CIPHERTEXT_BYTES = 1568
SHARED_SECRET_BYTES = 32
WIREGUARD_PSK_BYTES = 32
MAX_TRANSCRIPT_BYTES = 64 * 1024


@dataclass
class HybridEncapsulation:
    kem_ciphertext: bytes
    client_x25519_public_key: bytes
    shared_secret: bytearray = field(repr=False)
    _secure_buffer: mk1_memory_guard.SecureBuffer | None = field(
        default=None, init=False, repr=False, compare=False,
    )

    def __post_init__(self) -> None:
        if isinstance(self.shared_secret, bytearray) and len(self.shared_secret) > 0:
            self._secure_buffer = mk1_memory_guard.SecureBuffer(
                self.shared_secret, wipe_source=False,
            )

    @property
    def secure_buffer(self) -> mk1_memory_guard.SecureBuffer | None:
        return self._secure_buffer

    def destroy(self) -> None:
        if self._secure_buffer is not None:
            self._secure_buffer.zeroize()
        mk1_memory_guard.wipe_buffer(self.shared_secret)


def generate_x25519_keypair() -> tuple[X25519PrivateKey, bytes]:
    private_key = X25519PrivateKey.generate()
    return private_key, private_key.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw,
    )


def _validate_transcript(transcript: bytes) -> None:
    if not isinstance(transcript, bytes):
        raise TypeError("Transcript context must be bytes")
    if not transcript or len(transcript) > MAX_TRANSCRIPT_BYTES:
        raise HybridKEMError(
            f"Transcript context must contain 1 to {MAX_TRANSCRIPT_BYTES} bytes",
        )


def _validate_wireguard_psk(psk: bytes | bytearray) -> None:
    if not isinstance(psk, (bytes, bytearray)):
        raise TypeError("WireGuard preshared key must be bytes")
    if len(psk) != WIREGUARD_PSK_BYTES:
        raise HybridKEMError("A 32-byte WireGuard preshared key is required")


def _validate_public_key(key: bytes, size: int, name: str) -> None:
    if not isinstance(key, bytes) or len(key) != size:
        raise HybridKEMError(f"{name} must contain exactly {size} bytes")


def _combine(
    mlkem_secret: bytearray,
    x25519_secret: bytearray,
    wireguard_psk: bytes | bytearray,
    transcript: bytes,
    *,
    kem_ciphertext: bytes,
    client_public_key: bytes,
    server_public_key: bytes,
) -> bytearray:
    _validate_transcript(transcript)
    _validate_wireguard_psk(wireguard_psk)
    if len(mlkem_secret) != SHARED_SECRET_BYTES:
        raise HybridKEMError("ML-KEM-1024 returned an invalid shared-secret length")
    if len(x25519_secret) != SHARED_SECRET_BYTES:
        raise HybridKEMError("X25519 returned an invalid shared-secret length")

    transcript_hash = hashlib.sha384(b"".join((
        SUITE_ID,
        struct.pack(">I", len(transcript)),
        transcript,
        struct.pack(">I", len(kem_ciphertext)),
        kem_ciphertext,
        client_public_key,
        server_public_key,
    ))).digest()
    material = bytearray(
        mlkem_secret + x25519_secret + bytearray(wireguard_psk),
    )
    with mk1_memory_guard.SecureBuffer(material) as secure_material:
        derived = HKDF(
            algorithm=hashes.SHA384(),
            length=SHARED_SECRET_BYTES,
            salt=transcript_hash,
            info=SUITE_ID,
        ).derive(bytes(secure_material.raw_buffer))
        result = bytearray(derived)
        del derived
        try:
            mk1_memory_guard.lock_buffer(result)
        except OSError:
            mk1_memory_guard.wipe_buffer(result)
            raise
        return result


def encapsulate(
    kem_public_key: bytes,
    server_x25519_public_key: bytes,
    wireguard_psk: bytes | bytearray,
    transcript: bytes,
    *,
    production_mode: bool | None = None,
) -> HybridEncapsulation:
    verify_crypto_provider_integrity(production_mode=production_mode)
    _validate_public_key(
        kem_public_key, ML_KEM_1024_PUBLIC_KEY_BYTES, "ML-KEM-1024 public key",
    )
    _validate_public_key(server_x25519_public_key, 32, "X25519 public key")
    _validate_transcript(transcript)
    _validate_wireguard_psk(wireguard_psk)
    try:
        server_public = X25519PublicKey.from_public_bytes(server_x25519_public_key)
        kem_ciphertext, kem_secret_bytes = encaps(kem_public_key)
        kem_secret = bytearray(kem_secret_bytes)
        del kem_secret_bytes
        ephemeral_private = X25519PrivateKey.generate()
        x25519_secret = bytearray(ephemeral_private.exchange(server_public))
        client_public = ephemeral_private.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw,
        )
        with (
            mk1_memory_guard.SecureBuffer(kem_secret) as secure_kem,
            mk1_memory_guard.SecureBuffer(x25519_secret) as secure_x25519,
        ):
            combined = _combine(
                secure_kem.raw_buffer,
                secure_x25519.raw_buffer,
                wireguard_psk,
                transcript,
                kem_ciphertext=kem_ciphertext,
                client_public_key=client_public,
                server_public_key=server_x25519_public_key,
            )
            return HybridEncapsulation(
                kem_ciphertext=kem_ciphertext,
                client_x25519_public_key=client_public,
                shared_secret=combined,
            )
    except (ValueError, TypeError) as exc:
        if isinstance(exc, HybridKEMError):
            raise
        raise HybridKEMError("Hybrid encapsulation failed") from exc


def decapsulate(
    kem_secret_key: bytes,
    server_x25519_private_key: X25519PrivateKey,
    kem_ciphertext: bytes,
    client_x25519_public_key: bytes,
    wireguard_psk: bytes | bytearray,
    transcript: bytes,
    *,
    production_mode: bool | None = None,
) -> bytearray:
    verify_crypto_provider_integrity(production_mode=production_mode)
    _validate_public_key(
        kem_secret_key, ML_KEM_1024_SECRET_KEY_BYTES, "ML-KEM-1024 secret key",
    )
    _validate_public_key(
        kem_ciphertext, ML_KEM_1024_CIPHERTEXT_BYTES, "ML-KEM-1024 ciphertext",
    )
    _validate_public_key(client_x25519_public_key, 32, "client X25519 public key")
    if not isinstance(server_x25519_private_key, X25519PrivateKey):
        raise TypeError("Server X25519 private key must be an X25519PrivateKey")
    _validate_transcript(transcript)
    _validate_wireguard_psk(wireguard_psk)
    server_public = server_x25519_private_key.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw,
    )
    try:
        client_public = X25519PublicKey.from_public_bytes(client_x25519_public_key)
        kem_secret = bytearray(decaps(kem_secret_key, kem_ciphertext))
        x25519_secret = bytearray(server_x25519_private_key.exchange(client_public))
        with (
            mk1_memory_guard.SecureBuffer(kem_secret) as secure_kem,
            mk1_memory_guard.SecureBuffer(x25519_secret) as secure_x25519,
        ):
            return _combine(
                secure_kem.raw_buffer,
                secure_x25519.raw_buffer,
                wireguard_psk,
                transcript,
                kem_ciphertext=kem_ciphertext,
                client_public_key=client_x25519_public_key,
                server_public_key=server_public,
            )
    except (ValueError, TypeError) as exc:
        if isinstance(exc, HybridKEMError):
            raise
        raise HybridKEMError("Hybrid decapsulation failed") from exc


def verify_hybrid_key_fingerprint(
    kem_public_key: bytes,
    x25519_public_key: bytes,
    expected_fingerprint: str,
) -> str:
    _validate_public_key(
        kem_public_key, ML_KEM_1024_PUBLIC_KEY_BYTES, "ML-KEM-1024 public key",
    )
    _validate_public_key(x25519_public_key, 32, "X25519 public key")
    if not isinstance(expected_fingerprint, str) or not hmac.compare_digest(
        hashlib.sha384(SUITE_ID + kem_public_key + x25519_public_key).hexdigest(),
        expected_fingerprint.lower(),
    ):
        raise HybridKEMError("Hybrid key fingerprint does not match")
    return hashlib.sha384(SUITE_ID + kem_public_key + x25519_public_key).hexdigest()

