"""User-rooted key derivation with optional, non-authoritative factors."""

from __future__ import annotations

import hashlib
import importlib.machinery
import importlib.util
import os
import struct
import sys
import warnings
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

import argon2 as _argon2_mod
import cryptography as _cryptography_mod
from argon2 import Type
from argon2.low_level import hash_secret_raw
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class KeyDerivationError(RuntimeError):
    """Raised when key derivation cannot safely meet its minimum policy."""


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
    argon2_native = _is_native_c_extension_loaded(_argon2_mod, "argon2")
    cryptography_native = _is_native_c_extension_loaded(_cryptography_mod, "cryptography")
    status = {
        "argon2_native_c_extension": argon2_native,
        "cryptography_native_c_extension": cryptography_native,
        "production_mode": bool(production_mode),
        "fallback_shadowing_detected": not (argon2_native and cryptography_native),
    }
    if production_mode and not (argon2_native and cryptography_native):
        raise RuntimeError(
            "FAIL_CLOSED_BLOCK: Production mode requires native C-extension providers for "
            f"argon2 and cryptography (status={status})"
        )
    return status


MIN_PASSPHRASE_BYTES = 20
SALT_BYTES = 16
KEY_BYTES = 32
MIN_MEMORY_KIB = 64 * 1024
MAX_MEMORY_KIB = 256 * 1024
MIN_TIME_COST = 3
MAX_TIME_COST = 6
PARALLELISM = 1
LOW_MEMORY_WARNING_BYTES = 1024 * 1024 * 1024
MIN_SAFE_AVAILABLE_BYTES = 2 * MIN_MEMORY_KIB * 1024
MIN_OPTIONAL_FACTOR_BYTES = 16
MAX_FACTOR_BYTES = 4096


@dataclass
class DerivedKey:
    salt: bytes
    key: bytearray = field(repr=False)
    memory_kib: int
    time_cost: int
    low_memory: bool
    _secure_buffer: mk1_memory_guard.SecureBuffer | None = field(
        default=None, init=False, repr=False, compare=False,
    )

    def __post_init__(self) -> None:
        if isinstance(self.key, bytearray) and len(self.key) > 0:
            self._secure_buffer = mk1_memory_guard.SecureBuffer(
                self.key, wipe_source=False,
            )

    @property
    def secure_buffer(self) -> mk1_memory_guard.SecureBuffer | None:
        return self._secure_buffer

    def destroy(self) -> None:
        if self._secure_buffer is not None:
            self._secure_buffer.zeroize()
        mk1_memory_guard.wipe_buffer(self.key)


def _available_memory_bytes() -> int:
    available_kib: int | None = None
    with open("/proc/meminfo", "r", encoding="ascii") as meminfo:
        for line in meminfo:
            if line.startswith("MemAvailable:"):
                value = line.split()
                if len(value) != 3 or value[2] != "kB":
                    break
                available_kib = int(value[1])
                break
    if available_kib is None or available_kib <= 0:
        raise KeyDerivationError("Cannot determine available memory for Argon2id")
    return available_kib * 1024


def _parameters_for_memory(available_bytes: int) -> tuple[int, int, bool]:
    if isinstance(available_bytes, bool) or not isinstance(available_bytes, int):
        raise TypeError("Available memory must be an integer byte count")
    if available_bytes < MIN_SAFE_AVAILABLE_BYTES:
        raise KeyDerivationError(
            "Insufficient available memory for the minimum Argon2id policy",
        )
    memory_kib = min(
        MAX_MEMORY_KIB,
        max(MIN_MEMORY_KIB, available_bytes // (8 * 1024)),
    )
    memory_steps = (memory_kib - MIN_MEMORY_KIB) // (64 * 1024)
    time_cost = min(MAX_TIME_COST, MIN_TIME_COST + memory_steps)
    return (
        memory_kib,
        time_cost,
        available_bytes < LOW_MEMORY_WARNING_BYTES,
    )


def _validated_factor(value: bytes | bytearray | None, name: str) -> bytearray:
    if value is None:
        return bytearray()
    if not isinstance(value, (bytes, bytearray)):
        raise TypeError(f"{name} must be bytes, bytearray, or None")
    if not MIN_OPTIONAL_FACTOR_BYTES <= len(value) <= MAX_FACTOR_BYTES:
        raise ValueError(
            f"{name} must contain {MIN_OPTIONAL_FACTOR_BYTES} "
            f"to {MAX_FACTOR_BYTES} bytes",
        )
    return bytearray(value)


def derive_user_root_key(
    passphrase: str,
    *,
    hardware_factor: bytes | bytearray | None = None,
    fido2_factor: bytes | bytearray | None = None,
    salt: bytes | None = None,
    production_mode: bool | None = None,
) -> DerivedKey:
    """Derive a user-rooted key; optional factors can never replace the user factor."""
    verify_crypto_provider_integrity(production_mode=production_mode)
    if not isinstance(passphrase, str):
        raise TypeError("Passphrase must be text")
    password_buffer = bytearray(passphrase.encode("utf-8"))
    if len(password_buffer) < MIN_PASSPHRASE_BYTES:
        mk1_memory_guard.wipe_buffer(password_buffer)
        raise ValueError(
            f"Passphrase must contain at least {MIN_PASSPHRASE_BYTES} UTF-8 bytes",
        )
    if len(password_buffer) > MAX_FACTOR_BYTES:
        mk1_memory_guard.wipe_buffer(password_buffer)
        raise ValueError("Passphrase exceeds the maximum supported length")
    if salt is None:
        salt = os.urandom(SALT_BYTES)
    elif not isinstance(salt, bytes) or len(salt) != SALT_BYTES:
        mk1_memory_guard.wipe_buffer(password_buffer)
        raise ValueError(f"Salt must be exactly {SALT_BYTES} bytes")

    hardware = _validated_factor(hardware_factor, "hardware_factor")
    authenticator = _validated_factor(fido2_factor, "fido2_factor")
    try:
        memory_kib, time_cost, low_memory = _parameters_for_memory(
            _available_memory_bytes(),
        )
    except Exception:
        mk1_memory_guard.wipe_buffer(password_buffer)
        mk1_memory_guard.wipe_buffer(hardware)
        mk1_memory_guard.wipe_buffer(authenticator)
        raise
    if low_memory:
        warnings.warn(
            "Low available memory: Argon2id parameters are constrained by the low-memory policy",
            RuntimeWarning,
            stacklevel=2,
        )

    with mk1_memory_guard.SecureBuffer(password_buffer) as secure_password:
        user_key = bytearray()
        factor_material = bytearray()
        try:
            user_key.extend(hash_secret_raw(
                secret=bytes(secure_password.raw_buffer),
                salt=salt,
                time_cost=time_cost,
                memory_cost=memory_kib,
                parallelism=PARALLELISM,
                hash_len=KEY_BYTES,
                type=Type.ID,
            ))
            mk1_memory_guard.lock_buffer(user_key)
            factor_material.extend(b"MK1-optional-factors-v1\0")
            factor_material.extend(struct.pack(">I", len(hardware)))
            factor_material.extend(hardware)
            factor_material.extend(struct.pack(">I", len(authenticator)))
            factor_material.extend(authenticator)
            factor_salt = hashlib.sha384(factor_material).digest()
            derived = HKDF(
                algorithm=hashes.SHA384(),
                length=KEY_BYTES,
                salt=factor_salt,
                info=b"MK1-user-root-key-v1",
            ).derive(user_key)
            result_key = bytearray(derived)
            del derived
            try:
                mk1_memory_guard.lock_buffer(result_key)
            except OSError:
                mk1_memory_guard.wipe_buffer(result_key)
                raise
            return DerivedKey(
                salt=salt,
                key=result_key,
                memory_kib=memory_kib,
                time_cost=time_cost,
                low_memory=low_memory,
            )
        finally:
            mk1_memory_guard.wipe_buffer(user_key)
            mk1_memory_guard.wipe_buffer(factor_material)
            mk1_memory_guard.wipe_buffer(hardware)
            mk1_memory_guard.wipe_buffer(authenticator)

