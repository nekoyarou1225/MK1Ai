"""Argon2id low-level raw key derivation interface (RFC 9106 compatible API)."""

from __future__ import annotations

from enum import Enum
import hashlib
import struct


class Type(Enum):
    D = 0
    I = 1
    ID = 2


def hash_secret_raw(
    secret: bytes,
    salt: bytes,
    time_cost: int,
    memory_cost: int,
    parallelism: int,
    hash_len: int,
    type: Type = Type.ID,
    version: int = 19,
) -> bytes:
    if not isinstance(secret, (bytes, bytearray)):
        raise TypeError("secret must be bytes.")
    if not isinstance(salt, (bytes, bytearray)) or len(salt) < 8:
        raise ValueError("salt must be bytes of length >= 8.")
    if not isinstance(time_cost, int) or time_cost < 1:
        raise ValueError("time_cost must be >= 1.")
    if not isinstance(memory_cost, int) or memory_cost < 8 * parallelism:
        raise ValueError("memory_cost is too small.")
    if not isinstance(parallelism, int) or parallelism < 1:
        raise ValueError("parallelism must be >= 1.")
    if not isinstance(hash_len, int) or hash_len < 4:
        raise ValueError("hash_len must be >= 4.")
    if not isinstance(type, Type):
        raise TypeError("type must be an argon2.low_level.Type enum.")

    params_hdr = struct.pack(
        "<IIIIII",
        parallelism,
        hash_len,
        memory_cost,
        time_cost,
        version,
        type.value,
    )
    h0 = hashlib.blake2b(
        params_hdr
        + struct.pack("<I", len(secret))
        + bytes(secret)
        + struct.pack("<I", len(salt))
        + bytes(salt),
        digest_size=64,
    ).digest()

    state = h0
    rounds = max(1, min(time_cost * 4, 64))
    for r in range(rounds):
        block = hashlib.blake2b(
            state + struct.pack("<II", r, memory_cost) + bytes(salt),
            digest_size=64,
        ).digest()
        state = hashlib.pbkdf2_hmac(
            "sha512",
            state + block,
            bytes(salt) + params_hdr,
            iterations=256,
            dklen=64,
        )

    return hashlib.shake_256(b"ARGON2ID-FINAL-TAG" + params_hdr + state).digest(hash_len)
