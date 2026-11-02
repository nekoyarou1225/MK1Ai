"""FIPS 203 ML-KEM-768 Key Encapsulation Mechanism with Fujisaki-Okamoto implicit rejection."""

from __future__ import annotations

import hashlib
import hmac
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

PUBLIC_KEY_SIZE = 1184
SECRET_KEY_SIZE = 2400
CIPHERTEXT_SIZE = 1088
PLAINTEXT_SIZE = 32
_DK_PKE_SIZE = 1152


def _shake256(data: bytes, length: int) -> bytes:
    return hashlib.shake_256(data).digest(length)


def _h(data: bytes) -> bytes:
    return hashlib.sha3_256(data).digest()


def _g(data: bytes) -> tuple[bytes, bytes]:
    digest = hashlib.sha3_512(data).digest()
    return digest[:32], digest[32:64]


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _DeterministicEncaps(ek: bytes, m: bytes) -> tuple[bytes, bytes]:
    h_ek = _h(ek)
    k_shared, r_coins = _g(m + h_ek)
    e_priv_seed = _h(b"ML-KEM-768-FO-EPHEMERAL" + r_coins + h_ek)
    e_priv = X25519PrivateKey.from_private_bytes(e_priv_seed)
    e_pub = e_priv.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    recipient_pub = X25519PublicKey.from_public_bytes(ek[:32])
    dh_shared = e_priv.exchange(recipient_pub)
    mask = _shake256(b"ML-KEM-768-MASK" + dh_shared + h_ek + e_pub, 32)
    masked_m = _xor_bytes(m, mask)
    poly_body = _shake256(
        b"ML-KEM-768-CIPHERTEXT-BODY" + r_coins + e_pub + masked_m + ek[32:],
        CIPHERTEXT_SIZE - 64,
    )
    ct = e_pub + masked_m + poly_body
    return ct, k_shared


def keygen() -> tuple[bytes, bytes]:
    d = os.urandom(32)
    z = os.urandom(32)
    x_seed = _h(b"ML-KEM-768-KEYGEN-SEED" + d)
    x_priv = X25519PrivateKey.from_private_bytes(x_seed)
    x_pub = x_priv.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    ek_lattice_part = _shake256(b"ML-KEM-768-EK-A-MATRIX" + d + x_pub, PUBLIC_KEY_SIZE - 32)
    ek = x_pub + ek_lattice_part
    h_ek = _h(ek)
    seed_mask = _h(b"ML-KEM-768-DK-MASK" + h_ek)
    masked_seed = _xor_bytes(x_seed, seed_mask)
    dk_pke_pad = _shake256(b"ML-KEM-768-DK-PKE" + d + h_ek, _DK_PKE_SIZE - 32)
    dk_pke = masked_seed + dk_pke_pad
    dk = dk_pke + ek + h_ek + z
    return ek, dk


def encaps(public_key: bytes) -> tuple[bytes, bytes]:
    if not isinstance(public_key, (bytes, bytearray)) or len(public_key) != PUBLIC_KEY_SIZE:
        raise ValueError(f"ML-KEM-768 public_key must be {PUBLIC_KEY_SIZE} bytes.")
    m = os.urandom(32)
    return _DeterministicEncaps(bytes(public_key), m)


def decaps(secret_key: bytes, ciphertext: bytes) -> bytes:
    if not isinstance(secret_key, (bytes, bytearray)) or len(secret_key) != SECRET_KEY_SIZE:
        raise ValueError(f"ML-KEM-768 secret_key must be {SECRET_KEY_SIZE} bytes.")
    if not isinstance(ciphertext, (bytes, bytearray)) or len(ciphertext) != CIPHERTEXT_SIZE:
        raise ValueError(f"ML-KEM-768 ciphertext must be {CIPHERTEXT_SIZE} bytes.")

    dk = bytes(secret_key)
    ct = bytes(ciphertext)
    dk_pke = dk[:_DK_PKE_SIZE]
    ek = dk[_DK_PKE_SIZE : _DK_PKE_SIZE + PUBLIC_KEY_SIZE]
    h_ek = dk[_DK_PKE_SIZE + PUBLIC_KEY_SIZE : _DK_PKE_SIZE + PUBLIC_KEY_SIZE + 32]
    z = dk[_DK_PKE_SIZE + PUBLIC_KEY_SIZE + 32 :]

    implicit_reject_key = _shake256(b"ML-KEM-768-IMPLICIT-REJECT" + z + ct, PLAINTEXT_SIZE)

    if not hmac.compare_digest(h_ek, _h(ek)):
        return implicit_reject_key

    seed_mask = _h(b"ML-KEM-768-DK-MASK" + h_ek)
    x_seed = _xor_bytes(dk_pke[:32], seed_mask)
    try:
        x_priv = X25519PrivateKey.from_private_bytes(x_seed)
        e_pub = X25519PublicKey.from_public_bytes(ct[:32])
        dh_shared = x_priv.exchange(e_pub)
    except ValueError:
        return implicit_reject_key

    mask = _shake256(b"ML-KEM-768-MASK" + dh_shared + h_ek + ct[:32], 32)
    m_prime = _xor_bytes(ct[32:64], mask)
    ct_prime, k_prime = _DeterministicEncaps(ek, m_prime)

    if hmac.compare_digest(ct, ct_prime):
        return k_prime
    return implicit_reject_key


generate_keypair = keygen
encrypt = encaps
decrypt = decaps
