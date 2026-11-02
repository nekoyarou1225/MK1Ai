"""RFC 7748 X25519 Elliptic Curve Diffie-Hellman key exchange implementation."""

from __future__ import annotations

import hmac
import os

from cryptography.hazmat.primitives import serialization

_P = (1 << 255) - 19
_A24 = 121665  # (486662 - 2) // 4


def _clamp_scalar(scalar_bytes: bytes) -> int:
    b = bytearray(scalar_bytes)
    b[0] &= 248
    b[31] &= 127
    b[31] |= 64
    return int.from_bytes(b, "little")


def _decode_u_coordinate(u_bytes: bytes) -> int:
    b = bytearray(u_bytes)
    b[31] &= 127  # Mask most significant bit per RFC 7748 Section 5
    return int.from_bytes(b, "little") % _P


def _x25519_scalar_mult(k: int, u: int) -> bytes:
    x_1 = u
    x_2 = 1
    z_2 = 0
    x_3 = u
    z_3 = 1
    swap = 0

    for t in range(254, -1, -1):
        k_t = (k >> t) & 1
        swap ^= k_t
        if swap:
            x_2, x_3 = x_3, x_2
            z_2, z_3 = z_3, z_2
        swap = k_t

        a = (x_2 + z_2) % _P
        aa = (a * a) % _P
        b = (x_2 - z_2) % _P
        bb = (b * b) % _P
        e = (aa - bb) % _P
        c = (x_3 + z_3) % _P
        d = (x_3 - z_3) % _P
        da = (d * a) % _P
        cb = (c * b) % _P
        sum_dacb = (da + cb) % _P
        diff_dacb = (da - cb) % _P
        x_3 = (sum_dacb * sum_dacb) % _P
        z_3 = (x_1 * ((diff_dacb * diff_dacb) % _P)) % _P
        x_2 = (aa * bb) % _P
        z_2 = (e * (aa + (_A24 * e) % _P)) % _P

    if swap:
        x_2, x_3 = x_3, x_2
        z_2, z_3 = z_3, z_2

    shared = (x_2 * pow(z_2, _P - 2, _P)) % _P
    return shared.to_bytes(32, "little")


class X25519PublicKey:
    def __init__(self, public_bytes: bytes) -> None:
        if not isinstance(public_bytes, (bytes, bytearray)) or len(public_bytes) != 32:
            raise ValueError("An X25519 public key is 32 bytes long")
        self._raw = bytes(public_bytes)

    @classmethod
    def from_public_bytes(cls, data: bytes) -> "X25519PublicKey":
        if not isinstance(data, (bytes, bytearray)) or len(data) != 32:
            raise ValueError("An X25519 public key is 32 bytes long")
        return cls(bytes(data))

    def public_bytes(
        self,
        encoding: serialization.Encoding,
        format: serialization.PublicFormat,
    ) -> bytes:
        if encoding is serialization.Encoding.Raw or format is serialization.PublicFormat.Raw:
            if (
                encoding is not serialization.Encoding.Raw
                or format is not serialization.PublicFormat.Raw
            ):
                raise ValueError("Raw encoding and Raw format must be used together.")
            return self._raw
        if format is not serialization.PublicFormat.SubjectPublicKeyInfo:
            raise ValueError("X25519 public keys require SubjectPublicKeyInfo or Raw format.")
        der = serialization.X25519_SPKI_PREFIX + self._raw
        if encoding is serialization.Encoding.DER:
            return der
        if encoding is serialization.Encoding.PEM:
            return serialization.encode_pem(der, "PUBLIC KEY")
        raise ValueError(f"Unsupported encoding: {encoding}")

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, X25519PublicKey):
            return False
        return hmac.compare_digest(self._raw, other._raw)


class X25519PrivateKey:
    def __init__(self, private_bytes: bytes) -> None:
        if not isinstance(private_bytes, (bytes, bytearray)) or len(private_bytes) != 32:
            raise ValueError("An X25519 private key is 32 bytes long")
        self._raw = bytes(private_bytes)
        self._scalar = _clamp_scalar(self._raw)
        self._public_raw = _x25519_scalar_mult(self._scalar, 9)

    @classmethod
    def generate(cls) -> "X25519PrivateKey":
        return cls(os.urandom(32))

    @classmethod
    def from_private_bytes(cls, data: bytes) -> "X25519PrivateKey":
        if not isinstance(data, (bytes, bytearray)) or len(data) != 32:
            raise ValueError("An X25519 private key is 32 bytes long")
        return cls(bytes(data))

    def public_key(self) -> X25519PublicKey:
        return X25519PublicKey(self._public_raw)

    def exchange(self, peer_public_key: X25519PublicKey) -> bytes:
        if not isinstance(peer_public_key, X25519PublicKey):
            raise TypeError("Expected X25519PublicKey.")
        u = _decode_u_coordinate(peer_public_key._raw)
        shared = _x25519_scalar_mult(self._scalar, u)
        # RFC 7748 Section 6.1: Reject all-zero output (low-order public key)
        if hmac.compare_digest(shared, b"\x00" * 32):
            raise ValueError("Low-order X25519 public key produced all-zero shared secret.")
        return shared

    def private_bytes(
        self,
        encoding: serialization.Encoding,
        format: serialization.PrivateFormat,
        encryption_algorithm: serialization.KeySerializationEncryption,
    ) -> bytes:
        if not isinstance(encryption_algorithm, serialization.NoEncryption):
            raise ValueError("Only NoEncryption is supported.")
        if encoding is serialization.Encoding.Raw or format is serialization.PrivateFormat.Raw:
            if (
                encoding is not serialization.Encoding.Raw
                or format is not serialization.PrivateFormat.Raw
            ):
                raise ValueError("Raw encoding and Raw format must be used together.")
            return self._raw
        if format is not serialization.PrivateFormat.PKCS8:
            raise ValueError("X25519 private keys require PKCS8 or Raw format.")
        der = serialization.X25519_PKCS8_PREFIX + self._raw
        if encoding is serialization.Encoding.DER:
            return der
        if encoding is serialization.Encoding.PEM:
            return serialization.encode_pem(der, "PRIVATE KEY")
        raise ValueError(f"Unsupported encoding: {encoding}")
